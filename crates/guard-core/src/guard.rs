//! La máquina de estados: entra una orden con la hora, sale el resultado y
//! quedan anotados los eventos.

use serde::{Deserialize, Serialize};

use crate::approval::{parse_server_key, signature_is_valid, Approval};
use crate::clock::{TimePoint, TrustedClock};
use crate::error::GuardError;
use crate::event::{to_hex, Authorizer, Category, Envelope, EventId, EventKind, EventLog, Tamper};
use crate::mode::{normalize_domain, Action, Mode, Settings, Tightening};
use crate::notify::{urgency_of, AccessWindows, Heartbeat};
use crate::secret::{
    Failures, GuardianId, GuardianInfo, GuardianRecord, NewGuardian, RecoveryCode, ENTROPY_LEN,
    FAILURES_BEFORE_ALERT, MAX_GUARDIANS,
};
use crate::state::{open, seal, OpenError};
use crate::unlock::{Requests, UnlockRequest, DELAY_GRANT_SECS};

/// Lo que dura el permiso que da un guardián, con su clave o a distancia.
pub const SECRET_GRANT_SECS: u64 = 600;

/// Identificador del dispositivo: 16 bytes aleatorios que el agente genera al
/// instalar. Liga las aprobaciones a distancia a este dispositivo.
pub type DeviceId = [u8; 16];

/// Respuesta a «¿puede hacerse esto ahora?».
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Sí, hasta esta hora de confianza (segundos Unix).
    Allowed {
        /// Cuándo caduca el permiso.
        until: u64,
    },
    /// No.
    Denied(DenyReason),
}

/// Por qué no.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DenyReason {
    /// Aún no hay guardián: nada se puede aflojar.
    NotPaired,
    /// Hace falta que un guardián lo autorice.
    NeedsAuthorization,
    /// Hay una solicitud pendiente para esta acción.
    Waiting {
        /// Número de la solicitud.
        request: u64,
        /// Cuándo vence la espera; `None` si solo un guardián puede aprobarla.
        ready_at: Option<u64>,
    },
}

/// Permiso de un solo uso para una acción concreta.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Grant {
    action: Action,
    by: Authorizer,
    expires_at: u64,
}

/// Estado completo del anti-manipulación de un dispositivo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Guard {
    device: String,
    clock: TrustedClock,
    settings: Settings,
    guardians: Vec<GuardianRecord>,
    server_key: Option<[u8; 32]>,
    grants: Vec<Grant>,
    requests: Requests,
    failures: Failures,
    windows: AccessWindows,
    heartbeat: Heartbeat,
    log: EventLog,
}

impl Guard {
    /// Dispositivo sin emparejar: protección máxima y nada que aflojar.
    pub fn unpaired(device: DeviceId, now: TimePoint) -> Self {
        Self {
            device: to_hex(&device),
            clock: TrustedClock::start(now),
            settings: Settings::locked_down(),
            guardians: Vec::new(),
            server_key: None,
            grants: Vec::new(),
            requests: Requests::default(),
            failures: Failures::default(),
            windows: AccessWindows::default(),
            heartbeat: Heartbeat::default(),
            log: EventLog::new(),
        }
    }

    /// Arranca desde el estado guardado.
    ///
    /// Si falta, está alterado, se selló con otra clave o es de otro
    /// dispositivo, **falla cerrado**: arranca sin emparejar, con protección
    /// máxima, y anota la manipulación. En la primera instalación no hay
    /// estado: entonces se usa [`Guard::unpaired`], no esta función.
    pub fn load(saved: Option<&[u8]>, device_key: &[u8], device: DeviceId, now: TimePoint) -> Self {
        let tamper = match saved.map(|bytes| open(bytes, device_key)) {
            None => Tamper::StateMissing,
            Some(Err(OpenError::Malformed | OpenError::BadTag)) => Tamper::StateInvalid,
            Some(Ok(payload)) => match serde_json::from_slice::<Guard>(payload) {
                Ok(mut guard) if guard.device == to_hex(&device) => {
                    guard.observe(now);
                    return guard;
                }
                _ => Tamper::StateInvalid,
            },
        };
        let mut guard = Self::unpaired(device, now);
        guard.emit(EventKind::Tamper(tamper));
        guard
    }

    /// Estado listo para guardar, sellado con la clave del dispositivo.
    pub fn save(&self, device_key: &[u8]) -> Vec<u8> {
        // Serializar estos tipos no falla; si fallara, el sello vacío no
        // abriría como estado y el siguiente arranque fallaría cerrado.
        let payload = serde_json::to_vec(self).unwrap_or_default();
        seal(&payload, device_key)
    }

    /// Identificador del dispositivo, en hexadecimal.
    pub fn device_id(&self) -> &str {
        &self.device
    }

    /// `true` si hay un servidor vinculado para aprobaciones a distancia.
    pub fn server_linked(&self) -> bool {
        self.server_key.is_some()
    }

    /// Solicitudes de desbloqueo pendientes.
    pub fn pending_requests(&self) -> Vec<UnlockRequest> {
        self.requests.pending().to_vec()
    }

    // ---------------------------------------------------------------- consulta

    /// `true` si ya hay al menos un guardián.
    pub fn is_paired(&self) -> bool {
        !self.guardians.is_empty()
    }

    /// Ajustes protegidos vigentes.
    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    /// Los guardianes dados de alta (uno o dos).
    pub fn guardians(&self) -> Vec<GuardianInfo> {
        self.guardians.iter().map(GuardianRecord::info).collect()
    }

    /// Hora de confianza, en segundos Unix.
    pub fn now_secs(&self) -> u64 {
        self.clock.now_secs()
    }

    /// `false` mientras dura una pausa autorizada.
    pub fn protection_active(&self) -> bool {
        !self.settings.is_paused(self.clock.now_secs())
    }

    /// En modo parental el protegido solo ve el estado, no la configuración.
    pub fn protected_can_view_settings(&self) -> bool {
        self.settings.mode == Mode::SelfControl
    }

    /// ¿Puede hacerse `action` ahora mismo?
    pub fn check(&mut self, action: &Action, now: TimePoint) -> Decision {
        self.observe(now);
        if !self.is_paired() {
            return Decision::Denied(DenyReason::NotPaired);
        }
        let Ok(action) = action.normalized() else {
            return Decision::Denied(DenyReason::NeedsAuthorization);
        };
        if let Some(grant) = self.find_grant(&action) {
            return Decision::Allowed {
                until: grant.expires_at,
            };
        }
        match self.requests.pending().iter().find(|r| r.action == action) {
            Some(request) => Decision::Denied(DenyReason::Waiting {
                request: request.id,
                ready_at: request.ready_at,
            }),
            None => Decision::Denied(DenyReason::NeedsAuthorization),
        }
    }

    // ------------------------------------------------------------- emparejado

    /// Da de alta al primer guardián y fija el modo. Devuelve su código de
    /// recuperación, que hay que enseñarle una sola vez.
    pub fn setup(
        &mut self,
        mode: Mode,
        guardian: NewGuardian,
        now: TimePoint,
    ) -> Result<RecoveryCode, GuardError> {
        self.observe(now);
        if self.is_paired() {
            return Err(GuardError::AlreadyPaired);
        }
        let (record, code) = GuardianRecord::create(GuardianId::First, &guardian)?;
        self.settings.mode = mode;
        self.emit(EventKind::Paired {
            mode,
            guardian: record.id,
            name: record.name.clone(),
        });
        self.guardians.push(record);
        Ok(code)
    }

    /// Da de alta al segundo guardián. Exige un permiso para
    /// [`Action::AddGuardian`].
    pub fn add_guardian(
        &mut self,
        guardian: NewGuardian,
        now: TimePoint,
    ) -> Result<(GuardianId, RecoveryCode), GuardError> {
        self.observe(now);
        self.validate(&Action::AddGuardian)?;
        let id = if self.guardians.iter().any(|g| g.id == GuardianId::First) {
            GuardianId::Second
        } else {
            GuardianId::First
        };
        // Primero se comprueban los datos: un fallo aquí no gasta el permiso.
        let (record, code) = GuardianRecord::create(id, &guardian)?;
        let grant = self.take_grant(&Action::AddGuardian)?;
        self.requests.satisfy(&Action::AddGuardian);
        self.emit(EventKind::Performed {
            action: Action::AddGuardian,
            by: grant.by,
        });
        self.emit(EventKind::GuardianAdded {
            guardian: id,
            name: record.name.clone(),
        });
        self.guardians.push(record);
        Ok((id, code))
    }

    /// Cambia la clave de un guardián y renueva su código de recuperación.
    /// Exige un permiso para [`Action::ChangeSecret`].
    pub fn change_secret(
        &mut self,
        guardian: GuardianId,
        new_secret: &str,
        entropy: &[u8; ENTROPY_LEN],
        now: TimePoint,
    ) -> Result<RecoveryCode, GuardError> {
        self.observe(now);
        let action = Action::ChangeSecret { guardian };
        self.validate(&action)?;
        if self.find_grant(&action).is_none() {
            return Err(GuardError::NotAuthorized);
        }
        let record = self
            .guardians
            .iter_mut()
            .find(|g| g.id == guardian)
            .ok_or(GuardError::UnknownGuardian)?;
        // Si la clave nueva no vale, el permiso sigue disponible.
        let code = record.set_secret(new_secret, entropy)?;
        let grant = self.take_grant(&action)?;
        self.requests.satisfy(&action);
        self.emit(EventKind::Performed {
            action,
            by: grant.by,
        });
        self.emit(EventKind::SecretChanged { guardian });
        Ok(code)
    }

    // ------------------------------------------------------------ autorización

    /// Un guardián autoriza `action` escribiendo su clave. Vale la de
    /// cualquiera de los dos. El permiso sirve una vez y dura diez minutos.
    pub fn authorize_with_secret(
        &mut self,
        action: &Action,
        secret: &str,
        now: TimePoint,
    ) -> Result<GuardianId, GuardError> {
        self.observe(now);
        let action = self.validate(action)?;
        self.failures.ensure_unlocked(self.clock.now_secs())?;

        let Some(guardian) = self
            .guardians
            .iter()
            .find(|g| g.secret_matches(secret))
            .map(|g| g.id)
        else {
            self.register_failure();
            return Err(GuardError::WrongSecret);
        };
        self.failures.reset();
        self.grant(action, Authorizer::Secret { guardian }, SECRET_GRANT_SECS);
        Ok(guardian)
    }

    /// Un guardián que ha perdido su clave usa su código de recuperación. El
    /// código se gasta y da permiso solo para cambiar esa clave.
    pub fn authorize_with_recovery_code(
        &mut self,
        code: &str,
        now: TimePoint,
    ) -> Result<GuardianId, GuardError> {
        self.observe(now);
        if !self.is_paired() {
            return Err(GuardError::NotPaired);
        }
        self.failures.ensure_unlocked(self.clock.now_secs())?;

        let Some(guardian) = self
            .guardians
            .iter_mut()
            .find_map(|g| g.redeem_recovery_code(code).then_some(g.id))
        else {
            self.register_failure();
            return Err(GuardError::WrongRecoveryCode);
        };
        self.failures.reset();
        self.grant(
            Action::ChangeSecret { guardian },
            Authorizer::RecoveryCode { guardian },
            SECRET_GRANT_SECS,
        );
        Ok(guardian)
    }

    /// Aplica una acción autorizada y gasta su permiso.
    ///
    /// Para dar de alta un guardián o cambiar una clave se usan
    /// [`Guard::add_guardian`] y [`Guard::change_secret`], que necesitan datos.
    pub fn perform(&mut self, action: &Action, now: TimePoint) -> Result<(), GuardError> {
        self.observe(now);
        let action = self.validate(action)?;
        if matches!(action, Action::AddGuardian | Action::ChangeSecret { .. }) {
            return Err(GuardError::InvalidAction(
                "esta acción necesita datos: usa su función",
            ));
        }
        if self.find_grant(&action).is_none() {
            return Err(GuardError::NotAuthorized);
        }
        // Se aplica sobre una copia: si falla, ni cambia nada ni gasta el permiso.
        let mut settings = self.settings.clone();
        settings.apply(&action, self.clock.now_secs())?;
        let server_key = match &action {
            Action::LinkServer { public_key } => Some(parse_server_key(public_key)?),
            _ => self.server_key,
        };
        let grant = self.take_grant(&action)?;
        self.settings = settings;
        self.server_key = server_key;
        self.requests.satisfy(&action);
        match &action {
            Action::RemoveGuardian { guardian } => self.guardians.retain(|g| g.id != *guardian),
            Action::ChangeMode {
                mode: Mode::Parental,
            } => self.requests.stop_all_delays(),
            _ => {}
        }
        self.emit(EventKind::Performed {
            action,
            by: grant.by,
        });
        Ok(())
    }

    /// Endurece la protección. No necesita autorización.
    pub fn tighten(&mut self, change: &Tightening, now: TimePoint) -> Result<(), GuardError> {
        self.observe(now);
        let change = change.normalized()?;
        self.settings.tighten(&change)?;
        self.emit(EventKind::Tightened { change });
        Ok(())
    }

    // ------------------------------------------------------------- solicitudes

    /// El protegido pide autorización para `action`. Los guardianes reciben
    /// aviso al instante.
    ///
    /// En autocontrol, pasada la espera la acción queda permitida durante una
    /// hora. En parental la espera no vence: solo un guardián puede aprobarla,
    /// con su clave o a distancia. Pedir dos veces lo mismo devuelve la
    /// solicitud que ya había, sin reiniciar la espera.
    pub fn request(
        &mut self,
        action: &Action,
        now: TimePoint,
    ) -> Result<UnlockRequest, GuardError> {
        self.observe(now);
        let action = self.validate(action)?;
        let delay = match self.settings.mode {
            Mode::SelfControl => Some(u64::from(self.settings.delay_hours) * 3_600),
            Mode::Parental => None,
        };
        let (request, is_new) = self.requests.open(action, self.clock.now_secs(), delay)?;
        if is_new {
            self.emit(EventKind::UnlockRequested {
                request: request.id,
                action: request.action.clone(),
                ready_at: request.ready_at,
            });
        }
        Ok(request)
    }

    /// Cancela una solicitud pendiente. Puede hacerlo cualquiera.
    pub fn cancel_request(&mut self, request: u64, now: TimePoint) -> Result<(), GuardError> {
        self.observe(now);
        self.requests
            .remove(request)
            .ok_or(GuardError::UnknownRequest)?;
        self.emit(EventKind::UnlockCancelled { request });
        Ok(())
    }

    /// Un guardián ha aprobado a distancia una solicitud. El permiso sirve
    /// una vez y dura diez minutos.
    pub fn approve_remotely(
        &mut self,
        approval: &Approval,
        now: TimePoint,
    ) -> Result<GuardianId, GuardError> {
        self.observe(now);
        if !self.is_paired() {
            return Err(GuardError::NotPaired);
        }
        let server_key = self.server_key.ok_or(GuardError::NoServerLinked)?;
        // La firma primero: una aprobación falsificada se anota aunque además
        // sea incorrecta en otras cosas.
        if !signature_is_valid(approval, &server_key) {
            self.emit(EventKind::Tamper(Tamper::ForgedApproval));
            return Err(GuardError::InvalidApproval("firma incorrecta"));
        }
        let body = &approval.body;
        if body.device != self.device {
            return Err(GuardError::InvalidApproval("es para otro dispositivo"));
        }
        if body.expires_at <= self.clock.now_secs() {
            return Err(GuardError::InvalidApproval("ha caducado"));
        }
        if !self.guardians.iter().any(|g| g.id == body.guardian) {
            return Err(GuardError::InvalidApproval("el guardián ya no existe"));
        }
        let request = self
            .requests
            .get(body.request)
            .ok_or(GuardError::InvalidApproval(
                "la solicitud no existe o ya se usó",
            ))?;
        if request.action != body.action {
            return Err(GuardError::InvalidApproval("aprueba otra acción"));
        }
        // La situación puede haber cambiado desde que se pidió.
        let action = self.validate(&request.action)?;
        self.requests.remove(body.request);
        self.grant(
            action,
            Authorizer::Remote {
                guardian: body.guardian,
                request: body.request,
            },
            SECRET_GRANT_SECS,
        );
        Ok(body.guardian)
    }

    /// El agente lo llama cada minuto: vencen esperas y pausas, se cierran
    /// ventanas de agrupación y se emite la señal de vida.
    pub fn tick(&mut self, now: TimePoint) {
        self.observe(now);
    }

    // ---------------------------------------------------------------- registro

    /// El agente ha bloqueado una conexión. `site` es la regla de la lista que
    /// coincidió.
    pub fn record_access(&mut self, site: &str, category: Category, now: TimePoint) {
        self.observe(now);
        // Un nombre que no se puede normalizar se anota tal cual, recortado.
        let site =
            normalize_domain(site).unwrap_or_else(|_| site.chars().take(253).collect::<String>());
        for kind in self.windows.record(site, category, self.clock.now_secs()) {
            self.emit(kind);
        }
    }

    /// El agente ha detectado una manipulación.
    pub fn record_tamper(&mut self, tamper: Tamper, now: TimePoint) {
        self.observe(now);
        self.emit(EventKind::Tamper(tamper));
    }

    /// Eventos pendientes de entregar al servidor, por orden.
    pub fn outbox(&self) -> Vec<Envelope> {
        self.log.outbox().cloned().collect()
    }

    /// Cuántos eventos esperan a ser entregados.
    pub fn pending_events(&self) -> usize {
        self.log.pending()
    }

    /// El servidor confirma que tiene todos los eventos hasta `up_to`.
    pub fn acknowledge(&mut self, up_to: EventId, now: TimePoint) {
        self.observe(now);
        self.log
            .acknowledge(up_to, self.clock.now_secs(), self.clock.wall_secs());
    }

    // ----------------------------------------------------------------- interno

    /// Pone el reloj en hora, anota si lo han movido y retira lo caducado.
    fn observe(&mut self, now: TimePoint) {
        if let Some(jump) = self.clock.advance(now) {
            self.emit(EventKind::Tamper(Tamper::ClockChanged {
                expected_wall_secs: jump.expected_wall_secs,
                actual_wall_secs: jump.actual_wall_secs,
            }));
        }
        let now_secs = self.clock.now_secs();
        self.grants.retain(|grant| grant.expires_at > now_secs);

        // Esperas vencidas: solo en autocontrol.
        if self.settings.mode == Mode::Parental {
            self.requests.stop_all_delays();
        }
        for request in self.requests.take_ready(now_secs) {
            // Si la acción ya no tiene sentido (p. ej. quitar a un guardián
            // que ya no está), la solicitud simplemente caduca.
            let Ok(action) = self.validate(&request.action) else {
                continue;
            };
            self.grant(
                action.clone(),
                Authorizer::Delay {
                    request: request.id,
                },
                DELAY_GRANT_SECS,
            );
            self.emit(EventKind::UnlockReady {
                request: request.id,
                action,
                until: now_secs.saturating_add(DELAY_GRANT_SECS),
            });
        }

        if self
            .settings
            .paused_until
            .is_some_and(|until| until <= now_secs)
        {
            self.settings.paused_until = None;
            self.emit(EventKind::PauseEnded);
        }

        for kind in self.windows.close_expired(now_secs) {
            self.emit(kind);
        }

        let log = &self.log;
        if self.is_paired() && self.heartbeat.due(now_secs, |id| log.is_acknowledged(id)) {
            let protection_active = !self.settings.is_paused(now_secs);
            let id = self.emit(EventKind::Heartbeat { protection_active });
            self.heartbeat.sent(now_secs, id);
        }
    }

    /// Comprueba que la acción tiene sentido en el estado actual y la devuelve
    /// en forma canónica.
    fn validate(&self, action: &Action) -> Result<Action, GuardError> {
        if !self.is_paired() {
            return Err(GuardError::NotPaired);
        }
        let action = action.normalized()?;
        let exists = |id: &GuardianId| self.guardians.iter().any(|g| g.id == *id);
        match &action {
            Action::AddGuardian if self.guardians.len() >= MAX_GUARDIANS => {
                Err(GuardError::TooManyGuardians)
            }
            Action::RemoveGuardian { guardian } | Action::ChangeSecret { guardian }
                if !exists(guardian) =>
            {
                Err(GuardError::UnknownGuardian)
            }
            Action::RemoveGuardian { .. } if self.guardians.len() == 1 => {
                Err(GuardError::LastGuardian)
            }
            _ => Ok(action),
        }
    }

    fn grant(&mut self, action: Action, by: Authorizer, lasts_secs: u64) {
        // Un permiso nuevo para la misma acción sustituye al anterior.
        self.grants.retain(|grant| grant.action != action);
        self.grants.push(Grant {
            action: action.clone(),
            by,
            expires_at: self.clock.now_secs().saturating_add(lasts_secs),
        });
        self.emit(EventKind::Authorized { action, by });
    }

    fn find_grant(&self, action: &Action) -> Option<&Grant> {
        self.grants.iter().find(|grant| grant.action == *action)
    }

    fn take_grant(&mut self, action: &Action) -> Result<Grant, GuardError> {
        let position = self
            .grants
            .iter()
            .position(|grant| grant.action == *action)
            .ok_or(GuardError::NotAuthorized)?;
        Ok(self.grants.remove(position))
    }

    fn register_failure(&mut self) {
        let attempts = self.failures.register(self.clock.now_secs());
        if attempts >= FAILURES_BEFORE_ALERT {
            self.emit(EventKind::Tamper(Tamper::SecretGuessing { attempts }));
        }
    }

    fn emit(&mut self, kind: EventKind) -> Option<EventId> {
        let urgency = urgency_of(&kind);
        self.log
            .append(kind, urgency, self.clock.now_secs(), self.clock.wall_secs())
    }
}
