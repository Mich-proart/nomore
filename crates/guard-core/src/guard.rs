//! La máquina de estados: entra una orden con la hora, sale el resultado y
//! quedan anotados los eventos.

use serde::{Deserialize, Serialize};

use crate::clock::{TimePoint, TrustedClock};
use crate::error::GuardError;
use crate::event::{Authorizer, Category, Envelope, EventId, EventKind, EventLog, Tamper};
use crate::mode::{normalize_domain, Action, Mode, Settings, Tightening};
use crate::notify::urgency_of;
use crate::secret::{
    Failures, GuardianId, GuardianInfo, GuardianRecord, NewGuardian, RecoveryCode, ENTROPY_LEN,
    FAILURES_BEFORE_ALERT, MAX_GUARDIANS,
};

/// Lo que dura el permiso que da un guardián al escribir su clave.
pub const SECRET_GRANT_SECS: u64 = 600;

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
    clock: TrustedClock,
    settings: Settings,
    guardians: Vec<GuardianRecord>,
    grants: Vec<Grant>,
    failures: Failures,
    log: EventLog,
}

impl Guard {
    /// Dispositivo sin emparejar: protección máxima y nada que aflojar.
    pub fn unpaired(now: TimePoint) -> Self {
        Self {
            clock: TrustedClock::start(now),
            settings: Settings::locked_down(),
            guardians: Vec::new(),
            grants: Vec::new(),
            failures: Failures::default(),
            log: EventLog::new(),
        }
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
        let granted = action
            .normalized()
            .ok()
            .and_then(|action| self.grants.iter().find(|grant| grant.action == action));
        match granted {
            Some(grant) => Decision::Allowed {
                until: grant.expires_at,
            },
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
        self.grant(action, Authorizer::Secret(guardian));
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
            Authorizer::RecoveryCode(guardian),
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
        let grant = self.take_grant(&action)?;
        self.settings = settings;
        if let Action::RemoveGuardian { guardian } = &action {
            self.guardians.retain(|g| g.id != *guardian);
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

    // ---------------------------------------------------------------- registro

    /// El agente ha bloqueado una conexión. `site` es la regla de la lista que
    /// coincidió.
    pub fn record_access(&mut self, site: &str, category: Category, now: TimePoint) {
        self.observe(now);
        // Un nombre que no se puede normalizar se anota tal cual, recortado.
        let site =
            normalize_domain(site).unwrap_or_else(|_| site.chars().take(253).collect::<String>());
        self.emit(EventKind::AccessAttempt { site, category });
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

    fn grant(&mut self, action: Action, by: Authorizer) {
        // Un permiso nuevo para la misma acción sustituye al anterior.
        self.grants.retain(|grant| grant.action != action);
        self.grants.push(Grant {
            action: action.clone(),
            by,
            expires_at: self.clock.now_secs().saturating_add(SECRET_GRANT_SECS),
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

    fn emit(&mut self, kind: EventKind) {
        let urgency = urgency_of(&kind);
        self.log
            .append(kind, urgency, self.clock.now_secs(), self.clock.wall_secs());
    }
}
