//! Registro de eventos: qué ha pasado, en qué orden, y qué falta por contar
//! al servidor.
//!
//! Cada evento incluye la huella SHA-256 del anterior. Quien recibe la cadena
//! detecta si falta alguno, si se ha alterado o si el dispositivo ha vuelto a
//! un estado antiguo.

use std::collections::VecDeque;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::mode::{Action, Mode, Tightening};
use crate::secret::GuardianId;

/// Versión del formato de evento.
const FORMAT_VERSION: u8 = 1;
/// A partir de este tamaño de cola, los intentos de acceso se cuentan en vez
/// de anotarse uno a uno.
pub(crate) const ACCESS_CAPACITY: usize = 10_000;
/// Hueco reservado para todo lo demás (manipulación, autorizaciones).
pub(crate) const RESERVED_CAPACITY: usize = 2_000;

/// Número de orden de un evento. Empieza en 1 y no se reutiliza.
pub type EventId = u64;

/// Huella de un evento.
pub type Hash = [u8; 32];

/// Huella «anterior» del primer evento de un dispositivo.
pub const GENESIS: Hash = [0; 32];

/// Categoría del sitio al que se intentó acceder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    /// Pornografía y desnudos.
    Porn,
    /// Apuestas y juego.
    Gambling,
    /// Apps y webs de citas.
    Dating,
    /// Vías de escape: DoH, VPN, proxies.
    Bypass,
}

/// Qué clase de manipulación ha detectado el agente.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "what", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Tamper {
    /// El servicio de NoMore fue detenido o matado.
    ServiceStopped,
    /// Se intentó desinstalar sin autorización.
    UninstallAttempt,
    /// El DNS del sistema ya no apunta a NoMore.
    DnsChanged,
    /// El fichero hosts fue modificado.
    HostsChanged,
    /// Hay una VPN o un proxy ajeno activo.
    VpnDetected,
    /// El reloj del sistema no está donde debería.
    ClockChanged {
        /// Hora que debería marcar, en segundos Unix.
        expected_wall_secs: u64,
        /// Hora que marca.
        actual_wall_secs: u64,
    },
    /// El estado guardado de NoMore no estaba.
    StateMissing,
    /// El estado guardado de NoMore estaba corrupto o era de otro dispositivo.
    StateInvalid,
    /// Varias claves erróneas seguidas.
    SecretGuessing {
        /// Fallos consecutivos hasta ahora.
        attempts: u32,
    },
}

/// Quién ha autorizado una acción.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "via", content = "guardian", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Authorizer {
    /// Un guardián, escribiendo su clave en el dispositivo.
    Secret(GuardianId),
    /// Un guardián, con su código de recuperación.
    RecoveryCode(GuardianId),
}

/// Lo que ha pasado.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum EventKind {
    /// Intento de conexión a un sitio bloqueado.
    AccessAttempt {
        /// Regla de la lista que coincidió, p. ej. `pornhub.com`.
        site: String,
        /// Categoría de esa regla.
        category: Category,
    },
    /// La cola estaba llena y estos eventos solo se contaron.
    Overflow {
        /// Intentos de acceso que no se anotaron uno a uno.
        access: u64,
        /// Otros eventos que no cupieron ni en la reserva.
        other: u64,
    },
    /// Intento de manipulación.
    Tamper(Tamper),
    /// Se ha emparejado el primer guardián.
    Paired {
        /// Modo elegido.
        mode: Mode,
        /// Guardián dado de alta.
        guardian: GuardianId,
        /// Nombre con el que se identifica.
        name: String,
    },
    /// Se ha dado de alta el segundo guardián.
    GuardianAdded {
        /// Guardián dado de alta.
        guardian: GuardianId,
        /// Nombre con el que se identifica.
        name: String,
    },
    /// Un guardián ha cambiado de clave.
    SecretChanged {
        /// De quién es la clave.
        guardian: GuardianId,
    },
    /// Se ha autorizado una acción, todavía sin aplicar.
    Authorized {
        /// Acción autorizada.
        action: Action,
        /// Quién la autorizó.
        by: Authorizer,
    },
    /// Se ha aplicado una acción autorizada.
    Performed {
        /// Acción aplicada.
        action: Action,
        /// Quién la autorizó.
        by: Authorizer,
    },
    /// El protegido ha endurecido la protección por su cuenta.
    Tightened {
        /// Qué ha cambiado.
        change: Tightening,
    },
}

impl EventKind {
    /// Los intentos de acceso son los únicos que se pueden resumir.
    fn is_access(&self) -> bool {
        matches!(self, Self::AccessAttempt { .. })
    }
}

/// Con qué prisa hay que contárselo al guardián.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Urgency {
    /// Aviso al instante.
    Immediate,
    /// Va en el resumen diario.
    Digest,
}

/// Un evento tal como viaja al servidor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// Versión del formato.
    pub v: u8,
    /// Número de orden.
    pub id: EventId,
    /// Hora de confianza, en segundos Unix.
    pub at: u64,
    /// Reloj del sistema en ese momento, en segundos Unix.
    pub wall: u64,
    /// Huella del evento anterior, en hexadecimal.
    pub prev: String,
    /// Lo que ha pasado.
    pub kind: EventKind,
}

/// Un evento pendiente de entregar.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    /// Número de orden del evento.
    pub id: EventId,
    /// Con qué prisa hay que avisar.
    pub urgency: Urgency,
    /// El evento en JSON, exactamente como se calculó su huella.
    pub payload: String,
}

/// Por qué una cadena de eventos no es válida.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
    /// Un evento no es JSON válido de este formato.
    Unreadable {
        /// Posición en la secuencia recibida.
        index: usize,
    },
    /// Un evento no enlaza con el anterior: falta alguno o se ha alterado.
    Broken {
        /// Número de orden del evento que no encaja.
        id: EventId,
    },
    /// Los números de orden no son consecutivos.
    OutOfOrder {
        /// Número de orden del evento que no encaja.
        id: EventId,
    },
}

/// Comprueba que `payloads` continúa la cadena que terminaba en el evento
/// `last_id` con huella `last_hash`, y devuelve el nuevo final de la cadena.
///
/// Para una cadena desde el principio: `verify_chain(0, &GENESIS, …)`.
pub fn verify_chain<S: AsRef<str>>(
    last_id: EventId,
    last_hash: &Hash,
    payloads: &[S],
) -> Result<(EventId, Hash), ChainError> {
    let mut id = last_id;
    let mut hash = *last_hash;
    for (index, payload) in payloads.iter().enumerate() {
        let payload = payload.as_ref();
        let event: Event =
            serde_json::from_str(payload).map_err(|_| ChainError::Unreadable { index })?;
        if event.id != id.wrapping_add(1) {
            return Err(ChainError::OutOfOrder { id: event.id });
        }
        if event.prev != to_hex(&hash) {
            return Err(ChainError::Broken { id: event.id });
        }
        id = event.id;
        hash = hash_of(payload);
    }
    Ok((id, hash))
}

fn hash_of(payload: &str) -> Hash {
    Sha256::digest(payload.as_bytes()).into()
}

pub(crate) fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Registro encadenado más cola de salida.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct EventLog {
    last_id: EventId,
    last_hash: Hash,
    outbox: VecDeque<Envelope>,
    /// Intentos de acceso que no cupieron y están por resumir.
    overflow_access: u64,
    /// Otros eventos que no cupieron ni en la reserva.
    overflow_other: u64,
}

impl EventLog {
    pub(crate) fn new() -> Self {
        Self {
            last_id: 0,
            last_hash: GENESIS,
            outbox: VecDeque::new(),
            overflow_access: 0,
            overflow_other: 0,
        }
    }

    /// Anota un evento. Con la cola llena, los de acceso solo se cuentan.
    pub(crate) fn append(&mut self, kind: EventKind, urgency: Urgency, at: u64, wall: u64) {
        // Con la cola llena se pierde el detalle, pero no la cuenta.
        if kind.is_access() && self.outbox.len() >= ACCESS_CAPACITY {
            self.overflow_access = self.overflow_access.saturating_add(1);
        } else if self.outbox.len() >= ACCESS_CAPACITY + RESERVED_CAPACITY {
            self.overflow_other = self.overflow_other.saturating_add(1);
        } else {
            self.push(kind, urgency, at, wall);
        }
    }

    fn push(&mut self, kind: EventKind, urgency: Urgency, at: u64, wall: u64) {
        let event = Event {
            v: FORMAT_VERSION,
            id: self.last_id + 1,
            at,
            wall,
            prev: to_hex(&self.last_hash),
            kind,
        };
        // Serializar estos tipos no puede fallar; si algún día fallara, se
        // pierde el evento pero no se rompe la cadena ni el servicio.
        let Ok(payload) = serde_json::to_string(&event) else {
            return;
        };
        self.last_id = event.id;
        self.last_hash = hash_of(&payload);
        self.outbox.push_back(Envelope {
            id: event.id,
            urgency,
            payload,
        });
    }

    /// Eventos pendientes de entregar, del más antiguo al más reciente.
    pub(crate) fn outbox(&self) -> impl Iterator<Item = &Envelope> {
        self.outbox.iter()
    }

    /// El servidor confirma que tiene todo hasta `up_to` incluido.
    pub(crate) fn acknowledge(&mut self, up_to: EventId, at: u64, wall: u64) {
        while self
            .outbox
            .front()
            .is_some_and(|envelope| envelope.id <= up_to)
        {
            self.outbox.pop_front();
        }
        let lost = self.overflow_access > 0 || self.overflow_other > 0;
        if lost && self.outbox.len() < ACCESS_CAPACITY {
            let access = std::mem::take(&mut self.overflow_access);
            let other = std::mem::take(&mut self.overflow_other);
            // Perder eventos que no son de acceso es grave: aviso inmediato.
            let urgency = if other > 0 {
                Urgency::Immediate
            } else {
                Urgency::Digest
            };
            self.push(EventKind::Overflow { access, other }, urgency, at, wall);
        }
    }

    pub(crate) fn pending(&self) -> usize {
        self.outbox.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn access(site: &str) -> EventKind {
        EventKind::AccessAttempt {
            site: site.to_owned(),
            category: Category::Porn,
        }
    }

    fn payloads(log: &EventLog) -> Vec<String> {
        log.outbox().map(|e| e.payload.clone()).collect()
    }

    fn log_with(count: usize) -> EventLog {
        let mut log = EventLog::new();
        for i in 0..count {
            log.append(
                access(&format!("sitio{i}.com")),
                Urgency::Immediate,
                100 + i as u64,
                200,
            );
        }
        log
    }

    #[test]
    fn events_are_numbered_from_one_and_chained() {
        let log = log_with(3);
        let ids: Vec<_> = log.outbox().map(|e| e.id).collect();
        assert_eq!(ids, [1, 2, 3]);

        let first: Event = serde_json::from_str(&log.outbox().next().unwrap().payload).unwrap();
        assert_eq!(first.v, 1);
        assert_eq!(first.prev, "0".repeat(64));
        assert_eq!(first.at, 100);
        assert_eq!(first.wall, 200);
        assert_eq!(first.kind, access("sitio0.com"));
    }

    #[test]
    fn intact_chain_verifies() {
        let log = log_with(5);
        let (id, hash) = verify_chain(0, &GENESIS, &payloads(&log)).unwrap();
        assert_eq!(id, 5);
        assert_eq!(hash, log.last_hash);
    }

    #[test]
    fn chain_can_be_verified_in_batches() {
        let log = log_with(5);
        let all = payloads(&log);
        let (id, hash) = verify_chain(0, &GENESIS, &all[..2]).unwrap();
        assert_eq!(verify_chain(id, &hash, &all[2..]).unwrap().0, 5);
    }

    #[test]
    fn removed_event_is_detected() {
        let mut all = payloads(&log_with(5));
        all.remove(2);
        assert_eq!(
            verify_chain(0, &GENESIS, &all),
            Err(ChainError::OutOfOrder { id: 4 })
        );
    }

    #[test]
    fn altered_event_is_detected() {
        let mut all = payloads(&log_with(5));
        all[1] = all[1].replace("sitio1.com", "inocente.org");
        assert_eq!(
            verify_chain(0, &GENESIS, &all),
            Err(ChainError::Broken { id: 3 })
        );
    }

    #[test]
    fn a_forked_history_is_detected() {
        // El dispositivo vuelve a un estado antiguo y escribe otra historia
        // con los mismos números de orden.
        let original = log_with(3);
        let (id, hash) = verify_chain(0, &GENESIS, &payloads(&original)).unwrap();

        let mut restored = log_with(2);
        restored.append(access("otro.com"), Urgency::Immediate, 999, 999);
        restored.append(access("mas.com"), Urgency::Immediate, 999, 999);
        let forked = payloads(&restored);
        assert_eq!(
            verify_chain(id, &hash, &forked[3..]),
            Err(ChainError::Broken { id: 4 })
        );
    }

    #[test]
    fn garbage_is_reported_as_unreadable() {
        assert_eq!(
            verify_chain(0, &GENESIS, &["no es json"]),
            Err(ChainError::Unreadable { index: 0 })
        );
    }

    #[test]
    fn acknowledge_drops_delivered_events_only() {
        let mut log = log_with(5);
        log.acknowledge(3, 0, 0);
        let ids: Vec<_> = log.outbox().map(|e| e.id).collect();
        assert_eq!(ids, [4, 5]);
        // Confirmar de más o de menos no rompe nada.
        log.acknowledge(1, 0, 0);
        assert_eq!(log.pending(), 2);
        log.acknowledge(99, 0, 0);
        assert_eq!(log.pending(), 0);
        // La numeración sigue donde iba.
        log.append(access("nuevo.com"), Urgency::Immediate, 0, 0);
        assert_eq!(log.outbox().next().unwrap().id, 6);
    }

    #[test]
    fn full_queue_counts_access_attempts_and_keeps_tamper_events() {
        let mut log = log_with(ACCESS_CAPACITY);
        for _ in 0..40 {
            log.append(access("mas.com"), Urgency::Immediate, 0, 0);
        }
        assert_eq!(
            log.pending(),
            ACCESS_CAPACITY,
            "los accesos de más no entran"
        );
        assert_eq!(log.overflow_access, 40);

        log.append(
            EventKind::Tamper(Tamper::DnsChanged),
            Urgency::Immediate,
            0,
            0,
        );
        assert_eq!(log.pending(), ACCESS_CAPACITY + 1, "la manipulación sí");

        // Al hacer sitio sale un único resumen con la cuenta.
        log.acknowledge(10, 500, 600);
        let last: Event = serde_json::from_str(&log.outbox().last().unwrap().payload).unwrap();
        assert_eq!(
            last.kind,
            EventKind::Overflow {
                access: 40,
                other: 0
            }
        );
        assert_eq!(log.outbox().last().unwrap().urgency, Urgency::Digest);
        assert_eq!(last.at, 500);
        assert_eq!(log.overflow_access, 0);

        // Y la cadena sigue siendo válida de principio a fin.
        let rest = payloads(&log);
        let first: Event = serde_json::from_str(&rest[0]).unwrap();
        assert_eq!(first.id, 11);
    }

    #[test]
    fn the_queue_is_bounded_even_for_tamper_events() {
        let mut log = EventLog::new();
        for _ in 0..(ACCESS_CAPACITY + RESERVED_CAPACITY + 50) {
            log.append(
                EventKind::Tamper(Tamper::ServiceStopped),
                Urgency::Immediate,
                0,
                0,
            );
        }
        assert_eq!(log.pending(), ACCESS_CAPACITY + RESERVED_CAPACITY);
        assert_eq!(log.overflow_other, 50);

        // Al hacer sitio, la pérdida se cuenta y se avisa al instante.
        log.acknowledge(RESERVED_CAPACITY as u64 + 100, 0, 0);
        let last = log.outbox().last().unwrap();
        assert_eq!(last.urgency, Urgency::Immediate);
        let event: Event = serde_json::from_str(&last.payload).unwrap();
        assert_eq!(
            event.kind,
            EventKind::Overflow {
                access: 0,
                other: 50
            }
        );
    }

    #[test]
    fn hex_encoding_is_lowercase_and_padded() {
        assert_eq!(to_hex(&[0x00, 0x0f, 0xa0, 0xff]), "000fa0ff");
    }
}
