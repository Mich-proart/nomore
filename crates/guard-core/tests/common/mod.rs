//! Utilidades compartidas por las pruebas de integración.
#![allow(dead_code)]

use guard_core::{
    Event, EventKind, Guard, Mode, NewGuardian, RecoveryCode, TimePoint, ENTROPY_LEN,
};

pub const START: u64 = 1_800_000_000;
pub const ANA: &str = "clave-de-ana";
pub const LUIS: &str = "clave-de-luis";

/// `secs` segundos después del inicio, con todos los relojes acompasados.
pub fn t(secs: u64) -> TimePoint {
    TimePoint {
        wall_secs: START + secs,
        monotonic_ms: secs * 1000,
        boot_id: 1,
        server_secs: None,
    }
}

pub fn guardian(name: &str, secret: &str, seed: u8) -> NewGuardian {
    let mut entropy = [0u8; ENTROPY_LEN];
    for (i, byte) in entropy.iter_mut().enumerate() {
        *byte = seed.wrapping_mul(31).wrapping_add(i as u8).wrapping_mul(17);
    }
    NewGuardian {
        name: name.into(),
        secret: secret.into(),
        entropy,
    }
}

/// Dispositivo emparejado con Ana como única guardiana.
pub fn paired(mode: Mode) -> (Guard, RecoveryCode) {
    let mut guard = Guard::unpaired(t(0));
    let code = guard.setup(mode, guardian("Ana", ANA, 1), t(0)).unwrap();
    (guard, code)
}

pub fn events(guard: &Guard) -> Vec<EventKind> {
    guard
        .outbox()
        .iter()
        .map(|envelope| {
            serde_json::from_str::<Event>(&envelope.payload)
                .unwrap()
                .kind
        })
        .collect()
}

pub fn last_event(guard: &Guard) -> EventKind {
    events(guard).pop().expect("no hay eventos")
}
