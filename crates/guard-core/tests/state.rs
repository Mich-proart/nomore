//! Guardar, cargar y fallo cerrado.

mod common;

use common::{events, guardian, paired, t, ANA, DEVICE, LUIS, START};
use guard_core::{
    Action, Decision, DenyReason, EventKind, Guard, GuardianId, Mode, Tamper, Tightening,
    TimePoint, Toggle,
};

const KEY: &[u8] = b"clave-del-dispositivo-de-32-bytes";

/// Un dispositivo con un poco de todo: dos guardianes, ajustes cambiados,
/// una solicitud pendiente, un permiso vivo y eventos sin entregar.
fn busy() -> Guard {
    let (mut guard, _) = paired(Mode::SelfControl);
    guard
        .authorize_with_secret(&Action::AddGuardian, ANA, t(1))
        .unwrap();
    guard.add_guardian(guardian("Luis", LUIS, 2), t(1)).unwrap();
    let off = Action::DisableCategory {
        category: Toggle::Dating,
    };
    guard.authorize_with_secret(&off, LUIS, t(2)).unwrap();
    guard.perform(&off, t(2)).unwrap();
    guard
        .tighten(
            &Tightening::BlockDomain {
                domain: "extra.com".into(),
            },
            t(3),
        )
        .unwrap();
    guard.request(&Action::Uninstall, t(4)).unwrap();
    guard
        .authorize_with_secret(&Action::Pause { minutes: 30 }, ANA, t(5))
        .unwrap();
    guard.record_access("pornhub.com", guard_core::Category::Porn, t(6));
    guard
}

#[test]
fn save_and_load_keeps_everything() {
    let guard = busy();
    let saved = guard.save(KEY);
    let loaded = Guard::load(Some(&saved), KEY, DEVICE, t(7));

    assert_eq!(loaded.settings(), guard.settings());
    assert_eq!(loaded.guardians(), guard.guardians());
    assert_eq!(loaded.pending_requests(), guard.pending_requests());
    assert_eq!(loaded.outbox(), guard.outbox());
    assert_eq!(loaded.now_secs(), START + 7);
    assert_eq!(loaded.device_id(), guard.device_id());

    // Y sigue funcionando igual: claves, permisos y esperas.
    let mut loaded = loaded;
    assert!(matches!(
        loaded.check(&Action::Pause { minutes: 30 }, t(8)),
        Decision::Allowed { .. }
    ));
    assert_eq!(
        loaded.authorize_with_secret(&Action::Uninstall, LUIS, t(9)),
        Ok(GuardianId::Second)
    );
}

#[test]
fn a_wait_survives_a_restart_without_counting_the_time_off() {
    let (mut guard, _) = paired(Mode::SelfControl);
    guard.request(&Action::Uninstall, t(0)).unwrap();
    let saved = guard.save(KEY);

    // Se reinicia dos días después, sin conexión.
    let rebooted = TimePoint {
        wall_secs: START + 2 * 86_400,
        monotonic_ms: 1_000,
        boot_id: 2,
        server_secs: None,
    };
    let mut loaded = Guard::load(Some(&saved), KEY, DEVICE, rebooted);
    assert_eq!(loaded.now_secs(), START, "el tiempo apagado no cuenta");
    assert!(matches!(
        loaded.check(&Action::Uninstall, rebooted),
        Decision::Denied(DenyReason::Waiting { .. })
    ));
}

fn assert_failed_closed(loaded: &Guard, expected: Tamper) {
    assert!(!loaded.is_paired());
    assert!(loaded.protection_active());
    let settings = loaded.settings();
    assert!(settings.block_gambling && settings.block_dating);
    assert!(settings.allowlist.is_empty());
    assert!(loaded.pending_requests().is_empty());
    assert_eq!(events(loaded), [EventKind::Tamper(expected)]);
    assert_eq!(loaded.device_id(), "d5".repeat(16));
}

#[test]
fn missing_state_fails_closed() {
    let loaded = Guard::load(None, KEY, DEVICE, t(0));
    assert_failed_closed(&loaded, Tamper::StateMissing);
}

#[test]
fn any_altered_byte_fails_closed() {
    let saved = busy().save(KEY);
    // Recorre el fichero entero a saltos, más el principio y el final.
    let positions =
        (0..saved.len())
            .step_by(97)
            .chain([0, 4, 5, saved.len() - 33, saved.len() - 1]);
    for position in positions {
        let mut altered = saved.clone();
        altered[position] ^= 0x01;
        let loaded = Guard::load(Some(&altered), KEY, DEVICE, t(10));
        assert_failed_closed(&loaded, Tamper::StateInvalid);
    }
}

#[test]
fn hand_edited_json_fails_closed() {
    let saved = busy().save(KEY);
    let text = String::from_utf8_lossy(&saved).into_owned();
    // Se intenta poner apuestas a «no bloquear» directamente en el fichero.
    let edited = text.replacen("\"block_gambling\":true", "\"block_gambling\":false", 1);
    assert_ne!(edited, text);
    let loaded = Guard::load(Some(edited.as_bytes()), KEY, DEVICE, t(10));
    assert_failed_closed(&loaded, Tamper::StateInvalid);
}

#[test]
fn another_device_key_fails_closed() {
    let saved = busy().save(KEY);
    let loaded = Guard::load(Some(&saved), b"otra-clave", DEVICE, t(10));
    assert_failed_closed(&loaded, Tamper::StateInvalid);
}

#[test]
fn a_state_from_another_device_fails_closed() {
    // Misma clave (p. ej. copiada) pero el estado es de otro dispositivo.
    let saved = busy().save(KEY);
    let loaded = Guard::load(Some(&saved), KEY, [0xaa; 16], t(10));
    assert!(!loaded.is_paired());
    assert_eq!(loaded.device_id(), "aa".repeat(16));
    assert_eq!(events(&loaded), [EventKind::Tamper(Tamper::StateInvalid)]);
}

#[test]
fn garbage_and_truncation_fail_closed() {
    let saved = busy().save(KEY);
    for bytes in [
        &b""[..],
        b"NMGS",
        b"no es un estado",
        &saved[..saved.len() / 2],
    ] {
        let loaded = Guard::load(Some(bytes), KEY, DEVICE, t(10));
        assert_failed_closed(&loaded, Tamper::StateInvalid);
    }
}

#[test]
fn the_saved_state_never_contains_secrets() {
    let saved = busy().save(KEY);
    let text = String::from_utf8_lossy(&saved);
    for secret in [ANA, LUIS] {
        assert!(!text.contains(secret));
    }
}
