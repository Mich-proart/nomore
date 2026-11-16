//! Emparejar, guardianes y autorización con clave.

mod common;

use common::{events, guardian, last_event, paired, t, ANA, LUIS};
use guard_core::{
    Action, Authorizer, Decision, DenyReason, EventKind, Guard, GuardError, GuardianId, Mode,
    Tamper, Toggle, SECRET_GRANT_SECS,
};

fn allow(domain: &str) -> Action {
    Action::AllowDomain {
        domain: domain.into(),
    }
}

/// Dispositivo con Ana y Luis como guardianes.
fn with_two_guardians() -> Guard {
    let (mut guard, _) = paired(Mode::SelfControl);
    guard
        .authorize_with_secret(&Action::AddGuardian, ANA, t(1))
        .unwrap();
    guard.add_guardian(guardian("Luis", LUIS, 2), t(2)).unwrap();
    guard
}

// ------------------------------------------------------------------ emparejar

#[test]
fn pairing_sets_mode_and_first_guardian() {
    let (guard, code) = paired(Mode::Parental);
    assert!(guard.is_paired());
    assert_eq!(guard.settings().mode, Mode::Parental);
    let guardians = guard.guardians();
    assert_eq!(guardians.len(), 1);
    assert_eq!(guardians[0].id, GuardianId::First);
    assert_eq!(guardians[0].name, "Ana");
    assert_eq!(code.as_str().len(), 19);
    assert_eq!(
        events(&guard),
        [EventKind::Paired {
            mode: Mode::Parental,
            guardian: GuardianId::First,
            name: "Ana".into()
        }]
    );
}

#[test]
fn pairing_twice_is_refused() {
    let (mut guard, _) = paired(Mode::SelfControl);
    assert_eq!(
        guard
            .setup(Mode::Parental, guardian("Otro", "otra-clave-1", 3), t(1))
            .unwrap_err(),
        GuardError::AlreadyPaired
    );
    assert_eq!(guard.settings().mode, Mode::SelfControl);
    assert_eq!(guard.guardians().len(), 1);
}

#[test]
fn pairing_with_a_weak_secret_leaves_the_device_unpaired() {
    let mut guard = Guard::unpaired(t(0));
    assert_eq!(
        guard
            .setup(Mode::SelfControl, guardian("Ana", "corta", 1), t(0))
            .unwrap_err(),
        GuardError::WeakSecret
    );
    assert!(!guard.is_paired());
}

// ------------------------------------------------------------- clave correcta

#[test]
fn the_secret_grants_one_action_once() {
    let (mut guard, _) = paired(Mode::SelfControl);
    assert_eq!(
        guard.authorize_with_secret(&allow("ejemplo.com"), ANA, t(1)),
        Ok(GuardianId::First)
    );
    assert_eq!(
        last_event(&guard),
        EventKind::Authorized {
            action: allow("ejemplo.com"),
            by: Authorizer::Secret(GuardianId::First),
        }
    );

    // Solo vale para esa acción.
    assert_eq!(
        guard.perform(&allow("otro.com"), t(2)),
        Err(GuardError::NotAuthorized)
    );
    assert_eq!(
        guard.perform(&Action::Uninstall, t(2)),
        Err(GuardError::NotAuthorized)
    );

    // Y solo una vez.
    guard.perform(&allow("ejemplo.com"), t(3)).unwrap();
    assert_eq!(
        guard.perform(&allow("ejemplo.com"), t(4)),
        Err(GuardError::NotAuthorized)
    );
    assert_eq!(
        guard.check(&allow("ejemplo.com"), t(4)),
        Decision::Denied(DenyReason::NeedsAuthorization)
    );
}

#[test]
fn a_grant_matches_the_action_however_it_is_spelled() {
    let (mut guard, _) = paired(Mode::SelfControl);
    guard
        .authorize_with_secret(&allow("Ejemplo.COM."), ANA, t(1))
        .unwrap();
    guard.perform(&allow("ejemplo.com"), t(2)).unwrap();
    assert_eq!(guard.settings().allowlist, ["ejemplo.com"]);
}

#[test]
fn a_grant_expires_after_ten_minutes() {
    let (mut guard, _) = paired(Mode::SelfControl);
    guard
        .authorize_with_secret(&Action::Uninstall, ANA, t(0))
        .unwrap();
    assert_eq!(
        guard.check(&Action::Uninstall, t(SECRET_GRANT_SECS - 1)),
        Decision::Allowed {
            until: common::START + SECRET_GRANT_SECS
        }
    );
    assert_eq!(
        guard.check(&Action::Uninstall, t(SECRET_GRANT_SECS)),
        Decision::Denied(DenyReason::NeedsAuthorization)
    );
    assert_eq!(
        guard.perform(&Action::Uninstall, t(SECRET_GRANT_SECS)),
        Err(GuardError::NotAuthorized)
    );
}

#[test]
fn moving_the_system_clock_does_not_expire_or_extend_a_grant() {
    let (mut guard, _) = paired(Mode::SelfControl);
    guard
        .authorize_with_secret(&Action::Uninstall, ANA, t(0))
        .unwrap();
    // Pasan 11 minutos reales, pero el reloj del sistema se atrasa una hora.
    let mut rewound = t(SECRET_GRANT_SECS + 60);
    rewound.wall_secs -= 3_600;
    assert_eq!(
        guard.perform(&Action::Uninstall, rewound),
        Err(GuardError::NotAuthorized)
    );
}

// ------------------------------------------------------------ clave incorrecta

#[test]
fn a_wrong_secret_grants_nothing() {
    let (mut guard, _) = paired(Mode::SelfControl);
    assert_eq!(
        guard.authorize_with_secret(&Action::Uninstall, "no-es-la-clave", t(1)),
        Err(GuardError::WrongSecret)
    );
    assert_eq!(
        guard.perform(&Action::Uninstall, t(100)),
        Err(GuardError::NotAuthorized)
    );
}

#[test]
fn failures_lock_longer_each_time_and_alert_at_the_third() {
    let (mut guard, _) = paired(Mode::SelfControl);
    let wrong = |guard: &mut Guard, at| {
        guard.authorize_with_secret(&Action::Uninstall, "equivocada", t(at))
    };

    assert_eq!(wrong(&mut guard, 10), Err(GuardError::WrongSecret));
    // Durante la espera ni siquiera se comprueba la clave, aunque sea la buena.
    assert_eq!(
        guard.authorize_with_secret(&Action::Uninstall, ANA, t(10)),
        Err(GuardError::TooManyAttempts {
            retry_at_secs: common::START + 11
        })
    );
    assert_eq!(wrong(&mut guard, 11), Err(GuardError::WrongSecret));
    assert!(
        !events(&guard)
            .iter()
            .any(|e| matches!(e, EventKind::Tamper(_))),
        "dos fallos todavía no avisan"
    );
    assert_eq!(
        wrong(&mut guard, 12),
        Err(GuardError::TooManyAttempts {
            retry_at_secs: common::START + 13
        })
    );

    assert_eq!(wrong(&mut guard, 13), Err(GuardError::WrongSecret));
    assert_eq!(
        last_event(&guard),
        EventKind::Tamper(Tamper::SecretGuessing { attempts: 3 })
    );
    assert_eq!(
        wrong(&mut guard, 16),
        Err(GuardError::TooManyAttempts {
            retry_at_secs: common::START + 17
        })
    );
}

#[test]
fn the_lock_never_exceeds_an_hour_and_success_clears_it() {
    let (mut guard, _) = paired(Mode::SelfControl);
    let mut at = 0;
    for _ in 0..15 {
        match guard.authorize_with_secret(&Action::Uninstall, "equivocada", t(at)) {
            Err(GuardError::WrongSecret) => {}
            other => panic!("inesperado: {other:?}"),
        }
        // Salta justo al final de la espera vigente.
        at = match guard.authorize_with_secret(&Action::Uninstall, "equivocada", t(at)) {
            Err(GuardError::TooManyAttempts { retry_at_secs }) => {
                let wait = retry_at_secs - common::START - at;
                assert!(wait <= 3_600, "espera de {wait} s");
                retry_at_secs - common::START
            }
            other => panic!("inesperado: {other:?}"),
        };
    }

    guard
        .authorize_with_secret(&Action::Uninstall, ANA, t(at))
        .unwrap();
    // Tras acertar, un fallo vuelve a costar solo un segundo.
    assert_eq!(
        guard.authorize_with_secret(&Action::Uninstall, "equivocada", t(at + 1)),
        Err(GuardError::WrongSecret)
    );
    assert_eq!(
        guard.authorize_with_secret(&Action::Uninstall, ANA, t(at + 1)),
        Err(GuardError::TooManyAttempts {
            retry_at_secs: common::START + at + 2
        })
    );
}

// ------------------------------------------------------------- dos guardianes

#[test]
fn a_second_guardian_needs_authorization_from_the_first() {
    let (mut guard, _) = paired(Mode::SelfControl);
    assert_eq!(
        guard
            .add_guardian(guardian("Luis", LUIS, 2), t(1))
            .unwrap_err(),
        GuardError::NotAuthorized
    );
    assert_eq!(guard.guardians().len(), 1);

    guard
        .authorize_with_secret(&Action::AddGuardian, ANA, t(2))
        .unwrap();
    let (id, code) = guard.add_guardian(guardian("Luis", LUIS, 2), t(3)).unwrap();
    assert_eq!(id, GuardianId::Second);
    assert_eq!(code.as_str().len(), 19);
    assert_eq!(
        last_event(&guard),
        EventKind::GuardianAdded {
            guardian: GuardianId::Second,
            name: "Luis".into()
        }
    );
    let names: Vec<_> = guard.guardians().into_iter().map(|g| g.name).collect();
    assert_eq!(names, ["Ana", "Luis"]);
}

#[test]
fn there_is_never_a_third_guardian() {
    let mut guard = with_two_guardians();
    for secret in [ANA, LUIS] {
        assert_eq!(
            guard.authorize_with_secret(&Action::AddGuardian, secret, t(10)),
            Err(GuardError::TooManyGuardians)
        );
    }
    assert_eq!(
        guard
            .add_guardian(guardian("Eva", "clave-de-eva", 3), t(11))
            .unwrap_err(),
        GuardError::TooManyGuardians
    );
    assert_eq!(guard.guardians().len(), 2);
}

#[test]
fn either_guardian_can_authorize_anything() {
    for (secret, expected) in [(ANA, GuardianId::First), (LUIS, GuardianId::Second)] {
        for action in [
            allow("ejemplo.com"),
            Action::DisableCategory {
                category: Toggle::Gambling,
            },
            Action::Pause { minutes: 10 },
            Action::ChangeMode {
                mode: Mode::Parental,
            },
            Action::Uninstall,
        ] {
            let mut guard = with_two_guardians();
            assert_eq!(
                guard.authorize_with_secret(&action, secret, t(10)),
                Ok(expected)
            );
            guard.perform(&action, t(11)).unwrap();
            assert_eq!(
                last_event(&guard),
                EventKind::Performed {
                    action,
                    by: Authorizer::Secret(expected)
                },
                "el evento dice quién autorizó"
            );
        }
    }
}

#[test]
fn either_guardian_can_remove_the_other_but_not_the_last_one() {
    // Luis quita a Ana.
    let mut guard = with_two_guardians();
    let remove_ana = Action::RemoveGuardian {
        guardian: GuardianId::First,
    };
    guard
        .authorize_with_secret(&remove_ana, LUIS, t(10))
        .unwrap();
    guard.perform(&remove_ana, t(11)).unwrap();
    let left = guard.guardians();
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].name, "Luis");

    // La clave de Ana ya no sirve.
    assert_eq!(
        guard.authorize_with_secret(&Action::Uninstall, ANA, t(20)),
        Err(GuardError::WrongSecret)
    );
    // Y Luis no puede quitarse a sí mismo: siempre queda uno.
    assert_eq!(
        guard.authorize_with_secret(
            &Action::RemoveGuardian {
                guardian: GuardianId::Second
            },
            LUIS,
            t(30)
        ),
        Err(GuardError::LastGuardian)
    );
    // Quitar a quien ya no está tampoco tiene sentido.
    assert_eq!(
        guard.authorize_with_secret(&remove_ana, LUIS, t(31)),
        Err(GuardError::UnknownGuardian)
    );

    // El hueco se puede volver a ocupar, y sigue habiendo dos como mucho.
    guard
        .authorize_with_secret(&Action::AddGuardian, LUIS, t(40))
        .unwrap();
    let (id, _) = guard
        .add_guardian(guardian("Eva", "clave-de-eva", 3), t(41))
        .unwrap();
    assert_eq!(id, GuardianId::First);
    assert_eq!(guard.guardians().len(), 2);
}

#[test]
fn a_grant_to_remove_a_guardian_cannot_leave_the_device_without_any() {
    // Los dos permisos se conceden mientras hay dos guardianes…
    let mut guard = with_two_guardians();
    let remove_ana = Action::RemoveGuardian {
        guardian: GuardianId::First,
    };
    let remove_luis = Action::RemoveGuardian {
        guardian: GuardianId::Second,
    };
    guard
        .authorize_with_secret(&remove_ana, ANA, t(10))
        .unwrap();
    guard
        .authorize_with_secret(&remove_luis, ANA, t(11))
        .unwrap();
    // …pero el segundo ya no se puede aplicar.
    guard.perform(&remove_ana, t(12)).unwrap();
    assert_eq!(
        guard.perform(&remove_luis, t(13)),
        Err(GuardError::LastGuardian)
    );
    assert_eq!(guard.guardians().len(), 1);
}

#[test]
fn a_bad_second_guardian_does_not_waste_the_grant() {
    let (mut guard, _) = paired(Mode::SelfControl);
    guard
        .authorize_with_secret(&Action::AddGuardian, ANA, t(1))
        .unwrap();
    assert_eq!(
        guard
            .add_guardian(guardian("Luis", "corta", 2), t(2))
            .unwrap_err(),
        GuardError::WeakSecret
    );
    guard.add_guardian(guardian("Luis", LUIS, 2), t(3)).unwrap();
}

// ------------------------------------------------------- cambio de clave

#[test]
fn a_guardian_can_change_their_own_or_the_other_secret() {
    let mut guard = with_two_guardians();
    let change_luis = Action::ChangeSecret {
        guardian: GuardianId::Second,
    };
    guard
        .authorize_with_secret(&change_luis, ANA, t(10))
        .unwrap();
    guard
        .change_secret(GuardianId::Second, "nueva-de-luis", &[9; 48], t(11))
        .unwrap();
    assert_eq!(
        last_event(&guard),
        EventKind::SecretChanged {
            guardian: GuardianId::Second
        }
    );

    assert_eq!(
        guard.authorize_with_secret(&Action::Uninstall, LUIS, t(20)),
        Err(GuardError::WrongSecret)
    );
    assert_eq!(
        guard.authorize_with_secret(&Action::Uninstall, "nueva-de-luis", t(30)),
        Ok(GuardianId::Second)
    );
}

#[test]
fn changing_a_secret_needs_its_own_grant() {
    let mut guard = with_two_guardians();
    assert_eq!(
        guard
            .change_secret(GuardianId::First, "otra-clave-1", &[9; 48], t(10))
            .unwrap_err(),
        GuardError::NotAuthorized
    );
    // Un permiso para la clave de Luis no vale para la de Ana.
    guard
        .authorize_with_secret(
            &Action::ChangeSecret {
                guardian: GuardianId::Second,
            },
            ANA,
            t(11),
        )
        .unwrap();
    assert_eq!(
        guard
            .change_secret(GuardianId::First, "otra-clave-1", &[9; 48], t(12))
            .unwrap_err(),
        GuardError::NotAuthorized
    );
    // Y una clave nueva demasiado corta no gasta el permiso.
    assert_eq!(
        guard
            .change_secret(GuardianId::Second, "corta", &[9; 48], t(13))
            .unwrap_err(),
        GuardError::WeakSecret
    );
    guard
        .change_secret(GuardianId::Second, "nueva-de-luis", &[9; 48], t(14))
        .unwrap();
}

#[test]
fn perform_refuses_actions_that_need_data() {
    let (mut guard, _) = paired(Mode::SelfControl);
    guard
        .authorize_with_secret(&Action::AddGuardian, ANA, t(1))
        .unwrap();
    assert!(matches!(
        guard.perform(&Action::AddGuardian, t(2)),
        Err(GuardError::InvalidAction(_))
    ));
    assert_eq!(guard.guardians().len(), 1);
}

// --------------------------------------------------- código de recuperación

#[test]
fn recovery_code_lets_a_guardian_reset_only_their_own_secret() {
    let (mut guard, code) = paired(Mode::SelfControl);
    assert_eq!(
        guard.authorize_with_recovery_code(code.as_str(), t(1)),
        Ok(GuardianId::First)
    );
    assert_eq!(
        last_event(&guard),
        EventKind::Authorized {
            action: Action::ChangeSecret {
                guardian: GuardianId::First
            },
            by: Authorizer::RecoveryCode(GuardianId::First),
        }
    );
    // El código no autoriza nada más.
    assert_eq!(
        guard.perform(&Action::Uninstall, t(2)),
        Err(GuardError::NotAuthorized)
    );

    let new_code = guard
        .change_secret(GuardianId::First, "clave-nueva-1", &[5; 48], t(3))
        .unwrap();
    assert_ne!(new_code, code);
    guard
        .authorize_with_secret(&Action::Uninstall, "clave-nueva-1", t(4))
        .unwrap();

    // El código viejo ya no vale; el nuevo sí.
    assert_eq!(
        guard.authorize_with_recovery_code(code.as_str(), t(10)),
        Err(GuardError::WrongRecoveryCode)
    );
    assert_eq!(
        guard.authorize_with_recovery_code(new_code.as_str(), t(20)),
        Ok(GuardianId::First)
    );
}

#[test]
fn each_guardian_has_their_own_recovery_code() {
    let (mut guard, ana_code) = paired(Mode::SelfControl);
    guard
        .authorize_with_secret(&Action::AddGuardian, ANA, t(1))
        .unwrap();
    let (_, luis_code) = guard.add_guardian(guardian("Luis", LUIS, 2), t(2)).unwrap();
    assert_ne!(ana_code, luis_code);
    assert_eq!(
        guard.authorize_with_recovery_code(luis_code.as_str(), t(3)),
        Ok(GuardianId::Second)
    );
    assert_eq!(
        guard
            .change_secret(GuardianId::First, "otra-clave-1", &[5; 48], t(4))
            .unwrap_err(),
        GuardError::NotAuthorized
    );
}

#[test]
fn guessing_recovery_codes_is_throttled_too() {
    let (mut guard, code) = paired(Mode::SelfControl);
    assert_eq!(
        guard.authorize_with_recovery_code("AAAA-AAAA-AAAA-AAAA", t(1)),
        Err(GuardError::WrongRecoveryCode)
    );
    // Ni el código bueno entra durante la espera.
    assert_eq!(
        guard.authorize_with_recovery_code(code.as_str(), t(1)),
        Err(GuardError::TooManyAttempts {
            retry_at_secs: common::START + 2
        })
    );
    assert_eq!(
        guard.authorize_with_recovery_code(code.as_str(), t(2)),
        Ok(GuardianId::First)
    );
}

#[test]
fn secrets_never_appear_in_events() {
    let mut guard = with_two_guardians();
    let _ = guard.authorize_with_secret(&Action::Uninstall, "intento-fallido", t(10));
    let dump: String = guard.outbox().into_iter().map(|e| e.payload).collect();
    for secret in [ANA, LUIS, "intento-fallido"] {
        assert!(!dump.contains(secret));
    }
}
