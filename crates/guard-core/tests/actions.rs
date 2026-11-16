//! «Qué exige autorización»: endurecer es libre, aflojar no.

mod common;

use common::{events, last_event, paired, t, ANA};
use guard_core::{
    verify_chain, Action, Authorizer, Category, Decision, DenyReason, EventKind, Guard, GuardError,
    GuardianId, Mode, Tamper, Tightening, Toggle, Urgency, GENESIS,
};

fn domain(d: &str) -> String {
    d.to_owned()
}

/// Todas las acciones que aflojan y no necesitan datos adicionales.
fn loosening_actions() -> Vec<Action> {
    vec![
        Action::AllowDomain {
            domain: domain("ejemplo.com"),
        },
        Action::UnblockDomain {
            domain: domain("bloqueado.com"),
        },
        Action::DisableCategory {
            category: Toggle::Gambling,
        },
        Action::DisableCategory {
            category: Toggle::Dating,
        },
        Action::Pause { minutes: 60 },
        Action::ShortenDelay { hours: 24 },
        Action::ChangeMode {
            mode: Mode::Parental,
        },
        Action::Uninstall,
    ]
}

#[test]
fn unpaired_device_is_locked_down_and_nothing_can_be_loosened() {
    let mut guard = Guard::unpaired(t(0));
    assert!(!guard.is_paired());
    assert!(guard.protection_active());
    assert!(guard.settings().block_gambling && guard.settings().block_dating);

    for action in loosening_actions() {
        assert_eq!(
            guard.check(&action, t(1)),
            Decision::Denied(DenyReason::NotPaired)
        );
        assert_eq!(guard.perform(&action, t(1)), Err(GuardError::NotPaired));
        assert_eq!(
            guard.authorize_with_secret(&action, ANA, t(1)),
            Err(GuardError::NotPaired)
        );
    }
}

#[test]
fn every_loosening_action_is_denied_without_authorization() {
    let (mut guard, _) = paired(Mode::SelfControl);
    guard
        .tighten(
            &Tightening::BlockDomain {
                domain: domain("bloqueado.com"),
            },
            t(1),
        )
        .unwrap();
    let before = guard.settings().clone();

    for action in loosening_actions() {
        assert_eq!(
            guard.check(&action, t(2)),
            Decision::Denied(DenyReason::NeedsAuthorization),
            "{action:?}"
        );
        assert_eq!(
            guard.perform(&action, t(2)),
            Err(GuardError::NotAuthorized),
            "{action:?}"
        );
    }
    assert_eq!(guard.settings(), &before, "nada ha cambiado");
    assert!(guard.protection_active());
}

#[test]
fn every_loosening_action_works_once_authorized() {
    for action in loosening_actions() {
        let (mut guard, _) = paired(Mode::SelfControl);
        guard
            .tighten(
                &Tightening::BlockDomain {
                    domain: domain("bloqueado.com"),
                },
                t(1),
            )
            .unwrap();
        guard.authorize_with_secret(&action, ANA, t(2)).unwrap();
        assert!(
            matches!(guard.check(&action, t(3)), Decision::Allowed { .. }),
            "{action:?}"
        );
        guard.perform(&action, t(3)).unwrap();
        assert_eq!(
            last_event(&guard),
            EventKind::Performed {
                action: action.clone(),
                by: Authorizer::Secret(GuardianId::First),
            }
        );

        let settings = guard.settings();
        match action {
            Action::AllowDomain { domain } => assert_eq!(settings.allowlist, [domain]),
            Action::UnblockDomain { .. } => assert!(settings.extra_blocks.is_empty()),
            Action::DisableCategory {
                category: Toggle::Gambling,
            } => {
                assert!(!settings.block_gambling && settings.block_dating)
            }
            Action::DisableCategory {
                category: Toggle::Dating,
            } => {
                assert!(settings.block_gambling && !settings.block_dating)
            }
            Action::Pause { .. } => assert!(!guard.protection_active()),
            Action::ShortenDelay { hours } => assert_eq!(settings.delay_hours, hours),
            Action::ChangeMode { mode } => assert_eq!(settings.mode, mode),
            _ => {}
        }
    }
}

#[test]
fn tightening_is_free_and_recorded() {
    let (mut guard, _) = paired(Mode::SelfControl);
    guard
        .authorize_with_secret(
            &Action::DisableCategory {
                category: Toggle::Dating,
            },
            ANA,
            t(1),
        )
        .unwrap();
    guard
        .perform(
            &Action::DisableCategory {
                category: Toggle::Dating,
            },
            t(1),
        )
        .unwrap();
    guard
        .authorize_with_secret(
            &Action::AllowDomain {
                domain: domain("ejemplo.com"),
            },
            ANA,
            t(2),
        )
        .unwrap();
    guard
        .perform(
            &Action::AllowDomain {
                domain: domain("ejemplo.com"),
            },
            t(2),
        )
        .unwrap();

    let changes = [
        Tightening::BlockDomain {
            domain: domain("Nuevo.COM."),
        },
        Tightening::EnableCategory {
            category: Toggle::Dating,
        },
        Tightening::DisallowDomain {
            domain: domain("ejemplo.com"),
        },
        Tightening::LengthenDelay { hours: 100 },
    ];
    for change in &changes {
        guard.tighten(change, t(3)).unwrap();
    }

    let settings = guard.settings();
    assert_eq!(settings.extra_blocks, ["nuevo.com"]);
    assert!(settings.block_dating);
    assert!(settings.allowlist.is_empty());
    assert_eq!(settings.delay_hours, 100);
    assert_eq!(
        last_event(&guard),
        EventKind::Tightened {
            change: Tightening::LengthenDelay { hours: 100 }
        }
    );
    // Endurecer va al resumen diario, no avisa al instante.
    assert_eq!(guard.outbox().last().unwrap().urgency, Urgency::Digest);
}

#[test]
fn tightening_works_even_before_pairing() {
    let mut guard = Guard::unpaired(t(0));
    guard
        .tighten(
            &Tightening::BlockDomain {
                domain: domain("algo.com"),
            },
            t(1),
        )
        .unwrap();
    assert_eq!(guard.settings().extra_blocks, ["algo.com"]);
}

#[test]
fn pause_resumes_on_its_own_and_can_be_ended_early() {
    let (mut guard, _) = paired(Mode::SelfControl);
    let pause = Action::Pause { minutes: 30 };
    guard.authorize_with_secret(&pause, ANA, t(0)).unwrap();
    guard.perform(&pause, t(0)).unwrap();
    assert!(!guard.protection_active());

    // Cualquiera puede terminarla antes.
    guard.tighten(&Tightening::Resume, t(60)).unwrap();
    assert!(guard.protection_active());

    // Y si nadie la termina, acaba sola.
    guard.authorize_with_secret(&pause, ANA, t(100)).unwrap();
    guard.perform(&pause, t(100)).unwrap();
    guard.check(&pause, t(100 + 30 * 60 - 1));
    assert!(!guard.protection_active());
    guard.check(&pause, t(100 + 30 * 60));
    assert!(guard.protection_active());
}

#[test]
fn pause_longer_than_a_day_cannot_even_be_authorized() {
    let (mut guard, _) = paired(Mode::SelfControl);
    let too_long = Action::Pause {
        minutes: 24 * 60 + 1,
    };
    assert!(matches!(
        guard.authorize_with_secret(&too_long, ANA, t(0)),
        Err(GuardError::InvalidAction(_))
    ));
}

#[test]
fn an_action_that_fails_keeps_its_grant_and_changes_nothing() {
    let (mut guard, _) = paired(Mode::SelfControl);
    // 72 h no es más corta que 72 h: autorizada, pero no aplicable.
    let pointless = Action::ShortenDelay { hours: 72 };
    guard.authorize_with_secret(&pointless, ANA, t(0)).unwrap();
    assert!(matches!(
        guard.perform(&pointless, t(1)),
        Err(GuardError::InvalidAction(_))
    ));
    assert_eq!(guard.settings().delay_hours, 72);
    assert!(matches!(
        guard.check(&pointless, t(1)),
        Decision::Allowed { .. }
    ));
}

#[test]
fn settings_visibility_depends_on_mode() {
    let (self_control, _) = paired(Mode::SelfControl);
    assert!(self_control.protected_can_view_settings());
    let (parental, _) = paired(Mode::Parental);
    assert!(!parental.protected_can_view_settings());
}

#[test]
fn agent_reports_are_recorded_with_their_urgency() {
    let (mut guard, _) = paired(Mode::SelfControl);
    guard.acknowledge(u64::MAX, t(0));

    guard.record_access("PornHub.com.", Category::Porn, t(1));
    guard.record_access("bet365.es", Category::Gambling, t(2));
    guard.record_access("tinder.com", Category::Dating, t(3));
    guard.record_access("dns.google", Category::Bypass, t(4));
    guard.record_tamper(Tamper::DnsChanged, t(5));
    guard.record_tamper(Tamper::UninstallAttempt, t(6));

    let urgencies: Vec<_> = guard.outbox().iter().map(|e| e.urgency).collect();
    assert_eq!(
        urgencies,
        [
            Urgency::Immediate,
            Urgency::Digest,
            Urgency::Digest,
            Urgency::Digest,
            Urgency::Immediate,
            Urgency::Immediate,
        ]
    );
    assert_eq!(
        events(&guard)[0],
        EventKind::AccessAttempt {
            site: "pornhub.com".into(),
            category: Category::Porn
        }
    );
}

#[test]
fn moving_the_system_clock_is_recorded_as_tampering() {
    let (mut guard, _) = paired(Mode::SelfControl);
    let mut jumped = t(60);
    jumped.wall_secs += 3 * 86_400;
    guard.check(&Action::Uninstall, jumped);

    assert!(matches!(
        last_event(&guard),
        EventKind::Tamper(Tamper::ClockChanged { .. })
    ));
    assert_eq!(guard.outbox().last().unwrap().urgency, Urgency::Immediate);
    assert_eq!(
        guard.now_secs(),
        common::START + 60,
        "la hora de confianza no salta"
    );
}

#[test]
fn everything_ends_up_in_one_verifiable_chain() {
    let (mut guard, _) = paired(Mode::SelfControl);
    let allow = Action::AllowDomain {
        domain: domain("ejemplo.com"),
    };
    guard.authorize_with_secret(&allow, ANA, t(1)).unwrap();
    guard.perform(&allow, t(2)).unwrap();
    guard.record_tamper(Tamper::VpnDetected, t(3));

    assert_eq!(guard.pending_events(), 4);
    let payloads: Vec<String> = guard.outbox().into_iter().map(|e| e.payload).collect();
    let (last_id, hash) = verify_chain(0, &GENESIS, &payloads).unwrap();
    assert_eq!(last_id, 4);

    // Tras confirmar, la cadena continúa desde donde iba.
    guard.acknowledge(last_id, t(4));
    assert_eq!(guard.pending_events(), 0);
    guard.record_tamper(Tamper::HostsChanged, t(5));
    let payloads: Vec<String> = guard.outbox().into_iter().map(|e| e.payload).collect();
    assert_eq!(verify_chain(last_id, &hash, &payloads).unwrap().0, 5);
}
