//! Desbloqueo con espera, pausa y lo que hace el paso del tiempo.

mod common;

use common::{events, guardian, last_event, paired, t, ANA, LUIS, START};
use guard_core::{
    Action, Authorizer, Decision, DenyReason, EventKind, Guard, GuardError, GuardianId, Mode,
    Tightening, TimePoint, Toggle, Urgency, DELAY_GRANT_SECS, MAX_PENDING_REQUESTS,
};

const HOUR: u64 = 3_600;
const DELAY: u64 = 72 * HOUR;

fn allow(domain: &str) -> Action {
    Action::AllowDomain {
        domain: domain.into(),
    }
}

#[test]
fn self_control_request_matures_after_72_hours_for_one_hour() {
    let (mut guard, _) = paired(Mode::SelfControl);
    let request = guard.request(&allow("ejemplo.com"), t(0)).unwrap();
    assert_eq!(request.ready_at, Some(START + DELAY));
    assert_eq!(
        last_event(&guard),
        EventKind::UnlockRequested {
            request: request.id,
            action: allow("ejemplo.com"),
            ready_at: Some(START + DELAY),
        }
    );
    assert_eq!(guard.outbox().last().unwrap().urgency, Urgency::Immediate);

    // Durante la espera se ve que está pendiente, pero no se puede hacer.
    assert_eq!(
        guard.check(&allow("ejemplo.com"), t(DELAY - 1)),
        Decision::Denied(DenyReason::Waiting {
            request: request.id,
            ready_at: Some(START + DELAY),
        })
    );
    assert_eq!(
        guard.perform(&allow("ejemplo.com"), t(DELAY - 1)),
        Err(GuardError::NotAuthorized)
    );

    // Vence: los guardianes reciben aviso y la acción queda permitida una hora.
    guard.tick(t(DELAY));
    let all = events(&guard);
    assert!(all.contains(&EventKind::Authorized {
        action: allow("ejemplo.com"),
        by: Authorizer::Delay {
            request: request.id
        },
    }));
    assert!(all.contains(&EventKind::UnlockReady {
        request: request.id,
        action: allow("ejemplo.com"),
        until: START + DELAY + DELAY_GRANT_SECS,
    }));
    assert_eq!(
        guard.check(&allow("ejemplo.com"), t(DELAY + HOUR - 1)),
        Decision::Allowed {
            until: START + DELAY + HOUR
        }
    );
    assert!(guard.pending_requests().is_empty());

    // Pasada esa hora, otra vez denegado.
    assert_eq!(
        guard.check(&allow("ejemplo.com"), t(DELAY + HOUR)),
        Decision::Denied(DenyReason::NeedsAuthorization)
    );
}

#[test]
fn a_matured_request_is_used_like_any_grant() {
    let (mut guard, _) = paired(Mode::SelfControl);
    guard.request(&Action::Uninstall, t(0)).unwrap();
    guard.perform(&Action::Uninstall, t(DELAY + 10)).unwrap();
    assert!(matches!(
        last_event(&guard),
        EventKind::Performed {
            action: Action::Uninstall,
            by: Authorizer::Delay { .. }
        }
    ));
    assert_eq!(
        guard.perform(&Action::Uninstall, t(DELAY + 20)),
        Err(GuardError::NotAuthorized),
        "una vez"
    );
}

#[test]
fn moving_the_system_clock_does_not_shorten_the_wait() {
    let (mut guard, _) = paired(Mode::SelfControl);
    guard.request(&Action::Uninstall, t(0)).unwrap();
    // Un minuto real, con el reloj del sistema adelantado cuatro días.
    let jumped = TimePoint {
        wall_secs: START + 4 * 24 * HOUR,
        ..t(60)
    };
    assert!(matches!(
        guard.check(&Action::Uninstall, jumped),
        Decision::Denied(DenyReason::Waiting { .. })
    ));
    assert_eq!(
        guard.perform(&Action::Uninstall, jumped),
        Err(GuardError::NotAuthorized)
    );
    assert!(events(&guard)
        .iter()
        .any(|e| matches!(e, EventKind::Tamper(_))));
}

#[test]
fn time_powered_off_does_not_count_unless_the_server_says_so() {
    let (mut guard, _) = paired(Mode::SelfControl);
    guard.request(&Action::Uninstall, t(0)).unwrap();

    // Apagado cuatro días y encendido sin conexión: la espera no ha avanzado.
    let rebooted = TimePoint {
        wall_secs: START + 4 * 24 * HOUR,
        monotonic_ms: 5_000,
        boot_id: 2,
        server_secs: None,
    };
    assert!(matches!(
        guard.check(&Action::Uninstall, rebooted),
        Decision::Denied(DenyReason::Waiting { .. })
    ));

    // En cuanto el servidor confirma la hora, sí.
    let online = TimePoint {
        server_secs: Some(START + 4 * 24 * HOUR + 5),
        wall_secs: START + 4 * 24 * HOUR + 5,
        monotonic_ms: 10_000,
        boot_id: 2,
    };
    assert!(matches!(
        guard.check(&Action::Uninstall, online),
        Decision::Allowed { .. }
    ));
}

#[test]
fn asking_again_does_not_restart_or_shorten_the_wait() {
    let (mut guard, _) = paired(Mode::SelfControl);
    let first = guard.request(&allow("a.com"), t(0)).unwrap();
    let again = guard.request(&allow("A.com."), t(HOUR)).unwrap();
    assert_eq!(first, again);
    let requested = events(&guard)
        .iter()
        .filter(|e| matches!(e, EventKind::UnlockRequested { .. }))
        .count();
    assert_eq!(requested, 1, "los guardianes reciben un solo aviso");
}

#[test]
fn anyone_can_cancel_a_request() {
    let (mut guard, _) = paired(Mode::SelfControl);
    let request = guard.request(&Action::Uninstall, t(0)).unwrap();
    guard.cancel_request(request.id, t(10)).unwrap();
    assert_eq!(
        last_event(&guard),
        EventKind::UnlockCancelled {
            request: request.id
        }
    );
    guard.tick(t(DELAY + 10));
    assert_eq!(
        guard.check(&Action::Uninstall, t(DELAY + 10)),
        Decision::Denied(DenyReason::NeedsAuthorization)
    );
    assert_eq!(
        guard.cancel_request(request.id, t(DELAY + 20)),
        Err(GuardError::UnknownRequest)
    );
}

#[test]
fn parental_requests_never_mature_but_reach_the_guardians() {
    let (mut guard, _) = paired(Mode::Parental);
    let request = guard.request(&allow("juegos.com"), t(0)).unwrap();
    assert_eq!(request.ready_at, None);
    assert_eq!(
        last_event(&guard),
        EventKind::UnlockRequested {
            request: request.id,
            action: allow("juegos.com"),
            ready_at: None,
        }
    );
    guard.tick(t(365 * 24 * HOUR));
    assert_eq!(
        guard.check(&allow("juegos.com"), t(365 * 24 * HOUR)),
        Decision::Denied(DenyReason::Waiting {
            request: request.id,
            ready_at: None
        })
    );
    // Un guardián con su clave sí puede.
    guard
        .authorize_with_secret(&allow("juegos.com"), ANA, t(365 * 24 * HOUR))
        .unwrap();
    guard
        .perform(&allow("juegos.com"), t(365 * 24 * HOUR))
        .unwrap();
    assert!(
        guard.pending_requests().is_empty(),
        "la solicitud queda atendida"
    );
}

#[test]
fn switching_to_parental_stops_pending_waits() {
    let (mut guard, _) = paired(Mode::SelfControl);
    guard.request(&Action::Uninstall, t(0)).unwrap();
    let to_parental = Action::ChangeMode {
        mode: Mode::Parental,
    };
    guard
        .authorize_with_secret(&to_parental, ANA, t(10))
        .unwrap();
    guard.perform(&to_parental, t(10)).unwrap();
    assert_eq!(guard.pending_requests()[0].ready_at, None);
    guard.tick(t(DELAY + 10));
    assert!(matches!(
        guard.check(&Action::Uninstall, t(DELAY + 10)),
        Decision::Denied(DenyReason::Waiting { ready_at: None, .. })
    ));
}

#[test]
fn lengthening_the_wait_is_free_and_shortening_needs_a_guardian() {
    let (mut guard, _) = paired(Mode::SelfControl);
    guard
        .tighten(&Tightening::LengthenDelay { hours: 168 }, t(0))
        .unwrap();
    let request = guard.request(&Action::Uninstall, t(1)).unwrap();
    assert_eq!(request.ready_at, Some(START + 1 + 168 * HOUR));

    let shorten = Action::ShortenDelay { hours: 24 };
    assert_eq!(
        guard.perform(&shorten, t(2)),
        Err(GuardError::NotAuthorized)
    );
    guard.authorize_with_secret(&shorten, ANA, t(3)).unwrap();
    guard.perform(&shorten, t(3)).unwrap();
    assert_eq!(guard.settings().delay_hours, 24);

    // Las solicitudes ya hechas conservan su hora.
    assert_eq!(
        guard.pending_requests()[0].ready_at,
        Some(START + 1 + 168 * HOUR)
    );
    // Las nuevas usan la espera nueva.
    let new = guard.request(&allow("b.com"), t(4)).unwrap();
    assert_eq!(new.ready_at, Some(START + 4 + 24 * HOUR));
}

#[test]
fn a_request_that_no_longer_makes_sense_lapses() {
    // Se pide quitar a Luis, pero Ana lo quita antes por otra vía.
    let (mut guard, _) = paired(Mode::SelfControl);
    guard
        .authorize_with_secret(&Action::AddGuardian, ANA, t(0))
        .unwrap();
    guard.add_guardian(guardian("Luis", LUIS, 2), t(0)).unwrap();
    let remove_luis = Action::RemoveGuardian {
        guardian: GuardianId::Second,
    };
    let remove_ana = Action::RemoveGuardian {
        guardian: GuardianId::First,
    };
    guard.request(&remove_luis, t(1)).unwrap();
    guard
        .authorize_with_secret(&remove_ana, LUIS, t(2))
        .unwrap();
    guard.perform(&remove_ana, t(2)).unwrap();

    guard.tick(t(DELAY + 1));
    assert!(guard.pending_requests().is_empty());
    assert_eq!(
        guard.check(&remove_luis, t(DELAY + 1)),
        Decision::Denied(DenyReason::NeedsAuthorization),
        "no se puede quedar sin guardianes"
    );
}

#[test]
fn requests_need_pairing_valid_actions_and_have_a_limit() {
    let mut unpaired = Guard::unpaired(common::DEVICE, t(0));
    assert_eq!(
        unpaired.request(&Action::Uninstall, t(0)),
        Err(GuardError::NotPaired)
    );

    let (mut guard, _) = paired(Mode::SelfControl);
    assert!(matches!(
        guard.request(&Action::Pause { minutes: 5_000 }, t(0)),
        Err(GuardError::InvalidAction(_))
    ));
    for i in 0..MAX_PENDING_REQUESTS {
        guard.request(&allow(&format!("d{i}.com")), t(0)).unwrap();
    }
    assert_eq!(
        guard.request(&allow("uno-mas.com"), t(0)),
        Err(GuardError::TooManyRequests)
    );
}

#[test]
fn pause_ends_on_its_own_and_is_reported() {
    let (mut guard, _) = paired(Mode::SelfControl);
    let pause = Action::Pause { minutes: 30 };
    guard.authorize_with_secret(&pause, ANA, t(0)).unwrap();
    guard.perform(&pause, t(0)).unwrap();
    assert!(!guard.protection_active());
    guard.tick(t(30 * 60));
    assert!(guard.protection_active());
    assert!(events(&guard).contains(&EventKind::PauseEnded));
    assert_eq!(guard.settings().paused_until, None);
}

#[test]
fn a_pause_can_also_be_requested_with_the_wait() {
    let (mut guard, _) = paired(Mode::SelfControl);
    let pause = Action::Pause { minutes: 120 };
    guard.request(&pause, t(0)).unwrap();
    guard.perform(&pause, t(DELAY)).unwrap();
    assert!(!guard.protection_active());
    guard.tick(t(DELAY + 120 * 60));
    assert!(guard.protection_active());
}

#[test]
fn disabling_a_category_by_waiting() {
    let (mut guard, _) = paired(Mode::SelfControl);
    let action = Action::DisableCategory {
        category: Toggle::Dating,
    };
    guard.request(&action, t(0)).unwrap();
    guard.perform(&action, t(DELAY)).unwrap();
    assert!(!guard.settings().block_dating);
    assert!(guard.settings().block_gambling);
}
