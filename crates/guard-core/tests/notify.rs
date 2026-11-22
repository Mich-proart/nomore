//! Intentos de acceso agrupados, urgencias y señal de vida.

mod common;

use common::{events, paired, t, START};
use guard_core::{
    Category, Envelope, Event, EventKind, Mode, Tamper, Urgency, ACCESS_WINDOW_SECS, HEARTBEAT_SECS,
};

fn kinds(envelopes: &[Envelope]) -> Vec<(Urgency, EventKind)> {
    envelopes
        .iter()
        .map(|e| {
            let event: Event = serde_json::from_str(&e.payload).unwrap();
            (e.urgency, event.kind)
        })
        .collect()
}

/// Dispositivo emparejado con la cola vacía.
fn quiet() -> guard_core::Guard {
    let (mut guard, _) = paired(Mode::SelfControl);
    guard.acknowledge(u64::MAX, t(0));
    guard
}

#[test]
fn forty_attempts_in_a_minute_make_two_events() {
    let mut guard = quiet();
    for second in 0..40 {
        guard.record_access("cdn.pornhub.com", Category::Porn, t(1 + second));
    }
    assert_eq!(
        kinds(&guard.outbox()),
        [(
            Urgency::Immediate,
            EventKind::AccessAttempt {
                site: "cdn.pornhub.com".into(),
                category: Category::Porn
            }
        )]
    );

    guard.tick(t(1 + ACCESS_WINDOW_SECS));
    let all = kinds(&guard.outbox());
    assert!(all.contains(&(
        Urgency::Immediate,
        EventKind::AccessRepeated {
            site: "cdn.pornhub.com".into(),
            category: Category::Porn,
            count: 39,
            since: START + 1,
        }
    )));
}

#[test]
fn gambling_dating_and_bypass_go_to_the_digest() {
    let mut guard = quiet();
    guard.record_access("bet365.es", Category::Gambling, t(1));
    guard.record_access("bet365.es", Category::Gambling, t(2));
    guard.record_access("tinder.com", Category::Dating, t(3));
    guard.record_access("dns.google", Category::Bypass, t(4));
    guard.tick(t(1 + ACCESS_WINDOW_SECS));

    for (urgency, kind) in kinds(&guard.outbox()) {
        match kind {
            EventKind::AccessAttempt { .. } | EventKind::AccessRepeated { .. } => {
                assert_eq!(urgency, Urgency::Digest, "{kind:?}")
            }
            EventKind::Heartbeat { .. } => assert_eq!(urgency, Urgency::Silent),
            other => panic!("inesperado: {other:?}"),
        }
    }
}

#[test]
fn every_kind_of_tampering_is_immediate() {
    let mut guard = quiet();
    for tamper in [
        Tamper::ServiceStopped,
        Tamper::UninstallAttempt,
        Tamper::DnsChanged,
        Tamper::HostsChanged,
        Tamper::VpnDetected,
        Tamper::StateMissing,
        Tamper::StateInvalid,
        Tamper::ForgedApproval,
        Tamper::ForgedLists,
    ] {
        guard.record_tamper(tamper, t(1));
    }
    let all = kinds(&guard.outbox());
    assert_eq!(all.len(), 9);
    assert!(all
        .iter()
        .all(|(urgency, _)| *urgency == Urgency::Immediate));
}

#[test]
fn heartbeat_every_fifteen_minutes_and_never_piling_up() {
    let (mut guard, _) = paired(Mode::SelfControl);
    let heartbeats = |guard: &guard_core::Guard| {
        events(guard)
            .iter()
            .filter(|e| matches!(e, EventKind::Heartbeat { .. }))
            .count()
    };
    guard.tick(t(1));
    assert_eq!(heartbeats(&guard), 1);
    assert_eq!(
        guard
            .outbox()
            .iter()
            .find(|e| e.payload.contains("heartbeat"))
            .unwrap()
            .urgency,
        Urgency::Silent
    );

    // Sin conexión: pasan horas y sigue habiendo una sola en cola.
    for minute in 1..=240 {
        guard.tick(t(minute * 60));
    }
    assert_eq!(heartbeats(&guard), 1);

    // Al entregarla, la siguiente sale cuando toca.
    let now = 240 * 60;
    guard.acknowledge(u64::MAX, t(now));
    guard.tick(t(now + 1));
    assert_eq!(heartbeats(&guard), 1, "ya pasaron 15 min desde la última");
    guard.acknowledge(u64::MAX, t(now + 2));
    guard.tick(t(now + 3));
    assert_eq!(heartbeats(&guard), 0, "aún no toca");
    guard.tick(t(now + 1 + HEARTBEAT_SECS));
    assert_eq!(heartbeats(&guard), 1);
}

#[test]
fn heartbeat_says_whether_protection_is_active() {
    let (mut guard, _) = paired(Mode::SelfControl);
    let pause = guard_core::Action::Pause { minutes: 60 };
    guard
        .authorize_with_secret(&pause, common::ANA, t(0))
        .unwrap();
    guard.perform(&pause, t(0)).unwrap();
    guard.acknowledge(u64::MAX, t(0));
    guard.tick(t(HEARTBEAT_SECS));
    assert!(events(&guard).contains(&EventKind::Heartbeat {
        protection_active: false
    }));
}

#[test]
fn unpaired_devices_send_no_heartbeat() {
    let mut guard = guard_core::Guard::unpaired(common::DEVICE, t(0));
    for minute in 0..60 {
        guard.tick(t(minute * 60));
    }
    assert_eq!(guard.pending_events(), 0);
}

#[test]
fn authorizations_and_changes_are_immediate_tightening_is_digest() {
    let mut guard = quiet();
    let pause = guard_core::Action::Pause { minutes: 10 };
    guard.request(&pause, t(1)).unwrap();
    guard
        .authorize_with_secret(&pause, common::ANA, t(2))
        .unwrap();
    guard.perform(&pause, t(3)).unwrap();
    guard
        .tighten(&guard_core::Tightening::Resume, t(4))
        .unwrap();

    let all = kinds(&guard.outbox());
    let urgency_of = |pred: fn(&EventKind) -> bool| {
        all.iter()
            .find(|(_, kind)| pred(kind))
            .map(|(urgency, _)| *urgency)
            .unwrap()
    };
    assert_eq!(
        urgency_of(|k| matches!(k, EventKind::UnlockRequested { .. })),
        Urgency::Immediate
    );
    assert_eq!(
        urgency_of(|k| matches!(k, EventKind::Authorized { .. })),
        Urgency::Immediate
    );
    assert_eq!(
        urgency_of(|k| matches!(k, EventKind::Performed { .. })),
        Urgency::Immediate
    );
    assert_eq!(
        urgency_of(|k| matches!(k, EventKind::Tightened { .. })),
        Urgency::Digest
    );
}
