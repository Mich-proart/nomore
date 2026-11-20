//! Aprobación a distancia firmada por el servidor.

mod common;

use common::{events, guardian, last_event, paired, t, ANA, LUIS, START};
use ed25519_dalek::{Signer, SigningKey};
use guard_core::{
    Action, Approval, ApprovalBody, Authorizer, Decision, EventKind, Guard, GuardError, GuardianId,
    Mode, Tamper, SECRET_GRANT_SECS,
};

const SERVER_SEED: [u8; 32] = [0x5e; 32];

fn server() -> SigningKey {
    SigningKey::from_bytes(&SERVER_SEED)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sign(key: &SigningKey, body: ApprovalBody) -> Approval {
    let signature = key.sign(&body.signing_bytes());
    Approval {
        body,
        signature: hex(&signature.to_bytes()),
    }
}

/// Dispositivo emparejado, vinculado al servidor, con una solicitud de
/// desinstalar pendiente.
fn linked(mode: Mode) -> (Guard, u64) {
    let (mut guard, _) = paired(mode);
    let link = Action::LinkServer {
        public_key: hex(server().verifying_key().as_bytes()),
    };
    guard.authorize_with_secret(&link, ANA, t(0)).unwrap();
    guard.perform(&link, t(0)).unwrap();
    let request = guard.request(&Action::Uninstall, t(1)).unwrap();
    (guard, request.id)
}

fn body(guard: &Guard, request: u64) -> ApprovalBody {
    ApprovalBody {
        device: guard.device_id().to_owned(),
        request,
        action: Action::Uninstall,
        guardian: GuardianId::First,
        expires_at: START + 3_600,
    }
}

#[test]
fn a_valid_approval_grants_the_requested_action() {
    for mode in [Mode::SelfControl, Mode::Parental] {
        let (mut guard, request) = linked(mode);
        let approval = sign(&server(), body(&guard, request));
        assert_eq!(
            guard.approve_remotely(&approval, t(10)),
            Ok(GuardianId::First)
        );
        assert_eq!(
            last_event(&guard),
            EventKind::Authorized {
                action: Action::Uninstall,
                by: Authorizer::Remote {
                    guardian: GuardianId::First,
                    request
                },
            }
        );
        assert_eq!(
            guard.check(&Action::Uninstall, t(11)),
            Decision::Allowed {
                until: START + 10 + SECRET_GRANT_SECS
            }
        );
        assert!(guard.pending_requests().is_empty());
        guard.perform(&Action::Uninstall, t(12)).unwrap();
    }
}

#[test]
fn the_approval_says_which_guardian_approved() {
    let (mut guard, request) = linked(Mode::SelfControl);
    guard
        .authorize_with_secret(&Action::AddGuardian, ANA, t(2))
        .unwrap();
    guard.add_guardian(guardian("Luis", LUIS, 2), t(2)).unwrap();
    let approval = sign(
        &server(),
        ApprovalBody {
            guardian: GuardianId::Second,
            ..body(&guard, request)
        },
    );
    assert_eq!(
        guard.approve_remotely(&approval, t(3)),
        Ok(GuardianId::Second)
    );
}

#[test]
fn an_approval_works_only_once() {
    let (mut guard, request) = linked(Mode::SelfControl);
    let approval = sign(&server(), body(&guard, request));
    guard.approve_remotely(&approval, t(10)).unwrap();
    guard.perform(&Action::Uninstall, t(11)).unwrap();
    assert_eq!(
        guard.approve_remotely(&approval, t(12)),
        Err(GuardError::InvalidApproval(
            "la solicitud no existe o ya se usó"
        ))
    );
}

#[test]
fn a_forged_signature_is_rejected_and_reported() {
    let (mut guard, request) = linked(Mode::SelfControl);
    let impostor = SigningKey::from_bytes(&[0x11; 32]);
    let forged = sign(&impostor, body(&guard, request));
    assert_eq!(
        guard.approve_remotely(&forged, t(10)),
        Err(GuardError::InvalidApproval("firma incorrecta"))
    );
    assert_eq!(
        last_event(&guard),
        EventKind::Tamper(Tamper::ForgedApproval)
    );
    assert_eq!(
        guard.perform(&Action::Uninstall, t(11)),
        Err(GuardError::NotAuthorized)
    );

    // Cambiar lo aprobado invalida la firma.
    let mut tampered = sign(&server(), body(&guard, request));
    tampered.body.expires_at += 1;
    assert_eq!(
        guard.approve_remotely(&tampered, t(12)),
        Err(GuardError::InvalidApproval("firma incorrecta"))
    );

    // Y una firma que ni siquiera es hexadecimal también.
    let mut garbage = sign(&server(), body(&guard, request));
    garbage.signature = "zz".repeat(64);
    assert!(guard.approve_remotely(&garbage, t(13)).is_err());
}

#[test]
fn approvals_for_another_device_request_or_action_are_rejected() {
    let (mut guard, request) = linked(Mode::SelfControl);

    let other_device = sign(
        &server(),
        ApprovalBody {
            device: "ab".repeat(16),
            ..body(&guard, request)
        },
    );
    assert_eq!(
        guard.approve_remotely(&other_device, t(10)),
        Err(GuardError::InvalidApproval("es para otro dispositivo"))
    );

    let other_request = sign(
        &server(),
        ApprovalBody {
            request: request + 1,
            ..body(&guard, request)
        },
    );
    assert_eq!(
        guard.approve_remotely(&other_request, t(10)),
        Err(GuardError::InvalidApproval(
            "la solicitud no existe o ya se usó"
        ))
    );

    let other_action = sign(
        &server(),
        ApprovalBody {
            action: Action::Pause { minutes: 60 },
            ..body(&guard, request)
        },
    );
    assert_eq!(
        guard.approve_remotely(&other_action, t(10)),
        Err(GuardError::InvalidApproval("aprueba otra acción"))
    );

    let unknown_guardian = sign(
        &server(),
        ApprovalBody {
            guardian: GuardianId::Second,
            ..body(&guard, request)
        },
    );
    assert_eq!(
        guard.approve_remotely(&unknown_guardian, t(10)),
        Err(GuardError::InvalidApproval("el guardián ya no existe"))
    );

    // Nada de eso cuenta como falsificación: la firma era buena.
    assert!(!events(&guard)
        .iter()
        .any(|e| matches!(e, EventKind::Tamper(Tamper::ForgedApproval))));
    assert_eq!(guard.pending_requests().len(), 1, "la solicitud sigue viva");
}

#[test]
fn expired_approvals_are_rejected() {
    let (mut guard, request) = linked(Mode::SelfControl);
    let approval = sign(
        &server(),
        ApprovalBody {
            expires_at: START + 100,
            ..body(&guard, request)
        },
    );
    assert_eq!(
        guard.approve_remotely(&approval, t(100)),
        Err(GuardError::InvalidApproval("ha caducado"))
    );
}

#[test]
fn approvals_need_a_linked_server() {
    let (mut guard, _) = paired(Mode::SelfControl);
    let request = guard.request(&Action::Uninstall, t(0)).unwrap();
    let approval = sign(&server(), body(&guard, request.id));
    assert_eq!(
        guard.approve_remotely(&approval, t(1)),
        Err(GuardError::NoServerLinked)
    );
    assert!(!guard.server_linked());
}

#[test]
fn linking_a_server_needs_a_guardian_and_a_valid_key() {
    let (mut guard, _) = paired(Mode::SelfControl);
    let link = Action::LinkServer {
        public_key: hex(server().verifying_key().as_bytes()).to_uppercase(),
    };
    assert_eq!(guard.perform(&link, t(0)), Err(GuardError::NotAuthorized));

    for bad in ["", "abc", &"zz".repeat(32)] {
        assert!(matches!(
            guard.authorize_with_secret(
                &Action::LinkServer {
                    public_key: bad.to_owned()
                },
                ANA,
                t(0)
            ),
            Err(GuardError::InvalidAction(_))
        ));
    }

    guard.authorize_with_secret(&link, ANA, t(0)).unwrap();
    guard.perform(&link, t(0)).unwrap();
    assert!(guard.server_linked());
}

#[test]
fn relinking_to_another_server_invalidates_the_old_one() {
    let (mut guard, request) = linked(Mode::SelfControl);
    let other_server = SigningKey::from_bytes(&[0x77; 32]);
    let relink = Action::LinkServer {
        public_key: hex(other_server.verifying_key().as_bytes()),
    };
    guard.authorize_with_secret(&relink, ANA, t(5)).unwrap();
    guard.perform(&relink, t(5)).unwrap();

    let from_old = sign(&server(), body(&guard, request));
    assert!(guard.approve_remotely(&from_old, t(6)).is_err());
    let from_new = sign(&other_server, body(&guard, request));
    assert_eq!(
        guard.approve_remotely(&from_new, t(7)),
        Ok(GuardianId::First)
    );
}
