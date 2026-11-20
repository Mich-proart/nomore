//! Anti-manipulación de NoMore.
//!
//! Decide qué exige autorización, cómo se autoriza, qué se anota y con qué
//! urgencia hay que avisar a los guardianes. No abre sockets, no lee ficheros
//! y no tiene reloj propio: quien la usa le pasa la hora en cada llamada.
//!
//! ```
//! use guard_core::{Action, Decision, Guard, Mode, NewGuardian, TimePoint, ENTROPY_LEN};
//!
//! let now = TimePoint { wall_secs: 1_800_000_000, monotonic_ms: 0, boot_id: 1, server_secs: None };
//! let mut guard = Guard::unpaired([0x42; 16], now);
//! guard
//!     .setup(
//!         Mode::SelfControl,
//!         NewGuardian { name: "Ana".into(), secret: "clave-de-ana".into(), entropy: [7; ENTROPY_LEN] },
//!         now,
//!     )
//!     .unwrap();
//!
//! // Sin la clave del guardián no se puede aflojar nada.
//! let allow = Action::AllowDomain { domain: "ejemplo.com".into() };
//! assert!(matches!(guard.check(&allow, now), Decision::Denied(_)));
//! assert!(guard.perform(&allow, now).is_err());
//!
//! // Con ella, sí: una acción, una vez.
//! guard.authorize_with_secret(&allow, "clave-de-ana", now).unwrap();
//! guard.perform(&allow, now).unwrap();
//! assert_eq!(guard.settings().allowlist, ["ejemplo.com"]);
//! ```

mod approval;
mod clock;
mod error;
mod event;
mod guard;
mod mode;
mod notify;
mod secret;
mod state;
mod unlock;

pub use approval::{Approval, ApprovalBody};
pub use clock::TimePoint;
pub use error::GuardError;
pub use event::{
    verify_chain, Authorizer, Category, ChainError, Envelope, Event, EventId, EventKind, Hash,
    Tamper, Urgency, GENESIS,
};
pub use guard::{Decision, DenyReason, DeviceId, Guard, SECRET_GRANT_SECS};
pub use mode::{
    Action, Mode, Settings, Tightening, Toggle, DEFAULT_DELAY_HOURS, MAX_DELAY_HOURS,
    MAX_LIST_ENTRIES, MAX_PAUSE_MINUTES,
};
pub use notify::{ACCESS_WINDOW_SECS, HEARTBEAT_SECS};
pub use secret::{
    GuardianId, GuardianInfo, NewGuardian, RecoveryCode, ENTROPY_LEN, MAX_GUARDIANS,
    MIN_SECRET_CHARS,
};
pub use unlock::{UnlockRequest, DELAY_GRANT_SECS, MAX_PENDING_REQUESTS};
