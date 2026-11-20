//! Propiedades: sin la clave de un guardián, sin una aprobación firmada por
//! el servidor y sin que venza la espera, nada consigue aflojar la protección.

mod common;

use std::sync::LazyLock;

use common::{guardian, paired, ANA, DEVICE, LUIS, START};
use ed25519_dalek::{Signer, SigningKey};
use guard_core::{
    Action, Approval, ApprovalBody, Category, Decision, Guard, GuardianId, Mode, Tamper,
    Tightening, TimePoint, Toggle,
};
use proptest::prelude::*;

const KEY: &[u8] = b"clave-del-dispositivo";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Clave del servidor de verdad. El atacante no la tiene.
fn server() -> SigningKey {
    SigningKey::from_bytes(&[0x5e; 32])
}

/// Punto de partida: dos guardianes, servidor vinculado, citas desactivadas,
/// un dominio permitido y otro bloqueado de más.
static BASELINE: LazyLock<Guard> = LazyLock::new(|| {
    let at = |secs| TimePoint {
        wall_secs: START + secs,
        monotonic_ms: secs * 1000,
        boot_id: 1,
        server_secs: None,
    };
    let (mut guard, _) = paired(Mode::SelfControl);
    let authorize = |guard: &mut Guard, action: Action| {
        guard.authorize_with_secret(&action, ANA, at(0)).unwrap();
        if !matches!(action, Action::AddGuardian) {
            guard.perform(&action, at(0)).unwrap();
        }
    };
    authorize(&mut guard, Action::AddGuardian);
    guard
        .add_guardian(guardian("Luis", LUIS, 2), at(0))
        .unwrap();
    authorize(
        &mut guard,
        Action::LinkServer {
            public_key: hex(server().verifying_key().as_bytes()),
        },
    );
    authorize(
        &mut guard,
        Action::DisableCategory {
            category: Toggle::Dating,
        },
    );
    authorize(
        &mut guard,
        Action::AllowDomain {
            domain: "permitido.com".into(),
        },
    );
    guard
        .tighten(
            &Tightening::BlockDomain {
                domain: "extra.com".into(),
            },
            at(0),
        )
        .unwrap();
    guard.acknowledge(u64::MAX, at(0));
    guard
});

/// Todas las acciones que aflojan, con los valores que usa el atacante.
fn loosening(choice: u8, small: u32, key: [u8; 32]) -> Action {
    match choice % 13 {
        0 => Action::AllowDomain {
            domain: "pornhub.com".into(),
        },
        1 => Action::AllowDomain {
            domain: "permitido.com".into(),
        },
        2 => Action::UnblockDomain {
            domain: "extra.com".into(),
        },
        3 => Action::DisableCategory {
            category: Toggle::Gambling,
        },
        4 => Action::Pause {
            minutes: 1 + small % 1_440,
        },
        5 => Action::ShortenDelay {
            hours: 1 + small % 71,
        },
        6 => Action::ChangeMode {
            mode: Mode::Parental,
        },
        7 => Action::Uninstall,
        8 => Action::AddGuardian,
        9 => Action::RemoveGuardian {
            guardian: GuardianId::First,
        },
        10 => Action::ChangeSecret {
            guardian: GuardianId::Second,
        },
        11 => Action::LinkServer {
            public_key: hex(&key),
        },
        _ => Action::RemoveGuardian {
            guardian: GuardianId::Second,
        },
    }
}

/// Lo que puede hacer quien no tiene ninguna clave.
#[derive(Debug, Clone)]
enum Op {
    /// Pasa el tiempo de verdad.
    Wait {
        secs: u64,
    },
    /// Mueve el reloj del sistema a cualquier hora.
    SetWallClock {
        wall_secs: u64,
    },
    /// Reinicia el dispositivo tras estar apagado `off_secs`.
    Reboot {
        off_secs: u64,
    },
    /// El servidor (honesto) informa de la hora real.
    ServerTime,
    Request {
        action: Action,
    },
    Cancel {
        pick: usize,
    },
    Perform {
        action: Action,
    },
    Check {
        action: Action,
    },
    Tighten {
        change: Tightening,
    },
    Access {
        site: u8,
    },
    Tamper,
    Acknowledge {
        up_to: u64,
    },
    /// Prueba una clave inventada (cara: Argon2id).
    GuessSecret {
        action: Action,
        guess: String,
    },
    GuessRecoveryCode {
        guess: String,
    },
    /// Aprobación de una solicitud real firmada con otra clave.
    ForgeApproval {
        pick: usize,
        key_seed: u8,
        expires_in: u64,
    },
    /// Aprobación con una firma inventada.
    GarbageApproval {
        signature: String,
    },
    AddGuardian,
    ChangeSecret,
    /// El agente se reinicia: guarda y vuelve a cargar con la clave buena.
    SaveAndLoad,
}

/// Reloj simulado: la hora real y lo que ve el dispositivo.
struct Sim {
    real_secs: u64,
    wall_secs: u64,
    monotonic_ms: u64,
    boot_id: u64,
    server: bool,
}

impl Sim {
    fn new() -> Self {
        Self {
            real_secs: 0,
            wall_secs: START,
            monotonic_ms: 0,
            boot_id: 1,
            server: false,
        }
    }

    fn now(&mut self) -> TimePoint {
        let server_secs = std::mem::take(&mut self.server).then_some(START + self.real_secs);
        TimePoint {
            wall_secs: self.wall_secs,
            monotonic_ms: self.monotonic_ms,
            boot_id: self.boot_id,
            server_secs,
        }
    }
}

fn run(guard: &mut Guard, sim: &mut Sim, op: &Op) {
    match op {
        Op::Wait { secs } => {
            sim.real_secs += secs;
            sim.wall_secs = sim.wall_secs.saturating_add(*secs);
            sim.monotonic_ms += secs * 1000;
            let now = sim.now();
            guard.tick(now);
        }
        Op::SetWallClock { wall_secs } => {
            sim.wall_secs = *wall_secs;
            let now = sim.now();
            guard.tick(now);
        }
        Op::Reboot { off_secs } => {
            sim.real_secs += off_secs;
            sim.wall_secs = sim.wall_secs.saturating_add(*off_secs);
            sim.monotonic_ms = 1_000;
            sim.boot_id += 1;
            let saved = guard.save(KEY);
            *guard = Guard::load(Some(&saved), KEY, DEVICE, sim.now());
        }
        Op::ServerTime => {
            sim.server = true;
            let now = sim.now();
            guard.tick(now);
        }
        Op::Request { action } => {
            let _ = guard.request(action, sim.now());
        }
        Op::Cancel { pick } => {
            let pending = guard.pending_requests();
            if !pending.is_empty() {
                let id = pending[pick % pending.len()].id;
                guard.cancel_request(id, sim.now()).unwrap();
            }
        }
        Op::Perform { action } => {
            assert!(
                guard.perform(action, sim.now()).is_err(),
                "se aplicó {action:?} sin autorización"
            );
        }
        Op::Check { action } => {
            let decision = guard.check(action, sim.now());
            assert!(
                matches!(decision, Decision::Denied(_)),
                "{action:?} quedó permitida: {decision:?}"
            );
        }
        Op::Tighten { change } => {
            let _ = guard.tighten(change, sim.now());
        }
        Op::Access { site } => {
            let category = match site % 3 {
                0 => Category::Porn,
                1 => Category::Gambling,
                _ => Category::Bypass,
            };
            guard.record_access(&format!("sitio{}.com", site % 5), category, sim.now());
        }
        Op::Tamper => guard.record_tamper(Tamper::DnsChanged, sim.now()),
        Op::Acknowledge { up_to } => guard.acknowledge(*up_to, sim.now()),
        Op::GuessSecret { action, guess } => {
            assert!(guard
                .authorize_with_secret(action, guess, sim.now())
                .is_err());
        }
        Op::GuessRecoveryCode { guess } => {
            assert!(guard
                .authorize_with_recovery_code(guess, sim.now())
                .is_err());
        }
        Op::ForgeApproval {
            pick,
            key_seed,
            expires_in,
        } => {
            let pending = guard.pending_requests();
            let (request, action) = match pending.get(pick % pending.len().max(1)) {
                Some(r) => (r.id, r.action.clone()),
                None => (1, Action::Uninstall),
            };
            let body = ApprovalBody {
                device: guard.device_id().to_owned(),
                request,
                action,
                guardian: GuardianId::First,
                expires_at: START + sim.real_secs + expires_in,
            };
            // Cualquier clave menos la del servidor.
            let attacker = SigningKey::from_bytes(&[(*key_seed).max(1) ^ 0x5e; 32]);
            let signature = hex(&attacker.sign(&body.signing_bytes()).to_bytes());
            assert!(guard
                .approve_remotely(&Approval { body, signature }, sim.now())
                .is_err());
        }
        Op::GarbageApproval { signature } => {
            let body = ApprovalBody {
                device: guard.device_id().to_owned(),
                request: 1,
                action: Action::Uninstall,
                guardian: GuardianId::First,
                expires_at: u64::MAX,
            };
            let approval = Approval {
                body,
                signature: signature.clone(),
            };
            assert!(guard.approve_remotely(&approval, sim.now()).is_err());
        }
        Op::AddGuardian => {
            assert!(guard
                .add_guardian(guardian("Intruso", "clave-del-intruso", 9), sim.now())
                .is_err());
        }
        Op::ChangeSecret => {
            assert!(guard
                .change_secret(GuardianId::First, "clave-del-intruso", &[3; 48], sim.now())
                .is_err());
        }
        Op::SaveAndLoad => {
            let saved = guard.save(KEY);
            *guard = Guard::load(Some(&saved), KEY, DEVICE, sim.now());
        }
    }
}

/// Nada se ha aflojado respecto al punto de partida.
fn assert_not_loosened(guard: &mut Guard, sim: &mut Sim) {
    let base = BASELINE.settings();
    let now = guard.settings().clone();
    assert!(guard.is_paired());
    assert_eq!(guard.guardians(), BASELINE.guardians());
    assert!(guard.server_linked());
    assert_eq!(now.mode, base.mode);
    assert!(now.block_gambling, "apuestas desbloqueadas");
    assert!(now.allowlist.iter().all(|d| base.allowlist.contains(d)));
    assert!(base
        .extra_blocks
        .iter()
        .all(|d| now.extra_blocks.contains(d)));
    assert!(now.delay_hours >= base.delay_hours, "espera acortada");
    assert!(guard.protection_active(), "protección en pausa");
    for choice in 0..13 {
        let action = loosening(choice, 30, [7; 32]);
        let decision = guard.check(&action, sim.now());
        assert!(
            matches!(decision, Decision::Denied(_)),
            "{action:?}: {decision:?}"
        );
    }
}

/// Ningún paso de una secuencia dura más que esto: el total queda lejos de
/// las 72 h de espera.
const MAX_WAIT: u64 = 600;
const MAX_OFF: u64 = 3_600;
const MAX_OPS: usize = 40;

// ---------------------------------------------------------------- proptest

fn action() -> impl Strategy<Value = Action> {
    (any::<u8>(), any::<u32>(), any::<[u8; 32]>()).prop_map(|(c, s, k)| loosening(c, s, k))
}

fn tightening() -> impl Strategy<Value = Tightening> {
    prop_oneof![
        Just(Tightening::BlockDomain {
            domain: "nuevo.com".into()
        }),
        Just(Tightening::DisallowDomain {
            domain: "permitido.com".into()
        }),
        Just(Tightening::EnableCategory {
            category: Toggle::Dating
        }),
        Just(Tightening::Resume),
        (73u32..800).prop_map(|hours| Tightening::LengthenDelay { hours }),
    ]
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        4 => (0..=MAX_WAIT).prop_map(|secs| Op::Wait { secs }),
        3 => any::<u64>().prop_map(|wall_secs| Op::SetWallClock { wall_secs }),
        1 => (0..=MAX_OFF).prop_map(|off_secs| Op::Reboot { off_secs }),
        1 => Just(Op::ServerTime),
        3 => action().prop_map(|action| Op::Request { action }),
        1 => any::<usize>().prop_map(|pick| Op::Cancel { pick }),
        3 => action().prop_map(|action| Op::Perform { action }),
        2 => action().prop_map(|action| Op::Check { action }),
        2 => tightening().prop_map(|change| Op::Tighten { change }),
        2 => any::<u8>().prop_map(|site| Op::Access { site }),
        1 => Just(Op::Tamper),
        1 => any::<u64>().prop_map(|up_to| Op::Acknowledge { up_to }),
        1 => (action(), "[a-z0-9-]{0,16}")
            .prop_map(|(action, guess)| Op::GuessSecret { action, guess }),
        1 => "[A-Z2-7-]{0,24}".prop_map(|guess| Op::GuessRecoveryCode { guess }),
        2 => (any::<usize>(), any::<u8>(), 0u64..10_000)
            .prop_map(|(pick, key_seed, expires_in)| Op::ForgeApproval { pick, key_seed, expires_in }),
        1 => "[0-9a-f]{0,140}".prop_map(|signature| Op::GarbageApproval { signature }),
        1 => Just(Op::AddGuardian),
        1 => Just(Op::ChangeSecret),
        1 => Just(Op::SaveAndLoad),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn nothing_loosens_without_authorization(ops in proptest::collection::vec(op(), 1..MAX_OPS)) {
        let mut guard = BASELINE.clone();
        let mut sim = Sim::new();
        for op in &ops {
            run(&mut guard, &mut sim, op);
        }
        assert_not_loosened(&mut guard, &mut sim);
    }

    #[test]
    fn load_never_panics_and_fails_closed(bytes in proptest::collection::vec(any::<u8>(), 0..2_000)) {
        let guard = Guard::load(Some(&bytes), KEY, DEVICE, Sim::new().now());
        prop_assert!(!guard.is_paired());
        prop_assert!(guard.protection_active());
        prop_assert!(guard.settings().allowlist.is_empty());
    }

    #[test]
    fn corrupting_a_real_state_always_fails_closed(
        position in any::<prop::sample::Index>(),
        flip in 1u8..=255,
    ) {
        let mut saved = BASELINE.save(KEY);
        let index = position.index(saved.len());
        saved[index] ^= flip;
        let guard = Guard::load(Some(&saved), KEY, DEVICE, Sim::new().now());
        prop_assert!(!guard.is_paired());
    }
}

// --------------------------------------------- 100 000 secuencias (criterio 2)

/// Generador determinista (xorshift64*), para que un fallo sea reproducible.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, limit: u64) -> u64 {
        self.next() % limit
    }

    fn action(&mut self) -> Action {
        let mut key = [0u8; 32];
        key.iter_mut().for_each(|b| *b = self.next() as u8);
        loosening(self.next() as u8, self.next() as u32, key)
    }

    /// Lo mismo que la estrategia de proptest, sin probar claves (Argon2id
    /// cuesta decenas de milisegundos y aquí hay millones de pasos).
    fn op(&mut self) -> Op {
        match self.below(28) {
            0..=3 => Op::Wait {
                secs: self.below(MAX_WAIT + 1),
            },
            4..=6 => Op::SetWallClock {
                wall_secs: self.next(),
            },
            7 => Op::Reboot {
                off_secs: self.below(MAX_OFF + 1),
            },
            8 => Op::ServerTime,
            9..=11 => Op::Request {
                action: self.action(),
            },
            12 => Op::Cancel {
                pick: self.next() as usize,
            },
            13..=15 => Op::Perform {
                action: self.action(),
            },
            16 | 17 => Op::Check {
                action: self.action(),
            },
            18 => Op::Tighten {
                change: match self.below(4) {
                    0 => Tightening::BlockDomain {
                        domain: "nuevo.com".into(),
                    },
                    1 => Tightening::DisallowDomain {
                        domain: "permitido.com".into(),
                    },
                    2 => Tightening::Resume,
                    _ => Tightening::LengthenDelay {
                        hours: 73 + self.below(600) as u32,
                    },
                },
            },
            19 | 20 => Op::Access {
                site: self.next() as u8,
            },
            21 => Op::Tamper,
            22 => Op::Acknowledge {
                up_to: self.next() % 500,
            },
            23 => Op::GuessRecoveryCode {
                guess: format!("{:016X}", self.next()),
            },
            24 | 25 => Op::ForgeApproval {
                pick: self.next() as usize,
                key_seed: self.next() as u8,
                expires_in: self.below(10_000),
            },
            26 => Op::AddGuardian,
            _ => {
                if self.below(4) == 0 {
                    Op::SaveAndLoad
                } else {
                    Op::ChangeSecret
                }
            }
        }
    }
}

#[test]
#[ignore = "larga: ejecutar con --release -- --ignored"]
fn attack_100k_sequences() {
    const SEQUENCES: usize = 100_000;
    let mut rng = Rng(0x0123_4567_89AB_CDEF);
    let mut steps = 0usize;
    for sequence in 0..SEQUENCES {
        let mut guard = BASELINE.clone();
        let mut sim = Sim::new();
        let length = 1 + rng.below(MAX_OPS as u64) as usize;
        for _ in 0..length {
            let op = rng.op();
            run(&mut guard, &mut sim, &op);
        }
        steps += length;
        assert!(
            sim.real_secs < 72 * 3_600,
            "la secuencia {sequence} duró demasiado para la prueba"
        );
        assert_not_loosened(&mut guard, &mut sim);
    }
    println!("attack_100k: {SEQUENCES} secuencias, {steps} pasos, nada aflojado");
}

/// Criterio 3 por separado: con el reloj del sistema en cualquier sitio, una
/// solicitud vence exactamente a las 72 h de tiempo real encendido, nunca antes.
#[test]
fn the_system_clock_never_shortens_a_wait() {
    let mut rng = Rng(42);
    for _ in 0..200 {
        let mut guard = BASELINE.clone();
        let mut sim = Sim::new();
        guard.request(&Action::Uninstall, sim.now()).unwrap();
        let mut elapsed = 0;
        while elapsed < 72 * 3_600 - 600 {
            let step = 1 + rng.below(600);
            run(&mut guard, &mut sim, &Op::Wait { secs: step });
            elapsed += step;
            run(
                &mut guard,
                &mut sim,
                &Op::SetWallClock {
                    wall_secs: rng.next(),
                },
            );
            assert!(matches!(
                guard.check(&Action::Uninstall, sim.now()),
                Decision::Denied(_)
            ));
        }
        run(
            &mut guard,
            &mut sim,
            &Op::Wait {
                secs: 72 * 3_600 - elapsed,
            },
        );
        assert!(matches!(
            guard.check(&Action::Uninstall, sim.now()),
            Decision::Allowed { .. }
        ));
    }
}
