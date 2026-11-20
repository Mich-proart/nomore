//! Criterio 5: comprobar la clave de un guardián cuesta lo bastante para que
//! adivinarla sea lento, pero menos de un segundo para quien la sabe.

mod common;

use std::time::{Duration, Instant};

use common::{paired, t, ANA};
use guard_core::{Action, GuardError, Mode};

#[test]
#[ignore = "mide tiempos: ejecutar con --release -- --ignored"]
fn checking_a_secret_takes_less_than_a_second() {
    let (mut guard, _) = paired(Mode::SelfControl);
    let mut times = Vec::new();
    // Aciertos separados por más de un segundo para no chocar con la espera
    // entre fallos.
    for i in 0..5 {
        let start = Instant::now();
        guard
            .authorize_with_secret(&Action::Uninstall, ANA, t(10 + i * 10))
            .unwrap();
        times.push(start.elapsed());
    }
    let start = Instant::now();
    assert_eq!(
        guard.authorize_with_secret(&Action::Uninstall, "equivocada", t(100)),
        Err(GuardError::WrongSecret)
    );
    let wrong = start.elapsed();

    times.sort();
    let median = times[times.len() / 2];
    println!("Argon2id: mediana {median:?} con la clave buena, {wrong:?} con una errónea");
    assert!(
        median < Duration::from_secs(1),
        "demasiado lento: {median:?}"
    );
    // Una clave errónea cuesta lo mismo: si no, el tiempo delataría algo.
    assert!(
        wrong >= median / 4,
        "la errónea es sospechosamente rápida: {wrong:?}"
    );
}
