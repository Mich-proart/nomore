//! Criterio de éxito 2: con un millón de dominios, el filtro se construye en
//! menos de 1 s, ocupa menos de 32 MB y decide en menos de 20 µs de media.

mod common;

use std::hint::black_box;
use std::time::{Duration, Instant};

use common::query;
use filter_core::{Action, Category, CategoryList, Filter, Policy};
use hickory_proto::rr::RecordType;

const DOMAINS: usize = 1_000_000;
const QUERIES: usize = 1_000_000;

/// Memoria residente del proceso en bytes (solo Linux).
#[cfg(target_os = "linux")]
fn resident_bytes() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|l| l.starts_with("VmRSS:"))?;
    let kilobytes: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kilobytes * 1024)
}

#[cfg(not(target_os = "linux"))]
fn resident_bytes() -> Option<u64> {
    None
}

#[test]
#[ignore = "mide tiempos: ejecutar con --release -- --ignored"]
fn one_million_domains_meet_the_targets() {
    let list_bytes = CategoryList::build(
        Category::Porn,
        (0..DOMAINS).map(|i| format!("dominio{i}.ejemplo{}.com", i % 977)),
    )
    .unwrap();
    // Consultas preparadas de antemano: mitad bloqueadas, mitad permitidas.
    let queries: Vec<Vec<u8>> = (0..1000)
        .map(|i| {
            let name = if i % 2 == 0 {
                format!("www.dominio{}.ejemplo{}.com.", i * 997, (i * 997) % 977)
            } else {
                format!("www.permitido{i}.ejemplo.org.")
            };
            query(i as u16, &name, RecordType::A)
        })
        .collect();

    // Construcción.
    let before = resident_bytes();
    let start = Instant::now();
    let list = CategoryList::parse(&list_bytes).unwrap();
    let filter = Filter::new(vec![list], Policy::default()).unwrap();
    let build_time = start.elapsed();
    let after = resident_bytes();
    assert!(
        build_time < Duration::from_secs(1),
        "construir tardó {build_time:?}"
    );

    // Memoria.
    let memory = before.zip(after).map(|(b, a)| a.saturating_sub(b));
    if let Some(bytes) = memory {
        assert!(
            bytes < 32 * 1024 * 1024,
            "el filtro ocupa {} MB",
            bytes / (1024 * 1024)
        );
    }

    // Consultas.
    let (mut blocked, mut forwarded) = (0usize, 0usize);
    let start = Instant::now();
    for i in 0..QUERIES {
        match black_box(filter.handle_query(black_box(&queries[i % queries.len()]))) {
            Action::Respond(_) => blocked += 1,
            Action::Forward => forwarded += 1,
            Action::Rewrite { .. } => panic!("no debería haber redirecciones"),
        }
    }
    let per_query = start.elapsed() / QUERIES as u32;
    assert_eq!(blocked, QUERIES / 2);
    assert_eq!(forwarded, QUERIES / 2);
    assert!(
        per_query < Duration::from_micros(20),
        "cada consulta tardó {per_query:?}"
    );

    println!(
        "1M dominios: construir {build_time:?}, memoria {}, consulta {per_query:?}",
        memory.map_or("sin medir".to_owned(), |b| format!(
            "{:.1} MB",
            b as f64 / 1048576.0
        ))
    );
}
