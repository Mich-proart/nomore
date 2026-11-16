//! Propiedades que deben cumplirse con cualquier entrada.

mod common;

use std::net::Ipv4Addr;
use std::sync::LazyLock;

use common::{filter, query};
use filter_core::{Action, Category, Filter, Verdict};
use hickory_proto::op::Message;
use hickory_proto::rr::{RData, RecordType};
use proptest::prelude::*;

static FILTER: LazyLock<Filter> = LazyLock::new(filter);

/// Una etiqueta de dominio válida, de 1 a 12 caracteres.
fn label() -> impl Strategy<Value = String> {
    "[a-z0-9]([a-z0-9-]{0,10}[a-z0-9])?"
}

/// La respuesta conserva el identificador de la consulta.
fn assert_same_id(query: &[u8], response: &[u8]) {
    assert!(response.len() >= 12, "respuesta sin cabecera completa");
    if query.len() >= 2 {
        assert_eq!(&response[..2], &query[..2]);
    }
}

proptest! {
    #[test]
    fn random_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..600)) {
        if let Action::Respond(response) = FILTER.handle_query(&bytes) {
            assert_same_id(&bytes, &response);
        }
    }

    #[test]
    fn corrupted_queries_never_panic(
        labels in proptest::collection::vec(label(), 1..5),
        record_type in any::<u16>(),
        flips in proptest::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 0..6),
    ) {
        let name = format!("{}.", labels.join("."));
        let mut raw = query(1234, &name, RecordType::from(record_type));
        for (index, value) in flips {
            let position = index.index(raw.len());
            raw[position] = value;
        }
        match FILTER.handle_query(&raw) {
            Action::Respond(response) => assert_same_id(&raw, &response),
            Action::Rewrite { token, .. } => {
                let response = FILTER.finish_rewrite(token, Some(&raw));
                assert_same_id(&raw, &response);
            }
            Action::Forward => {}
        }
    }

    #[test]
    fn finish_rewrite_never_panics_and_never_leaks(
        bytes in proptest::collection::vec(any::<u8>(), 0..600),
    ) {
        let raw = query(4321, "www.google.com.", RecordType::A);
        let Action::Rewrite { token, .. } = FILTER.handle_query(&raw) else {
            panic!("se esperaba Rewrite");
        };
        let response = Message::from_vec(&FILTER.finish_rewrite(token, Some(&bytes))).unwrap();
        prop_assert_eq!(response.metadata.id, 4321);
        // O bien hay una dirección sacada de la respuesta externa, o bien es
        // un bloqueo; nunca una respuesta vacía que deje al cliente reintentar
        // por otra vía.
        prop_assert!(response.answers.iter().any(|r| matches!(r.data, RData::A(_))));
    }

    #[test]
    fn every_subdomain_of_a_blocked_domain_is_blocked(
        labels in proptest::collection::vec(label(), 1..5),
    ) {
        let name = format!("{}.pornhub.com", labels.join("."));
        prop_assert_eq!(FILTER.explain(&name), Verdict::Blocked(Category::Porn));

        let raw = query(1, &format!("{name}."), RecordType::A);
        let Action::Respond(bytes) = FILTER.handle_query(&raw) else {
            panic!("se esperaba Respond para {name}");
        };
        let response = Message::from_vec(&bytes).unwrap();
        match &response.answers[0].data {
            RData::A(a) => prop_assert_eq!(a.0, Ipv4Addr::UNSPECIFIED),
            other => panic!("tipo inesperado: {other:?}"),
        }
    }

    #[test]
    fn lookalikes_are_not_blocked(prefix in "[a-z0-9]{1,10}") {
        // Mismo final de texto, pero no es un subdominio.
        let glued = format!("{prefix}pornhub.com");
        prop_assert_eq!(FILTER.explain(&glued), Verdict::Allowed);
        // El dominio bloqueado aparece, pero no al final.
        let nested = format!("pornhub.com.{prefix}.org");
        prop_assert_eq!(FILTER.explain(&nested), Verdict::Allowed);
    }

    #[test]
    fn explain_never_panics(text in ".{0,300}") {
        let _ = FILTER.explain(&text);
    }
}

/// Generador determinista (xorshift64*), para que un fallo sea reproducible.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, limit: usize) -> usize {
        (self.next() % limit as u64) as usize
    }

    fn fill(&mut self, buffer: &mut Vec<u8>, len: usize) {
        buffer.clear();
        buffer.extend((0..len).map(|_| self.next() as u8));
    }
}

/// Criterio de éxito 3: diez millones de entradas sin un solo pánico.
///
/// Mezcla bytes aleatorios, consultas válidas y consultas válidas con bytes
/// alterados, y comprueba que se ejercitan las tres acciones.
#[test]
#[ignore = "larga: ejecutar con --release -- --ignored"]
fn fuzz_10m() {
    const ITERATIONS: usize = 10_000_000;
    const NAMES: &[&str] = &[
        "es.pornhub.com.",
        "bet365.es.",
        "api.gotinder.com.",
        "dns.google.",
        "use-application-dns.net.",
        "www.google.es.",
        "www.youtube.com.",
        "duckduckgo.com.",
        "wikipedia.org.",
        "a.b.c.d.e.f.ejemplo.org.",
    ];
    const TYPES: &[RecordType] = &[
        RecordType::A,
        RecordType::AAAA,
        RecordType::HTTPS,
        RecordType::SVCB,
        RecordType::TXT,
        RecordType::MX,
    ];

    let templates: Vec<Vec<u8>> = NAMES
        .iter()
        .flat_map(|name| TYPES.iter().map(|t| query(0x1234, name, *t)))
        .collect();
    let filter = filter();
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut buffer = Vec::with_capacity(128);
    let mut answer = Vec::with_capacity(128);
    let (mut responded, mut rewritten, mut forwarded) = (0usize, 0usize, 0usize);

    for _ in 0..ITERATIONS {
        match rng.below(3) {
            0 => {
                let len = rng.below(96);
                rng.fill(&mut buffer, len);
            }
            mode => {
                buffer.clear();
                buffer.extend_from_slice(&templates[rng.below(templates.len())]);
                if mode == 2 {
                    for _ in 0..=rng.below(3) {
                        let position = rng.below(buffer.len());
                        buffer[position] = rng.next() as u8;
                    }
                }
            }
        }

        match filter.handle_query(&buffer) {
            Action::Respond(response) => {
                assert_same_id(&buffer, &response);
                responded += 1;
            }
            Action::Rewrite {
                upstream_query,
                token,
            } => {
                // Como respuesta externa: nada, basura, o la propia consulta alterada.
                let response = match rng.below(3) {
                    0 => filter.finish_rewrite(token, None),
                    1 => {
                        let len = rng.below(96);
                        rng.fill(&mut answer, len);
                        filter.finish_rewrite(token, Some(&answer))
                    }
                    _ => {
                        answer.clear();
                        answer.extend_from_slice(&upstream_query);
                        answer[2] |= 0x80;
                        let position = rng.below(answer.len());
                        answer[position] = rng.next() as u8;
                        filter.finish_rewrite(token, Some(&answer))
                    }
                };
                assert_same_id(&buffer, &response);
                rewritten += 1;
            }
            Action::Forward => forwarded += 1,
        }
    }

    assert_eq!(responded + rewritten + forwarded, ITERATIONS);
    for (kind, count) in [
        ("Respond", responded),
        ("Rewrite", rewritten),
        ("Forward", forwarded),
    ] {
        assert!(
            count > ITERATIONS / 100,
            "{kind} apenas se ejercitó: {count}"
        );
    }
    println!("fuzz_10m: {responded} respondidas, {rewritten} reescritas, {forwarded} reenviadas");
}
