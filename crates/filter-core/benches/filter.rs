//! Rendimiento con una lista sintética de un millón de dominios.
//!
//! `cargo bench -p filter-core`

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use filter_core::{Category, CategoryList, Filter, Policy};
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};

const DOMAINS: usize = 1_000_000;

fn query(name: &str) -> Vec<u8> {
    let mut message = Message::new(1, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    message.to_vec().unwrap()
}

fn benches(c: &mut Criterion) {
    let list_bytes = CategoryList::build(
        Category::Porn,
        (0..DOMAINS).map(|i| format!("dominio{i}.ejemplo{}.com", i % 977)),
    )
    .unwrap();

    c.bench_function("construir filtro (1M dominios)", |b| {
        b.iter(|| {
            let list = CategoryList::parse(black_box(&list_bytes)).unwrap();
            Filter::new(vec![list], Policy::default()).unwrap()
        })
    });

    let list = CategoryList::parse(&list_bytes).unwrap();
    let filter = Filter::new(vec![list], Policy::default()).unwrap();
    for (label, name) in [
        ("consulta bloqueada", "www.dominio997.ejemplo20.com."),
        ("consulta permitida", "www.wikipedia.org."),
        ("consulta SafeSearch", "www.google.es."),
        (
            "consulta permitida, 8 etiquetas",
            "a.b.c.d.e.f.ejemplo.org.",
        ),
    ] {
        let raw = query(name);
        c.bench_function(label, |b| b.iter(|| filter.handle_query(black_box(&raw))));
    }
}

criterion_group!(all, benches);
criterion_main!(all);
