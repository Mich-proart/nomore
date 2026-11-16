//! Utilidades compartidas por las pruebas de integración.
#![allow(dead_code)]

use filter_core::{Action, Category, CategoryList, Filter, Policy};
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};

pub fn list(category: Category, domains: &[&str]) -> CategoryList {
    CategoryList::parse(&CategoryList::build(category, domains).unwrap()).unwrap()
}

pub fn filter_with(policy: Policy) -> Filter {
    let lists = vec![
        list(Category::Porn, &["pornhub.com", "xxx"]),
        list(Category::Gambling, &["bet365.es", "loteriasyapuestas.es"]),
        list(Category::Dating, &["tinder.com", "gotinder.com"]),
        list(Category::Bypass, &["dns.google", "cloudflare-dns.com"]),
    ];
    Filter::new(lists, policy).unwrap()
}

pub fn filter() -> Filter {
    filter_with(Policy::default())
}

pub fn query(id: u16, name: &str, record_type: RecordType) -> Vec<u8> {
    let mut message = Message::new(id, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(Name::from_ascii(name).unwrap(), record_type));
    message.to_vec().unwrap()
}

pub fn responded(action: Action) -> Message {
    match action {
        Action::Respond(bytes) => Message::from_vec(&bytes).unwrap(),
        other => panic!("se esperaba Respond, llegó {other:?}"),
    }
}
