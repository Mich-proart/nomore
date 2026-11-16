//! Consultas DNS en bruto: bloqueos, canarios, errores y reenvíos.

mod common;

use std::net::{Ipv4Addr, Ipv6Addr};

use common::{filter, filter_with, query, responded};
use filter_core::{Action, Policy};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, RecordType};

#[test]
fn blocked_a_query_gets_exact_expected_bytes() {
    // Consulta escrita a mano: id 0xBEEF, RD, una pregunta "pornhub.com A IN".
    let question = b"\x07pornhub\x03com\x00\x00\x01\x00\x01";
    let mut raw = vec![0xBE, 0xEF, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    raw.extend_from_slice(question);

    let Action::Respond(bytes) = filter().handle_query(&raw) else {
        panic!("se esperaba Respond");
    };

    // Cabecera: mismo id, QR+RD, RA, sin error, 1 pregunta, 1 respuesta.
    let mut expected = vec![0xBE, 0xEF, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
    expected.extend_from_slice(question);
    // Respuesta: puntero al nombre de la pregunta, A, IN, TTL 60, 4 bytes, 0.0.0.0.
    expected.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 0, 0, 0, 0]);
    assert_eq!(bytes, expected);
}

#[test]
fn blocked_a_query_answers_unspecified_ipv4() {
    let response = responded(filter().handle_query(&query(7, "es.pornhub.com.", RecordType::A)));
    assert_eq!(response.metadata.id, 7);
    assert_eq!(response.metadata.message_type, MessageType::Response);
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert!(response.metadata.recursion_desired);
    assert!(response.metadata.recursion_available);
    assert_eq!(response.queries.len(), 1);
    assert_eq!(response.answers.len(), 1);
    assert_eq!(response.answers[0].ttl, 60);
    match &response.answers[0].data {
        RData::A(a) => assert_eq!(a.0, Ipv4Addr::UNSPECIFIED),
        other => panic!("tipo inesperado: {other:?}"),
    }
}

#[test]
fn blocked_aaaa_query_answers_unspecified_ipv6() {
    let response = responded(filter().handle_query(&query(8, "bet365.es.", RecordType::AAAA)));
    assert_eq!(response.answers.len(), 1);
    match &response.answers[0].data {
        RData::AAAA(aaaa) => assert_eq!(aaaa.0, Ipv6Addr::UNSPECIFIED),
        other => panic!("tipo inesperado: {other:?}"),
    }
}

#[test]
fn blocked_other_types_get_empty_answer() {
    for record_type in [
        RecordType::HTTPS,
        RecordType::SVCB,
        RecordType::TXT,
        RecordType::MX,
        RecordType::CNAME,
    ] {
        let response =
            responded(filter().handle_query(&query(9, "api.gotinder.com.", record_type)));
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert!(response.answers.is_empty(), "{record_type}");
        assert_eq!(response.queries[0].query_type, record_type);
    }
}

#[test]
fn response_echoes_question_with_original_case() {
    let raw = query(10, "Es.PornHub.COM.", RecordType::A);
    let response = responded(filter().handle_query(&raw));
    assert_eq!(response.queries[0].name.to_ascii(), "Es.PornHub.COM.");
    assert_eq!(response.answers[0].name.to_ascii(), "Es.PornHub.COM.");
}

#[test]
fn bypass_domains_are_blocked() {
    let response = responded(filter().handle_query(&query(11, "dns.google.", RecordType::A)));
    assert_eq!(response.answers.len(), 1);
}

#[test]
fn canary_gets_nxdomain() {
    for record_type in [RecordType::A, RecordType::AAAA] {
        let response =
            responded(filter().handle_query(&query(12, "use-application-dns.net.", record_type)));
        assert_eq!(response.metadata.id, 12);
        assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
        assert!(response.answers.is_empty());
    }
}

#[test]
fn allowed_domains_are_forwarded() {
    let f = filter();
    for name in ["wikipedia.org.", "notpornhub.com.", "maps.google.com."] {
        assert_eq!(
            f.handle_query(&query(13, name, RecordType::A)),
            Action::Forward,
            "{name}"
        );
    }
}

#[test]
fn guardian_allowlist_forwards() {
    let f = filter_with(Policy {
        allowlist: vec!["loteriasyapuestas.es".into()],
        ..Policy::default()
    });
    let raw = query(14, "www.loteriasyapuestas.es.", RecordType::A);
    assert_eq!(f.handle_query(&raw), Action::Forward);
}

#[test]
fn root_and_odd_names_are_forwarded() {
    let f = filter();
    assert_eq!(
        f.handle_query(&query(15, ".", RecordType::NS)),
        Action::Forward
    );
    // Etiqueta con un espacio: válida en DNS, imposible en una lista.
    let question = b"\x03a b\x03com\x00\x00\x01\x00\x01";
    let mut raw = vec![0, 16, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    raw.extend_from_slice(question);
    assert_eq!(f.handle_query(&raw), Action::Forward);
}

#[test]
fn non_internet_class_is_forwarded() {
    let mut message = Message::new(17, MessageType::Query, OpCode::Query);
    let mut q = Query::query(Name::from_ascii("pornhub.com.").unwrap(), RecordType::TXT);
    q.set_query_class(DNSClass::CH);
    message.add_query(q);
    assert_eq!(
        filter().handle_query(&message.to_vec().unwrap()),
        Action::Forward
    );
}

#[test]
fn other_opcodes_are_forwarded() {
    let mut message = Message::new(18, MessageType::Query, OpCode::Status);
    message.add_query(Query::query(
        Name::from_ascii("pornhub.com.").unwrap(),
        RecordType::A,
    ));
    assert_eq!(
        filter().handle_query(&message.to_vec().unwrap()),
        Action::Forward
    );
}

#[test]
fn garbage_gets_formerr_with_same_id() {
    let f = filter();
    for raw in [
        &[0xAB, 0xCD, 0x01][..],
        &[0xAB, 0xCD, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF][..],
    ] {
        let Action::Respond(bytes) = f.handle_query(raw) else {
            panic!("se esperaba Respond");
        };
        assert_eq!(bytes, [0xAB, 0xCD, 0x80, 0x01, 0, 0, 0, 0, 0, 0, 0, 0]);
    }
}

#[test]
fn empty_input_gets_formerr_with_zero_id() {
    let Action::Respond(bytes) = filter().handle_query(&[]) else {
        panic!("se esperaba Respond");
    };
    assert_eq!(bytes, [0, 0, 0x80, 0x01, 0, 0, 0, 0, 0, 0, 0, 0]);
}

#[test]
fn messages_without_exactly_one_question_get_formerr() {
    let none = Message::new(19, MessageType::Query, OpCode::Query);
    let response = responded(filter().handle_query(&none.to_vec().unwrap()));
    assert_eq!(response.metadata.id, 19);
    assert_eq!(response.metadata.response_code, ResponseCode::FormErr);

    let mut two = Message::new(20, MessageType::Query, OpCode::Query);
    two.add_query(Query::query(
        Name::from_ascii("wikipedia.org.").unwrap(),
        RecordType::A,
    ));
    two.add_query(Query::query(
        Name::from_ascii("pornhub.com.").unwrap(),
        RecordType::A,
    ));
    let response = responded(filter().handle_query(&two.to_vec().unwrap()));
    assert_eq!(response.metadata.response_code, ResponseCode::FormErr);
}

#[test]
fn a_response_sent_as_query_gets_formerr() {
    let mut message = Message::new(21, MessageType::Response, OpCode::Query);
    message.add_query(Query::query(
        Name::from_ascii("pornhub.com.").unwrap(),
        RecordType::A,
    ));
    let response = responded(filter().handle_query(&message.to_vec().unwrap()));
    assert_eq!(response.metadata.response_code, ResponseCode::FormErr);
}
