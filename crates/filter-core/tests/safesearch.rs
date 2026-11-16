//! SafeSearch y YouTube restringido de extremo a extremo.

mod common;

use std::net::{Ipv4Addr, Ipv6Addr};

use common::{filter, filter_with, list, query, responded};
use filter_core::{Action, Category, Filter, Policy, RewriteToken, Verdict};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME};
use hickory_proto::rr::{Name, RData, Record, RecordType};

fn name(s: &str) -> Name {
    Name::from_ascii(s).unwrap()
}

fn rewrite(f: &Filter, raw: &[u8]) -> (Message, RewriteToken) {
    match f.handle_query(raw) {
        Action::Rewrite {
            upstream_query,
            token,
        } => (Message::from_vec(&upstream_query).unwrap(), token),
        other => panic!("se esperaba Rewrite, llegó {other:?}"),
    }
}

/// Respuesta que daría el DNS de salida a `upstream`, con estos registros.
fn upstream_answer(upstream: &Message, code: ResponseCode, records: Vec<Record>) -> Vec<u8> {
    let mut response = Message::new(upstream.metadata.id, MessageType::Response, OpCode::Query);
    response.metadata.response_code = code;
    response.add_queries(upstream.queries.clone());
    response.add_answers(records);
    response.to_vec().unwrap()
}

fn a(owner: &str, ttl: u32, ip: [u8; 4]) -> Record {
    Record::from_rdata(name(owner), ttl, RData::A(A(Ipv4Addr::from(ip))))
}

fn assert_blocked_a(bytes: &[u8], id: u16) {
    let response = Message::from_vec(bytes).unwrap();
    assert_eq!(response.metadata.id, id);
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert_eq!(response.answers.len(), 1);
    match &response.answers[0].data {
        RData::A(addr) => assert_eq!(addr.0, Ipv4Addr::UNSPECIFIED),
        other => panic!("tipo inesperado: {other:?}"),
    }
}

#[test]
fn explain_reports_safesearch_targets() {
    let f = filter();
    assert_eq!(
        f.explain("www.google.es"),
        Verdict::SafeSearch("forcesafesearch.google.com")
    );
    assert_eq!(
        f.explain("www.bing.com"),
        Verdict::SafeSearch("strict.bing.com")
    );
    assert_eq!(
        f.explain("duckduckgo.com"),
        Verdict::SafeSearch("safe.duckduckgo.com")
    );
    assert_eq!(
        f.explain("m.youtube.com"),
        Verdict::SafeSearch("restrict.youtube.com")
    );
}

#[test]
fn google_query_asks_upstream_for_the_safe_name() {
    let f = filter();
    let (upstream, _) = rewrite(&f, &query(30, "www.google.es.", RecordType::A));
    assert_eq!(upstream.metadata.id, 30);
    assert_eq!(upstream.metadata.message_type, MessageType::Query);
    assert!(upstream.metadata.recursion_desired);
    assert_eq!(upstream.queries.len(), 1);
    assert_eq!(
        upstream.queries[0].name,
        name("forcesafesearch.google.com.")
    );
    assert_eq!(upstream.queries[0].query_type, RecordType::A);
}

#[test]
fn final_answer_is_cname_plus_addresses() {
    let f = filter();
    let (upstream, token) = rewrite(&f, &query(31, "WWW.Google.es.", RecordType::A));
    let answer = upstream_answer(
        &upstream,
        ResponseCode::NoError,
        vec![a("forcesafesearch.google.com.", 300, [216, 239, 38, 120])],
    );

    let response = Message::from_vec(&f.finish_rewrite(token, Some(&answer))).unwrap();

    assert_eq!(response.metadata.id, 31);
    assert_eq!(response.metadata.message_type, MessageType::Response);
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert_eq!(response.queries[0].name.to_ascii(), "WWW.Google.es.");
    assert_eq!(response.answers.len(), 2);

    let cname = &response.answers[0];
    assert_eq!(cname.name.to_ascii(), "WWW.Google.es.");
    assert_eq!(cname.ttl, 60);
    assert_eq!(
        cname.data,
        RData::CNAME(CNAME(name("forcesafesearch.google.com.")))
    );

    let address = &response.answers[1];
    assert_eq!(address.name, name("forcesafesearch.google.com."));
    assert_eq!(address.ttl, 60, "el TTL se recorta a 60 s");
    assert_eq!(address.data, RData::A(A(Ipv4Addr::new(216, 239, 38, 120))));
}

#[test]
fn upstream_cname_chains_are_flattened() {
    let f = filter();
    let (upstream, token) = rewrite(&f, &query(32, "www.bing.com.", RecordType::A));
    let answer = upstream_answer(
        &upstream,
        ResponseCode::NoError,
        vec![
            Record::from_rdata(
                name("strict.bing.com."),
                300,
                RData::CNAME(CNAME(name("strict-bing-com.a-0001.a-msedge.net."))),
            ),
            a(
                "strict-bing-com.a-0001.a-msedge.net.",
                20,
                [204, 79, 197, 220],
            ),
        ],
    );

    let response = Message::from_vec(&f.finish_rewrite(token, Some(&answer))).unwrap();

    assert_eq!(response.answers.len(), 2);
    assert_eq!(
        response.answers[0].data,
        RData::CNAME(CNAME(name("strict.bing.com.")))
    );
    assert_eq!(response.answers[1].name, name("strict.bing.com."));
    assert_eq!(response.answers[1].ttl, 20, "un TTL menor de 60 se respeta");
}

#[test]
fn aaaa_queries_are_rewritten_too() {
    let f = filter();
    let (upstream, token) = rewrite(&f, &query(33, "www.youtube.com.", RecordType::AAAA));
    assert_eq!(upstream.queries[0].name, name("restrict.youtube.com."));
    assert_eq!(upstream.queries[0].query_type, RecordType::AAAA);

    let ip: Ipv6Addr = "2001:4860:4802:32::78".parse().unwrap();
    let answer = upstream_answer(
        &upstream,
        ResponseCode::NoError,
        vec![Record::from_rdata(
            name("restrict.youtube.com."),
            60,
            RData::AAAA(AAAA(ip)),
        )],
    );
    let response = Message::from_vec(&f.finish_rewrite(token, Some(&answer))).unwrap();
    assert_eq!(response.answers.len(), 2);
    assert_eq!(response.answers[1].data, RData::AAAA(AAAA(ip)));
}

#[test]
fn aaaa_without_ipv6_answers_cname_only() {
    let f = filter();
    let (upstream, token) = rewrite(&f, &query(34, "www.bing.com.", RecordType::AAAA));
    let answer = upstream_answer(&upstream, ResponseCode::NoError, vec![]);
    let response = Message::from_vec(&f.finish_rewrite(token, Some(&answer))).unwrap();
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert_eq!(response.answers.len(), 1);
    assert_eq!(response.answers[0].record_type(), RecordType::CNAME);
}

#[test]
fn records_of_the_wrong_type_are_ignored() {
    let f = filter();
    let (upstream, token) = rewrite(&f, &query(35, "www.google.com.", RecordType::A));
    let ip: Ipv6Addr = "2001:4860:4802:32::78".parse().unwrap();
    let answer = upstream_answer(
        &upstream,
        ResponseCode::NoError,
        vec![Record::from_rdata(
            name("forcesafesearch.google.com."),
            60,
            RData::AAAA(AAAA(ip)),
        )],
    );
    assert_blocked_a(&f.finish_rewrite(token, Some(&answer)), 35);
}

#[test]
fn failed_upstream_blocks_instead_of_leaking() {
    let f = filter();
    let raw = query(36, "www.google.com.", RecordType::A);

    // Sin respuesta.
    let (_, token) = rewrite(&f, &raw);
    assert_blocked_a(&f.finish_rewrite(token, None), 36);

    // Respuesta ilegible.
    let (_, token) = rewrite(&f, &raw);
    assert_blocked_a(&f.finish_rewrite(token, Some(&[1, 2, 3])), 36);

    // Error del servidor.
    let (upstream, token) = rewrite(&f, &raw);
    let servfail = upstream_answer(&upstream, ResponseCode::ServFail, vec![]);
    assert_blocked_a(&f.finish_rewrite(token, Some(&servfail)), 36);

    // Respuesta correcta pero sin direcciones.
    let (upstream, token) = rewrite(&f, &raw);
    let empty = upstream_answer(&upstream, ResponseCode::NoError, vec![]);
    assert_blocked_a(&f.finish_rewrite(token, Some(&empty)), 36);

    // Algo que no es una respuesta.
    let (_, token) = rewrite(&f, &raw);
    assert_blocked_a(&f.finish_rewrite(token, Some(&raw)), 36);
}

#[test]
fn https_and_svcb_queries_to_search_engines_get_empty_answer() {
    let f = filter();
    for record_type in [RecordType::HTTPS, RecordType::SVCB] {
        let response = responded(f.handle_query(&query(37, "www.google.com.", record_type)));
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert!(response.answers.is_empty());
    }
}

#[test]
fn other_record_types_for_search_engines_are_forwarded() {
    let raw = query(38, "www.google.com.", RecordType::TXT);
    assert_eq!(filter().handle_query(&raw), Action::Forward);
}

#[test]
fn allowlisting_a_search_engine_does_not_remove_safesearch() {
    let f = filter_with(Policy {
        allowlist: vec!["www.google.com".into(), "google.com".into()],
        ..Policy::default()
    });
    assert_eq!(
        f.explain("www.google.com"),
        Verdict::SafeSearch("forcesafesearch.google.com")
    );
    rewrite(&f, &query(39, "www.google.com.", RecordType::A));
}

#[test]
fn a_listed_search_engine_is_blocked_not_redirected() {
    let lists = vec![
        list(Category::Porn, &["ejemplo.xxx"]),
        list(Category::Bypass, &["www.bing.com"]),
    ];
    let f = Filter::new(lists, Policy::default()).unwrap();
    assert_eq!(
        f.explain("www.bing.com"),
        Verdict::Blocked(Category::Bypass)
    );
    responded(f.handle_query(&query(40, "www.bing.com.", RecordType::A)));
}

#[test]
fn unrelated_question_in_upstream_answer_does_not_matter() {
    // El agente es quien empareja consulta y respuesta; aquí solo importan
    // los registros de dirección.
    let f = filter();
    let (_, token) = rewrite(&f, &query(41, "duckduckgo.com.", RecordType::A));
    let mut other = Message::new(999, MessageType::Response, OpCode::Query);
    other.add_query(Query::query(name("safe.duckduckgo.com."), RecordType::A));
    other.add_answer(a("safe.duckduckgo.com.", 60, [52, 142, 124, 215]));
    let response =
        Message::from_vec(&f.finish_rewrite(token, Some(&other.to_vec().unwrap()))).unwrap();
    assert_eq!(response.metadata.id, 41);
    assert_eq!(response.answers.len(), 2);
}
