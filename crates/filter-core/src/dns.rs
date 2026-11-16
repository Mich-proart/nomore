//! De una consulta DNS en bruto a una acción.

use std::net::{Ipv4Addr, Ipv6Addr};

use hickory_proto::op::{Message, MessageType, Metadata, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};

use crate::domain::DomainName;
use crate::policy::{Filter, Verdict};

/// Vida de las respuestas fabricadas: un cambio de política surte efecto en
/// un minuto como mucho.
const TTL_SECS: u32 = 60;

/// Qué hacer con una consulta DNS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Devolver estos bytes al cliente tal cual.
    Respond(Vec<u8>),
    /// SafeSearch: resolver `upstream_query` en el DNS de salida y pasar el
    /// resultado a [`Filter::finish_rewrite`] junto con `token`.
    Rewrite {
        /// Consulta que hay que enviar al DNS de salida.
        upstream_query: Vec<u8>,
        /// Estado necesario para montar la respuesta final.
        token: RewriteToken,
    },
    /// Reenviar la consulta original al DNS de salida.
    Forward,
}

/// Estado de una redirección de SafeSearch pendiente de resolver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewriteToken {
    request: Metadata,
    query: Query,
    target: &'static str,
}

impl Filter {
    /// Decide qué hacer con una consulta DNS en bruto.
    ///
    /// Nunca entra en pánico: lo que no se puede leer se responde con FORMERR.
    pub fn handle_query(&self, query: &[u8]) -> Action {
        let Ok(message) = Message::from_vec(query) else {
            return Action::Respond(header_only(query, ResponseCode::FormErr));
        };
        let request = message.metadata;
        if request.message_type != MessageType::Query {
            return Action::Respond(header_only(query, ResponseCode::FormErr));
        }
        if request.op_code != OpCode::Query {
            return Action::Forward;
        }
        let [question] = message.queries.as_slice() else {
            return Action::Respond(header_only(query, ResponseCode::FormErr));
        };
        if question.query_class != DNSClass::IN {
            return Action::Forward;
        }
        // Un nombre que no se puede normalizar no puede estar en ninguna lista.
        let Ok(name) = DomainName::parse(&question.name.to_ascii()) else {
            return Action::Forward;
        };

        match self.verdict(&name) {
            Verdict::Allowed | Verdict::AllowedByGuardian | Verdict::Invalid => Action::Forward,
            Verdict::Canary => {
                let mut response = response_to(&request, question);
                response.metadata.response_code = ResponseCode::NXDomain;
                Action::Respond(encode(&response, query))
            }
            Verdict::Blocked(_) => Action::Respond(blocked(&request, question, query)),
            Verdict::SafeSearch(target) => match question.query_type {
                RecordType::A | RecordType::AAAA => rewrite(request, question, target, query),
                // Sin esto el navegador podría conectar por otra vía y saltarse
                // la redirección.
                RecordType::HTTPS | RecordType::SVCB => {
                    Action::Respond(encode(&response_to(&request, question), query))
                }
                _ => Action::Forward,
            },
        }
    }

    /// Monta la respuesta final de una redirección de SafeSearch.
    ///
    /// `upstream_response` es lo que contestó el DNS de salida a la consulta
    /// de [`Action::Rewrite`], o `None` si no contestó. Si no hay una dirección
    /// utilizable se responde con bloqueo: nunca se deja pasar el buscador sin
    /// filtro.
    pub fn finish_rewrite(&self, token: RewriteToken, upstream_response: Option<&[u8]>) -> Vec<u8> {
        let RewriteToken {
            request,
            query,
            target,
        } = token;
        let fallback = request.id.to_be_bytes();

        let addresses = upstream_response
            .and_then(|bytes| Message::from_vec(bytes).ok())
            .filter(|m| {
                m.metadata.message_type == MessageType::Response
                    && m.metadata.response_code == ResponseCode::NoError
            })
            .map(|m| addresses_of(m, query.query_type));
        let Some(addresses) = addresses else {
            return blocked(&request, &query, &fallback);
        };
        // Sin dirección IPv4 el buscador no cargaría; sin IPv6 basta con
        // contestar "no hay" y el cliente usa IPv4.
        if addresses.is_empty() && query.query_type == RecordType::A {
            return blocked(&request, &query, &fallback);
        }
        let Ok(target_name) = Name::from_ascii(format!("{target}.")) else {
            return blocked(&request, &query, &fallback);
        };

        let mut response = response_to(&request, &query);
        response.add_answer(Record::from_rdata(
            query.name.clone(),
            TTL_SECS,
            RData::CNAME(CNAME(target_name.clone())),
        ));
        for (ttl, data) in addresses {
            response.add_answer(Record::from_rdata(
                target_name.clone(),
                ttl.min(TTL_SECS),
                data,
            ));
        }
        encode(&response, &fallback)
    }
}

fn rewrite(request: Metadata, question: &Query, target: &'static str, raw: &[u8]) -> Action {
    let Ok(target_name) = Name::from_ascii(format!("{target}.")) else {
        return Action::Respond(blocked(&request, question, raw));
    };
    let mut upstream = Message::new(request.id, MessageType::Query, OpCode::Query);
    upstream.metadata.recursion_desired = true;
    upstream.add_query(Query::query(target_name, question.query_type));
    match upstream.to_vec() {
        Ok(upstream_query) => Action::Rewrite {
            upstream_query,
            token: RewriteToken {
                request,
                query: question.clone(),
                target,
            },
        },
        Err(_) => Action::Respond(blocked(&request, question, raw)),
    }
}

/// Direcciones del tipo pedido en la respuesta del DNS de salida.
fn addresses_of(message: Message, wanted: RecordType) -> Vec<(u32, RData)> {
    message
        .answers
        .into_iter()
        .filter(|record| {
            matches!(
                (&record.data, wanted),
                (RData::A(_), RecordType::A) | (RData::AAAA(_), RecordType::AAAA)
            )
        })
        .map(|record| (record.ttl, record.data))
        .collect()
}

/// Respuesta vacía a `question`, con los indicadores que espera el cliente.
fn response_to(request: &Metadata, question: &Query) -> Message {
    let mut response = Message::new(request.id, MessageType::Response, request.op_code);
    response.metadata = Metadata::response_from_request(request);
    response.metadata.recursion_available = true;
    response.add_query(question.clone());
    response
}

/// Respuesta de bloqueo: dirección nula para A y AAAA, vacía para el resto.
fn blocked(request: &Metadata, question: &Query, raw: &[u8]) -> Vec<u8> {
    let mut response = response_to(request, question);
    let data = match question.query_type {
        RecordType::A => Some(RData::A(A(Ipv4Addr::UNSPECIFIED))),
        RecordType::AAAA => Some(RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED))),
        _ => None,
    };
    if let Some(data) = data {
        response.add_answer(Record::from_rdata(question.name.clone(), TTL_SECS, data));
    }
    encode(&response, raw)
}

/// Serializa `message`; si no se puede, responde SERVFAIL con el
/// identificador de `raw` para que el cliente no se quede esperando.
fn encode(message: &Message, raw: &[u8]) -> Vec<u8> {
    message
        .to_vec()
        .unwrap_or_else(|_| header_only(raw, ResponseCode::ServFail))
}

/// Respuesta mínima de 12 bytes: solo cabecera, con el identificador de `raw`
/// (cero si ni siquiera trae dos bytes).
fn header_only(raw: &[u8], code: ResponseCode) -> Vec<u8> {
    let (id_high, id_low) = match raw {
        [high, low, ..] => (*high, *low),
        _ => (0, 0),
    };
    // 0x80: es una respuesta. Los cuatro bits bajos del cuarto byte son el código.
    vec![id_high, id_low, 0x80, code.low(), 0, 0, 0, 0, 0, 0, 0, 0]
}
