//! Fuentes: descarga, reserva y fallos.

mod common;

use std::io::{Read, Write};
use std::net::TcpListener;

use blocklists_build::sources::{gather, write_copy, Fetcher, Http, Status};
use common::{config, remote, temp_dir, PORN};

#[test]
fn fresh_sources_are_parsed_and_normalized() {
    let dir = temp_dir("fresh");
    let config = config(&dir, "Propio.COM.\nno válido\n");
    let gathered = gather(&config, &remote(PORN), None).unwrap();
    let by_name = |name: &str| gathered.iter().find(|g| g.source.name == name).unwrap();

    let porn = by_name("porn-hosts");
    assert_eq!(porn.status, Status::Fresh);
    assert!(porn.domains.contains("es.pornhub.com"));
    assert!(!porn.domains.contains("localhost"));
    assert_eq!(porn.ignored, 1, "localhost no es un dominio bloqueable");

    let own = by_name("own-porn");
    assert_eq!(own.domains.iter().collect::<Vec<_>>(), ["propio.com"]);
    assert_eq!(own.ignored, 1);

    let gambling = by_name("gambling-adblock");
    assert_eq!(gambling.domains.len(), 2, "la excepción @@ no cuenta");
    assert!(by_name("dating-wild").domains.contains("tinder.com"));
}

#[test]
fn a_failing_or_shrinking_source_falls_back_to_the_previous_copy() {
    let dir = temp_dir("fallback");
    let config = config(&dir, "propio.com\n");
    let previous = dir.join("anterior");
    for g in gather(&config, &remote(PORN), None).unwrap() {
        write_copy(&previous, &g).unwrap();
    }

    // La fuente de porno no responde.
    let mut down = remote(PORN);
    down.0.remove("https://ejemplo.test/porn.hosts");
    let gathered = gather(&config, &down, Some(&previous)).unwrap();
    let porn = gathered
        .iter()
        .find(|g| g.source.name == "porn-hosts")
        .unwrap();
    assert!(matches!(&porn.status, Status::Fallback(reason) if reason.contains("no responde")));
    assert_eq!(porn.domains.len(), PORN.len(), "la copia de ayer entera");

    // La fuente responde, pero ha perdido más de un 30 %.
    let shrunk = remote(&PORN[..4]);
    let gathered = gather(&config, &shrunk, Some(&previous)).unwrap();
    let porn = gathered
        .iter()
        .find(|g| g.source.name == "porn-hosts")
        .unwrap();
    assert!(matches!(&porn.status, Status::Fallback(reason) if reason.contains("encogido")));
    assert_eq!(porn.previous_count, Some(PORN.len()));

    // Perder un poco es normal.
    let slightly = remote(&PORN[..6]);
    let gathered = gather(&config, &slightly, Some(&previous)).unwrap();
    let porn = gathered
        .iter()
        .find(|g| g.source.name == "porn-hosts")
        .unwrap();
    assert_eq!(porn.status, Status::Fresh);
}

#[test]
fn a_failing_source_without_copy_stops_the_build() {
    let dir = temp_dir("nocopy");
    let config = config(&dir, "propio.com\n");
    let mut down = remote(PORN);
    down.0.remove("https://ejemplo.test/dating.txt");
    let error = gather(&config, &down, None).unwrap_err();
    assert!(error.contains("dating-wild"), "{error}");

    // Por debajo del mínimo, igual.
    let tiny = remote(&["uno.com"]);
    let error = gather(&config, &tiny, None).unwrap_err();
    assert!(error.contains("mínimo"), "{error}");
}

#[test]
fn http_fetcher_downloads_from_a_real_server() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0u8; 1024];
        let _ = stream.read(&mut request).unwrap();
        let body = "0.0.0.0 uno.com\n";
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
    });
    let bytes = Http::new()
        .fetch(&format!("http://{address}/lista.hosts"))
        .unwrap();
    assert_eq!(bytes, b"0.0.0.0 uno.com\n");
    server.join().unwrap();

    // Y un servidor que no existe da error, no se cuelga.
    assert!(Http::new().fetch("http://127.0.0.1:1/nada").is_err());
}
