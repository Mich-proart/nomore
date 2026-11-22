//! Descarga de fuentes, con reserva si una falla o encoge de golpe.

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;

use crate::clean::normalize;
use crate::config::{Config, Source};
use crate::parse::parse;

/// Ninguna fuente razonable pasa de esto.
const MAX_SOURCE_BYTES: u64 = 256 << 20;
/// Si una fuente pierde más de este porcentaje de dominios de un día para
/// otro, se sospecha de un fallo y se usa la copia anterior.
const MAX_DROP_PERCENT: usize = 30;

/// Algo que descarga direcciones. En las pruebas se sustituye.
pub trait Fetcher {
    /// Contenido de `url`.
    fn fetch(&self, url: &str) -> Result<Vec<u8>, String>;
}

/// Descargas HTTP de verdad.
pub struct Http {
    agent: ureq::Agent,
}

impl Http {
    /// Cliente con tiempo límite de dos minutos por fuente.
    pub fn new() -> Self {
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(120)))
            .user_agent("nomore-lists (+https://github.com/Mich-proart/nomore)")
            .build()
            .into();
        Self { agent }
    }
}

impl Default for Http {
    fn default() -> Self {
        Self::new()
    }
}

impl Fetcher for Http {
    fn fetch(&self, url: &str) -> Result<Vec<u8>, String> {
        let mut response = self.agent.get(url).call().map_err(|e| e.to_string())?;
        response
            .body_mut()
            .with_config()
            .limit(MAX_SOURCE_BYTES)
            .read_to_vec()
            .map_err(|e| e.to_string())
    }
}

/// Qué se ha usado de una fuente.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    /// Descargada hoy.
    Fresh,
    /// Se usó la copia de la publicación anterior.
    Fallback(String),
}

/// Resultado de una fuente.
#[derive(Debug, Clone)]
pub struct Gathered {
    /// La fuente.
    pub source: Source,
    /// Fresca o de reserva.
    pub status: Status,
    /// Dominios normalizados, sin repetir.
    pub domains: BTreeSet<String>,
    /// Líneas ignoradas o candidatos no válidos.
    pub ignored: usize,
    /// Dominios en la copia anterior, si la había.
    pub previous_count: Option<usize>,
}

/// Fichero con la copia de una fuente dentro de una publicación. Plano, sin
/// subcarpetas, porque las publicaciones de GitHub no las admiten.
pub fn copy_path(release_dir: &Path, name: &str) -> PathBuf {
    release_dir.join(format!("source-{name}.txt.gz"))
}

/// Guarda la copia de una fuente (un dominio por línea, comprimido).
pub fn write_copy(release_dir: &Path, gathered: &Gathered) -> Result<(), String> {
    std::fs::create_dir_all(release_dir).map_err(|e| e.to_string())?;
    let path = copy_path(release_dir, &gathered.source.name);
    let mut text = String::new();
    for domain in &gathered.domains {
        text.push_str(domain);
        text.push('\n');
    }
    // Compresión con nivel y cabecera fijos: mismo contenido, mismos bytes.
    let mut encoder = GzEncoder::new(Vec::new(), Compression::new(9));
    encoder
        .write_all(text.as_bytes())
        .map_err(|e| e.to_string())?;
    let bytes = encoder.finish().map_err(|e| e.to_string())?;
    std::fs::write(&path, bytes).map_err(|e| e.to_string())
}

fn read_copy(previous: Option<&Path>, name: &str) -> Option<BTreeSet<String>> {
    let bytes = std::fs::read(copy_path(previous?, name)).ok()?;
    let mut text = String::new();
    GzDecoder::new(bytes.as_slice())
        .read_to_string(&mut text)
        .ok()?;
    Some(text.lines().map(str::to_owned).collect())
}

/// Reúne todas las fuentes. Falla solo si una fuente no tiene ni descarga
/// válida ni copia anterior.
pub fn gather(
    config: &Config,
    fetcher: &dyn Fetcher,
    previous: Option<&Path>,
) -> Result<Vec<Gathered>, String> {
    config
        .sources
        .iter()
        .map(|source| gather_one(config, source, fetcher, previous))
        .collect()
}

fn gather_one(
    config: &Config,
    source: &Source,
    fetcher: &dyn Fetcher,
    previous: Option<&Path>,
) -> Result<Gathered, String> {
    let copy = read_copy(previous, &source.name);
    let previous_count = copy.as_ref().map(BTreeSet::len);

    let fresh = load(config, source, fetcher).and_then(|(domains, ignored)| {
        if domains.len() < source.min_domains {
            return Err(format!(
                "solo {} dominios, mínimo {}",
                domains.len(),
                source.min_domains
            ));
        }
        if let Some(before) = previous_count {
            if domains.len() * 100 < before * (100 - MAX_DROP_PERCENT) {
                return Err(format!(
                    "ha encogido de {before} a {} dominios",
                    domains.len()
                ));
            }
        }
        Ok((domains, ignored))
    });

    match (fresh, copy) {
        (Ok((domains, ignored)), _) => Ok(Gathered {
            source: source.clone(),
            status: Status::Fresh,
            domains,
            ignored,
            previous_count,
        }),
        (Err(reason), Some(domains)) => Ok(Gathered {
            source: source.clone(),
            status: Status::Fallback(reason),
            domains,
            ignored: 0,
            previous_count,
        }),
        (Err(reason), None) => Err(format!(
            "la fuente {} ha fallado y no hay copia anterior: {reason}",
            source.name
        )),
    }
}

fn load(
    config: &Config,
    source: &Source,
    fetcher: &dyn Fetcher,
) -> Result<(BTreeSet<String>, usize), String> {
    let bytes = match (&source.url, &source.path) {
        (Some(url), _) => fetcher.fetch(url)?,
        (None, Some(path)) => {
            std::fs::read(config.base_dir.join(path)).map_err(|e| e.to_string())?
        }
        (None, None) => return Err("sin url ni path".into()),
    };
    let text = String::from_utf8_lossy(&bytes);
    let parsed = parse(&text, source.format);
    let mut ignored = parsed.ignored;
    let mut domains = BTreeSet::new();
    for candidate in parsed.candidates {
        match normalize(&candidate) {
            Some(domain) => {
                domains.insert(domain);
            }
            None => ignored += 1,
        }
    }
    Ok((domains, ignored))
}
