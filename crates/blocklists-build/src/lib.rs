//! Generador de las listas de NoMore.

pub mod clean;
pub mod config;
pub mod parse;
pub mod publish;
pub mod quality;
pub mod sources;

use std::collections::HashSet;
use std::path::Path;

/// Lee un fichero de un dominio por línea (`#` para comentarios). Si la
/// línea tiene varias columnas, el dominio es la última (formato de Tranco:
/// `posición,dominio`).
pub fn read_domain_set(path: &Path) -> Result<HashSet<String>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("no se puede leer {}: {e}", path.display()))?;
    Ok(text
        .lines()
        .map(|line| line.split('#').next().unwrap_or("").trim())
        .filter(|line| !line.is_empty())
        .filter_map(|line| line.rsplit([',', ' ', '\t']).next())
        .filter_map(clean::normalize)
        .collect())
}

/// Los primeros `limit` dominios de un ranking (`posición,dominio`), en orden.
pub fn read_ranked(path: &Path, limit: usize) -> Result<Vec<String>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("no se puede leer {}: {e}", path.display()))?;
    Ok(text
        .lines()
        .filter_map(|line| line.rsplit(',').next())
        .filter_map(clean::normalize)
        .take(limit)
        .collect())
}
