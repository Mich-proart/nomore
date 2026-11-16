//! Errores de la librería.

use std::fmt;

/// Todo lo que puede fallar al construir listas o filtros.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterError {
    /// El texto no es un nombre de dominio válido.
    InvalidDomain(String),
    /// El binario de lista está truncado, corrupto o no es una lista.
    CorruptList(&'static str),
    /// La lista usa una versión de formato que esta librería no entiende.
    UnsupportedListVersion(u8),
    /// La lista declara una categoría desconocida.
    UnknownCategory(u8),
    /// No se puede construir un filtro sin lista de pornografía.
    MissingPornList,
}

impl fmt::Display for FilterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDomain(d) => write!(f, "dominio no válido: {d:?}"),
            Self::CorruptList(why) => write!(f, "lista corrupta: {why}"),
            Self::UnsupportedListVersion(v) => write!(f, "versión de lista no soportada: {v}"),
            Self::UnknownCategory(c) => write!(f, "categoría desconocida: {c}"),
            Self::MissingPornList => write!(f, "falta la lista de pornografía"),
        }
    }
}

impl std::error::Error for FilterError {}
