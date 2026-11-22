//! Errores del verificador.

use std::fmt;

use filter_core::Category;

/// Por qué no se aceptan unas listas.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListError {
    /// La firma no es de ninguna clave de confianza, o el manifiesto se alteró.
    BadSignature,
    /// La versión publicada no es más nueva que la instalada.
    NotNewer {
        /// Versión instalada.
        installed: u64,
        /// Versión que se ofrecía.
        offered: u64,
    },
    /// El manifiesto no se entiende: formato desconocido, campos que faltan…
    BadManifest(&'static str),
    /// Falta un fichero que hacía falta.
    MissingFile(String),
    /// Un fichero no coincide con la huella o el tamaño del manifiesto.
    HashMismatch(String),
    /// Una diferencia no se puede aplicar sobre la lista instalada.
    BadDelta(&'static str),
    /// Tras aplicar la diferencia, la lista no es la que anuncia el manifiesto.
    DeltaResultMismatch(Category),
    /// Un binario de lista no es válido.
    BadList(String),
}

impl fmt::Display for ListError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadSignature => write!(f, "firma no válida"),
            Self::NotNewer { installed, offered } => {
                write!(f, "la versión {offered} no es más nueva que {installed}")
            }
            Self::BadManifest(why) => write!(f, "manifiesto no válido: {why}"),
            Self::MissingFile(name) => write!(f, "falta el fichero {name}"),
            Self::HashMismatch(name) => write!(f, "{name} no coincide con el manifiesto"),
            Self::BadDelta(why) => write!(f, "diferencia no válida: {why}"),
            Self::DeltaResultMismatch(category) => {
                write!(f, "la diferencia de {category:?} no da la lista esperada")
            }
            Self::BadList(why) => write!(f, "lista no válida: {why}"),
        }
    }
}

impl std::error::Error for ListError {}
