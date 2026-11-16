//! Normalización de nombres de dominio.
//!
//! Todas las comparaciones de la librería se hacen sobre la forma normalizada:
//! minúsculas, sin punto final y en ASCII (los nombres internacionales llegan
//! ya en punycode, que es como viajan en el protocolo DNS).

use crate::error::FilterError;

const MAX_NAME_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;

/// Nombre de dominio ya validado y normalizado.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DomainName(String);

impl DomainName {
    /// Valida y normaliza `input`.
    ///
    /// Acepta mayúsculas y un punto final opcional. Rechaza nombres vacíos,
    /// etiquetas vacías o demasiado largas y cualquier carácter que no sea
    /// letra ASCII, dígito, guion o guion bajo.
    pub fn parse(input: &str) -> Result<Self, FilterError> {
        let invalid = || FilterError::InvalidDomain(input.to_owned());

        let trimmed = input.strip_suffix('.').unwrap_or(input);
        if trimmed.is_empty() || trimmed.len() > MAX_NAME_LEN {
            return Err(invalid());
        }
        for label in trimmed.split('.') {
            let valid_chars = label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
            if label.is_empty() || label.len() > MAX_LABEL_LEN || !valid_chars {
                return Err(invalid());
            }
        }
        Ok(Self(trimmed.to_ascii_lowercase()))
    }

    /// El nombre normalizado.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// El nombre y todos sus dominios padre, del más específico al más general.
    ///
    /// Para `a.b.c` devuelve `a.b.c`, `b.c` y `c`. Los cortes caen siempre en
    /// un punto, así que `notejemplo.com` nunca produce `ejemplo.com`.
    pub fn suffixes(&self) -> impl Iterator<Item = &str> {
        let name = self.0.as_str();
        std::iter::once(name).chain(name.match_indices('.').map(move |(i, _)| &name[i + 1..]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_case_and_trailing_dot() {
        let d = DomainName::parse("WWW.Ejemplo.COM.").unwrap();
        assert_eq!(d.as_str(), "www.ejemplo.com");
    }

    #[test]
    fn suffixes_go_from_specific_to_general() {
        let d = DomainName::parse("a.b.c").unwrap();
        assert_eq!(d.suffixes().collect::<Vec<_>>(), ["a.b.c", "b.c", "c"]);
    }

    #[test]
    fn single_label_has_one_suffix() {
        let d = DomainName::parse("localhost").unwrap();
        assert_eq!(d.suffixes().collect::<Vec<_>>(), ["localhost"]);
    }

    #[test]
    fn accepts_punycode_and_underscore_labels() {
        assert!(DomainName::parse("xn--espaa-rta.com").is_ok());
        assert!(DomainName::parse("_dmarc.ejemplo.com").is_ok());
    }

    #[test]
    fn rejects_invalid_names() {
        let long_label = format!("{}.com", "a".repeat(64));
        let long_name = format!("{}com", "a.".repeat(126));
        for bad in [
            "",
            ".",
            "..",
            "a..b",
            ".a.com",
            "españa.com",
            "a b.com",
            "a/b.com",
            long_label.as_str(),
            long_name.as_str(),
        ] {
            assert!(
                matches!(DomainName::parse(bad), Err(FilterError::InvalidDomain(_))),
                "debería rechazar {bad:?}"
            );
        }
    }

    #[test]
    fn accepts_maximum_lengths() {
        let label = "a".repeat(63);
        assert!(DomainName::parse(&format!("{label}.com")).is_ok());
        // 253 caracteres exactos: 126 etiquetas "a." más "b".
        let name = format!("{}b", "a.".repeat(126));
        assert_eq!(name.len(), 253);
        assert!(DomainName::parse(&name).is_ok());
    }
}
