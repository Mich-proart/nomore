//! Normalizar, unir, quitar protegidos, poner en cuarentena dominios
//! populares nuevos y colapsar subdominios.

use std::collections::{BTreeSet, HashSet};
use std::net::IpAddr;

use filter_core::{CategoryList, DomainName};

/// Nombres que aparecen en los ficheros hosts y nunca son sitios.
const LOCAL_NAMES: &[&str] = &[
    "localhost",
    "localhost.localdomain",
    "local",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-localnet",
    "ip6-mcastprefix",
    "ip6-allnodes",
    "ip6-allrouters",
    "ip6-allhosts",
];

/// Forma canónica de un candidato, o `None` si no es un dominio bloqueable:
/// minúsculas, sin punto inicial ni final, en punycode y con al menos dos
/// etiquetas (los dominios de primer nivel se bloquean solo por
/// configuración, nunca porque los traiga una fuente).
pub fn normalize(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_start_matches("*.").trim_matches('.');
    if trimmed.is_empty() || trimmed.parse::<IpAddr>().is_ok() {
        return None;
    }
    let ascii = idna::domain_to_ascii(trimmed).ok()?;
    let name = DomainName::parse(&ascii).ok()?;
    let name = name.as_str();
    if !name.contains('.') || LOCAL_NAMES.contains(&name) {
        return None;
    }
    Some(name.to_owned())
}

/// Dominios que nunca se bloquean.
#[derive(Debug, Clone, Default)]
pub struct Protected {
    /// Cada protegido y todos sus dominios padre.
    covering: HashSet<String>,
}

impl Protected {
    /// Lee `protected.txt`: un dominio por línea, `#` para comentarios.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut covering = HashSet::new();
        for (number, line) in text.lines().enumerate() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let domain = normalize(line)
                .ok_or_else(|| format!("protected.txt:{}: dominio no válido", number + 1))?;
            let mut rest = domain.as_str();
            loop {
                covering.insert(rest.to_owned());
                match rest.split_once('.') {
                    Some((_, parent)) => rest = parent,
                    None => break,
                }
            }
        }
        Ok(Self { covering })
    }

    /// `true` si bloquear `domain` bloquearía algún protegido: es un
    /// protegido o uno de sus dominios padre. Los subdominios de un
    /// protegido sí se pueden bloquear.
    pub fn blocks_protected(&self, domain: &str) -> bool {
        self.covering.contains(domain)
    }
}

/// Lo que se ha quitado y por qué.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Removed {
    /// Quitados por proteger un dominio legítimo.
    pub protected: BTreeSet<String>,
    /// Dominios populares nuevos, pendientes de revisar.
    pub quarantined: BTreeSet<String>,
    /// Subdominios que ya cubre su dominio padre.
    pub collapsed: usize,
}

/// Entradas para limpiar una categoría.
pub struct Cleaning<'a> {
    /// Protegidos.
    pub protected: &'a Protected,
    /// Dominios más visitados (top de Tranco).
    pub popular: &'a HashSet<String>,
    /// Dominios populares ya revisados y aceptados.
    pub reviewed: &'a HashSet<String>,
    /// La lista de esta categoría en la publicación anterior, si la hay.
    pub previous: Option<&'a CategoryList>,
}

/// Limpia la unión de candidatos ya normalizados de una categoría.
pub fn clean(
    domains: BTreeSet<String>,
    tlds: &[String],
    with: &Cleaning,
) -> (BTreeSet<String>, Removed) {
    let mut removed = Removed::default();
    let mut kept = BTreeSet::new();
    for domain in domains {
        if with.protected.blocks_protected(&domain) {
            removed.protected.insert(domain);
        } else if with.popular.contains(&domain)
            && !with.reviewed.contains(&domain)
            && !with.previous.is_some_and(|list| list.blocks(&domain))
        {
            removed.quarantined.insert(domain);
        } else {
            kept.insert(domain);
        }
    }
    kept.extend(tlds.iter().cloned());

    let collapsed = collapse(&kept);
    removed.collapsed = kept.len() - collapsed.len();
    (collapsed, removed)
}

/// Quita los dominios que ya cubre un dominio padre presente.
pub fn collapse(domains: &BTreeSet<String>) -> BTreeSet<String> {
    domains
        .iter()
        .filter(|domain| {
            let mut rest = domain.as_str();
            while let Some((_, parent)) = rest.split_once('.') {
                if domains.contains(parent) {
                    return false;
                }
                rest = parent;
            }
            true
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn normalization() {
        assert_eq!(normalize("ES.PornHub.COM."), Some("es.pornhub.com".into()));
        assert_eq!(normalize("*.uno.com"), Some("uno.com".into()));
        assert_eq!(normalize(".uno.com"), Some("uno.com".into()));
        assert_eq!(normalize("españa.com"), Some("xn--espaa-rta.com".into()));
        assert_eq!(
            normalize("xn--espaa-rta.com"),
            Some("xn--espaa-rta.com".into())
        );
        for bad in [
            "",
            "localhost",
            "com",
            "0.0.0.0",
            "::1",
            "a b.com",
            "a..com",
            "ip6-localhost",
        ] {
            assert_eq!(normalize(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn protected_covers_itself_and_parents_but_not_children() {
        let protected = Protected::parse("# buscadores\nwww.google.com\nreddit.com\n").unwrap();
        for blocked in ["www.google.com", "google.com", "com", "reddit.com"] {
            assert!(protected.blocks_protected(blocked), "{blocked}");
        }
        for allowed in ["mail.google.com", "nsfw.reddit.com", "pornhub.com"] {
            assert!(!protected.blocks_protected(allowed), "{allowed}");
        }
        assert!(Protected::parse("no válido\n").is_err());
    }

    #[test]
    fn collapse_keeps_only_the_highest_listed_parent() {
        let kept = collapse(&set(&[
            "pornhub.com",
            "es.pornhub.com",
            "a.b.pornhub.com",
            "x.com",
            "notpornhub.com",
        ]));
        assert_eq!(kept, set(&["notpornhub.com", "pornhub.com", "x.com"]));
    }

    #[test]
    fn cleaning_removes_protected_and_quarantines_new_popular_domains() {
        let protected = Protected::parse("www.google.com\n").unwrap();
        let popular: HashSet<String> = ["pornhub.com", "xvideos.com", "nuevo-popular.com"]
            .map(String::from)
            .into();
        let reviewed: HashSet<String> = ["xvideos.com".to_owned()].into();
        let previous = CategoryList::parse(
            &CategoryList::build(filter_core::Category::Porn, ["pornhub.com"]).unwrap(),
        )
        .unwrap();
        let with = Cleaning {
            protected: &protected,
            popular: &popular,
            reviewed: &reviewed,
            previous: Some(&previous),
        };
        let input = set(&[
            "google.com",
            "pornhub.com",
            "es.pornhub.com",
            "xvideos.com",
            "nuevo-popular.com",
            "pequeño.com",
        ]);
        let (kept, removed) = clean(input, &["xxx".into()], &with);
        assert_eq!(
            kept,
            set(&["pequeño.com", "pornhub.com", "xvideos.com", "xxx"])
        );
        assert_eq!(removed.protected, set(&["google.com"]));
        assert_eq!(removed.quarantined, set(&["nuevo-popular.com"]));
        assert_eq!(removed.collapsed, 1);
    }
}
