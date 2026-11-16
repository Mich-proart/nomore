//! Política de filtrado: qué categorías están activas, qué permite el
//! guardián y en qué orden se aplican las reglas.

use crate::blocklist::{Category, CategoryList, SuffixSet};
use crate::domain::DomainName;
use crate::error::FilterError;

/// Dominios canario: responder NXDOMAIN hace que el navegador o el sistema
/// desactive su DNS propio y vuelva a usar el del sistema, que es el nuestro.
const CANARY_DOMAINS: &[&str] = &[
    // Firefox: desactiva DNS-over-HTTPS automático.
    "use-application-dns.net",
    // Apple: desactiva iCloud Private Relay.
    "mask.icloud.com",
    "mask-h2.icloud.com",
];

/// Configuración que decide el guardián.
///
/// Pornografía y vías de escape no aparecen aquí porque no se pueden apagar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    /// Bloquear apuestas y juego.
    pub block_gambling: bool,
    /// Bloquear apps y webs de citas.
    pub block_dating: bool,
    /// Dominios que el guardián permite aunque estén en una lista. Cada
    /// entrada cubre también sus subdominios. No desbloquea vías de escape.
    pub allowlist: Vec<String>,
}

impl Default for Policy {
    /// Todo bloqueado y nada permitido.
    fn default() -> Self {
        Self {
            block_gambling: true,
            block_dating: true,
            allowlist: Vec::new(),
        }
    }
}

/// Qué se decide sobre un dominio y por qué.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Verdict {
    /// No está en ninguna lista activa: se reenvía.
    Allowed,
    /// Está en una lista, pero el guardián lo ha permitido: se reenvía.
    AllowedByGuardian,
    /// Está en una lista activa de esta categoría: se bloquea.
    Blocked(Category),
    /// Dominio canario: se responde NXDOMAIN.
    Canary,
    /// El texto no es un nombre de dominio válido.
    Invalid,
}

/// Filtro listo para usar. Inmutable: para cambiar listas o política se
/// construye otro y se sustituye.
#[derive(Debug, Clone)]
pub struct Filter {
    /// Listas de categorías activas, en el orden en que se consultan.
    lists: Vec<CategoryList>,
    bypass: Vec<CategoryList>,
    allowlist: SuffixSet,
    canaries: SuffixSet,
}

impl Filter {
    /// Construye el filtro.
    ///
    /// `lists` puede traer varias listas de la misma categoría. Debe incluir
    /// al menos una de pornografía: un filtro sin ella parecería funcionar sin
    /// bloquear nada. Las listas de categorías apagadas en `policy` se ignoran.
    pub fn new(lists: Vec<CategoryList>, policy: Policy) -> Result<Self, FilterError> {
        if !lists.iter().any(|l| l.category() == Category::Porn) {
            return Err(FilterError::MissingPornList);
        }

        let mut active = Vec::new();
        let mut bypass = Vec::new();
        for list in lists {
            match list.category() {
                Category::Bypass => bypass.push(list),
                Category::Porn => active.push(list),
                Category::Gambling if policy.block_gambling => active.push(list),
                Category::Dating if policy.block_dating => active.push(list),
                Category::Gambling | Category::Dating => {}
            }
        }

        Ok(Self {
            lists: active,
            bypass,
            allowlist: SuffixSet::from_domains(&policy.allowlist)?,
            canaries: SuffixSet::from_domains(CANARY_DOMAINS)?,
        })
    }

    /// Decide sobre un dominio escrito como texto (ASCII o punycode).
    pub fn explain(&self, domain: &str) -> Verdict {
        match DomainName::parse(domain) {
            Ok(name) => self.verdict(&name),
            Err(_) => Verdict::Invalid,
        }
    }

    /// Orden de precedencia: canario → vía de escape → permitido por el
    /// guardián → categoría bloqueada → permitido.
    pub(crate) fn verdict(&self, name: &DomainName) -> Verdict {
        if self.canaries.contains(name) {
            return Verdict::Canary;
        }
        if self.bypass.iter().any(|l| l.contains(name)) {
            return Verdict::Blocked(Category::Bypass);
        }
        let blocked = self.lists.iter().find(|l| l.contains(name));
        match blocked {
            Some(_) if self.allowlist.contains(name) => Verdict::AllowedByGuardian,
            Some(list) => Verdict::Blocked(list.category()),
            None => Verdict::Allowed,
        }
    }
}
