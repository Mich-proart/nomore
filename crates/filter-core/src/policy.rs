//! Política de filtrado: qué categorías están activas, qué permite el
//! guardián y en qué orden se aplican las reglas.

use crate::blocklist::{Category, CategoryList, SuffixSet};
use crate::domain::DomainName;
use crate::error::FilterError;
use crate::safesearch;

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
    /// Buscador o YouTube: se redirige a este nombre, que fuerza el modo seguro.
    SafeSearch(&'static str),
    /// El texto no es un nombre de dominio válido.
    Invalid,
}

/// Regla de una lista que ha bloqueado un dominio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockedRule {
    /// Categoría de la lista.
    pub category: Category,
    /// Entrada de la lista que coincidió, p. ej. `pornhub.com` para
    /// `cdn.es.pornhub.com`.
    pub rule: String,
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

    /// Si `domain` está bloqueado, qué regla lo bloquea. Sirve para agrupar
    /// los avisos por sitio y no por cada subdominio consultado.
    pub fn blocked_rule(&self, domain: &str) -> Option<BlockedRule> {
        let name = DomainName::parse(domain).ok()?;
        let Verdict::Blocked(category) = self.verdict(&name) else {
            return None;
        };
        let lists = if category == Category::Bypass {
            &self.bypass
        } else {
            &self.lists
        };
        lists
            .iter()
            .filter(|list| list.category() == category)
            .find_map(|list| list.matching_suffix(&name))
            .map(|rule| BlockedRule {
                category,
                rule: rule.to_owned(),
            })
    }

    /// Orden de precedencia: canario → vía de escape → permitido por el
    /// guardián → categoría bloqueada → SafeSearch → permitido.
    ///
    /// SafeSearch va después de la lista de permitidos a propósito: permitir
    /// un buscador no le quita el modo seguro.
    pub(crate) fn verdict(&self, name: &DomainName) -> Verdict {
        if self.canaries.contains(name) {
            return Verdict::Canary;
        }
        if self.bypass.iter().any(|l| l.contains(name)) {
            return Verdict::Blocked(Category::Bypass);
        }
        let blocked = self.lists.iter().find(|l| l.contains(name));
        let allowed_by_guardian = blocked.is_some() && self.allowlist.contains(name);
        match (blocked, safesearch::target_for(name.as_str())) {
            (Some(list), _) if !allowed_by_guardian => Verdict::Blocked(list.category()),
            (_, Some(target)) => Verdict::SafeSearch(target),
            (Some(_), None) => Verdict::AllowedByGuardian,
            (None, None) => Verdict::Allowed,
        }
    }
}
