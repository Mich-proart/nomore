//! Controles de calidad de cada publicación: lo que tiene que estar
//! bloqueado lo está, y los sitios legítimos más visitados no.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::Path;

use filter_core::{Category, CategoryList, Filter, Policy, Verdict};

use crate::clean::normalize;

/// Sitios de control: los que siempre deben quedar bloqueados, por categoría.
pub type Control = BTreeMap<Category, BTreeSet<String>>;

/// Lee `control/<categoría>.txt`, un dominio por línea.
pub fn load_control(dir: &Path) -> Result<Control, String> {
    let mut control = Control::new();
    for category in Category::ALL {
        let name = format!("{}.txt", blocklists::category_name(category));
        let text =
            std::fs::read_to_string(dir.join(&name)).map_err(|e| format!("control/{name}: {e}"))?;
        let mut domains = BTreeSet::new();
        for (number, line) in text.lines().enumerate() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let domain = normalize(line)
                .ok_or_else(|| format!("control/{name}:{}: dominio no válido", number + 1))?;
            domains.insert(domain);
        }
        control.insert(category, domains);
    }
    Ok(control)
}

/// Resultado de los controles.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QualityReport {
    /// Sitios de control que no han quedado bloqueados en su categoría.
    pub missing: Vec<(Category, String)>,
    /// Sitios legítimos populares que han quedado bloqueados.
    pub false_positives: Vec<(String, Category)>,
    /// Sitios comprobados en cada control.
    pub checked: (usize, usize),
}

impl QualityReport {
    /// `true` si se puede publicar.
    pub fn passed(&self) -> bool {
        self.missing.is_empty() && self.false_positives.is_empty()
    }
}

/// Comprueba las listas generadas.
///
/// `legit` son los sitios más visitados; de ellos se excluyen los que están
/// en el control o revisados, porque esos sí deben bloquearse.
pub fn check(
    lists: &BTreeMap<Category, CategoryList>,
    control: &Control,
    legit: &[String],
    reviewed: &HashSet<String>,
) -> Result<QualityReport, String> {
    let filter = Filter::new(lists.values().cloned().collect(), Policy::default())
        .map_err(|e| e.to_string())?;
    let mut report = QualityReport::default();

    for (category, domains) in control {
        for domain in domains {
            report.checked.0 += 1;
            if filter.explain(domain) != Verdict::Blocked(*category) {
                report.missing.push((*category, domain.clone()));
            }
        }
    }

    let expected: HashSet<&String> = control.values().flatten().chain(reviewed).collect();
    for domain in legit {
        if expected.contains(domain) {
            continue;
        }
        report.checked.1 += 1;
        if let Verdict::Blocked(category) = filter.explain(domain) {
            report.false_positives.push((domain.clone(), category));
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lists() -> BTreeMap<Category, CategoryList> {
        let mut lists = BTreeMap::new();
        for (category, domains) in [
            (Category::Porn, vec!["pornhub.com", "google.es"]),
            (Category::Gambling, vec!["bet365.es"]),
            (Category::Dating, vec![]),
            (Category::Bypass, vec!["dns.google"]),
        ] {
            let bytes = CategoryList::build(category, domains).unwrap();
            lists.insert(category, CategoryList::parse(&bytes).unwrap());
        }
        lists
    }

    #[test]
    fn reports_missing_control_sites_and_false_positives() {
        let mut control = Control::new();
        control.insert(Category::Porn, ["pornhub.com".to_owned()].into());
        control.insert(Category::Dating, ["tinder.com".to_owned()].into());
        let legit = ["wikipedia.org", "google.es", "pornhub.com", "bet365.es"].map(String::from);
        let reviewed: HashSet<String> = ["bet365.es".to_owned()].into();

        let report = check(&lists(), &control, &legit, &reviewed).unwrap();
        assert_eq!(
            report.missing,
            [(Category::Dating, "tinder.com".to_owned())]
        );
        assert_eq!(
            report.false_positives,
            [("google.es".to_owned(), Category::Porn)]
        );
        assert_eq!(report.checked, (2, 2));
        assert!(!report.passed());
    }

    #[test]
    fn clean_lists_pass() {
        let mut control = Control::new();
        control.insert(Category::Porn, ["es.pornhub.com".to_owned()].into());
        let report = check(
            &lists(),
            &control,
            &["wikipedia.org".to_owned()],
            &HashSet::new(),
        )
        .unwrap();
        assert!(report.passed(), "{report:?}");
    }
}
