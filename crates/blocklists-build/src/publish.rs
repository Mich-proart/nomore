//! Publicación: binarios, diferencias, manifiesto firmado, atribuciones e
//! informe. Todo en orden fijo para que sea reproducible.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use blocklists::{
    category_name, delta_file_name, full_file_name, signing_bytes, Delta, DeltaRef, FileRef,
    ListEntry, Manifest, MANIFEST_FORMAT,
};
use ed25519_dalek::{Signer, SigningKey};
use filter_core::{Category, CategoryList};

use crate::clean::{clean, Cleaning, Protected, Removed};
use crate::config::{category, Config, OWN_MAINTAINER};
use crate::quality::{check, Control, QualityReport};
use crate::sources::{gather, write_copy, Fetcher, Gathered, Status};

/// Diferencias que se publican: desde las 7 versiones anteriores.
pub const DELTA_HISTORY: usize = 7;

/// Una publicación anterior, ya verificada.
#[derive(Debug, Clone)]
pub struct Previous {
    /// Carpeta donde está descargada.
    pub dir: PathBuf,
    /// Versión.
    pub version: u64,
    /// Sus listas.
    pub lists: BTreeMap<Category, CategoryList>,
}

/// Lee y verifica una publicación anterior descargada en `dir`.
pub fn load_previous(dir: &Path, keys: &[[u8; 32]]) -> Result<Previous, String> {
    let read = |name: &str| {
        std::fs::read(dir.join(name)).map_err(|e| format!("{}/{name}: {e}", dir.display()))
    };
    let manifest = Manifest::verify(&read("manifest.json")?, &read("manifest.sig")?, keys, None)
        .map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut files = BTreeMap::new();
    for fetch in manifest.plan_full() {
        files.insert(fetch.name.clone(), read(&fetch.name)?);
    }
    let installed = manifest
        .apply(None, &files)
        .map_err(|e| format!("{}: {e}", dir.display()))?;
    let lists = installed
        .category_lists()
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|list| (list.category(), list))
        .collect();
    Ok(Previous {
        dir: dir.to_path_buf(),
        version: manifest.version,
        lists,
    })
}

/// 32 bytes a partir de 64 caracteres hexadecimales.
pub fn parse_hex32(hex: &str) -> Result<[u8; 32], String> {
    let hex = hex.trim();
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("se esperaban 64 caracteres hexadecimales".into());
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
}

/// Clave de firma a partir de su semilla en hexadecimal.
pub fn signing_key(hex: &str) -> Result<SigningKey, String> {
    Ok(SigningKey::from_bytes(&parse_hex32(hex)?))
}

/// Todo lo necesario para generar una publicación.
pub struct Inputs<'a> {
    /// Fuentes.
    pub config: &'a Config,
    /// Protegidos.
    pub protected: &'a Protected,
    /// Top de dominios más visitados.
    pub popular: &'a HashSet<String>,
    /// Populares ya revisados.
    pub reviewed: &'a HashSet<String>,
    /// Publicaciones anteriores, de la más reciente a la más antigua.
    pub previous: &'a [Previous],
    /// Versión nueva, `AAAAMMDDnn`.
    pub version: u64,
    /// Fecha, `AAAA-MM-DD`.
    pub date: &'a str,
    /// Clave de firma.
    pub key: &'a SigningKey,
    /// Sitios que deben quedar bloqueados.
    pub control: Option<&'a Control>,
    /// Sitios legítimos más visitados, que no deben quedar bloqueados.
    pub legit: &'a [String],
}

/// Resumen de una categoría.
#[derive(Debug, Clone)]
pub struct CategorySummary {
    /// Dominios publicados.
    pub domains: usize,
    /// Lo quitado.
    pub removed: Removed,
    /// Dominios populares aceptados sin revisión (dos fuentes, lista propia
    /// o control).
    pub trusted_popular: usize,
    /// Tamaño del binario.
    pub bytes: u64,
    /// Añadidos y quitados respecto a la publicación anterior.
    pub change: Option<(usize, usize)>,
}

/// Resultado de una generación.
#[derive(Debug, Clone)]
pub struct Summary {
    /// Versión publicada.
    pub version: u64,
    /// Por categoría.
    pub categories: BTreeMap<Category, CategorySummary>,
    /// Fuentes que han usado su copia anterior.
    pub fallbacks: Vec<(String, String)>,
    /// Controles de calidad.
    pub quality: QualityReport,
}

/// Genera la publicación en `out`.
pub fn build(inputs: &Inputs, fetcher: &dyn Fetcher, out: &Path) -> Result<Summary, String> {
    if let Some(newest) = inputs.previous.first() {
        if inputs.version <= newest.version {
            return Err(format!(
                "la versión {} no es mayor que la anterior {}",
                inputs.version, newest.version
            ));
        }
    }
    std::fs::create_dir_all(out).map_err(|e| e.to_string())?;
    let latest = inputs.previous.first();
    let gathered = gather(inputs.config, fetcher, latest.map(|p| p.dir.as_path()))?;

    let mut lists = BTreeMap::new();
    let mut categories = BTreeMap::new();
    for cat in Category::ALL {
        let union: BTreeSet<String> = gathered
            .iter()
            .filter(|g| category(&g.source.category) == Ok(cat))
            .flat_map(|g| g.domains.iter().cloned())
            .collect();
        let trusted = trusted_popular(&union, &gathered, cat, inputs);
        let cleaning = Cleaning {
            protected: inputs.protected,
            popular: inputs.popular,
            reviewed: inputs.reviewed,
            trusted: &trusted,
            previous: latest.and_then(|p| p.lists.get(&cat)),
        };
        let (kept, removed) = clean(union, &inputs.config.tlds(cat), &cleaning);
        let bytes = CategoryList::build(cat, &kept).map_err(|e| e.to_string())?;
        let list = CategoryList::parse(&bytes).map_err(|e| e.to_string())?;
        let change = latest
            .and_then(|p| p.lists.get(&cat))
            .map(|old| Delta::between(old, &list, 0, 0).map(|d| d.counts()))
            .transpose()
            .map_err(|e| e.to_string())?;
        categories.insert(
            cat,
            CategorySummary {
                trusted_popular: trusted.len(),
                domains: kept.len(),
                removed,
                bytes: bytes.len() as u64,
                change,
            },
        );
        lists.insert(cat, list);
    }

    let quality = match inputs.control {
        Some(control) => check(&lists, control, inputs.legit, inputs.reviewed)?,
        None => QualityReport::default(),
    };
    if !quality.passed() {
        // Se escribe el informe para poder ver qué ha fallado, pero ni las
        // listas ni el manifiesto: no hay nada publicable.
        let mut text = String::from("# Controles de calidad fallidos\n\n");
        for (category, domain) in &quality.missing {
            let _ = writeln!(text, "- falta en {}: {domain}", category_name(*category));
        }
        for (domain, category) in &quality.false_positives {
            let _ = writeln!(
                text,
                "- bloqueado por {}: {domain}",
                category_name(*category)
            );
        }
        write(out, "quality-failed.md", text.as_bytes())?;
        let partial = Summary {
            version: inputs.version,
            categories: categories.clone(),
            fallbacks: Vec::new(),
            quality: quality.clone(),
        };
        write(out, "quarantine.txt", quarantine_txt(&partial).as_bytes())?;
        return Err(format!(
            "controles de calidad: {} sitios de control sin bloquear, {} sitios legítimos bloqueados (ver quality-failed.md)",
            quality.missing.len(),
            quality.false_positives.len()
        ));
    }

    let mut entries = BTreeMap::new();
    for (cat, list) in &lists {
        let full = list.to_bytes();
        write(out, &full_file_name(*cat), &full)?;
        let mut deltas = Vec::new();
        for previous in inputs.previous.iter().take(DELTA_HISTORY) {
            let Some(old) = previous.lists.get(cat) else {
                continue;
            };
            let delta = Delta::between(old, list, previous.version, inputs.version)
                .map_err(|e| e.to_string())?
                .to_bytes();
            write(out, &delta_file_name(*cat, previous.version), &delta)?;
            deltas.push(DeltaRef {
                from: previous.version,
                file: FileRef::of(&delta),
            });
        }
        entries.insert(
            category_name(*cat).to_owned(),
            ListEntry {
                domains: list.len() as u64,
                file: FileRef::of(&full),
                deltas,
            },
        );
    }

    let manifest = Manifest {
        format: MANIFEST_FORMAT,
        version: inputs.version,
        created: inputs.date.to_owned(),
        lists: entries,
    }
    .to_json();
    let signature = inputs.key.sign(&signing_bytes(&manifest)).to_bytes();
    write(out, "manifest.json", &manifest)?;
    write(out, "manifest.sig", hex(&signature).as_bytes())?;

    for g in &gathered {
        write_copy(out, g)?;
    }
    let summary = Summary {
        version: inputs.version,
        fallbacks: gathered
            .iter()
            .filter_map(|g| match &g.status {
                Status::Fallback(reason) => Some((g.source.name.clone(), reason.clone())),
                Status::Fresh => None,
            })
            .collect(),
        categories,
        quality,
    };
    write(out, "SOURCES.md", sources_md(inputs.config).as_bytes())?;
    write(
        out,
        "report.md",
        report_md(inputs, &gathered, &summary).as_bytes(),
    )?;
    write(out, "quarantine.txt", quarantine_txt(&summary).as_bytes())?;
    Ok(summary)
}

/// Dominios populares de `union` que no necesitan revisión: los traen dos
/// mantenedores distintos, una lista propia, o están en el control.
fn trusted_popular(
    union: &BTreeSet<String>,
    gathered: &[Gathered],
    cat: Category,
    inputs: &Inputs,
) -> HashSet<String> {
    let sources: Vec<&Gathered> = gathered
        .iter()
        .filter(|g| category(&g.source.category) == Ok(cat))
        .collect();
    let control = inputs.control.and_then(|c| c.get(&cat));
    union
        .iter()
        .filter(|domain| inputs.popular.contains(*domain))
        .filter(|domain| {
            if control.is_some_and(|c| c.contains(*domain)) {
                return true;
            }
            let maintainers: HashSet<&str> = sources
                .iter()
                .filter(|g| g.domains.contains(*domain))
                .map(|g| g.source.maintainer.as_str())
                .collect();
            maintainers.contains(OWN_MAINTAINER) || maintainers.len() >= 2
        })
        .cloned()
        .collect()
}

fn write(out: &Path, name: &str, bytes: &[u8]) -> Result<(), String> {
    std::fs::write(out.join(name), bytes).map_err(|e| format!("{name}: {e}"))
}

/// Bytes en hexadecimal.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sources_md(config: &Config) -> String {
    let mut text = String::from(
        "# Fuentes\n\nEstas listas combinan las fuentes siguientes. Se publican bajo GPL-3.0 \
         porque algunas fuentes usan esa licencia.\n\n\
         | Fuente | Categoría | Licencia | Proyecto |\n|---|---|---|---|\n",
    );
    for source in &config.sources {
        let _ = writeln!(
            text,
            "| {} | {} | {} | {} |",
            source.name, source.category, source.license, source.homepage
        );
    }
    text
}

fn report_md(inputs: &Inputs, gathered: &[Gathered], summary: &Summary) -> String {
    let mut text = format!(
        "# Informe de la versión {}\n\nFecha: {}\n\n",
        inputs.version, inputs.date
    );
    text.push_str("## Categorías\n\n| Categoría | Dominios | Tamaño | Añadidos | Quitados | Protegidos descartados | Populares aceptados | En cuarentena | Subdominios colapsados |\n|---|---|---|---|---|---|---|---|---|\n");
    for (cat, s) in &summary.categories {
        let (added, removed) = s.change.map_or(("—".into(), "—".into()), |(a, r)| {
            (a.to_string(), r.to_string())
        });
        let _ = writeln!(
            text,
            "| {} | {} | {} KB | {added} | {removed} | {} | {} | {} | {} |",
            category_name(*cat),
            s.domains,
            s.bytes / 1024,
            s.removed.protected.len(),
            s.trusted_popular,
            s.removed.quarantined.len(),
            s.removed.collapsed
        );
    }
    let (control, legit) = summary.quality.checked;
    let _ = writeln!(
        text,
        "\nControles: {control} sitios de control bloqueados; {legit} sitios populares legítimos sin bloquear.",
    );
    text.push_str("\n## Fuentes\n\n| Fuente | Estado | Dominios | Antes | Ignorados |\n|---|---|---|---|---|\n");
    for g in gathered {
        let status = match &g.status {
            Status::Fresh => "descargada".to_owned(),
            Status::Fallback(reason) => format!("**copia anterior**: {reason}"),
        };
        let before = g.previous_count.map_or("—".into(), |n| n.to_string());
        let _ = writeln!(
            text,
            "| {} | {status} | {} | {before} | {} |",
            g.source.name,
            g.domains.len(),
            g.ignored
        );
    }
    for (cat, s) in &summary.categories {
        if !s.removed.protected.is_empty() {
            let _ = writeln!(
                text,
                "\n## Protegidos descartados en {}\n",
                category_name(*cat)
            );
            for domain in &s.removed.protected {
                let _ = writeln!(text, "- {domain}");
            }
        }
    }
    text
}

fn quarantine_txt(summary: &Summary) -> String {
    let mut text = String::from(
        "# Dominios populares nuevos, fuera de las listas hasta revisarlos.\n\
         # Para aceptarlos, añadirlos a reviewed.txt.\n",
    );
    for (cat, s) in &summary.categories {
        for domain in &s.removed.quarantined {
            let _ = writeln!(text, "{} {domain}", category_name(*cat));
        }
    }
    text
}
