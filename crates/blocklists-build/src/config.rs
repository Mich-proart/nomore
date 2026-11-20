//! Configuración de fuentes (`lists.toml`).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use filter_core::Category;
use serde::Deserialize;

use crate::parse::Format;

/// Mantenedor de las listas propias de NoMore: lo que está en ellas se ha
/// añadido a mano y no pasa por cuarentena.
pub const OWN_MAINTAINER: &str = "nomore";

/// Una fuente de dominios.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    /// Nombre corto y estable: se usa para guardar su copia.
    pub name: String,
    /// Categoría a la que aporta.
    pub category: String,
    /// Dirección de descarga. Exclusivo con `path`.
    pub url: Option<String>,
    /// Fichero local, relativo a `lists.toml` (listas propias).
    pub path: Option<PathBuf>,
    /// Quién mantiene la lista. Dos fuentes del mismo mantenedor no cuentan
    /// como independientes. Las listas propias usan [`OWN_MAINTAINER`].
    pub maintainer: String,
    /// Formato.
    pub format: Format,
    /// Licencia, tal como se cita en `SOURCES.md`.
    pub license: String,
    /// Página del proyecto.
    pub homepage: String,
    /// Por debajo de esto, la descarga se considera rota.
    #[serde(default)]
    pub min_domains: usize,
}

/// Opciones de una categoría.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CategoryConfig {
    /// Dominios de primer nivel que se bloquean enteros (p. ej. `xxx`).
    #[serde(default)]
    pub tlds: Vec<String>,
}

/// `lists.toml` completo.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Opciones por categoría.
    #[serde(default)]
    pub categories: BTreeMap<String, CategoryConfig>,
    /// Fuentes.
    #[serde(rename = "source")]
    pub sources: Vec<Source>,
    /// Carpeta de `lists.toml`, para resolver rutas relativas.
    #[serde(skip)]
    pub base_dir: PathBuf,
}

/// Categoría a partir de su nombre en la configuración.
pub fn category(name: &str) -> Result<Category, String> {
    Category::ALL
        .into_iter()
        .find(|c| blocklists::category_name(*c) == name)
        .ok_or_else(|| format!("categoría desconocida: {name}"))
}

impl Config {
    /// Lee y valida `lists.toml`.
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("no se puede leer {}: {e}", path.display()))?;
        let mut config: Self =
            toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        config.base_dir = path.parent().map(Path::to_path_buf).unwrap_or_default();
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), String> {
        let mut names = std::collections::HashSet::new();
        for source in &self.sources {
            category(&source.category)?;
            if !names.insert(&source.name) {
                return Err(format!("fuente repetida: {}", source.name));
            }
            if !source
                .name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            {
                return Err(format!("nombre de fuente no válido: {}", source.name));
            }
            if source.url.is_some() == source.path.is_some() {
                return Err(format!(
                    "{}: hace falta `url` o `path`, uno solo",
                    source.name
                ));
            }
        }
        for (name, options) in &self.categories {
            category(name)?;
            for tld in &options.tlds {
                if tld.is_empty() || !tld.bytes().all(|b| b.is_ascii_lowercase()) {
                    return Err(format!("dominio de primer nivel no válido: {tld}"));
                }
            }
        }
        Ok(())
    }

    /// Dominios de primer nivel bloqueados en una categoría.
    pub fn tlds(&self, category: Category) -> Vec<String> {
        self.categories
            .get(blocklists::category_name(category))
            .map(|c| c.tlds.clone())
            .unwrap_or_default()
    }
}
