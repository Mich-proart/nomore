//! De un manifiesto verificado a listas de confianza.

use std::collections::BTreeMap;

use filter_core::{Category, CategoryList};

use crate::delta::Delta;
use crate::error::ListError;
use crate::manifest::{delta_file_name, full_file_name, FileRef, Manifest};

/// Listas instaladas en el dispositivo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    /// Versión de la publicación de la que vienen.
    pub version: u64,
    /// Binario de cada categoría, tal como hay que guardarlo.
    pub lists: BTreeMap<Category, Vec<u8>>,
}

impl Installed {
    /// Las listas listas para `filter_core::Filter::new`.
    pub fn category_lists(&self) -> Result<Vec<CategoryList>, ListError> {
        self.lists
            .values()
            .map(|bytes| CategoryList::parse(bytes).map_err(|e| ListError::BadList(e.to_string())))
            .collect()
    }
}

/// Un fichero que hay que descargar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetch {
    /// Categoría a la que corresponde.
    pub category: Category,
    /// Nombre del fichero en la publicación.
    pub name: String,
    /// Tamaño y huella esperados: no descargar más de `file.size` bytes.
    pub file: FileRef,
    /// `true` si es una diferencia y no el binario completo.
    pub is_delta: bool,
}

impl Manifest {
    /// Qué ficheros hacen falta para pasar de `installed` a esta publicación:
    /// la diferencia si la hay desde la versión instalada y ocupa menos que
    /// el binario completo, y si no el completo.
    pub fn plan(&self, installed: Option<&Installed>) -> Vec<Fetch> {
        Category::ALL
            .into_iter()
            .filter_map(|category| {
                let entry = self.entry(category)?;
                let delta = installed
                    .filter(|i| i.lists.contains_key(&category))
                    .and_then(|i| entry.deltas.iter().find(|d| d.from == i.version))
                    .filter(|delta| delta.file.size < entry.file.size);
                Some(match delta {
                    Some(delta) => Fetch {
                        category,
                        name: delta_file_name(category, delta.from),
                        file: delta.file.clone(),
                        is_delta: true,
                    },
                    None => self.full(category),
                })
            })
            .collect()
    }

    /// Plan sin diferencias: todos los binarios completos. Sirve de reserva
    /// cuando aplicar una diferencia ha fallado.
    pub fn plan_full(&self) -> Vec<Fetch> {
        Category::ALL
            .into_iter()
            .filter(|category| self.entry(*category).is_some())
            .map(|category| self.full(category))
            .collect()
    }

    fn full(&self, category: Category) -> Fetch {
        let file = self
            .entry(category)
            .map(|entry| entry.file.clone())
            .unwrap_or(FileRef {
                size: 0,
                sha256: String::new(),
            });
        Fetch {
            category,
            name: full_file_name(category),
            file,
            is_delta: false,
        }
    }

    /// Construye las listas nuevas a partir de lo descargado.
    ///
    /// `files` asocia cada nombre de [`Manifest::plan`] con sus bytes. Si
    /// algo no cuadra, devuelve error y `installed` sigue siendo válido: no
    /// se cambia nada hasta que todo está comprobado.
    pub fn apply(
        &self,
        installed: Option<&Installed>,
        files: &BTreeMap<String, Vec<u8>>,
    ) -> Result<Installed, ListError> {
        let mut lists = BTreeMap::new();
        for category in Category::ALL {
            let entry = self
                .entry(category)
                .ok_or(ListError::BadManifest("falta una categoría"))?;
            let full_name = full_file_name(category);
            let bytes = if let Some(full) = files.get(&full_name) {
                if !entry.file.matches(full) {
                    return Err(ListError::HashMismatch(full_name));
                }
                full.clone()
            } else {
                self.apply_delta(category, installed, files)?
            };
            let list =
                CategoryList::parse(&bytes).map_err(|e| ListError::BadList(e.to_string()))?;
            if list.category() != category || list.len() as u64 != entry.domains {
                return Err(ListError::BadList(format!(
                    "{full_name} no es la lista anunciada"
                )));
            }
            lists.insert(category, bytes);
        }
        Ok(Installed {
            version: self.version,
            lists,
        })
    }

    fn apply_delta(
        &self,
        category: Category,
        installed: Option<&Installed>,
        files: &BTreeMap<String, Vec<u8>>,
    ) -> Result<Vec<u8>, ListError> {
        let entry = self
            .entry(category)
            .ok_or(ListError::BadManifest("falta una categoría"))?;
        let Some((installed, base_bytes)) =
            installed.and_then(|i| Some((i, i.lists.get(&category)?)))
        else {
            return Err(ListError::MissingFile(full_file_name(category)));
        };
        let delta_ref = entry
            .deltas
            .iter()
            .find(|d| d.from == installed.version)
            .ok_or_else(|| ListError::MissingFile(full_file_name(category)))?;
        let name = delta_file_name(category, delta_ref.from);
        let delta_bytes = files
            .get(&name)
            .ok_or_else(|| ListError::MissingFile(name.clone()))?;
        if !delta_ref.file.matches(delta_bytes) {
            return Err(ListError::HashMismatch(name));
        }
        let delta = Delta::parse(delta_bytes)?;
        if delta.category != category || delta.from != installed.version || delta.to != self.version
        {
            return Err(ListError::BadDelta("no corresponde a esta actualización"));
        }
        let base =
            CategoryList::parse(base_bytes).map_err(|e| ListError::BadList(e.to_string()))?;
        let result = delta.apply(&base)?.to_bytes();
        if !entry.file.matches(&result) {
            return Err(ListError::DeltaResultMismatch(category));
        }
        Ok(result)
    }
}
