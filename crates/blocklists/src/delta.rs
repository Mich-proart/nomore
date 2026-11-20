//! Diferencias entre dos versiones de una lista.
//!
//! ```text
//! bytes 0..4    marca "NMDL"
//! byte  4       versión de formato (1)
//! byte  5       categoría (mismo código que en los binarios de filter-core)
//! bytes 6..8    reservado, a cero
//! bytes 8..16   versión de origen, u64 little-endian
//! bytes 16..24  versión de destino
//! bytes 24..32  número de huellas añadidas
//! bytes 32..40  número de huellas quitadas
//! bytes 40..    añadidas y luego quitadas, u64 little-endian, cada grupo en
//!               orden estrictamente creciente
//! ```

use filter_core::{Category, CategoryList};

use crate::error::ListError;

const MAGIC: &[u8; 4] = b"NMDL";
const FORMAT_VERSION: u8 = 1;
const HEADER_LEN: usize = 40;

/// Una diferencia ya leída.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delta {
    /// Categoría de la lista.
    pub category: Category,
    /// Versión sobre la que se aplica.
    pub from: u64,
    /// Versión que resulta.
    pub to: u64,
    added: Vec<u64>,
    removed: Vec<u64>,
}

impl Delta {
    /// Calcula la diferencia que lleva de `old` a `new`.
    pub fn between(
        old: &CategoryList,
        new: &CategoryList,
        from: u64,
        to: u64,
    ) -> Result<Self, ListError> {
        if old.category() != new.category() {
            return Err(ListError::BadDelta("categorías distintas"));
        }
        let (old_hashes, new_hashes) = (old.hashes(), new.hashes());
        let (mut added, mut removed) = (Vec::new(), Vec::new());
        let (mut i, mut j) = (0, 0);
        while i < old_hashes.len() && j < new_hashes.len() {
            let (x, y) = (old_hashes[i], new_hashes[j]);
            if x == y {
                i += 1;
                j += 1;
            } else if x < y {
                removed.push(x);
                i += 1;
            } else {
                added.push(y);
                j += 1;
            }
        }
        removed.extend_from_slice(&old_hashes[i..]);
        added.extend_from_slice(&new_hashes[j..]);
        Ok(Self {
            category: new.category(),
            from,
            to,
            added,
            removed,
        })
    }

    /// Huellas añadidas y quitadas.
    pub fn counts(&self) -> (usize, usize) {
        (self.added.len(), self.removed.len())
    }

    /// El binario de la diferencia.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + (self.added.len() + self.removed.len()) * 8);
        out.extend_from_slice(MAGIC);
        out.push(FORMAT_VERSION);
        out.push(self.category.code());
        out.extend_from_slice(&[0, 0]);
        for value in [
            self.from,
            self.to,
            self.added.len() as u64,
            self.removed.len() as u64,
        ] {
            out.extend_from_slice(&value.to_le_bytes());
        }
        for hash in self.added.iter().chain(&self.removed) {
            out.extend_from_slice(&hash.to_le_bytes());
        }
        out
    }

    /// Lee una diferencia.
    pub fn parse(bytes: &[u8]) -> Result<Self, ListError> {
        if bytes.len() < HEADER_LEN || &bytes[..4] != MAGIC {
            return Err(ListError::BadDelta("no es una diferencia"));
        }
        if bytes[4] != FORMAT_VERSION {
            return Err(ListError::BadDelta("versión de formato desconocida"));
        }
        let category = Category::from_code(bytes[5])
            .map_err(|_| ListError::BadDelta("categoría desconocida"))?;
        let word = |index: usize| {
            let mut raw = [0u8; 8];
            raw.copy_from_slice(&bytes[8 + index * 8..16 + index * 8]);
            u64::from_le_bytes(raw)
        };
        let (from, to, added_len, removed_len) = (word(0), word(1), word(2), word(3));
        let body = &bytes[HEADER_LEN..];
        let expected = added_len
            .checked_add(removed_len)
            .and_then(|n| n.checked_mul(8));
        if expected != Some(body.len() as u64) {
            return Err(ListError::BadDelta("el tamaño no cuadra con la cabecera"));
        }
        let hashes: Vec<u64> = body
            .as_chunks::<8>()
            .0
            .iter()
            .map(|raw| u64::from_le_bytes(*raw))
            .collect();
        let (added, removed) = hashes.split_at(added_len as usize);
        for group in [added, removed] {
            if group.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err(ListError::BadDelta("huellas desordenadas"));
            }
        }
        Ok(Self {
            category,
            from,
            to,
            added: added.to_vec(),
            removed: removed.to_vec(),
        })
    }

    /// Aplica la diferencia sobre `base`.
    ///
    /// Exige que todo lo quitado esté en `base` y que nada de lo añadido lo
    /// esté: una diferencia que no encaja exactamente se rechaza.
    pub fn apply(&self, base: &CategoryList) -> Result<CategoryList, ListError> {
        if base.category() != self.category {
            return Err(ListError::BadDelta("otra categoría"));
        }
        let mut out = Vec::with_capacity(base.hashes().len() + self.added.len());
        let mut added = self.added.iter().peekable();
        let mut removed = self.removed.iter().peekable();
        for &hash in base.hashes() {
            while let Some(&&new) = added.peek() {
                if new > hash {
                    break;
                }
                if new == hash {
                    return Err(ListError::BadDelta("añade algo que ya estaba"));
                }
                out.push(new);
                added.next();
            }
            if removed.peek() == Some(&&hash) {
                removed.next();
            } else {
                out.push(hash);
            }
        }
        out.extend(added);
        if removed.next().is_some() {
            return Err(ListError::BadDelta("quita algo que no estaba"));
        }
        CategoryList::from_hashes(self.category, out).map_err(|e| ListError::BadList(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(hashes: &[u64]) -> CategoryList {
        CategoryList::from_hashes(Category::Porn, hashes.to_vec()).unwrap()
    }

    #[test]
    fn between_and_apply() {
        let old = list(&[1, 3, 5, 7]);
        let new = list(&[2, 3, 7, 9, 10]);
        let delta = Delta::between(&old, &new, 1, 2).unwrap();
        assert_eq!(delta.added, [2, 9, 10]);
        assert_eq!(delta.removed, [1, 5]);
        assert_eq!(delta.apply(&old).unwrap(), new);
        let parsed = Delta::parse(&delta.to_bytes()).unwrap();
        assert_eq!(parsed, delta);
    }

    #[test]
    fn a_delta_that_does_not_fit_is_rejected() {
        let delta = Delta::between(&list(&[1, 2]), &list(&[2, 3]), 1, 2).unwrap();
        // Sobre una base que ya tiene el 3, o que no tiene el 1.
        assert!(delta.apply(&list(&[1, 2, 3])).is_err());
        assert!(delta.apply(&list(&[2])).is_err());
        let other = CategoryList::from_hashes(Category::Dating, vec![1, 2]).unwrap();
        assert!(delta.apply(&other).is_err());
    }

    #[test]
    fn corrupt_bytes_are_rejected() {
        let bytes = Delta::between(&list(&[1]), &list(&[2, 3]), 1, 2)
            .unwrap()
            .to_bytes();
        assert!(Delta::parse(&bytes[..bytes.len() - 1]).is_err());
        assert!(Delta::parse(&bytes[..20]).is_err());
        let mut bad_magic = bytes.clone();
        bad_magic[0] = b'X';
        assert!(Delta::parse(&bad_magic).is_err());
        let mut huge_count = bytes.clone();
        huge_count[24..32].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(Delta::parse(&huge_count).is_err());
        let mut unsorted = bytes.clone();
        let (first, second) = (bytes[40..48].to_vec(), bytes[48..56].to_vec());
        unsorted[40..48].copy_from_slice(&second);
        unsorted[48..56].copy_from_slice(&first);
        assert!(Delta::parse(&unsorted).is_err());
    }
}
