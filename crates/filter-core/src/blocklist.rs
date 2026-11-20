//! Formato binario de lista y búsqueda por sufijo.
//!
//! Una lista es una tabla ordenada de huellas xxh3 de 64 bits, una por
//! dominio. Un nombre está en la lista si lo está él o cualquiera de sus
//! dominios padre.
//!
//! ```text
//! bytes 0..4    marca "NMBL"
//! byte  4       versión de formato (1)
//! byte  5       categoría
//! bytes 6..8    reservado, a cero
//! bytes 8..16   número de huellas, u64 little-endian
//! bytes 16..    huellas, u64 little-endian, en orden estrictamente creciente
//! ```

use xxhash_rust::xxh3::xxh3_64;

use crate::domain::DomainName;
use crate::error::FilterError;

const MAGIC: &[u8; 4] = b"NMBL";
const FORMAT_VERSION: u8 = 1;
const HEADER_LEN: usize = 16;

/// Categoría de una lista de bloqueo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Category {
    /// Pornografía y desnudos. Siempre activa.
    Porn,
    /// Apuestas y juego.
    Gambling,
    /// Apps y webs de citas.
    Dating,
    /// Vías de escape: DoH, VPN, proxies y buscadores sin modo seguro. Siempre activa.
    Bypass,
}

impl Category {
    /// Las cuatro categorías, en orden.
    pub const ALL: [Category; 4] = [Self::Porn, Self::Gambling, Self::Dating, Self::Bypass];

    /// Código de un byte con que la categoría viaja en los binarios.
    pub fn code(self) -> u8 {
        match self {
            Self::Porn => 1,
            Self::Gambling => 2,
            Self::Dating => 3,
            Self::Bypass => 4,
        }
    }

    /// Categoría a partir de su código.
    pub fn from_code(code: u8) -> Result<Self, FilterError> {
        match code {
            1 => Ok(Self::Porn),
            2 => Ok(Self::Gambling),
            3 => Ok(Self::Dating),
            4 => Ok(Self::Bypass),
            other => Err(FilterError::UnknownCategory(other)),
        }
    }
}

/// Conjunto de dominios con búsqueda por sufijo.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SuffixSet {
    /// Huellas en orden estrictamente creciente.
    hashes: Vec<u64>,
}

impl SuffixSet {
    pub(crate) fn from_domains<I, S>(domains: I) -> Result<Self, FilterError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut hashes = Vec::new();
        for domain in domains {
            let name = DomainName::parse(domain.as_ref())?;
            hashes.push(xxh3_64(name.as_str().as_bytes()));
        }
        hashes.sort_unstable();
        hashes.dedup();
        Ok(Self { hashes })
    }

    /// `true` si `name` o alguno de sus dominios padre está en el conjunto.
    pub(crate) fn contains(&self, name: &DomainName) -> bool {
        self.matching_suffix(name).is_some()
    }

    /// La entrada que coincide con `name`: él mismo o el dominio padre más
    /// específico que esté en el conjunto.
    pub(crate) fn matching_suffix<'a>(&self, name: &'a DomainName) -> Option<&'a str> {
        if self.hashes.is_empty() {
            return None;
        }
        name.suffixes().find(|suffix| {
            self.hashes
                .binary_search(&xxh3_64(suffix.as_bytes()))
                .is_ok()
        })
    }

    pub(crate) fn len(&self) -> usize {
        self.hashes.len()
    }
}

/// Lista de dominios de una categoría, tal como la publica `blocklists`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CategoryList {
    category: Category,
    set: SuffixSet,
}

impl CategoryList {
    /// Genera el binario de una lista a partir de sus dominios.
    ///
    /// Los duplicados se eliminan. Falla si algún dominio no es válido.
    pub fn build<I, S>(category: Category, domains: I) -> Result<Vec<u8>, FilterError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let set = SuffixSet::from_domains(domains)?;
        Ok(Self { category, set }.to_bytes())
    }

    /// Construye una lista a partir de sus huellas, que deben estar en orden
    /// estrictamente creciente. La usa `blocklists` al aplicar diferencias.
    pub fn from_hashes(category: Category, hashes: Vec<u64>) -> Result<Self, FilterError> {
        if hashes.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(FilterError::CorruptList("huellas desordenadas o repetidas"));
        }
        Ok(Self {
            category,
            set: SuffixSet { hashes },
        })
    }

    /// Huellas de la lista, en orden estrictamente creciente.
    pub fn hashes(&self) -> &[u64] {
        &self.set.hashes
    }

    /// El binario de la lista, tal como lo lee [`CategoryList::parse`].
    pub fn to_bytes(&self) -> Vec<u8> {
        let hashes = &self.set.hashes;
        let mut out = Vec::with_capacity(HEADER_LEN + hashes.len() * 8);
        out.extend_from_slice(MAGIC);
        out.push(FORMAT_VERSION);
        out.push(self.category.code());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&(hashes.len() as u64).to_le_bytes());
        for hash in hashes {
            out.extend_from_slice(&hash.to_le_bytes());
        }
        out
    }

    /// Lee un binario generado por [`CategoryList::build`].
    pub fn parse(bytes: &[u8]) -> Result<Self, FilterError> {
        if bytes.len() < HEADER_LEN {
            return Err(FilterError::CorruptList("cabecera incompleta"));
        }
        let (header, body) = bytes.split_at(HEADER_LEN);
        if &header[0..4] != MAGIC {
            return Err(FilterError::CorruptList("marca incorrecta"));
        }
        if header[4] != FORMAT_VERSION {
            return Err(FilterError::UnsupportedListVersion(header[4]));
        }
        let category = Category::from_code(header[5])?;

        let mut count_bytes = [0u8; 8];
        count_bytes.copy_from_slice(&header[8..16]);
        let count = u64::from_le_bytes(count_bytes);
        if body.len() % 8 != 0 || (body.len() / 8) as u64 != count {
            return Err(FilterError::CorruptList(
                "el tamaño no coincide con la cabecera",
            ));
        }

        let mut hashes = Vec::with_capacity(body.len() / 8);
        for raw in body.as_chunks::<8>().0 {
            let hash = u64::from_le_bytes(*raw);
            if hashes.last().is_some_and(|&previous| previous >= hash) {
                return Err(FilterError::CorruptList("huellas desordenadas o repetidas"));
            }
            hashes.push(hash);
        }
        Ok(Self {
            category,
            set: SuffixSet { hashes },
        })
    }

    /// Categoría a la que pertenece la lista.
    pub fn category(&self) -> Category {
        self.category
    }

    /// Número de dominios distintos.
    pub fn len(&self) -> usize {
        self.set.len()
    }

    /// `true` si la lista no tiene dominios.
    pub fn is_empty(&self) -> bool {
        self.set.len() == 0
    }

    pub(crate) fn contains(&self, name: &DomainName) -> bool {
        self.set.contains(name)
    }

    pub(crate) fn matching_suffix<'a>(&self, name: &'a DomainName) -> Option<&'a str> {
        self.set.matching_suffix(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(category: Category, domains: &[&str]) -> CategoryList {
        CategoryList::parse(&CategoryList::build(category, domains).unwrap()).unwrap()
    }

    fn name(s: &str) -> DomainName {
        DomainName::parse(s).unwrap()
    }

    #[test]
    fn finds_listed_domain_and_its_subdomains() {
        let l = list(Category::Porn, &["pornhub.com", "xvideos.com"]);
        assert!(l.contains(&name("pornhub.com")));
        assert!(l.contains(&name("es.pornhub.com")));
        assert!(l.contains(&name("a.b.c.xvideos.com")));
        assert!(l.contains(&name("ES.PornHub.com.")));
    }

    #[test]
    fn does_not_match_lookalikes_or_parents() {
        let l = list(Category::Porn, &["pornhub.com", "sub.ejemplo.org"]);
        assert!(!l.contains(&name("notpornhub.com")));
        assert!(!l.contains(&name("pornhub.com.evil.net")));
        assert!(!l.contains(&name("pornhub.org")));
        assert!(!l.contains(&name("com")));
        assert!(!l.contains(&name("ejemplo.org")));
    }

    #[test]
    fn matching_suffix_is_the_most_specific_listed_entry() {
        let l = list(Category::Porn, &["pornhub.com", "es.pornhub.com"]);
        let deep = name("cdn.fr.pornhub.com");
        assert_eq!(l.matching_suffix(&deep), Some("pornhub.com"));
        let spanish = name("img.es.pornhub.com");
        assert_eq!(l.matching_suffix(&spanish), Some("es.pornhub.com"));
        let other = name("notpornhub.com");
        assert_eq!(l.matching_suffix(&other), None);
    }

    #[test]
    fn hashes_roundtrip_through_from_hashes_and_to_bytes() {
        let bytes = CategoryList::build(Category::Gambling, ["a.com", "b.com", "c.com"]).unwrap();
        let parsed = CategoryList::parse(&bytes).unwrap();
        let rebuilt =
            CategoryList::from_hashes(Category::Gambling, parsed.hashes().to_vec()).unwrap();
        assert_eq!(rebuilt.to_bytes(), bytes);
        assert!(CategoryList::from_hashes(Category::Porn, vec![2, 1]).is_err());
        assert!(CategoryList::from_hashes(Category::Porn, vec![1, 1]).is_err());
        assert!(CategoryList::from_hashes(Category::Porn, vec![]).is_ok());
    }

    #[test]
    fn category_codes_roundtrip() {
        for category in Category::ALL {
            assert_eq!(Category::from_code(category.code()), Ok(category));
        }
    }

    #[test]
    fn whole_tld_can_be_listed() {
        let l = list(Category::Porn, &["xxx"]);
        assert!(l.contains(&name("cualquiera.xxx")));
        assert!(!l.contains(&name("xxx.com")));
    }

    #[test]
    fn roundtrip_keeps_category_and_dedups() {
        let l = list(
            Category::Dating,
            &["tinder.com", "TINDER.com.", "bumble.com"],
        );
        assert_eq!(l.category(), Category::Dating);
        assert_eq!(l.len(), 2);
        assert!(!l.is_empty());
    }

    #[test]
    fn empty_list_is_valid_and_matches_nothing() {
        let l = list(Category::Gambling, &[]);
        assert!(l.is_empty());
        assert!(!l.contains(&name("bet365.es")));
    }

    #[test]
    fn build_rejects_invalid_domain() {
        let err = CategoryList::build(Category::Porn, ["ok.com", "mal dominio"]).unwrap_err();
        assert_eq!(err, FilterError::InvalidDomain("mal dominio".into()));
    }

    #[test]
    fn parse_rejects_corrupt_input() {
        let good = CategoryList::build(Category::Porn, ["a.com", "b.com", "c.com"]).unwrap();

        assert!(matches!(
            CategoryList::parse(&good[..10]),
            Err(FilterError::CorruptList(_))
        ));
        assert!(matches!(
            CategoryList::parse(&good[..good.len() - 3]),
            Err(FilterError::CorruptList(_))
        ));
        assert!(matches!(
            CategoryList::parse(&good[..good.len() - 8]),
            Err(FilterError::CorruptList(_))
        ));

        let mut bad_magic = good.clone();
        bad_magic[0] = b'X';
        assert!(matches!(
            CategoryList::parse(&bad_magic),
            Err(FilterError::CorruptList(_))
        ));

        let mut bad_version = good.clone();
        bad_version[4] = 2;
        assert_eq!(
            CategoryList::parse(&bad_version),
            Err(FilterError::UnsupportedListVersion(2))
        );

        let mut bad_category = good.clone();
        bad_category[5] = 99;
        assert_eq!(
            CategoryList::parse(&bad_category),
            Err(FilterError::UnknownCategory(99))
        );

        // Intercambia las dos primeras huellas: deja de estar ordenada.
        let mut unsorted = good.clone();
        let (first, second) = (good[16..24].to_vec(), good[24..32].to_vec());
        unsorted[16..24].copy_from_slice(&second);
        unsorted[24..32].copy_from_slice(&first);
        assert!(matches!(
            CategoryList::parse(&unsorted),
            Err(FilterError::CorruptList(_))
        ));
    }

    #[test]
    fn hash_is_stable_across_versions() {
        // Si esta huella cambia, las listas ya publicadas dejan de funcionar.
        assert_eq!(xxh3_64(b"example.com"), 0x8b66107e8045bb73);
    }
}
