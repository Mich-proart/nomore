//! Utilidades para las pruebas del generador.
#![allow(dead_code)]

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use blocklists_build::clean::Protected;
use blocklists_build::config::Config;
use blocklists_build::publish::{build, load_previous, Inputs, Previous, Summary};
use blocklists_build::sources::Fetcher;
use ed25519_dalek::SigningKey;

/// Carpeta temporal propia de cada prueba.
pub fn temp_dir(label: &str) -> PathBuf {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("nomore-lists-{label}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Descargas falsas: dirección → contenido, o error si no está.
#[derive(Default)]
pub struct Fake(pub BTreeMap<String, String>);

impl Fetcher for Fake {
    fn fetch(&self, url: &str) -> Result<Vec<u8>, String> {
        self.0
            .get(url)
            .map(|text| text.clone().into_bytes())
            .ok_or_else(|| format!("{url}: no responde"))
    }
}

pub fn key() -> SigningKey {
    SigningKey::from_bytes(&[0x42; 32])
}

pub fn public() -> [u8; 32] {
    *key().verifying_key().as_bytes()
}

/// `lists.toml` con una fuente remota por categoría y una propia de porno.
pub fn config(dir: &Path, own_porn: &str) -> Config {
    std::fs::write(dir.join("own-porn.txt"), own_porn).unwrap();
    let toml = r#"
[categories.porn]
tlds = ["xxx", "porn"]

[[source]]
name = "porn-hosts"
category = "porn"
url = "https://ejemplo.test/porn.hosts"
format = "hosts"
license = "MIT"
homepage = "https://ejemplo.test"
min_domains = 3

[[source]]
name = "own-porn"
category = "porn"
path = "own-porn.txt"
format = "domains"
license = "GPL-3.0"
homepage = "https://github.com/Mich-proart/nomore-lists"

[[source]]
name = "gambling-adblock"
category = "gambling"
url = "https://ejemplo.test/gambling.txt"
format = "adblock"
license = "Unlicense"
homepage = "https://ejemplo.test"

[[source]]
name = "dating-wild"
category = "dating"
url = "https://ejemplo.test/dating.txt"
format = "wildcard"
license = "CC BY-SA"
homepage = "https://ejemplo.test"

[[source]]
name = "bypass-domains"
category = "bypass"
url = "https://ejemplo.test/bypass.txt"
format = "domains"
license = "GPL-3.0"
homepage = "https://ejemplo.test"
"#;
    let path = dir.join("lists.toml");
    std::fs::write(&path, toml).unwrap();
    Config::load(&path).unwrap()
}

/// Contenido de las fuentes remotas.
pub fn remote(porn: &[&str]) -> Fake {
    let mut fake = Fake::default();
    let hosts: String = porn.iter().map(|d| format!("0.0.0.0 {d}\n")).collect();
    fake.0.insert(
        "https://ejemplo.test/porn.hosts".into(),
        format!("# lista\n127.0.0.1 localhost\n{hosts}"),
    );
    fake.0.insert(
        "https://ejemplo.test/gambling.txt".into(),
        "! título\n||bet365.es^\n||casino.example^\n@@||loteria.es^\n".into(),
    );
    fake.0.insert(
        "https://ejemplo.test/dating.txt".into(),
        "*.tinder.com\nbumble.com\n".into(),
    );
    fake.0.insert(
        "https://ejemplo.test/bypass.txt".into(),
        "dns.google\ncloudflare-dns.com\nnordvpn.com\n".into(),
    );
    fake
}

pub struct World {
    pub dir: PathBuf,
    pub config: Config,
    pub protected: Protected,
    pub popular: HashSet<String>,
    pub reviewed: HashSet<String>,
}

pub fn world(label: &str) -> World {
    let dir = temp_dir(label);
    World {
        config: config(&dir, "propio.com\n"),
        protected: Protected::parse("www.google.com\nreddit.com\n").unwrap(),
        popular: ["pornhub.com", "xvideos.com", "popular-nuevo.com"]
            .map(String::from)
            .into(),
        reviewed: ["pornhub.com", "xvideos.com"].map(String::from).into(),
        dir,
    }
}

impl World {
    pub fn build(
        &self,
        version: u64,
        previous: &[Previous],
        fetcher: &dyn Fetcher,
        out: &str,
    ) -> Result<(PathBuf, Summary), String> {
        let out = self.dir.join(out);
        let inputs = Inputs {
            config: &self.config,
            protected: &self.protected,
            popular: &self.popular,
            reviewed: &self.reviewed,
            previous,
            version,
            date: "2026-11-20",
            key: &key(),
            control: None,
            legit: &[],
        };
        build(&inputs, fetcher, &out).map(|summary| (out, summary))
    }

    pub fn load(&self, dir: &Path) -> Previous {
        load_previous(dir, &[public()]).unwrap()
    }
}

pub const PORN: &[&str] = &[
    "pornhub.com",
    "es.pornhub.com",
    "xvideos.com",
    "google.com",
    "popular-nuevo.com",
    "pequeno-porno.com",
    "otro-porno.net",
];
