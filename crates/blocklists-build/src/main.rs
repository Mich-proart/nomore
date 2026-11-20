//! `nomore-lists`: genera, verifica y firma las listas de NoMore.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;

use blocklists::Manifest;
use blocklists_build::clean::Protected;
use blocklists_build::config::Config;
use blocklists_build::publish::{build, hex, load_previous, parse_hex32, signing_key, Inputs};
use blocklists_build::read_domain_set;
use blocklists_build::sources::Http;
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;

#[derive(Parser)]
#[command(name = "nomore-lists", about = "Listas de bloqueo de NoMore")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Genera una publicación.
    Build {
        /// Fuentes.
        #[arg(long, default_value = "lists.toml")]
        config: PathBuf,
        /// Dominios que nunca se bloquean.
        #[arg(long)]
        protected: PathBuf,
        /// Top de dominios más visitados (Tranco), para la cuarentena.
        #[arg(long)]
        popular: Option<PathBuf>,
        /// Populares ya revisados.
        #[arg(long)]
        reviewed: Option<PathBuf>,
        /// Publicaciones anteriores descargadas, de la más reciente a la más antigua.
        #[arg(long)]
        previous: Vec<PathBuf>,
        /// Versión nueva, AAAAMMDDnn.
        #[arg(long)]
        version: u64,
        /// Fecha, AAAA-MM-DD.
        #[arg(long)]
        date: String,
        /// Carpeta de salida.
        #[arg(long)]
        out: PathBuf,
    },
    /// Verifica una publicación y, si se indica, que se puede actualizar desde otra.
    Verify {
        /// Publicación a verificar.
        dir: PathBuf,
        /// Clave pública en hexadecimal.
        #[arg(long)]
        public_key: String,
        /// Publicación anterior desde la que probar la actualización con diferencias.
        #[arg(long)]
        from: Option<PathBuf>,
    },
    /// Muestra la clave pública de una clave privada guardada con `keygen`.
    PublicKey {
        /// Fichero de la clave privada.
        #[arg(long)]
        key: PathBuf,
    },
    /// Crea un par de claves de firma.
    Keygen {
        /// Fichero donde guardar la clave privada. No se sobrescribe.
        #[arg(long)]
        out: PathBuf,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse().command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run(command: Command) -> Result<(), String> {
    match command {
        Command::Build {
            config,
            protected,
            popular,
            reviewed,
            previous,
            version,
            date,
            out,
        } => {
            let key_hex = std::env::var("NOMORE_LISTS_SIGNING_KEY")
                .map_err(|_| "falta la variable NOMORE_LISTS_SIGNING_KEY".to_owned())?;
            let key = signing_key(&key_hex)?;
            let public = *key.verifying_key().as_bytes();
            let config = Config::load(&config)?;
            let protected =
                Protected::parse(&std::fs::read_to_string(&protected).map_err(|e| e.to_string())?)?;
            let popular = popular
                .map(|p| read_domain_set(&p))
                .transpose()?
                .unwrap_or_default();
            let reviewed = reviewed
                .map(|p| read_domain_set(&p))
                .transpose()?
                .unwrap_or_default();
            let previous = previous
                .iter()
                .map(|dir| load_previous(dir, &[public]))
                .collect::<Result<Vec<_>, _>>()?;
            let inputs = Inputs {
                config: &config,
                protected: &protected,
                popular: &popular,
                reviewed: &reviewed,
                previous: &previous,
                version,
                date: &date,
                key: &key,
            };
            let summary = build(&inputs, &Http::new(), &out)?;
            for (category, s) in &summary.categories {
                println!(
                    "{:<9} {:>9} dominios  {:>7} KB  cuarentena {}",
                    blocklists::category_name(*category),
                    s.domains,
                    s.bytes / 1024,
                    s.removed.quarantined.len()
                );
            }
            for (name, reason) in &summary.fallbacks {
                println!("copia anterior: {name}: {reason}");
            }
            Ok(())
        }
        Command::Verify {
            dir,
            public_key,
            from,
        } => {
            let key = parse_hex32(&public_key)?;
            let read = |dir: &PathBuf, name: &str| {
                std::fs::read(dir.join(name)).map_err(|e| format!("{name}: {e}"))
            };
            let previous = from.map(|d| load_previous(&d, &[key])).transpose()?;
            let manifest = Manifest::verify(
                &read(&dir, "manifest.json")?,
                &read(&dir, "manifest.sig")?,
                &[key],
                previous.as_ref().map(|p| p.version),
            )
            .map_err(|e| e.to_string())?;
            let installed = previous.map(|p| blocklists::Installed {
                version: p.version,
                lists: p.lists.iter().map(|(c, l)| (*c, l.to_bytes())).collect(),
            });
            let plan = manifest.plan(installed.as_ref());
            let mut files = BTreeMap::new();
            for fetch in &plan {
                files.insert(fetch.name.clone(), read(&dir, &fetch.name)?);
            }
            let updated = manifest
                .apply(installed.as_ref(), &files)
                .map_err(|e| e.to_string())?;
            let downloaded: u64 = plan.iter().map(|f| f.file.size).sum();
            println!(
                "versión {} correcta; {} ficheros, {} KB",
                updated.version,
                plan.len(),
                downloaded / 1024
            );
            Ok(())
        }
        Command::PublicKey { key } => {
            let seed = std::fs::read_to_string(&key).map_err(|e| e.to_string())?;
            let public = signing_key(&seed)?.verifying_key().to_bytes();
            println!("{}", hex(&public));
            Ok(())
        }
        Command::Keygen { out } => {
            if out.exists() {
                return Err(format!("{} ya existe: no se sobrescribe", out.display()));
            }
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed).map_err(|e| e.to_string())?;
            let key = SigningKey::from_bytes(&seed);
            std::fs::write(&out, format!("{}\n", hex(&seed))).map_err(|e| e.to_string())?;
            let public = key.verifying_key().to_bytes();
            println!("Clave privada guardada en {}", out.display());
            println!(
                "Guárdala como secreto NOMORE_LISTS_SIGNING_KEY y en una copia fuera de línea."
            );
            println!("Clave pública: {}", hex(&public));
            println!(
                "Para keys.rs: [{}]",
                public
                    .iter()
                    .map(|b| format!("0x{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            Ok(())
        }
    }
}
