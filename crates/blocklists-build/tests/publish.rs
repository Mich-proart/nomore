//! De las fuentes a una publicación que el verificador acepta.

mod common;

use std::collections::BTreeMap;

use blocklists::{Installed, Manifest};
use common::{public, remote, world, PORN};
use filter_core::{Category, Filter, Policy, Verdict};

fn read(dir: &std::path::Path, name: &str) -> Vec<u8> {
    std::fs::read(dir.join(name)).unwrap()
}

fn install(dir: &std::path::Path, from: Option<&Installed>) -> (Installed, u64) {
    let manifest = Manifest::verify(
        &read(dir, "manifest.json"),
        &read(dir, "manifest.sig"),
        &[public()],
        from.map(|i| i.version),
    )
    .unwrap();
    let plan = manifest.plan(from);
    let downloaded = plan.iter().map(|f| f.file.size).sum();
    let files: BTreeMap<String, Vec<u8>> = plan
        .iter()
        .map(|f| (f.name.clone(), read(dir, &f.name)))
        .collect();
    (manifest.apply(from, &files).unwrap(), downloaded)
}

#[test]
fn first_release_blocks_what_it_should_and_nothing_protected() {
    let w = world("first");
    let (out, summary) = w.build(2026112001, &[], &remote(PORN), "v1").unwrap();
    let (installed, _) = install(&out, None);
    let filter = Filter::new(installed.category_lists().unwrap(), Policy::default()).unwrap();

    for blocked in [
        "pornhub.com",
        "es.pornhub.com",
        "xvideos.com",
        "propio.com",
        "algo.xxx",
        "algo.porn",
    ] {
        assert_eq!(
            filter.explain(blocked),
            Verdict::Blocked(Category::Porn),
            "{blocked}"
        );
    }
    assert_eq!(
        filter.explain("bet365.es"),
        Verdict::Blocked(Category::Gambling)
    );
    assert_eq!(
        filter.explain("api.tinder.com"),
        Verdict::Blocked(Category::Dating)
    );
    assert_eq!(
        filter.explain("dns.google"),
        Verdict::Blocked(Category::Bypass)
    );
    assert_eq!(
        filter.explain("loteria.es"),
        Verdict::Allowed,
        "excepción @@"
    );
    // google.com venía en la fuente de porno, pero protege www.google.com.
    assert!(!matches!(filter.explain("google.com"), Verdict::Blocked(_)));
    // Popular, nuevo y sin revisar: en cuarentena.
    assert_eq!(filter.explain("popular-nuevo.com"), Verdict::Allowed);

    let porn = &summary.categories[&Category::Porn];
    assert!(porn.removed.protected.contains("google.com"));
    assert!(porn.removed.quarantined.contains("popular-nuevo.com"));
    assert_eq!(porn.removed.collapsed, 1, "es.pornhub.com sobra");

    let quarantine = String::from_utf8(read(&out, "quarantine.txt")).unwrap();
    assert!(quarantine.contains("porn popular-nuevo.com"));
    let sources = String::from_utf8(read(&out, "SOURCES.md")).unwrap();
    assert!(sources.contains("GPL-3.0") && sources.contains("porn-hosts"));
    let report = String::from_utf8(read(&out, "report.md")).unwrap();
    assert!(report.contains("2026112001") && report.contains("google.com"));
}

#[test]
fn the_next_release_updates_with_small_deltas() {
    let w = world("next");
    let (v1_dir, _) = w.build(2026112001, &[], &remote(PORN), "v1").unwrap();
    let v1 = w.load(&v1_dir);

    let mut porn: Vec<&str> = PORN.to_vec();
    porn.push("nuevo-porno.com");
    let (v2_dir, summary) = w.build(2026112101, &[v1], &remote(&porn), "v2").unwrap();
    assert_eq!(summary.categories[&Category::Porn].change, Some((1, 0)));

    let (first, _) = install(&v1_dir, None);
    let (updated, downloaded) = install(&v2_dir, Some(&first));
    assert_eq!(updated.version, 2026112101);
    let (fresh, full_size) = install(&v2_dir, None);
    assert_eq!(
        updated, fresh,
        "por diferencias o completo, el mismo resultado"
    );
    assert!(downloaded < full_size, "{downloaded} >= {full_size}");
}

#[test]
fn quarantined_domains_stay_out_until_reviewed() {
    let mut w = world("review");
    let (v1_dir, _) = w.build(2026112001, &[], &remote(PORN), "v1").unwrap();
    let v1 = w.load(&v1_dir);
    // Al día siguiente sigue en cuarentena.
    let (_, summary) = w
        .build(2026112101, std::slice::from_ref(&v1), &remote(PORN), "v2")
        .unwrap();
    assert!(summary.categories[&Category::Porn]
        .removed
        .quarantined
        .contains("popular-nuevo.com"));
    // Revisado, entra.
    w.reviewed.insert("popular-nuevo.com".into());
    let (v3_dir, _) = w.build(2026112201, &[v1], &remote(PORN), "v3").unwrap();
    let (installed, _) = install(&v3_dir, None);
    let filter = Filter::new(installed.category_lists().unwrap(), Policy::default()).unwrap();
    assert_eq!(
        filter.explain("popular-nuevo.com"),
        Verdict::Blocked(Category::Porn)
    );
}

#[test]
fn same_inputs_give_identical_bytes() {
    let w = world("repro");
    let (a, _) = w.build(2026112001, &[], &remote(PORN), "a").unwrap();
    let (b, _) = w.build(2026112001, &[], &remote(PORN), "b").unwrap();
    let mut names: Vec<_> = std::fs::read_dir(&a)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    names.sort();
    assert!(names.len() >= 10);
    for name in names {
        let path_a = a.join(&name);
        if path_a.is_dir() {
            for entry in std::fs::read_dir(&path_a).unwrap() {
                let entry = entry.unwrap();
                let other = b.join(&name).join(entry.file_name());
                assert_eq!(
                    std::fs::read(entry.path()).unwrap(),
                    std::fs::read(other).unwrap()
                );
            }
        } else {
            assert_eq!(
                read(&a, name.to_str().unwrap()),
                read(&b, name.to_str().unwrap()),
                "{name:?}"
            );
        }
    }
}

#[test]
fn version_must_grow() {
    let w = world("version");
    let (v1_dir, _) = w.build(2026112001, &[], &remote(PORN), "v1").unwrap();
    let v1 = w.load(&v1_dir);
    let error = w.build(2026112001, &[v1], &remote(PORN), "v2").unwrap_err();
    assert!(error.contains("no es mayor"), "{error}");
}

#[test]
fn deltas_cover_the_last_seven_releases() {
    let w = world("history");
    let mut previous = Vec::new();
    for day in 1..=9u64 {
        let mut porn: Vec<String> = PORN.iter().map(|s| s.to_string()).collect();
        porn.push(format!("dia{day}.com"));
        let refs: Vec<&str> = porn.iter().map(String::as_str).collect();
        let version = 2026110000 + day * 100 + 1;
        let (dir, _) = w
            .build(version, &previous, &remote(&refs), &format!("d{day}"))
            .unwrap();
        previous.insert(0, w.load(&dir));
    }
    let newest = &previous[0];
    let manifest: Manifest = serde_json::from_slice(&read(&newest.dir, "manifest.json")).unwrap();
    let froms: Vec<u64> = manifest
        .entry(Category::Porn)
        .unwrap()
        .deltas
        .iter()
        .map(|d| d.from)
        .collect();
    assert_eq!(froms.len(), 7);
    assert_eq!(froms[0], previous[1].version);
}

#[test]
fn a_previous_release_signed_by_another_key_is_refused() {
    let w = world("foreign");
    let (dir, _) = w.build(2026112001, &[], &remote(PORN), "v1").unwrap();
    let other = [0x99u8; 32];
    assert!(blocklists_build::publish::load_previous(&dir, &[other]).is_err());
}

#[test]
fn popular_domains_from_two_independent_sources_or_own_lists_skip_quarantine() {
    let w = world("trusted");
    let (out, summary) = w.build(2026112001, &[], &remote(PORN), "v1").unwrap();
    let (installed, _) = install(&out, None);
    let filter = Filter::new(installed.category_lists().unwrap(), Policy::default()).unwrap();

    // Dos mantenedores distintos.
    assert_eq!(
        filter.explain("doble.com"),
        Verdict::Blocked(Category::Porn)
    );
    // Lista propia.
    assert_eq!(
        filter.explain("propio.com"),
        Verdict::Blocked(Category::Porn)
    );
    // Una sola fuente: a revisión.
    assert_eq!(filter.explain("solo-extra-popular.com"), Verdict::Allowed);
    assert_eq!(filter.explain("popular-nuevo.com"), Verdict::Allowed);

    let porn = &summary.categories[&Category::Porn];
    assert_eq!(porn.trusted_popular, 2);
    assert!(porn.removed.quarantined.contains("solo-extra-popular.com"));
}
