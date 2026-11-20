//! Plan de descarga y construcción de las listas nuevas.

mod common;

use std::collections::BTreeMap;

use blocklists::{full_file_name, Installed, ListError, Manifest};
use common::{content, evolve, fetch, key, public, release, Content, Release};
use filter_core::{Category, Filter, Policy, Verdict};

fn installed(version: u64, content: &Content) -> Installed {
    Installed {
        version,
        lists: content.iter().map(|(c, l)| (*c, l.to_bytes())).collect(),
    }
}

fn verified(r: &Release, installed: Option<u64>) -> Manifest {
    Manifest::verify(&r.manifest, &r.signature, &[public(&key())], installed).unwrap()
}

#[test]
fn first_install_downloads_full_lists() {
    let v1 = content("a");
    let r = release(1, &v1, &[], &key());
    let m = verified(&r, None);
    let plan = m.plan(None);
    assert_eq!(plan.len(), 4);
    assert!(plan.iter().all(|f| !f.is_delta));
    let result = m.apply(None, &fetch(&r, &plan)).unwrap();
    assert_eq!(result, installed(1, &v1));

    // Y sirven para filtrar.
    let filter = Filter::new(result.category_lists().unwrap(), Policy::default()).unwrap();
    assert_eq!(
        filter.explain("porn3.a.com"),
        Verdict::Blocked(Category::Porn)
    );
}

#[test]
fn a_daily_update_uses_small_deltas() {
    let v1 = content("a");
    let v2 = evolve(&v1, "b");
    let r = release(2, &v2, &[(1, &v1)], &key());
    let m = verified(&r, Some(1));
    let current = installed(1, &v1);

    let plan = m.plan(Some(&current));
    assert!(plan.iter().all(|f| f.is_delta), "{plan:?}");
    let delta_bytes: u64 = plan.iter().map(|f| f.file.size).sum();
    let full_bytes: u64 = m.plan_full().iter().map(|f| f.file.size).sum();
    assert!(delta_bytes < full_bytes);

    let result = m.apply(Some(&current), &fetch(&r, &plan)).unwrap();
    assert_eq!(result, installed(2, &v2));
}

#[test]
fn too_far_behind_downloads_full_lists() {
    let v1 = content("a");
    let v5 = evolve(&evolve(&v1, "b"), "c");
    let v4 = evolve(&v1, "d");
    // La publicación 5 solo trae diferencias desde la 4.
    let r = release(5, &v5, &[(4, &v4)], &key());
    let m = verified(&r, Some(1));
    let plan = m.plan(Some(&installed(1, &v1)));
    assert!(plan.iter().all(|f| !f.is_delta));
    m.apply(Some(&installed(1, &v1)), &fetch(&r, &plan))
        .unwrap();
}

#[test]
fn a_tampered_full_list_is_rejected() {
    let v1 = content("a");
    let r = release(1, &v1, &[], &key());
    let m = verified(&r, None);
    let mut files = fetch(&r, &m.plan(None));
    let porn = files.get_mut(&full_file_name(Category::Porn)).unwrap();
    // Quita el último dominio de la lista y arregla la cabecera: un binario
    // válido, pero no el publicado.
    porn.truncate(porn.len() - 8);
    let count = (porn.len() as u64 - 16) / 8;
    porn[8..16].copy_from_slice(&count.to_le_bytes());
    assert_eq!(
        m.apply(None, &files),
        Err(ListError::HashMismatch("porn.nmbl".into()))
    );
}

#[test]
fn a_tampered_delta_is_rejected_and_full_lists_still_work() {
    let v1 = content("a");
    let v2 = evolve(&v1, "b");
    let r = release(2, &v2, &[(1, &v1)], &key());
    let m = verified(&r, Some(1));
    let current = installed(1, &v1);
    let plan = m.plan(Some(&current));
    let mut files = fetch(&r, &plan);
    let name = plan[0].name.clone();
    let delta = files.get_mut(&name).unwrap();
    let last = delta.len() - 1;
    delta[last] ^= 0xff;
    assert_eq!(
        m.apply(Some(&current), &files),
        Err(ListError::HashMismatch(name))
    );

    // Reserva: binarios completos.
    let full = fetch(&r, &m.plan_full());
    assert_eq!(m.apply(Some(&current), &full).unwrap(), installed(2, &v2));
}

#[test]
fn a_delta_over_the_wrong_base_does_not_produce_the_announced_list() {
    let v1 = content("a");
    let v2 = evolve(&v1, "b");
    let r = release(2, &v2, &[(1, &v1)], &key());
    let m = verified(&r, Some(1));
    // El dispositivo dice tener la versión 1, pero sus listas son otras
    // (p. ej. corruptas o manipuladas).
    let wrong = installed(1, &content("z"));
    let plan = m.plan(Some(&wrong));
    assert!(matches!(
        m.apply(Some(&wrong), &fetch(&r, &plan)),
        Err(ListError::BadDelta(_) | ListError::DeltaResultMismatch(_))
    ));
}

#[test]
fn missing_files_are_reported() {
    let v1 = content("a");
    let r = release(1, &v1, &[], &key());
    let m = verified(&r, None);
    let mut files = fetch(&r, &m.plan(None));
    files.remove("dating.nmbl");
    assert_eq!(
        m.apply(None, &files),
        Err(ListError::MissingFile("dating.nmbl".into()))
    );
    assert_eq!(
        m.apply(None, &BTreeMap::new()),
        Err(ListError::MissingFile("porn.nmbl".into()))
    );
}

#[test]
fn a_list_of_the_wrong_category_is_rejected_even_if_listed_in_the_manifest() {
    // Un generador con un error que publicara la lista de citas como porno
    // tampoco debe pasar.
    let mut v1 = content("a");
    let dating = v1[&Category::Dating].clone();
    v1.insert(Category::Porn, dating);
    let r = release(1, &v1, &[], &key());
    let m = verified(&r, None);
    assert!(matches!(
        m.apply(None, &fetch(&r, &m.plan(None))),
        Err(ListError::BadList(_))
    ));
}

#[test]
fn a_delta_bigger_than_the_full_list_is_not_used() {
    // Lista casi entera nueva: la diferencia ocupa más que el binario.
    let v1 = content("a");
    let v2 = content("b");
    let r = release(2, &v2, &[(1, &v1)], &key());
    let m = verified(&r, Some(1));
    let current = installed(1, &v1);
    let plan = m.plan(Some(&current));
    assert!(plan.iter().all(|f| !f.is_delta), "{plan:?}");
    assert_eq!(
        m.apply(Some(&current), &fetch(&r, &plan)).unwrap(),
        installed(2, &v2)
    );
}
