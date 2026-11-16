# Tareas: `filter-core`

Plan: [filter-core-plan.md](filter-core-plan.md). Comprobación común a todas las tareas:

```
cargo fmt --all -- --check
cargo clippy -p filter-core --all-targets -- -D warnings
cargo test -p filter-core
```

## Fase 1: Base

- [x] **Tarea 1: Esqueleto del repositorio** (S)
  - Mover el prototipo a `legacy/`, quitar `build/` y `dist/` de git, añadir `.gitignore`, crear el workspace de Cargo con `crates/filter-core` vacío y sustituir el workflow de macOS por uno de CI (formato, clippy y pruebas en Linux y Windows).
  - Aceptación: `cargo test -p filter-core` pasa con cero pruebas; no queda ningún `.exe` versionado; el CI corre en cada push.
  - Verificación: comprobación común; `git ls-files | grep -E '\.(exe|pyc|pyz)$'` no devuelve nada.
  - Dependencias: ninguna.
  - Ficheros: `Cargo.toml`, `.gitignore`, `.github/workflows/ci.yml`, `crates/filter-core/Cargo.toml`, `crates/filter-core/src/lib.rs`.

- [x] **Tarea 2: Normalización de dominios** (S)
  - `domain.rs`: minúsculas, sin punto final, validación de longitud y caracteres, e iterador de sufijos por etiquetas.
  - Aceptación: `WWW.Ejemplo.COM.` → `www.ejemplo.com`; los sufijos de `a.b.c` son `a.b.c`, `b.c`, `c`; nombres inválidos devuelven error, sin pánico.
  - Verificación: comprobación común.
  - Dependencias: 1.
  - Ficheros: `src/domain.rs`, `src/lib.rs`.

- [x] **Tarea 3: Formato de lista y búsqueda por sufijo** (M)
  - `blocklist.rs`: `CategoryList::build` (dominios → binario) y `CategoryList::parse` (binario → tabla), con búsqueda por huella xxh3-64.
  - Aceptación: un dominio listado y cualquier subdominio suyo se encuentran; `notpornhub.com` no coincide con `pornhub.com`; un binario corrupto o de otra versión devuelve `FilterError`.
  - Verificación: comprobación común.
  - Dependencias: 2.
  - Ficheros: `src/blocklist.rs`, `src/lib.rs`, `Cargo.toml` del crate.

- [x] **Tarea 4: Política y veredicto** (M)
  - `policy.rs`: categorías activas, lista de permitidos del guardián, canarios y el orden de precedencia de la especificación. Expone `Filter::new` y `Filter::explain`.
  - Aceptación: `porn` no se puede desactivar; la lista de permitidos desbloquea `gambling` pero nunca `bypass`; cada escalón de la precedencia tiene su prueba.
  - Verificación: comprobación común.
  - Dependencias: 3.
  - Ficheros: `src/policy.rs`, `src/lib.rs`, `tests/policy.rs`.

### Punto de control A
- [x] Comprobación común en verde.
- [x] `explain` da el veredicto correcto para un ejemplo de cada fila de «Qué decide» salvo SafeSearch.
- [x] Revisión con Michell antes de seguir.

## Fase 2: DNS

- [x] **Tarea 5: Consultas DNS y respuestas de bloqueo** (M)
  - `dns.rs`: `handle_query` lee la consulta y fabrica la respuesta: `0.0.0.0` para A, `::` para AAAA, vacía para HTTPS, SVCB y el resto, NXDOMAIN para canarios, FORMERR para bytes ilegibles, y `Forward` para lo permitido. TTL de 60 s.
  - Aceptación: la respuesta conserva el identificador y la pregunta de la consulta; cada tipo de la sección «Forma de un bloqueo» tiene su prueba sobre bytes reales.
  - Verificación: comprobación común.
  - Dependencias: 4.
  - Ficheros: `src/dns.rs`, `src/lib.rs`, `tests/dns.rs`, `Cargo.toml` del crate.

- [x] **Tarea 6: SafeSearch y YouTube restringido** (M)
  - `safesearch.rs`: tabla de redirecciones, variante `Action::Rewrite` y `Filter::finish_rewrite`.
  - Aceptación: `www.google.es` produce una consulta a `forcesafesearch.google.com` y la respuesta final lleva CNAME más direcciones; si la resolución externa falla, se responde con bloqueo; las consultas HTTPS a un buscador redirigido reciben respuesta vacía.
  - Verificación: comprobación común.
  - Dependencias: 5.
  - Ficheros: `src/safesearch.rs`, `src/dns.rs`, `src/lib.rs`, `tests/safesearch.rs`.

### Punto de control B
- [x] Comprobación común en verde.
- [x] Todas las filas de «Qué decide» tienen prueba (criterio de éxito 1).
- [x] Revisión con Michell antes de seguir.

## Fase 3: Garantías

- [x] **Tarea 7: Pruebas de propiedades** (S)
  - `proptest` para las tres propiedades de la especificación y una prueba larga de 10 millones de entradas aleatorias.
  - Aceptación: ningún pánico en 10 millones de entradas (criterio 3).
  - Verificación: `cargo test -p filter-core --release -- --ignored fuzz_10m`.
  - Dependencias: 6.
  - Ficheros: `tests/properties.rs`, `Cargo.toml` del crate.

- [x] **Tarea 8: Rendimiento y memoria** (S)
  - Banco de pruebas con una lista sintética de un millón de dominios.
  - Aceptación: construir el filtro en menos de 1 s, menos de 32 MB y menos de 20 µs de media por consulta (criterio 2).
  - Verificación: `cargo test -p filter-core --release -- --ignored one_million` (umbrales) y `cargo bench -p filter-core` (cifras).
  - Dependencias: 6.
  - Ficheros: `benches/filter.rs`, `Cargo.toml` del crate.

- [x] **Tarea 9: Compilación para Windows y Android** (S)
  - Añadir al CI `cargo check` para `x86_64-pc-windows-msvc` y las tres arquitecturas de Android.
  - Aceptación: los cuatro destinos compilan sin avisos (criterio 4).
  - Verificación: el CI pasa en la rama.
  - Dependencias: 6.
  - Ficheros: `.github/workflows/ci.yml`.

### Punto de control final
- [x] Los cinco criterios de éxito de la especificación se cumplen.
- [x] Revisión con Michell y fusión en `development`.
