# Spec: `filter-core`

Módulo del [mapa de capacidades](CAPABILITY-MAP.md). Estado: **aprobada el 16-11-2026 e implementada**. Plan en [tasks/plan.md](tasks/plan.md).

## Objetivo

Librería Rust que responde a una sola pregunta: **qué hacer con una consulta DNS**. Es la misma en Windows y en Android, de modo que el criterio de bloqueo es idéntico en todos los dispositivos.

Recibe una consulta DNS en bruto y devuelve una de tres cosas:

- una **respuesta ya fabricada** (bloqueo),
- la orden de **reescribirla** (SafeSearch): quien usa la librería resuelve el nombre seguro y ella monta la respuesta final, o
- la orden de **reenviarla** al DNS de verdad.

No abre sockets, no lee ficheros, no descarga listas y no sabe nada de guardianes ni contraseñas. Eso es trabajo de `windows-agent`, `android-app`, `blocklists` y `guard-core`.

### Qué decide

| Caso | Ejemplo | Resultado |
|---|---|---|
| Dominio en una categoría bloqueada, o subdominio de uno | `es.pornhub.com`, `bet365.es`, `api.gotinder.com` | Bloqueo |
| Buscador con modo seguro | `www.google.es`, `www.bing.com`, `duckduckgo.com` | Redirección a su versión SafeSearch |
| YouTube | `www.youtube.com`, `m.youtube.com` | Redirección a modo restringido estricto |
| Buscador sin modo seguro forzable | los que se listen en `blocklists` | Bloqueo |
| Vía de escape: DoH, VPN, proxy web | `dns.google`, `cloudflare-dns.com` | Bloqueo |
| Dominios canario | `use-application-dns.net` (Firefox), `mask.icloud.com` | NXDOMAIN, para que el navegador desactive su DNS propio |
| Dominio en la lista de permitidos del guardián | — | Reenviar, aunque esté en una lista |
| Todo lo demás | `wikipedia.org` | Reenviar |

### Categorías

- `porn`: siempre activa, no se puede apagar.
- `gambling` y `dating`: activas por defecto; el guardián puede apagarlas.
- `bypass` (DoH, VPN, proxies) y SafeSearch: siempre activos.

### Forma de un bloqueo

- Consultas `A` → `0.0.0.0`. Consultas `AAAA` → `::`.
- Consultas `HTTPS` y `SVCB` → respuesta vacía (sin esto, un navegador puede saltarse la redirección de SafeSearch).
- Cualquier otro tipo → respuesta vacía.
- TTL de 60 s en respuestas fabricadas, para que un cambio de configuración surta efecto en un minuto.

## Tecnología

- Rust estable, edición 2021. Compila en Windows (`x86_64-pc-windows-msvc`), Android (`aarch64-linux-android`, `armv7-linux-androideabi`, `x86_64-linux-android`) y Linux (para pruebas y CI).
- `hickory-proto` para leer y escribir mensajes DNS.
- `proptest` y `criterion` solo en desarrollo.
- Sin `unsafe`, sin runtime asíncrono, sin acceso a red ni a disco.

## Comandos

```
Compilar:     cargo build -p filter-core
Probar:       cargo test -p filter-core
Garantías:    cargo test -p filter-core --release -- --ignored --nocapture
Lint:         cargo clippy -p filter-core --all-targets -- -D warnings
Formato:      cargo fmt --all -- --check
Rendimiento:  cargo bench -p filter-core
```

## Estructura

```
Cargo.toml                      → workspace
crates/filter-core/
  src/lib.rs                    → API pública
  src/domain.rs                 → normalización de nombres (minúsculas, punto final, IDN)
  src/blocklist.rs              → formato binario de lista y búsqueda por sufijo
  src/safesearch.rs             → tabla de redirecciones
  src/policy.rs                 → categorías activas, lista de permitidos, orden de precedencia
  src/dns.rs                    → consulta en bruto → respuesta fabricada o reenviar
  tests/                        → pruebas de integración con listas de ejemplo
  benches/                      → rendimiento
legacy/                         → prototipo anterior (Python y .bat), sin tocar
```

## API y estilo

La API pública es pequeña y sin genéricos ni referencias con tiempo de vida, para poder exponerla a Kotlin más adelante.

```rust
/// Qué hacer con una consulta DNS.
pub enum Action {
    /// Devolver estos bytes al cliente tal cual.
    Respond(Vec<u8>),
    /// SafeSearch: resolver `upstream_query` fuera y pasar el resultado a
    /// `finish_rewrite` junto con `token`.
    Rewrite { upstream_query: Vec<u8>, token: RewriteToken },
    /// Reenviar la consulta original al DNS de salida.
    Forward,
}

pub struct Filter { /* listas + política */ }

impl Filter {
    /// `lists`: una lista binaria por categoría, tal como las publica `blocklists`.
    pub fn new(lists: Vec<CategoryList>, policy: Policy) -> Result<Filter, FilterError>;

    /// Nunca entra en pánico: una consulta ilegible se responde con FORMERR.
    pub fn handle_query(&self, query: &[u8]) -> Action;

    /// Respuesta final de una redirección de SafeSearch. Si el DNS de salida
    /// no dio una dirección utilizable, responde con bloqueo.
    pub fn finish_rewrite(&self, token: RewriteToken, upstream_response: Option<&[u8]>) -> Vec<u8>;

    /// Para la interfaz y las pruebas: por qué se decide algo sobre un dominio.
    pub fn explain(&self, domain: &str) -> Verdict;
}
```

Convenciones:

- Nombres de código en inglés; comentarios y documentación en español.
- Errores con tipos propios (`FilterError`), sin `unwrap` ni `expect` fuera de pruebas.
- `Filter` es inmutable y `Send + Sync`: para cambiar listas o política se construye otro y se sustituye.

Orden de precedencia, de mayor a menor: canario → `bypass` → lista de permitidos del guardián → categoría bloqueada → SafeSearch → reenviar. La lista de permitidos nunca puede desbloquear `bypass`.

## Pruebas

- **Unitarias** en cada fichero: normalización, búsqueda por sufijo, precedencia.
- **De propiedades** (`proptest`): `handle_query` no entra en pánico con bytes aleatorios; todo subdominio de un dominio bloqueado queda bloqueado; `notpornhub.com` no se bloquea por parecerse a `pornhub.com`.
- **De integración**: consultas DNS reales en bruto contra listas de ejemplo, comprobando los bytes de la respuesta.
- **Rendimiento** con una lista sintética de un millón de dominios.

## Límites

- **Siempre**: pruebas, clippy y formato en verde antes de cada commit; toda regla de la tabla «Qué decide» con su prueba.
- **Preguntar antes**: añadir dependencias, cambiar el formato binario de lista, cambiar la API pública.
- **Nunca**: red o disco dentro de esta librería; `unsafe`; listas reales de dominios dentro del código fuente (van en `blocklists`).

## Criterios de éxito

1. Cada fila de la tabla «Qué decide» tiene al menos una prueba que pasa.
2. Con una lista de un millón de dominios: construir el filtro tarda menos de 1 s, ocupa menos de 32 MB de memoria y `handle_query` tarda menos de 20 µs de media.
3. 10 millones de entradas aleatorias en `handle_query` sin un solo pánico.
4. Compila sin avisos para Windows y para las tres arquitecturas de Android.
5. `cargo clippy -- -D warnings` y `cargo fmt --check` pasan.

## Resultados medidos

Con una lista de un millón de dominios, en Linux x86-64 (16-11-2026):

| Criterio | Objetivo | Medido |
|---|---|---|
| Construir el filtro | < 1 s | 4 ms |
| Memoria del filtro | < 32 MB | 7,6 MB |
| Tiempo medio por consulta | < 20 µs | 1,1 µs |
| Entradas aleatorias sin pánico | 10 millones | 10 millones |

## Decisiones

- **Loterías del Estado y la ONCE**: cuentan como apuestas; el guardián puede permitirlas una a una.
- **YouTube**: modo restringido estricto.
- **Redes sociales** (X, Reddit, Telegram web): no se bloquean en este módulo; las cubrirá `screen-ai`.
