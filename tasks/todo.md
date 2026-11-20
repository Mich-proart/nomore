# Tareas: `blocklists`

Plan: [plan.md](plan.md). Comprobación común a todas las tareas:

```
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Fase 1: Verificador

- [x] **Tarea 1: Crate y manifiesto firmado** (M)
  - Crear `crates/blocklists` con el formato del manifiesto, su firma y la comprobación de versión.
  - Aceptación: un manifiesto bien firmado y más nuevo se acepta; se rechazan firma de otra clave, un byte alterado, versión igual o menor, y formato desconocido. Admite varias claves públicas (rotación).
  - Verificación: comprobación común.
  - Dependencias: ninguna.
  - Ficheros: `Cargo.toml` del crate, `src/lib.rs`, `src/manifest.rs`, `src/error.rs`, `tests/manifest.rs`.

- [x] **Tarea 2: Diferencias** (M)
  - `delta.rs`: generar la diferencia entre dos binarios `NMBL` y aplicarla.
  - Aceptación: aplicar la diferencia de A a B sobre A da exactamente B (propiedad); diferencia de otra categoría, de otra versión de origen o corrupta se rechaza.
  - Verificación: comprobación común.
  - Dependencias: 1.
  - Ficheros: `src/delta.rs`, `src/lib.rs`, `tests/properties.rs`; en `filter-core`: `CategoryList::hashes`, `from_hashes`, `to_bytes` y `Category::code`.

- [x] **Tarea 3: Plan de descarga y aplicación** (M)
  - `verify.rs`: `plan` (qué ficheros pedir) y `apply` (listas nuevas o error).
  - Aceptación: con la versión anterior instalada pide diferencias; con 8 o más versiones de atraso, o sin listas, pide completos; un fichero que no cuadra con su huella, una diferencia que no da la huella esperada o un fichero que falta producen error y las listas anteriores siguen intactas.
  - Verificación: comprobación común.
  - Dependencias: 2.
  - Ficheros: `src/verify.rs`, `src/lib.rs`, `tests/verify.rs`.

- [x] **Tarea 4: Robustez del verificador** (S)
  - Pruebas de propiedades con bytes aleatorios en manifiesto, firma, binarios y diferencias.
  - Aceptación: ningún pánico; nada que no esté firmado por una clave conocida llega a producir listas.
  - Verificación: comprobación común.
  - Dependencias: 3.
  - Ficheros: `tests/properties.rs`.

### Punto de control A
- [x] Comprobación común en verde.
- [x] Los cinco tipos de material alterado de la especificación se rechazan (criterio 2).
- [x] Revisión con Michell antes de seguir.

## Fase 2: Generador

- [x] **Tarea 5: Lectura de formatos** (S)
  - Crear `crates/blocklists-build` y `parse.rs`: hosts, un dominio por línea, comodín y Adblock básico; lo demás se cuenta como ignorado.
  - Aceptación: cada formato con su prueba sobre ficheros de ejemplo reales recortados; IP, `localhost`, comentarios y reglas Adblock complejas se ignoran y se cuentan.
  - Verificación: comprobación común.
  - Dependencias: ninguna.
  - Ficheros: `Cargo.toml` del crate, `src/main.rs`, `src/parse.rs`, `tests/fixtures/`.

- [x] **Tarea 6: Limpieza y combinación** (M)
  - `clean.rs`: normalizar (incluido punycode), unir, quitar duplicados, colapsar subdominios, protegidos y cuarentena de populares.
  - Aceptación: `ES.PornHub.com.` y `xn--…` se normalizan; `es.pornhub.com` desaparece si está `pornhub.com`; un protegido nunca sale; un dominio del top nuevo en la categoría va a cuarentena y al informe.
  - Verificación: comprobación común.
  - Dependencias: 5.
  - Ficheros: `src/clean.rs`, `src/lib.rs`; `protected.txt` real en la tarea 9.

- [x] **Tarea 7: Fuentes, descarga y reserva** (M)
  - `sources.rs`: leer `lists.toml`, descargar con tiempo límite, comprobar tamaño mínimo y caída máxima del 30 %, y usar la última versión buena si falla.
  - Aceptación: con un servidor HTTP local de pruebas, una fuente caída o que encoge usa la copia anterior y lo dice el informe; una fuente sin copia anterior que falla hace fallar la ejecución sin publicar.
  - Verificación: comprobación común.
  - Dependencias: 6.
  - Ficheros: `src/sources.rs`, `src/config.rs`, `tests/sources.rs`; `lists.toml` real en la tarea 9.

- [x] **Tarea 8: Publicación, firma y `keygen`** (M)
  - `publish.rs`: binarios, diferencias con las 7 versiones anteriores, manifiesto, firma, `SOURCES.md` e informe; subcomandos `keygen` y `verify`.
  - Aceptación: el verificador de la fase 1 acepta la publicación y actualiza con diferencias desde la anterior; dos ejecuciones con las mismas entradas dan bytes idénticos (criterio 6).
  - Verificación: comprobación común; `nomore-lists keygen`, dos `build` seguidos y `verify --from` probados a mano.
  - Dependencias: 3 y 7.
  - Ficheros: `src/publish.rs`, `src/main.rs`, `tests/publish.rs`.

### Punto de control B
- [x] Comprobación común en verde.
- [x] Generar → verificar → actualizar con diferencia funciona de punta a punta con fuentes de ejemplo.
- [ ] Revisión con Michell antes de seguir.

## Fase 3: Producción

- [ ] **Tarea 9: Fuentes reales y controles de calidad** (M)
  - `lists.toml` con las fuentes de la especificación; `protected.txt` completo; conjunto de control de ~300 sitios; comprobación del top 1 000 de Tranco.
  - Aceptación: la ejecución falla si un sitio de control no queda bloqueado o si un sitio del top 1 000 legítimo queda bloqueado (criterio 1).
  - Verificación: comprobación común; revisión manual de `protected.txt` y del conjunto de control contigo.
  - Dependencias: 8.
  - Ficheros: `crates/blocklists-build/lists.toml`, `protected.txt`, `control/*.txt`, `src/quality.rs`.

- [ ] **Tarea 10: Repositorio de listas y ejecución diaria** (M)
  - Necesita que crees `Mich-proart/nomore-lists` y la clave de firma. Workflow diario que compila el generador, descarga la publicación anterior, genera, comprueba calidad, publica la release y abre un aviso si hay cuarentena o fuentes caídas.
  - Aceptación: la ejecución manual del workflow publica una release firmada; la clave pública queda fijada en `crates/blocklists/src/keys.rs`.
  - Verificación: release visible en `nomore-lists`; `verify` en local sobre lo publicado.
  - Dependencias: 9.
  - Ficheros: en `nomore-lists`: `.github/workflows/daily.yml`, `README.md`, `quarantine.txt`; en este repositorio: `crates/blocklists/src/keys.rs`.

- [ ] **Tarea 11: Primera publicación medida** (S)
  - Dos ejecuciones reales en días distintos; medir tamaños, memoria de la lista de pornografía y peso de la diferencia diaria.
  - Aceptación: criterios 3 (diferencia < 1 MB) y 4 (pornografía < 32 MB en memoria) cumplidos, o aplicado el plan de reducción de la especificación; resultados en la especificación.
  - Verificación: informe de las dos ejecuciones.
  - Dependencias: 10.
  - Ficheros: `SPEC-blocklists.md`.

### Punto de control final
- [ ] Los seis criterios de éxito de la especificación se cumplen.
- [ ] Revisión con Michell y fusión en `development`.
