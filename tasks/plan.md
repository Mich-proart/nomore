# Plan de implementación: `filter-core`

Especificación: [SPEC-filter-core.md](../SPEC-filter-core.md). Tareas: [todo.md](todo.md). Estado: **pendiente de aprobación**.

## Resumen

Librería Rust que convierte una consulta DNS en bruto en una respuesta fabricada (bloqueo, SafeSearch) o en la orden de reenviarla. Se construye de dentro hacia fuera: nombres de dominio → listas → política → mensajes DNS → SafeSearch, y al final las pruebas masivas, el rendimiento y la compilación cruzada.

## Decisiones de arquitectura

1. **Formato de lista: tabla ordenada de huellas de 64 bits.** Cada dominio se guarda como su huella xxh3-64. Para consultar `a.b.ejemplo.com` se calcula la huella de `a.b.ejemplo.com`, `b.ejemplo.com`, `ejemplo.com` y `com`, y se busca cada una por búsqueda binaria. Un millón de dominios ocupa 8 MB y no hay que reservar memoria al consultar. La probabilidad de bloquear por error un dominio ajeno es despreciable (del orden de 1 entre 10¹³ por consulta).
2. **El constructor de listas vive aquí.** `CategoryList::build` genera el binario y `blocklists` lo reutiliza, así el formato tiene una sola implementación. Cabecera: marca `NMBL`, versión, categoría y número de entradas.
3. **Cambio en la API respecto a la especificación: tercera variante `Rewrite`.** SafeSearch exige responder con las direcciones de `forcesafesearch.google.com`, y esta librería no tiene red. Por eso `handle_query` devuelve `Rewrite { upstream_query, token }`: el agente resuelve esa consulta fuera y llama a `finish_rewrite(token, respuesta)` para obtener la respuesta final (CNAME más direcciones). Si la resolución falla, se responde con bloqueo, nunca con el buscador sin filtrar.
4. **Tablas pequeñas en el código, listas grandes fuera.** Los dominios de SafeSearch (Google y sus dominios por país, Bing, DuckDuckGo, YouTube) y los canarios van en el código porque son pocos y definen comportamiento. Porno, apuestas, citas y vías de escape (incluidos los buscadores sin modo seguro) llegan como listas desde `blocklists`.
5. **Sin dependencia de IDN.** En el protocolo DNS los nombres ya viajan en ASCII (punycode). Las listas se publican en punycode y `explain` acepta solo esa forma.
6. **Dependencias**: `hickory-proto` (mensajes DNS) y `xxhash-rust` (huella estable entre plataformas). En desarrollo, `proptest` y `criterion`.

## Dependencias entre piezas

```
domain ──→ blocklist ──→ policy ──→ dns ──→ safesearch (Rewrite)
                                     │
                                     └──→ pruebas masivas, rendimiento, compilación cruzada
```

## Fases

1. **Base**: tareas 1 a 4. Al terminar, `explain("es.pornhub.com")` dice «bloqueado, categoría porn».
2. **DNS**: tareas 5 y 6. Al terminar, la librería responde consultas reales en bruto.
3. **Garantías**: tareas 7 a 9. Al terminar, se cumplen los cinco criterios de éxito.

## Riesgos

| Riesgo | Impacto | Mitigación |
|---|---|---|
| `hickory-proto` no acepta fabricar algún tipo de respuesta (HTTPS/SVCB vacía) | Medio | Se prueba en la tarea 5, la primera de DNS; alternativa: escribir esos pocos bytes a mano |
| No se llega a 20 µs por consulta | Bajo | El diseño no reserva memoria al consultar; se mide en la tarea 8 y hay margen para optimizar el análisis del mensaje |
| La variante `Rewrite` complica a los agentes | Medio | El token lleva todo el estado; el agente solo reenvía y devuelve bytes |
| Los dominios de Google por país cambian | Bajo | Tabla con prueba que la compara con la lista pública de Google; se actualiza con cada versión |

## Fuera de este plan

Listas reales, descarga y actualización (`blocklists`); sockets, reenvío y caché (`windows-agent`, `android-app`); enlace con Kotlin (`android-app`).
