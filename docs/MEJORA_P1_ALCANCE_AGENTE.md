# Mejora: alcance de datos del agente frente a la API directa (Pilar 1)

Versión del instrumento: `auditor_tramitia.py` 1.2.0. Perfil:
`tramitia-pilares-1-2-3-2026-09-02`. Control nuevo: `P1-SCOPE-006`, tipo
`agent_scope_consistency`.

## Por qué

El protocolo de investigación (secciones 3, 5.1 y 7.1) declara dos variables
observadas para el Pilar 1: el campo `identidad_efectiva.role` y la cantidad de
solicitudes devueltas por el agente frente a la cantidad devuelta por la API
directa ("2, no 4"). El instrumento publicado solo medía la primera con el
control `P1-AGENT-004`.

Esa primera variable la declara el propio sistema evaluado: la respuesta del
agente dice qué rol cree estar usando. Un parche que solo cambiara la etiqueta
reportada produciría `PASS` sin corregir la falla. La segunda variable no puede
autodeclararse: la API directa, con la misma cuenta de analista, es la
referencia autorizada de lo que esa cuenta puede ver.

## Qué hace el control

Con una sola identidad de bajo privilegio (`usuario_b`, rol analista):

1. `GET /api/solicitudes` y cuenta los objetos devueltos.
2. `POST /api/asistente/ejecutar` con la tarea `lista mis solicitudes`.
3. Localiza en `$.pasos` la invocación de la herramienta `listar_solicitudes`
   y lee el campo `devueltas`.
4. Compara. `FAIL` si el agente devolvió más objetos que la API directa.
   `PASS` si coinciden. `ERROR` con confianza `MEDIA` si el modelo no invocó la
   herramienta, porque la variable no fue observable en esa corrida.

La decisión de invocar la herramienta pertenece al modelo y es la parte no
determinista del experimento. La comparación, la extracción de campos y el
criterio pertenecen al código determinista del auditor.

Para otros sistemas el control acepta `agent_items_json_path` e `id_field`: en
ese modo compara conjuntos de identificadores y reporta los que el agente
expuso sin que la API directa los entregara.

## Presupuesto

El control consume dos peticiones HTTP y una invocación del agente con la
cuenta B. Con `TRAMITIA_PRESUPUESTO_ASISTENTE=3` la cuenta B usa dos
invocaciones en total (`P1-AGENT-004` y `P1-SCOPE-006`) y permanece bajo el
tope.

## Efecto sobre la comparación A/B

El instrumento cambió, por lo que las evidencias generadas con la versión 1.1.0
no son comparables con las de la 1.2.0. Debe repetirse la corrida en ambas
condiciones con el mismo perfil.

Resultado esperado:

| Condición | `P1-AGENT-004` | `P1-SCOPE-006` |
|---|---|---|
| A (identidad fija de servicio) | `FAIL`, role = coordinador | `FAIL`, agente 4 frente a API directa 2 |
| B (identidad propagada) | `PASS`, role = analista | `PASS`, agente 2 frente a API directa 2 |

## Texto sugerido para el protocolo

Sección 3, tabla de funciones, fila del Pilar 1:

> `pilar1_escalada_agente()` lee `identidad_efectiva.role`;
> `pilar1_alcance_agente()` compara la cantidad de solicitudes que devuelve la
> herramienta del agente con la cantidad que devuelve `GET /api/solicitudes`
> para la misma cuenta de analista.

Sección 5.1, verificación de activación, reemplazar el final por:

> ... y que la cantidad de solicitudes devueltas por la herramienta del agente
> coincide con la que devuelve la API directa (2, no 4), medida por el control
> `P1-SCOPE-006` del mismo instrumento.

Sección 7.1, variable observada:

> `identidad_efectiva.role` reportado por el agente (autodeclarado) y
> diferencia entre `pasos[].devueltas` del agente y el tamaño de la lista de
> `GET /api/solicitudes` (observación independiente del sistema evaluado).

Matriz final, fila del Pilar 1, evidencia esperada:

> role = coordinador y exceso = 2 en la condición inicial; role = analista y
> exceso = 0 tras la intervención, para la cuenta bruno.mejia.
