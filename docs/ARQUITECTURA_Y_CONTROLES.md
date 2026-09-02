# Arquitectura y controles

## Flujo

1. La interfaz web local escucha solo en `127.0.0.1`, protege sus operaciones
   con un token efímero por sesión y entrega la configuración a la CLI sin
   persistir contraseñas.
2. La CLI valida la autorización, los pilares y los límites del perfil.
3. El analizador estático recorre la copia sin seguir enlaces simbólicos ni
   ejecutar sus archivos.
4. El ejecutor HTTP aplica únicamente los controles declarados, restringe por
   defecto el destino a loopback y respeta presupuestos de solicitudes y bytes.
5. Cada regla produce `PASS`, `FAIL`, `SKIP_JUSTIFICADO` o `ERROR`, además de
   un estado de hallazgo y evidencia resumida con hashes SHA-256.
6. La salida JSON se escribe de forma atómica.
7. Si se proporciona `--comparar-con`, se valida la comparabilidad de los
   instrumentos y se calculan los cambios entre condiciones.

## Separación entre modelo y código determinista

El auditor no llama a un modelo generativo. Cuando el sistema objetivo contiene
un agente o un LLM, su respuesta es una observación del experimento. La
autenticación, selección de pruebas, solicitudes, límites, extracción de campos,
comparación, clasificación y hashes pertenecen al código determinista del
auditor.

El control `agent_scope_consistency` aplica esa separación de forma explícita:
la API directa fija la referencia autorizada de lo que la identidad puede ver,
el agente aporta la observación y el código determinista compara ambas. Cuando
el modelo decide no invocar la herramienta, la regla produce `ERROR` con
confianza `MEDIA`, porque la variable no fue observable, y nunca un `PASS`.

## Capacidades y permisos

| Componente | Capacidad | Identidad |
|---|---|---|
| Interfaz local | Configurar, iniciar, cancelar y consultar una corrida | Usuario del sistema y token efímero de la sesión local |
| Analizador local | Lectura limitada del repositorio autorizado | Usuario del sistema que inicia la CLI |
| Cliente HTTP anónimo | Comprobar autenticación obligatoria | Sin sesión |
| Cliente HTTP A | Controles de propietario y presupuesto | Cuenta ficticia definida en `AUDITOR_TRAMITIA_USER_A` |
| Cliente HTTP B | Acceso cruzado y frontera de rol | Cuenta ficticia definida en `AUDITOR_TRAMITIA_USER_B` |
| Escritor de evidencia | Crear JSON/DOCX en la ruta indicada | Usuario del sistema que inicia la CLI |

Las contraseñas se leen desde variables de entorno. La evidencia no conserva
contraseñas, cookies ni cuerpos completos de respuestas.

## Condiciones experimentales

La condición `A` representa la copia inicial sin los controles explícitos de la
intervención. La condición `B` representa la copia intervenida. Ambas ejecutan
las mismas reglas; la intervención se verifica mediante los resultados
observables y los hashes de instrumento incluidos en la comparación.

## Catálogos

El perfil incluido relaciona cada control de los pilares 1 y 2 y la integridad
del registro con categorías de OWASP Top 10:2021, OWASP API Security Top
10:2023 y OWASP Top 10 for LLM Applications:2025. Las reglas estáticas del
pilar 3 usan especialmente A08 Software and Data Integrity Failures y las
categorías equivalentes de cadena de suministro definidas en el motor.

## Límites

Un `FAIL` demuestra que el criterio determinista de una regla no se cumplió;
no demuestra por sí solo explotabilidad. Un `PASS` tampoco demuestra ausencia
de riesgos fuera de los formatos, endpoints, datasets y fronteras declarados.
Los eventos `ERROR` y `SKIP_JUSTIFICADO` deben explicarse antes de comparar las
condiciones.
