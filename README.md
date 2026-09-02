# Auditor de seguridad Python — tres pilares

Proyecto autónomo para ejecutar y comparar un estudio de seguridad sobre una
copia local y autorizada de una aplicación. El auditor conserva evidencia JSON
reproducible y ejecuta el mismo instrumento en las condiciones `A` y `B`.

El informe profesional y la interfaz fueron preparados por Diego Andrés García
Álvarez, Angel Danilo Marin Giraldo y Brayan Alexander Salazar Reyes,
Ingenieros de Sistemas.

## Interfaz gráfica

En Windows, abra `iniciar_auditor.cmd` con doble clic. El lanzador inicia un
servidor web exclusivamente local (`127.0.0.1`) y abre la interfaz en el
navegador predeterminado; no publica el auditor en la red. También puede
iniciarla desde PowerShell:

```powershell
cd "C:\Users\Brayan Salazar\Desktop\Projects\auditor"
.\iniciar_auditor.cmd
```

La interfaz permite seleccionar el repositorio y la política mediante botones
**Examinar** con selector nativo de Python, activar los tres pilares e introducir
usuarios y contraseñas ficticios sin guardarlos. Inicialmente aparece únicamente
el usuario A; el botón **Agregar otro usuario** incorpora B, C, D y hasta L. También permite ejecutar las
condiciones A y B, comparar evidencias, consultar hallazgos y generar el informe
Word. La sección **Manual integrado** explica el flujo completo y el alcance
ético. Use **Cerrar interfaz** en la parte inferior de la barra lateral para
detener el servidor local; si hay una auditoría activa, primero se cancela.

## Alcance de los tres pilares

| Pilar | Qué evalúa | Mecanismo |
|---|---|---|
| 1. Identidad y control de acceso | Autenticación, BOLA, fronteras de rol, agencia excesiva del agente y alcance de datos del agente frente a la API directa | Pruebas HTTP declarativas con dos identidades ficticias |
| 2. Arquitectura y configuración | Consumo de recursos, CORS, cabeceras, secretos, modo depuración y límites de cuerpo | Pruebas HTTP acotadas y reglas estáticas |
| 3. Integridad y cadena de suministro | Versiones, lockfiles, hashes, procedencia, referencias de CI/CD y cadena de integridad del registro | Análisis estático y verificación HTTP del registro |

Los problemas se anclan a OWASP Top 10, OWASP API Security Top 10 y OWASP
Top 10 for LLM Applications dentro del perfil de configuración. El motor no
instala dependencias ni ejecuta código del repositorio auditado.

El control `agent_scope_consistency` del pilar 1 mide la agencia excesiva con
un dato que el agente no puede autodeclarar: con la misma identidad de bajo
privilegio consulta la API directa y luego pide al agente la misma lista. Si la
herramienta del agente devuelve más objetos que la API directa, el agente
ejecuta con una identidad distinta a la del solicitante. Si el modelo no
invoca la herramienta, la regla termina en `ERROR` y no en `PASS`.

## Requisitos

- Python 3.11 o posterior.
- Una copia local del repositorio que se va a auditar.
- Para los pilares 1 y 2 y la verificación HTTP del pilar 3: una instancia de
  laboratorio autorizada y dos cuentas ficticias.
- `python-docx` solamente si se desea generar el informe DOCX.

El núcleo usa exclusivamente la biblioteca estándar. Para instalar el comando
y la dependencia opcional del informe:

```powershell
cd "C:\Users\Brayan Salazar\Desktop\Projects\auditor"
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[reports]"
```

También puede ejecutarse directamente sin instalar el proyecto.

## Configuración de las identidades

En la interfaz cada identidad contiene únicamente nombre de usuario y contraseña.
Inicialmente se muestra A; agregue B, C u otras identidades cuando la política de
pruebas las necesite. Todos esos valores permanecen únicamente en memoria y no
se escriben en la evidencia ni en el informe Word.

No escriba contraseñas en los JSON ni las confirme en Git. Defínalas en la
terminal que ejecutará el auditor:

```powershell
$env:AUDITOR_TRAMITIA_USER_A = "usuario.propietario"
$env:AUDITOR_TRAMITIA_PASSWORD_A = "<clave-de-laboratorio>"
$env:AUDITOR_TRAMITIA_USER_B = "usuario.analista"
$env:AUDITOR_TRAMITIA_PASSWORD_B = "<clave-de-laboratorio>"
```

El archivo `configurar_entorno.example.ps1` contiene la misma plantilla. Antes
de usar otro sistema, copie `auditor_config.tramitia.example.json` y ajuste sus
rutas, identidades, criterios y límites sin cambiar el motor.

## Ejecutar los tres pilares

Con la aplicación de laboratorio iniciada, ejecute desde esta carpeta:

```powershell
$RepoObjetivo = "C:\ruta\a\la\copia\tramitia-app"

python .\auditor_tramitia.py `
  --repo $RepoObjetivo `
  --config .\auditor_config.tramitia.example.json `
  --pilares 1,2,3 `
  --base-url http://127.0.0.1:5050 `
  --condicion A `
  --out .\resultados\evidencia_A.json `
  --autorizado `
  --permitir-pruebas-activas
```

Después de aplicar y verificar la intervención, reinicie la aplicación y
repita con el mismo repositorio de prueba, datos, identidades, semilla y
presupuesto:

```powershell
python .\auditor_tramitia.py `
  --repo $RepoObjetivo `
  --config .\auditor_config.tramitia.example.json `
  --pilares 1,2,3 `
  --base-url http://127.0.0.1:5050 `
  --condicion B `
  --out .\resultados\evidencia_B.json `
  --comparar-con .\resultados\evidencia_A.json `
  --out-docx .\resultados\Informe_Profesional_Ciberseguridad_B.docx `
  --autorizado `
  --permitir-pruebas-activas
```

`A` y `B` son etiquetas experimentales: no activan ni desactivan reglas. Las
dos corridas usan exactamente el mismo instrumento. Lo único que debe cambiar
es la intervención de seguridad aplicada al sistema estudiado. La comparación
comprueba las diferencias de instrumento e informa los hashes de política,
catálogo, reglas y parámetros para establecer si el resultado es comparable.

## Ejecutar solamente el pilar 3 estático

No necesita servidor ni credenciales para los controles estáticos:

```powershell
python .\auditor_tramitia.py `
  --repo $RepoObjetivo `
  --config .\auditor_config.example.json `
  --pilares 3 `
  --condicion A `
  --out .\resultados\evidencia_pilar3.json `
  --autorizado
```

El perfil genérico no incluye la comprobación HTTP del registro. Para evaluar
esa parte del pilar 3 use el perfil Tramitia completo y una `base-url` local.

## Resultados y códigos de salida

- El JSON es la evidencia canónica: inventario, hashes, eventos de regla,
  métricas, limitaciones, resumen por pilar y comparación A/B.
- El DOCX es opcional y se deriva del mismo JSON.
- Una ejecución válida devuelve `0`, aunque encuentre riesgos.
- `--fail-on ALTA` devuelve `2` cuando existe un hallazgo confirmado de
  severidad alta o crítica.
- Errores de configuración, autorización o ejecución devuelven un código
  distinto de cero y se explican por consola.

Para ver todas las opciones:

```powershell
python .\auditor_tramitia.py --help
```

## Pruebas del proyecto

```powershell
python -m unittest discover -s tests -v
python -m py_compile .\auditor_tramitia.py .\generar_informe_evidencia.py .\interfaz_auditor.py
```

## Límite ético

No está permitido ejecutar pruebas activas contra sistemas, cuentas, datos o
redes sin autorización expresa. Use únicamente copias locales y entornos de
laboratorio; no use información personal o institucional real. La bandera
`--permitir-red` solo corresponde a un host no local incluido expresamente en
el alcance autorizado.

## Licencia

Este proyecto se distribuye bajo la [Licencia MIT](LICENSE). Sus titulares son:

- Diego Andrés García Álvarez — Ingeniero de Sistemas.
- Angel Danilo Marin Giraldo — Ingeniero de Sistemas.
- Brayan Alexander Salazar Reyes — Ingeniero de Sistemas.

La licencia permite usar, copiar, modificar y distribuir el software, incluso
con fines comerciales, siempre que se conserve el aviso de derechos de autor y
el texto de la licencia. El software se entrega sin garantía.
