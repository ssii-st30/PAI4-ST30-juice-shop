# Notas técnicas — Persona C (DAST + gestión de vulnerabilidades)

Security Team ST-30 · PAI-4 DevSecOps · Responsable: Pablo Camino Pavón

Ficheros propios: `.github/workflows/_dast.yml`, `.github/actions/defectdojo-import/`, `security/zap/`, `scripts/defectdojo/`, `evidencias/C/`.

> Los campos marcados con **[COMPLETAR]** hay que rellenarlos con el dato exacto antes de la entrega.

## 1. Despliegue de DefectDojo

- **Herramienta:** DefectDojo (open source), versión **[COMPLETAR: versión exacta, pie de página o `docker compose images`]** de la rama 3.x. En la 3.x, *Product* pasa a llamarse **Asset** y *Product Type* pasa a llamarse **Organization** en la interfaz, pero la API v2 conserva los nombres antiguos (`/api/v2/products/`, `product_name`), así que la acción no tuvo que cambiar.
- **Por qué DefectDojo:** está recomendado en el enunciado, es gratuito y tiene parser para nuestras cinco herramientas. Además, su API v2 permite el envío automático desde el pipeline (objetivo 5) e incluye deduplicación y triaje.
- **Dónde:** Kali Linux en VirtualBox, en el PC de C, con **Docker Compose** desde el repositorio oficial (`django-DefectDojo`). Servicios: nginx, uWSGI (Django), PostgreSQL, Valkey, Celery (worker y beat) e initializer. RAM de la VM: **12 GB**. Se subió tras el primer escaneo ZAP (ver problemas).
- **Por qué en la Kali:** era la opción gratuita y la más rápida de montar. Las alternativas se descartaron: una VM en la nube consume crédito y DefectDojo necesita varios GB de RAM; un runner autoalojado está desaconsejado por GitHub en repositorios públicos; un DefectDojo efímero dentro del job pierde los datos y no permite triaje.
- **Configuración:**
  - Organization `PAI-4` y Asset `Juice Shop ST-30`.
  - Deduplicación activada en *System Settings*.
  - Usuario dedicado **`ci-pipeline`**, sin superuser ni staff, con rol **Writer solo sobre el Asset** (mínimo privilegio).
  - El token de la API v2 de ese usuario se guarda como secreto `DEFECTDOJO_API_KEY` y la URL como `DEFECTDOJO_URL`, en *Settings → Secrets and variables → Actions*. Nunca están en el repositorio.
- **Parsers verificados** por la API (`/api/v2/test_types/`): `Semgrep JSON Report`, `Dependency Check Scan`, `KICS Scan`, `Trivy Scan` y `ZAP Scan`. Coinciden con la tabla 3.2, así que no hubo que cambiar el contrato. (`Trivy Operator Scan` es otro parser distinto, para Kubernetes.)
- Evidencias: `puesta_en_marcha/P01`–`P07`, `P10`.

## 2. Túnel ngrok

- **Problema:** los runners de GitHub Actions están en internet y DefectDojo está detrás de la NAT de VirtualBox y del router.
- **Solución:** el agente `ngrok` abre una **conexión saliente** desde la Kali y publica `localhost:8080` en un **dominio fijo gratuito** (`*.ngrok-free.dev`). Al ser saliente funciona a través de la NAT sin abrir puertos, y al ser fijo el secreto `DEFECTDOJO_URL` no cambia.
- **Si la Kali o el túnel están apagados:** la acción de importación detecta que DefectDojo no responde, emite un `::warning::` y **no rompe el pipeline** (P14). Los resultados de esa ejecución no llegan a DefectDojo. Es una limitación asumida: hay que avisar a C antes de lanzar ejecuciones que deban registrarse.
- **Seguridad:** la URL pública solo enseña el login (usuario y contraseña, o token). El dominio no se publica en el repositorio ni en las capturas, y el túnel se cierra cuando no se usa. La cabecera `ngrok-skip-browser-warning` evita la página intermedia de ngrok en las llamadas a la API.
- Evidencias: `P08`, `P09`.

## 3. Acción `defectdojo-import`

Acción compuesta (`.github/actions/defectdojo-import/action.yml` + `import.sh`). Entradas: `file`, `scan-type`, `tool`, `url` y `api-key`.

1. Comprueba que hay secretos y que existe el informe. Si falta algo, **avisa y sale con 0**.
2. Comprueba que DefectDojo responde (`/api/v2/user_profile/`).
3. Busca el Asset y crea, si no existe, **un engagement de tipo CI/CD por rama** (`CI/CD <rama>`).
4. Llama a **`/api/v2/reimport-scan/`** con `auto_create_context=true`, enviando la **rama** (`branch_tag`), el **SHA del commit** (`commit_hash`) y el **número de ejecución** (`build_id`). Así se puede rastrear cada importación.

- **Por qué reimport y no import:** reimport actualiza el mismo test en lugar de crear uno nuevo en cada ejecución. Los hallazgos que siguen apareciendo quedan *untouched*, los nuevos se crean y los que **ya no aparecen se cierran como *Mitigated*** (comportamiento `close_old_findings` del reimport). Gracias a esto, la remediación se refleja sola en DefectDojo (sección 6).
- **Prueba local** antes de integrarla: una importación con 9 hallazgos creados y un reimport con 9 *untouched* y 0 nuevos (P15–P18).
- La usan los cinco jobs del pipeline (Semgrep, Dependency-Check, KICS, Trivy y ZAP), con `if: always()` para enviar el informe aunque la herramienta marque fallo.

## 4. DAST con ZAP (`_dast.yml`)

- **Herramienta:** OWASP ZAP. Es gratuito, automatizable con Docker y con acciones oficiales de GitHub, y DefectDojo lo importa. Burp Community no permite automatizar escaneos, y Wapiti tiene menos soporte en DefectDojo.
- **Aplicación:** Juice Shop levantada como **contenedor de servicio** del job y atacada en `localhost:3000` (uso responsable: solo nuestra instancia, dentro del runner). Imagen: ** `bkimminich/juice-shop` o `ghcr.io/ssii-st30/juice-shop:<sha>` si ya se cambió a la nuestra de GHCR]**.
- **Escaneo:** `zaproxy/action-baseline` (pasivo) con **AJAX spider** (`-j`, 3 minutos). Juice Shop es una SPA en Angular y el spider clásico apenas descubre rutas.
- **Reglas como código:** `security/zap/rules.tsv` decide qué es aviso, fallo o se ignora (por ejemplo, 10096 *Timestamp Disclosure* = IGNORE, 40012/40018 XSS/SQLi = FAIL).
- **Modo aviso:** `continue-on-error: true` en el paso de ZAP. Un paso de resumen publica la tabla High/Medium/Low en el *job summary* y emite warnings. El job sube el artifact **`report-zap`** (`zap-report.xml`, contrato 3.2) que lee el gate final de B, y lo envía a DefectDojo.
- **Resultado:** en el pipeline, ZAP detectó **1 alerta High** (**[COMPLETAR: nombre de la alerta]**) más varias Medium/Low (CSP no definida, configuración cross-domain/CORS, cabeceras COEP/COOP…). El pipeline continuó, como corresponde al modo aviso (P21).
- En local, el baseline dio 0 High, 2 Medium, 4 Low y 3 Info (P11–P13).

## 5. Triaje en DefectDojo (engagement `CI/CD master`)

| Decisión | Hallazgo | Justificación |
|---|---|---|
| **Falso positivo** | *Timestamp Disclosure - Unix* (ZAP, id 21; sus duplicados 221/830/1128) | Son constantes numéricas en los bundles JS minificados, no fechas del servidor. Regla también en IGNORE en `rules.tsv`. |
| **Falso positivo** | *JWT token* (Trivy) en `frontend/src/app/app.guard.spec.ts` | Token de ejemplo de una prueba unitaria; los `*.spec.ts` no entran en el build de producción. |
| **Verdadero positivo** (no FP) | *Image Without Digest* (KICS, `k8s/`) | El manifiesto referencia la imagen por etiqueta, no por digest. Se valoró como falso positivo y se descartó. |
| **Verdadero positivo** | *Asymmetric Private Key* en `lib/insecurity.ts` (Trivy 439, 435) | Clave RSA real con la que Juice Shop firma los JWT; permite falsificar sesiones. Prioridad alta. Contrasta con el JWT del `.spec.ts`. |
| **Riesgo aceptado** (3 meses) | *GHSA-5mrr-rgp6-x4gr marsdb 0.6.11* (Dependency-Check, 405) | Sin versión corregida publicada; dependencia funcional de Juice Shop; solo en el entorno de pruebas. Revisión en 3 meses o sustitución. |
| **Riesgo aceptado** (6 meses) | Puerto **443** abierto a 0.0.0.0/0 en el security group del ALB (KICS 231, 233, 234, 235) | Es el balanceador público y debe ser accesible; solo expone HTTPS. El puerto 80 (230, 232, 236, 237) **no** se acepta. |

- **Deduplicación:** el mismo hallazgo detectado en ramas distintas aparece como *Duplicate* del original (por ejemplo, Timestamp 221 → 21, o Trivy *tar* en `alvhurcab-patch-1`) (C05). El reimport no duplica entre ejecuciones (P18).
- **Priorización:** se trabaja con la lista de findings Critical/High activos, sin falsos positivos ni riesgos aceptados, ordenada por severidad y con su SLA (C08).
- Una misma vulnerabilidad aparece varias veces cuando el código está repetido (`terraform/` e `infrastructure/terraform/`, o fuente y compilado de `insecurity`). Por eso las decisiones se aplican a todas sus copias.

## 6. Remediación (PR #25, `feature/remediacion`)

Tras fusionar el PR, el pipeline de `master` reimportó los cinco informes y DefectDojo pasó a **Mitigated** lo que ya no aparecía:

- **KICS sobre `k8s/deployment.yaml`:** escalada de privilegios (229; también Semgrep 130), contenedor como root y UID bajo (252, 253), capabilities (264, 292), seccomp (266), token de la service account (271), security context y sistema de ficheros de solo lectura (295, 296) (C09).
- **Trivy:** la clave privada de `infrastructure/terraform/networking.tf` (438) deja de estar en la imagen gracias al `.dockerignore` (C10).

## 7. Problemas encontrados y soluciones

| Problema | Causa | Solución |
|---|---|---|
| `gh` no se instalaba con apt | No está en los repositorios de Kali | Repositorio oficial de GitHub CLI; los secretos se crearon por la web |
| ngrok: *repository is not signed* | El fichero de la clave GPG no tenía permiso de lectura | `chmod 644` a la clave / binario oficial |
| `read: -p: no coprocess` | La shell de Kali es zsh | Ejecutar los comandos en `bash` |
| No aparecía "Product" en DefectDojo | La versión 3.x renombra a Asset/Organization | Usar los nombres nuevos; la API mantiene los antiguos |
| `ERR_NGROK_3200` | Túnel no lanzado | Ejecutar `ngrok http 8080 --url=…` y mantenerlo abierto |
| La VM se colgó durante ZAP | RAM agotada (DefectDojo + ZAP + navegador del AJAX spider) | Más RAM, parar DefectDojo durante el escaneo local y `--memory` en el contenedor; en el pipeline corre en el runner |
| curl a ngrok falla con *TLS unexpected eof* en la universidad | La red filtra por SNI los dominios de ngrok (curl.exe en Windows falla igual; el navegador entra por ECH) | Pruebas locales contra `localhost:8080`; no afecta al pipeline, porque el runner accede desde internet |
| Capturas con datos sensibles | El token, la contraseña inicial y el dominio salían en la terminal | Tapados antes de subirlos; token de `ci-pipeline` regenerado |

## 8. Cambios respecto al diseño inicial

- DefectDojo 3.x (Asset/Organization) en lugar de la terminología Product/Product Type del reparto.
- Se valoró marcar *Image Without Digest* como falso positivo y se descartó: es un verdadero positivo.
- Se añade un engagement por rama con tipo CI/CD creado por la acción, y las pruebas locales se hacen contra `localhost` por el filtrado de ngrok en la red de la universidad.
