# Notas técnicas – Persona B (IaC, imagen, quality gate final, despliegue y diagramas)

## 1. Seguridad en IaC: KICS (`_iac-container.yml`, job `iac`)
- **Qué analiza:** `Dockerfile`, `terraform/`, `infrastructure/` (Terraform y `docker-compose.yml`) y los manifiestos de `k8s/`.
- **Por qué KICS:** un solo escáner cubre Dockerfile, Terraform, docker-compose y Kubernetes, y asigna severidad a cada hallazgo (necesaria para el umbral). Checkov sin cuenta de pago no asigna severidad; Trivy en modo `config` cubre menos formatos de una vez.
- **Configuración:** imagen `checkmarx/kics` fijada por digest (`sha256:49ccc54b…`, v2.2.1). Umbral `--fail-on critical,high` (KICS sale con código 50 si el hallazgo más grave es High). **Modo aviso** con `continue-on-error` en el paso. Resumen por severidad en el job, aviso `::warning::` e informe `results.json` como artifact `report-kics`.
- **Resultados:**
  - Sin `k8s/`: 0 Critical, 10 High, 35 Medium, 12 Low. Los 10 High son 5 hallazgos duplicados porque `terraform/` e `infrastructure/terraform/` son idénticos.
  - Más grave: **clave privada RSA escrita en `networking.tf`** (línea 171, recurso `aws_iam_server_certificate`). Verdadero positivo; Juice Shop la incluye a propósito (`iacLeakedKeyChallenge`).
  - Resto de High: grupo de seguridad del balanceador abierto a `0.0.0.0/0` en los puertos 80 y 443. Esperable en un balanceador web público (443 = riesgo aceptado); el 80 debería redirigir a HTTPS.
  - Con `k8s/` v1: 0 Critical, 11 High, 40 Medium, 21 Low (15 hallazgos nuevos en `deployment.yaml`, sección 4).

## 2. Imagen de contenedor: build, GHCR y Trivy (`_iac-container.yml`, job `image-scan`)
- **Qué hace:** construye la imagen con el Dockerfile de Juice Shop, la publica en GHCR como `ghcr.io/ssii-st30/juice-shop:<sha del commit>` usando `GITHUB_TOKEN` (sin secretos propios) y la analiza con Trivy. El DAST (C) y el despliegue usan esa misma imagen.
- **Por qué Trivy:** cubre la capa de contenedores del escenario: paquetes del sistema base, dependencias empaquetadas y secretos dentro de la imagen. KICS revisa la receta; Trivy, el artefacto que realmente se despliega.
- **Configuración:** imagen `aquasec/trivy:0.69.3`, sin usar `trivy-action` (sección 6). Informe JSON completo con todas las severidades (`trivy-image.json`, artifact `report-trivy`); el umbral Critical/High se aplica en un paso aparte en **modo aviso**.
- **Resultados (16/11):** 7 Critical, 25 High, 70 Medium, 15 Low.
  - El sistema base (Debian 13.7) no tiene ningún Critical ni High.
  - Las 7 críticas están en dependencias de Node.js: `jsonwebtoken` 0.1.0/0.4.0 (CVE-2015-9235, se puede saltar la verificación del JWT), `crypto-js` 3.3.0 (2), `lodash` 2.4.2 (CVE-2019-10744, prototype pollution), `marsdb` 0.6.11 (inyección de comandos, **sin versión corregida**) y `tar` 6.2.1.
  - Varias son intencionadas: `express-jwt` 0.1.3, `jsonwebtoken` 0.4.0 y `sanitize-html` 1.4.2 están excluidas de las actualizaciones en `.dependabot/config.yml` de Juice Shop.
  - 3 de los High son **claves privadas dentro de la imagen**. La de `infrastructure/terraform/networking.tf` la detectan **KICS y Trivy**: llega a la imagen porque `.dockerignore` excluye `terraform/` pero no `infrastructure/`.

## 3. Quality gate final bloqueante (`security/gate/gate.py` y `_security-gate.yml`)
- **Qué hace:** descarga los 5 artifacts `report-*`, traduce la severidad de cada herramienta a una escala común y falla si hay **al menos un Critical o High** o si **falta algún informe obligatorio** (*fail-closed*). Es el **único paso bloqueante** del pipeline: sin `continue-on-error`. Si falla, `deploy` no se ejecuta.
- **Traducción de severidades:** Semgrep `ERROR` → High; Dependency-Check `critical`/`high` (en minúsculas) → Critical/High; KICS y Trivy `CRITICAL`/`HIGH`; ZAP `riskcode 3` → High (ZAP no tiene Critical).
- **Salida:** tabla por herramienta en el resumen del job, anotación `::error::` con el recuento y `gate-result.json` como artifact.
- **Por qué un único gate al final:** la aplicación es vulnerable a propósito; un gate bloqueante en el build impediría llegar al DAST (lo advierte el enunciado).
- **Resultados:** ejecución #36 (17/11): 12 Critical y 60 High (Semgrep 0/16, Dependency-Check 5/9, KICS 0/11, Trivy 7/24) y falta el informe de ZAP → el gate falla y `deploy` queda omitido. Evidencias B07–B09. Las cifras varían ligeramente entre ejecuciones porque las bases de datos de vulnerabilidades se actualizan cada día.

## 4. Kubernetes (`k8s/`)
- **v1:** `Namespace`, `Deployment` (2 réplicas, límites de CPU y memoria, *readiness* y *liveness probes*) y `Service` ClusterIP. Se escribió como un manifiesto habitual, sin endurecer y sin introducir fallos a propósito. Por un error al crearlo, la imagen quedó como `juice-shop:latest` en lugar del marcador `IMAGE_TAG` (ver sección 8).
- **Hallazgos de KICS en la v1 (15):** 1 High (*Privilege Escalation Allowed*), 5 Medium (ejecución como root y UID bajo, *capabilities* NET_RAW sin eliminar, sin perfil seccomp, token de service account montado) y 9 Low (sin PodDisruptionBudget, LimitRange ni ResourceQuota, sin AppArmor, sin `securityContext`, sistema de ficheros raíz no de solo lectura, imagen sin digest / etiqueta no válida).
- **v2 endurecida (preparada para la sesión DefectDojo):** `allowPrivilegeEscalation: false`, `runAsNonRoot`/`runAsUser: 65532`, `capabilities: drop ALL`, `seccompProfile: RuntimeDefault`, `automountServiceAccountToken: false`, PodDisruptionBudget, LimitRange y ResourceQuota.
  - **Riesgo aceptado:** perfil AppArmor no configurado (severidad baja). El nodo del clúster *kind* no tiene AppArmor activado y Kubernetes rechaza los pods que lo exigen; en un clúster de producción con AppArmor se añadiría `appArmorProfile: RuntimeDefault`.
  - **Riesgo aceptado:** `readOnlyRootFilesystem: false`, porque Juice Shop escribe en tiempo de ejecución su base de datos SQLite, los logs y los ficheros subidos.
  - **Falso positivo en contexto:** *Image Without Digest* / *Invalid Image Tag*, porque KICS ve el marcador `IMAGE_TAG`, que el despliegue sustituye por la imagen real.
  - Se añade una `startupProbe` (hasta 3 minutos) para que la *liveness probe* no reinicie Juice Shop mientras arranca con 0,5 CPU.

## 5. Despliegue y aviso al equipo (`_deploy.yml` y `_security-gate.yml`)
- **Despliegue (solo si el gate pasa):** sustituye `IMAGE_TAG` por la imagen del commit, la descarga de GHCR, crea un clúster Kubernetes efímero con *kind* dentro del runner, aplica los manifiestos, espera a que las réplicas estén listas y hace una prueba de humo contra la aplicación. No hay producción real: el clúster desaparece al terminar el job. Admite un ensayo manual (*workflow_dispatch*).
- **Aviso si el gate falla:** abre un issue en GitHub (uno por rama; si ya existe, añade un comentario) con mención al autor del commit, enlace a la ejecución, resultado del gate y siguiente paso (triaje en DefectDojo). Se suma al correo que GitHub envía al autor y al resumen del job. Evidencias B10–B11.

## 6. Seguridad de la cadena de suministro de las propias herramientas
- En marzo de 2026 se comprometió Trivy: binario v0.69.4 e imágenes 0.69.5 y 0.69.6 maliciosas, y 76 de las 77 etiquetas de `trivy-action` reescritas para robar secretos del pipeline. Aqua Security publicó como seguras las versiones v0.69.2 y v0.69.3.
- En abril de 2026 se comprometieron `kics-github-action` y varias etiquetas de la imagen `checkmarx/kics`, entre ellas `latest`.
- **Medidas:** Trivy por imagen Docker fijada a 0.69.3 y no por la acción; KICS fijado por digest; un paso que registra en el log el digest exacto de cada herramienta en cada ejecución (evidencia B05). El equipo extendió la misma política a Semgrep (1.185.0), Dependency-Check (13.0.0) y la acción de ZAP (por SHA).

## 7. Diagramas del objetivo 1 (`docs/diagramas/`)
- **1.a:** etapas en orden, herramienta, informe, umbral y modo de cada etapa, envío a DefectDojo y gate bloqueante con aviso al equipo.
- **1.b:** decisiones (¿supera el umbral?, ¿etapa bloqueante?, ¿falso positivo?, ¿se corrige ahora?), qué hace el pipeline en cada caso, a quién se avisa y cómo se registra y cierra el hallazgo en DefectDojo.
- **Cambios respecto a la v1 (16/11) y motivo:**
  - El DAST ataca la imagen propia de GHCR en lugar de una imagen genérica, para probar el mismo artefacto que se analiza y se despliega.
  - El gate también falla si falta un informe (*fail-closed*).
  - El despliegue se concreta en un clúster *kind* efímero.
  - El aviso al equipo se implementa con un issue en GitHub (en la v1 figuraba como opcional).
  - DefectDojo cierra como *Mitigated* lo que deja de aparecer (`close_old_findings`) y, si no responde, solo avisa.

## 8. Problemas encontrados y soluciones
1. **Pull request abierto contra el repositorio original de Juice Shop** (cerrado como spam por sus responsables): en un fork, GitHub propone por defecto el repositorio original. Se repitió contra el nuestro y se fijó la norma de comprobar siempre el *base repository*.
2. **`git` dejó de funcionar:** se usaba el Git incluido en GitHub Desktop, que se actualizó y borró su carpeta anterior del PATH. Se añadió la nueva ruta al PATH.
3. **Commit hecho en `master` en lugar de en la rama:** se movió a su rama (`git branch -f` y `git reset --hard origin/master`). La protección de `master` impedía subirlo directamente.
4. **Sangría incorrecta del job `dast` en `devsecops.yml`:** el job se fusionaba con `iac-container` y GitHub rechazaba el workflow. Se corrigió en el pull request #13.
5. **Bloque JSON mal cerrado en el issue de aviso:** `gate-result.json` no terminaba con salto de línea. Se corrigió en `gate.py`.
6. **El primer ensayo del despliegue falló (`ImagePullBackOff`):** la v1 de `deployment.yaml` tenía `juice-shop:latest`, una etiqueta que el pipeline no publica, así que no se sustituyó por la imagen del commit y Kubernetes no pudo descargarla. El paso de diagnóstico mostró la causa. Se corrige con la v2, que usa `IMAGE_TAG`. Además, el despliegue no puso en marcha ninguna imagen distinta de la verificada.
7. **El segundo ensayo del despliegue falló (pods rechazados por AppArmor):** la v2 exigía un perfil AppArmor, pero el nodo de *kind* no tiene AppArmor activado, así que Kubernetes rechazó cada pod (*"Cannot enforce AppArmor: AppArmor is not enabled on the host"*) y el Deployment creó pods nuevos continuamente. Se eliminó el perfil y se documentó como riesgo aceptado. Lección: un control de seguridad hay que validarlo en el entorno real donde se va a aplicar.
8. **DefectDojo apagado durante una ejecución:** la acción avisó (*"DefectDojo no responde"*) y el pipeline continuó, como estaba diseñado (evidencia B12).

## 9. Evidencias del bloque B (`evidencias/B/`)
| Fichero | Qué muestra |
|---|---|
| B01, B02 | KICS en modo aviso (exit code 50) y su resumen |
| B03, B04 | Trivy: resumen y anotaciones de KICS y Trivy en modo aviso |
| B05 | Digest exacto de KICS registrado en el log |
| B06 | KICS con los manifiestos de Kubernetes v1 |
| B07, B08, B09 | Ejecución detenida por el quality gate: grafo, tabla y anotaciones |
| B10, B11 | Issue de aviso creado por el pipeline |
| B12 | Pipeline completo (con DAST) y aviso de DefectDojo no disponible |
| `report-kics.zip`, `report-kics-k8s.zip`, `report-trivy.zip`, `gate-result.zip` | Informes generados por las herramientas |
