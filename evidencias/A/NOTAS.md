# Notas Técnicas – Persona A (Base del pipeline, SAST y SCA)

## 1. Arquitectura base del pipeline y Build (`devsecops.yml` y `_build.yml`)
- **Plataforma CI/CD:** GitHub Actions sobre repositorio público (`ssii-st30/PAI4-ST30-juice-shop`), aprovechando runners gratuitos sin consumo de minutos, gestión segura de secretos (`NVD_API_KEY`) y workflows reutilizables (`workflow_call`) para aislar el trabajo de cada miembro.
- **Gestión de `package-lock.json`:** OWASP Juice Shop incluye `.npmrc` con `package-lock=false`, por lo que carece de fichero de bloqueo en el repositorio. En `_build.yml` (Node.js 22 LTS) se genera `package-lock.json` mediante `npm install --package-lock-only --ignore-scripts --legacy-peer-deps` y se publica como artifact temporal (`juice-shop-lockfile`) para que la etapa SCA analice el árbol exacto de dependencias transitivas.

## 2. Herramienta SAST: Semgrep Community Edition (`_sast-sca.yml`)
- **Justificación frente a alternativas:**
  - *Frente a CodeQL:* Ejecuta en menos de 1 minuto sin requerir construir previamente toda la base de datos semántica de TypeScript/Angular, y dispone de reglas declarativas en YAML.
  - *Frente a SonarQube:* No requiere desplegar ni mantener un servidor externo con base de datos adicional (evitando duplicar infraestructura junto a DefectDojo).
- **Configuración, modo aviso y resultados:** CLI fijada en `semgrep==1.185.0` con reglas `p/javascript`, `p/typescript` y `p/owasp-top-ten` y `continue-on-error: true` a nivel de paso. Exporta `semgrep.json` (artifact `report-semgrep`).
  - Total hallazgos detectados: **53** (ERROR: **13**, WARNING: **38**).
  - Ejemplos representativos:
- **yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag** en `.github/workflows/_build.yml` (línea 13) — Severidad: WARNING
- **yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag** en `.github/workflows/_build.yml` (línea 16) — Severidad: WARNING
  - *Nota de triaje:* Entre los hallazgos `ERROR` figura `secrets-inherit` en `.github/workflows/devsecops.yml` (6 ocurrencias), hallazgo real que se evaluará en la fase de triaje en DefectDojo.
- **Gestión de falsos positivos:** Fichero `.semgrepignore` en la raíz (sincronizado con `security/semgrep/.semgrepignore` y cargado explícitamente mediante `--exclude`) y soporte para anotaciones `nosemgrep`.

## 3. Herramienta SCA: OWASP Dependency-Check (`_sast-sca.yml`)
- **Justificación frente a alternativas:**
  - *Frente a Dependabot:* Integración nativa en el pipeline CI/CD con exportación directa de informes XML estándar hacia DefectDojo y control explícito del umbral CVSS.
  - *Frente a Snyk:* Evita depender de cuentas comerciales externas o límites de escaneos, apoyándose directamente en la base pública NVD mediante `NVD_API_KEY`.
- **Configuración, modo aviso y resultados:** Imagen oficial fijada en `owasp/dependency-check:13.0.0` sobre `package.json` y `package-lock.json` con `--failOnCVSS 7` (umbral High/Critical) y caché persistente (`actions/cache@v4`) de la base NVD. Al superar el umbral devuelve `exit code 15`, capturado en modo aviso (`continue-on-error: true` en el paso). Exporta `dependency-check-report.xml` (artifact `report-dependency-check`).
  - Total vulnerabilidades detectadas: **35** (**5** Critical, **10** High — Total Critical/High CVSS >= 7: **15**).
  - Ejemplos representativos:
- **GHSA-q69g-4hcv-6jg4** — Severidad: HIGH (CVSS: )
- **GHSA-v75r-vx73-82pj** — Severidad: HIGH (CVSS: )
- **Gestión de falsos positivos:** Fichero XML `security/dependency-check/suppressions.xml` pasado mediante `--suppression`.

## 4. Problemas encontrados y soluciones aplicadas
1. **Ausencia de `package-lock.json`:** Resuelto generándolo en `_build.yml` y compartiéndolo entre jobs como artifact.
2. **Disparo automático de `postinstall` de Angular:** Al generar el lockfile sin `--ignore-scripts`, `npm` intentaba compilar el frontend fallando por falta de `ng` global. Se resolvió añadiendo `--ignore-scripts` y verificando el servidor con `npm run build:server`.
3. **Permisos de escritura en el contenedor de Dependency-Check:** Resuelto asignando `chmod -R 777` sobre las carpetas montadas para datos NVD y salida de informes.
4. **Sensibilidad a mayúsculas/minúsculas y atributos XML en el resumen SCA y doble ejecución de Semgrep:** Corregido usando `grep -Eic "<severity[^>]*>..."` (Dependency-Check v13 exporta `<severity unscored="true">` en minúsculas, contabilizando 5 Critical y 10 High), fijando versiones de ambas herramientas (`1.185.0` y `13.0.0`) y eliminando la acción duplicada de Semgrep.

## 5. Integración con DefectDojo (Persona C)
- Conectada la acción compuesta `.github/actions/defectdojo-import` al final de los jobs `sast` (`scan-type: 'Semgrep JSON Report'`) y `sca` (`scan-type: 'Dependency Check Scan'`) mediante `if: always()`, enviando automáticamente ambos informes a DefectDojo usando los secretos `DEFECTDOJO_URL` y `DEFECTDOJO_API_KEY`.
