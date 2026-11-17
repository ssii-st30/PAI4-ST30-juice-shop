# defectdojo-import (persona C)

Acción compuesta que sube un informe a DefectDojo con la API v2 (`reimport-scan`, `auto_create_context`).
Crea un engagement de tipo CI/CD por rama y envía rama, SHA del commit y número de ejecución.
Si DefectDojo no responde, emite un warning y NO rompe el pipeline.

## Uso (añadir al final del job, después de checkout y de generar el informe)
```yaml
- name: Enviar a DefectDojo
  if: always()
  uses: ./.github/actions/defectdojo-import
  with:
    file: semgrep.json
    scan-type: Semgrep JSON Report
    tool: Semgrep
    url: ${{ secrets.DEFECTDOJO_URL }}
    api-key: ${{ secrets.DEFECTDOJO_API_KEY }}
```
Tipos de escaneo verificados (DefectDojo 3.x): Semgrep JSON Report, Dependency Check Scan,
KICS Scan, Trivy Scan, ZAP Scan.
