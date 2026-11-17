#!/usr/bin/env python3
"""Quality gate final del pipeline DevSecOps de ST-30 (responsable: persona B).

Lee los informes de las cinco herramientas, traduce la severidad de cada una a
una escala común (Critical, High, Medium, Low) y decide si el pipeline puede
continuar hasta el despliegue.

Política:
  * Falla si hay al menos un hallazgo Critical o High en cualquier informe.
  * Falla también si falta algún informe obligatorio (fail-closed): si no
    sabemos qué ha encontrado una herramienta, no podemos dar el visto bueno.

Uso:  python3 gate.py <carpeta_con_los_artifacts>
Variables de entorno:
  GATE_REQUIRED  herramientas obligatorias, separadas por comas
                 (por defecto: semgrep,dependency-check,kics,trivy,zap)
  GITHUB_STEP_SUMMARY  fichero de resumen del job (lo define GitHub Actions)

Solo usa la biblioteca estándar de Python.
"""
import json
import os
import sys
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

LEVELS = ["Critical", "High", "Medium", "Low"]

# Artifact (contrato, sección 3.2) -> fichero dentro del artifact
REPORTS = {
    "semgrep": ("report-semgrep", "semgrep.json"),
    "dependency-check": ("report-dependency-check", "dependency-check-report.xml"),
    "kics": ("report-kics", "results.json"),
    "trivy": ("report-trivy", "trivy-image.json"),
    "zap": ("report-zap", "zap-report.xml"),
}


def _norm(value, table):
    return table.get(str(value).strip().upper())


def parse_semgrep(path):
    # Semgrep: ERROR = alta; WARNING = media; INFO = baja.
    # Las versiones recientes también pueden emitir CRITICAL/HIGH/MEDIUM/LOW.
    table = {"CRITICAL": "Critical", "ERROR": "High", "HIGH": "High",
             "WARNING": "Medium", "MEDIUM": "Medium", "INFO": "Low", "LOW": "Low"}
    data = json.loads(path.read_text(encoding="utf-8"))
    return Counter(_norm(r["extra"]["severity"], table) for r in data.get("results", []))


def parse_dependency_check(path):
    # Dependency-Check: severidad en minúsculas (critical, high, medium/moderate, low).
    # Las vulnerabilidades suprimidas van en <suppressedVulnerabilities> y no cuentan.
    table = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium",
             "MODERATE": "Medium", "LOW": "Low"}
    root = ET.parse(path).getroot()
    ns = root.tag.split("}")[0] + "}" if root.tag.startswith("{") else ""
    c = Counter()
    for vuln in root.iter(f"{ns}vulnerability"):
        c[_norm(vuln.findtext(f"{ns}severity", default=""), table)] += 1
    return c


def parse_kics(path):
    # KICS ya trae el recuento por severidad.
    counters = json.loads(path.read_text(encoding="utf-8")).get("severity_counters", {})
    return Counter({"Critical": counters.get("CRITICAL", 0), "High": counters.get("HIGH", 0),
                    "Medium": counters.get("MEDIUM", 0), "Low": counters.get("LOW", 0)})


def parse_trivy(path):
    # Trivy: vulnerabilidades y secretos, con severidad CRITICAL/HIGH/MEDIUM/LOW.
    table = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low"}
    data = json.loads(path.read_text(encoding="utf-8"))
    c = Counter()
    for result in data.get("Results") or []:
        for item in (result.get("Vulnerabilities") or []) + (result.get("Secrets") or []):
            c[_norm(item.get("Severity", ""), table)] += 1
    return c


def parse_zap(path):
    # ZAP: riskcode 3 = High, 2 = Medium, 1 = Low, 0 = Informativo. ZAP no tiene "Critical".
    # Se cuenta cada tipo de alerta una vez (no cada URL afectada).
    table = {"3": "High", "2": "Medium", "1": "Low"}
    root = ET.parse(path).getroot()
    return Counter(table.get((item.findtext("riskcode") or "").strip())
                   for item in root.iter("alertitem"))


PARSERS = {"semgrep": parse_semgrep, "dependency-check": parse_dependency_check,
           "kics": parse_kics, "trivy": parse_trivy, "zap": parse_zap}


def find_report(base, artifact, filename):
    # download-artifact deja cada artifact en su carpeta: <base>/<artifact>/<fichero>
    for candidate in (base / artifact / filename, base / filename):
        if candidate.is_file():
            return candidate
    matches = list((base / artifact).rglob(filename)) if (base / artifact).is_dir() else []
    return matches[0] if matches else None


def main():
    base = Path(sys.argv[1] if len(sys.argv) > 1 else "reports")
    required = [t.strip() for t in os.environ.get(
        "GATE_REQUIRED", ",".join(REPORTS)).split(",") if t.strip()]

    rows, problems = [], []
    total = Counter()
    for tool, (artifact, filename) in REPORTS.items():
        path = find_report(base, artifact, filename)
        if path is None:
            status = "falta el informe"
            if tool in required:
                problems.append(f"Falta el informe obligatorio de {tool} ({artifact})")
                status = "FALTA (obligatorio)"
            rows.append((tool, None, status))
            continue
        try:
            counts = PARSERS[tool](path)
        except Exception as exc:  # informe corrupto = no se puede evaluar
            problems.append(f"No se pudo leer el informe de {tool}: {exc}")
            rows.append((tool, None, "ERROR de lectura"))
            continue
        counts.pop(None, None)
        total.update(counts)
        ch = counts["Critical"] + counts["High"]
        rows.append((tool, counts, "supera el umbral" if ch else "OK"))

    blocking = total["Critical"] + total["High"]
    passed = blocking == 0 and not problems

    lines = ["## Quality gate final (bloqueante)", "",
             "Umbral: el pipeline se detiene si hay **al menos un hallazgo Critical o High** "
             "o si falta algún informe obligatorio.", "",
             "| Herramienta | Critical | High | Medium | Low | Estado |",
             "|---|---|---|---|---|---|"]
    for tool, counts, status in rows:
        if counts is None:
            lines.append(f"| {tool} | – | – | – | – | {status} |")
        else:
            lines.append(f"| {tool} | " + " | ".join(str(counts[l]) for l in LEVELS) + f" | {status} |")
    lines.append("| **Total** | " + " | ".join(f"**{total[l]}**" for l in LEVELS) + " | |")
    lines.append("")
    if passed:
        lines.append("### ✅ RESULTADO: el gate PASA. Se permite el despliegue.")
    else:
        lines.append("### ❌ RESULTADO: el gate FALLA. El pipeline se detiene y no se despliega.")
        if blocking:
            lines.append(f"- {total['Critical']} Critical y {total['High']} High por encima del umbral.")
        for p in problems:
            lines.append(f"- {p}")
        lines.append("")
        lines.append("Siguiente paso: triaje en DefectDojo (corregir, marcar falso positivo "
                     "o aceptar el riesgo) y volver a ejecutar el pipeline.")
    summary = "\n".join(lines) + "\n"

    print(summary)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as fh:
            fh.write(summary)

    result = {"passed": passed, "total": {l: total[l] for l in LEVELS}, "problems": problems,
              "tools": {t: ({l: c[l] for l in LEVELS} if c is not None else None)
                        for t, c, _ in rows}}
    Path("gate-result.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    if not passed:
        print(f"::error title=Quality gate::El gate falla: {total['Critical']} Critical, "
              f"{total['High']} High" + (f"; {len(problems)} informe(s) sin evaluar" if problems else ""))
        sys.exit(1)


if __name__ == "__main__":
    main()
