#!/usr/bin/env bash
# Sube un informe a DefectDojo (API v2). Si algo falla, AVISA pero NO rompe el pipeline.
set -uo pipefail
SUMMARY="${GITHUB_STEP_SUMMARY:-/dev/stdout}"
warn() { echo "::warning title=DefectDojo (${TOOL:-?})::$1"; echo "⚠️ DefectDojo (${TOOL:-?}): $1" >> "$SUMMARY"; exit 0; }

[ -n "${DD_URL:-}" ] && [ -n "${DD_API_KEY:-}" ] || warn "Faltan los secretos DEFECTDOJO_URL / DEFECTDOJO_API_KEY"
[ -s "$REPORT_FILE" ] || warn "No existe el informe $REPORT_FILE"

API="${DD_URL%/}/api/v2"
BRANCH="${GITHUB_HEAD_REF:-${GITHUB_REF_NAME:-local}}"
ENGAGEMENT="CI/CD ${BRANCH}"
H=(-H "Authorization: Token ${DD_API_KEY}" -H "ngrok-skip-browser-warning: 1")

# 1) ¿DefectDojo accesible? (Kali + ngrok encendidos)
curl -sf -m 20 "${H[@]}" "$API/user_profile/" >/dev/null || warn "DefectDojo no responde (¿Kali o ngrok apagados?)"

# 2) Asset (en la API v2 sigue llamándose "product")
PROD_ID=$(curl -sf -m 20 -G "${H[@]}" --data-urlencode "name=$PRODUCT" "$API/products/" | jq -r '.results[0].id // empty')
[ -n "$PROD_ID" ] || warn "No existe el Asset '$PRODUCT'"

# 3) Un engagement de tipo CI/CD por rama (se crea la primera vez)
ENG_ID=$(curl -sf -m 20 -G "${H[@]}" --data-urlencode "product=$PROD_ID" --data-urlencode "name=$ENGAGEMENT" \
         "$API/engagements/" | jq -r '.results[0].id // empty')
if [ -z "$ENG_ID" ]; then
  BODY=$(jq -n --arg n "$ENGAGEMENT" --argjson p "$PROD_ID" --arg b "$BRANCH" \
         --arg s "$(date +%F)" --arg e "$(date -d '+1 year' +%F)" \
         '{name:$n, product:$p, target_start:$s, target_end:$e, engagement_type:"CI/CD", status:"In Progress", branch_tag:$b}')
  curl -sf -m 20 "${H[@]}" -H "Content-Type: application/json" -d "$BODY" "$API/engagements/" >/dev/null \
    || warn "No se pudo crear el engagement '$ENGAGEMENT'"
fi

# 4) Reimport: si el test ya existe, actualiza los hallazgos en vez de duplicarlos.
#    close_old_findings=true: los que ya no aparecen en el informe pasan a Mitigated.
CODE=$(curl -s -o dd_resp.json -w '%{http_code}' -m 300 "${H[@]}" \
  -F "scan_type=$SCAN_TYPE" -F "file=@$REPORT_FILE" \
  -F "product_name=$PRODUCT" -F "engagement_name=$ENGAGEMENT" -F "test_title=$TOOL" \
  -F "auto_create_context=true" \
  -F "close_old_findings=true" \
  -F "branch_tag=$BRANCH" -F "commit_hash=${GITHUB_SHA:-local}" -F "build_id=${GITHUB_RUN_NUMBER:-0}" \
  -F "minimum_severity=Info" -F "active=true" -F "verified=false" \
  "$API/reimport-scan/")

if [[ "$CODE" =~ ^20[01]$ ]]; then
  echo "✅ $TOOL importado en DefectDojo (test $(jq -r '.test_id // .test // "?"' dd_resp.json), rama $BRANCH, commit ${GITHUB_SHA:0:7}, ejecución ${GITHUB_RUN_NUMBER:-0})" | tee -a "$SUMMARY"
else
  echo "Respuesta de la API: $(head -c 500 dd_resp.json)"
  warn "La API devolvió HTTP $CODE"
fi
rm -f dd_resp.json
