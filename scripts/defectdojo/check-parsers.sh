#!/usr/bin/env bash
# Uso: DD_URL=... DD_API_KEY=... ./check-parsers.sh
curl -s -H "Authorization: Token $DD_API_KEY" -H "ngrok-skip-browser-warning: 1" \
  "${DD_URL%/}/api/v2/test_types/?limit=1000" | jq -r '.results[].name' \
  | grep -Ei 'semgrep|dependency check|kics|trivy|^zap'
