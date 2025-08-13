#!/usr/bin/env bash
set -euo pipefail

export DC_DB_PATH="${DC_DB_PATH:-/data/bot.db}"

# Inicia el bot en background
/app/bot.sh &
BOT_PID=$!

# Levanta un servidor HTTP mínimo para el health check de Render
while true; do
  printf 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK' \
    | nc -l -p "${PORT:-10000}" -q 1 || true
done &

# Espera a que el bot inicialice y muestra el enlace de cifrado
sleep 5
ENC_LINK=$(deltachat-cli identity --db "$DC_DB_PATH" --json | jq -r '.identityUri')
echo "🔐 Enlace de cifrado E2E: $ENC_LINK"

# Mantiene vivo el proceso principal
wait "$BOT_PID"