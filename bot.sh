#!/usr/bin/env bash
set -euo pipefail

: "${DC_ADDR:?Falta DC_ADDR}"
: "${DC_MAIL_PW:?Falta DC_MAIL_PW}"
: "${DC_DB_PATH:?Falta DC_DB_PATH}"

# argumentos del daemon
DAEMON_ARGS=(daemon --db "$DC_DB_PATH" --addr "$DC_ADDR" --mail-pw "$DC_MAIL_PW")

[[ -n "${DC_IMAP_SERVER:-}" ]] && DAEMON_ARGS+=(--imap-server "$DC_IMAP_SERVER")
[[ -n "${DC_IMAP_PORT:-}" ]]   && DAEMON_ARGS+=(--imap-port "$DC_IMAP_PORT")
[[ -n "${DC_IMAP_SECURE:-}" ]] && DAEMON_ARGS+=(--imap-secure "$DC_IMAP_SECURE")
[[ -n "${DC_SMTP_SERVER:-}" ]] && DAEMON_ARGS+=(--smtp-server "$DC_SMTP_SERVER")
[[ -n "${DC_SMTP_PORT:-}" ]]   && DAEMON_ARGS+=(--smtp-port "$DC_SMTP_PORT")
[[ -n "${DC_SMTP_SECURE:-}" ]] && DAEMON_ARGS+=(--smtp-secure "$DC_SMTP_SECURE")

# Arranca el daemon de DeltaChat
deltachat-cli "${DAEMON_ARGS[@]}" &
DAEMON_PID=$!

sleep 4

# Bucle para procesar eventos
deltachat-cli events | while read -r line; do
  if echo "$line" | grep -q '"type":"message"'; then
    from_me=$(echo "$line" | jq -r '.from_me // false')
    chat_id=$(echo "$line" | jq -r '.chat_id // empty')
    [[ "$from_me" == "true" || -z "$chat_id" ]] && continue
    deltachat-cli send-text "$chat_id" "Hola" || echo "Error enviando a $chat_id" >&2
  fi
done

wait "$DAEMON_PID"