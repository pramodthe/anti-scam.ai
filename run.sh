#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

VENV_PATH="${VENV_PATH:-$ROOT_DIR/.venv-webapp313}"
BACKEND_HOST="${BACKEND_HOST:-127.0.0.1}"
BACKEND_PORT="${BACKEND_PORT:-8000}"
FRONTEND_HOST="${FRONTEND_HOST:-127.0.0.1}"
FRONTEND_PORT="${FRONTEND_PORT:-8501}"
LANGGRAPH_HOST="${LANGGRAPH_HOST:-127.0.0.1}"
LANGGRAPH_PORT="${LANGGRAPH_PORT:-2024}"
VOICE_BACKEND_HOST="${VOICE_BACKEND_HOST:-127.0.0.1}"
VOICE_BACKEND_PORT="${VOICE_BACKEND_PORT:-8100}"
VOICE_FRONTEND_HOST="${VOICE_FRONTEND_HOST:-127.0.0.1}"
VOICE_FRONTEND_PORT="${VOICE_FRONTEND_PORT:-8502}"
RUN_STUDIO=1
STUDIO_TUNNEL=0

usage() {
  cat <<'EOF'
Usage: ./run.sh [options]

Options:
  --no-studio      Start only backend + frontend (skip langgraph dev)
  --tunnel         Start langgraph dev with --tunnel
  -h, --help       Show this help

Env overrides:
  VENV_PATH, BACKEND_HOST, BACKEND_PORT, FRONTEND_HOST, FRONTEND_PORT,
  LANGGRAPH_HOST, LANGGRAPH_PORT, VOICE_BACKEND_HOST, VOICE_BACKEND_PORT,
  VOICE_FRONTEND_HOST, VOICE_FRONTEND_PORT
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-studio)
      RUN_STUDIO=0
      shift
      ;;
    --tunnel)
      STUDIO_TUNNEL=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ ! -d "$VENV_PATH" ]]; then
  echo "Virtualenv not found: $VENV_PATH" >&2
  exit 1
fi

source "$VENV_PATH/bin/activate"

for cmd in uvicorn streamlit langgraph; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Missing command in venv: $cmd" >&2
    exit 1
  fi
done

check_port_free() {
  local port="$1"
  if lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "Port $port is already in use. Stop the existing process first." >&2
    return 1
  fi
}

wait_for_http() {
  local url="$1"
  local retries="${2:-25}"
  local delay="${3:-0.4}"
  local i
  for ((i = 0; i < retries; i++)); do
    if curl -s -o /dev/null "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep "$delay"
  done
  return 1
}

wait_for_any() {
  # Bash 4+ supports wait -n, but macOS default Bash 3.2 does not.
  if (( BASH_VERSINFO[0] >= 4 )); then
    wait -n "$@"
    return $?
  fi

  local pids=("$@")
  local pid
  while true; do
    for pid in "${pids[@]}"; do
      if ! kill -0 "$pid" >/dev/null 2>&1; then
        wait "$pid" >/dev/null 2>&1 || true
        return 0
      fi
    done
    sleep 1
  done
}

check_port_free "$BACKEND_PORT"
check_port_free "$FRONTEND_PORT"
check_port_free "$VOICE_BACKEND_PORT"
check_port_free "$VOICE_FRONTEND_PORT"
if [[ "$RUN_STUDIO" -eq 1 ]]; then
  check_port_free "$LANGGRAPH_PORT"
fi

mkdir -p .run-logs
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKEND_LOG=".run-logs/backend-$STAMP.log"
FRONTEND_LOG=".run-logs/frontend-$STAMP.log"
VOICE_BACKEND_LOG=".run-logs/voice-backend-$STAMP.log"
VOICE_FRONTEND_LOG=".run-logs/voice-frontend-$STAMP.log"
STUDIO_LOG=".run-logs/studio-$STAMP.log"

PIDS=()

cleanup() {
  local pid
  for pid in "${PIDS[@]:-}"; do
    if kill -0 "$pid" >/dev/null 2>&1; then
      kill "$pid" >/dev/null 2>&1 || true
    fi
  done
  wait >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

echo "Starting backend on http://$BACKEND_HOST:$BACKEND_PORT ..."
uvicorn backend.api:app --host "$BACKEND_HOST" --port "$BACKEND_PORT" --reload >"$BACKEND_LOG" 2>&1 &
BACKEND_PID=$!
PIDS+=("$BACKEND_PID")

if ! wait_for_http "http://$BACKEND_HOST:$BACKEND_PORT/health"; then
  echo "Backend failed to start. See $BACKEND_LOG" >&2
  exit 1
fi

echo "Starting frontend on http://$FRONTEND_HOST:$FRONTEND_PORT ..."
EMAIL_ASSISTANT_API="http://$BACKEND_HOST:$BACKEND_PORT" \
  streamlit run frontend/streamlit_app.py \
    --server.address "$FRONTEND_HOST" \
    --server.port "$FRONTEND_PORT" >"$FRONTEND_LOG" 2>&1 &
FRONTEND_PID=$!
PIDS+=("$FRONTEND_PID")

if ! wait_for_http "http://$FRONTEND_HOST:$FRONTEND_PORT"; then
  echo "Frontend failed to start. See $FRONTEND_LOG" >&2
  exit 1
fi

echo "Starting voice backend on http://$VOICE_BACKEND_HOST:$VOICE_BACKEND_PORT ..."
uvicorn backend.voice_api:app --host "$VOICE_BACKEND_HOST" --port "$VOICE_BACKEND_PORT" --reload >"$VOICE_BACKEND_LOG" 2>&1 &
VOICE_BACKEND_PID=$!
PIDS+=("$VOICE_BACKEND_PID")

if ! wait_for_http "http://$VOICE_BACKEND_HOST:$VOICE_BACKEND_PORT/health"; then
  echo "Voice backend failed to start. See $VOICE_BACKEND_LOG" >&2
  exit 1
fi

echo "Starting voice frontend on http://$VOICE_FRONTEND_HOST:$VOICE_FRONTEND_PORT ..."
VOICE_API_URL="http://$VOICE_BACKEND_HOST:$VOICE_BACKEND_PORT" \
  streamlit run frontend/voice_app.py \
    --server.address "$VOICE_FRONTEND_HOST" \
    --server.port "$VOICE_FRONTEND_PORT" >"$VOICE_FRONTEND_LOG" 2>&1 &
VOICE_FRONTEND_PID=$!
PIDS+=("$VOICE_FRONTEND_PID")

if ! wait_for_http "http://$VOICE_FRONTEND_HOST:$VOICE_FRONTEND_PORT"; then
  echo "Voice frontend failed to start. See $VOICE_FRONTEND_LOG" >&2
  exit 1
fi

if [[ "$RUN_STUDIO" -eq 1 ]]; then
  echo "Starting LangGraph Studio server on http://$LANGGRAPH_HOST:$LANGGRAPH_PORT ..."
  STUDIO_CMD=(langgraph dev --config langgraph.json --host "$LANGGRAPH_HOST" --port "$LANGGRAPH_PORT" --no-browser)
  if [[ "$STUDIO_TUNNEL" -eq 1 ]]; then
    STUDIO_CMD+=(--tunnel)
  fi
  "${STUDIO_CMD[@]}" >"$STUDIO_LOG" 2>&1 &
  STUDIO_PID=$!
  PIDS+=("$STUDIO_PID")

  if ! wait_for_http "http://$LANGGRAPH_HOST:$LANGGRAPH_PORT/openapi.json"; then
    echo "LangGraph server failed to start. See $STUDIO_LOG" >&2
    exit 1
  fi
fi

echo
echo "Services started:"
echo "  Email Backend:    http://$BACKEND_HOST:$BACKEND_PORT"
echo "  Email Frontend:   http://$FRONTEND_HOST:$FRONTEND_PORT"
echo "  Voice Backend:    http://$VOICE_BACKEND_HOST:$VOICE_BACKEND_PORT"
echo "  Voice Frontend:   http://$VOICE_FRONTEND_HOST:$VOICE_FRONTEND_PORT"
if [[ "$RUN_STUDIO" -eq 1 ]]; then
  echo "  Studio API: http://$LANGGRAPH_HOST:$LANGGRAPH_PORT"
  echo "  Studio UI:  https://smith.langchain.com/studio/?baseUrl=http://$LANGGRAPH_HOST:$LANGGRAPH_PORT"
fi
echo
echo "Logs:"
echo "  $BACKEND_LOG"
echo "  $FRONTEND_LOG"
echo "  $VOICE_BACKEND_LOG"
echo "  $VOICE_FRONTEND_LOG"
if [[ "$RUN_STUDIO" -eq 1 ]]; then
  echo "  $STUDIO_LOG"
fi
echo
echo "Press Ctrl+C to stop all services."

if [[ "$RUN_STUDIO" -eq 1 ]]; then
  wait_for_any "$BACKEND_PID" "$FRONTEND_PID" "$VOICE_BACKEND_PID" "$VOICE_FRONTEND_PID" "$STUDIO_PID"
else
  wait_for_any "$BACKEND_PID" "$FRONTEND_PID" "$VOICE_BACKEND_PID" "$VOICE_FRONTEND_PID"
fi

echo "A service exited. Shutting down the rest..."
