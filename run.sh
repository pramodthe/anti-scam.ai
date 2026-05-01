#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

VENV_PATH="${VENV_PATH:-$ROOT_DIR/.venv-webapp313}"
BACKEND_HOST="${BACKEND_HOST:-127.0.0.1}"
BACKEND_PORT="${BACKEND_PORT:-8000}"
FRONTEND_HOST="${FRONTEND_HOST:-127.0.0.1}"
FRONTEND_PORT="${FRONTEND_PORT:-3000}"
LANGGRAPH_HOST="${LANGGRAPH_HOST:-127.0.0.1}"
LANGGRAPH_PORT="${LANGGRAPH_PORT:-2024}"
RUN_STUDIO=1
STUDIO_TUNNEL=0

usage() {
  cat <<'EOF'
Usage: ./run.sh [options]

Options:
  --no-studio      Start backend + Next.js frontend only
  --tunnel         Start langgraph dev with --tunnel
  -h, --help       Show this help

Env overrides:
  VENV_PATH, BACKEND_HOST, BACKEND_PORT, FRONTEND_HOST, FRONTEND_PORT,
  LANGGRAPH_HOST, LANGGRAPH_PORT
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

if [[ ! -d "$ROOT_DIR/frontend-next" ]]; then
  echo "Missing frontend-next directory." >&2
  exit 1
fi

source "$VENV_PATH/bin/activate"

for cmd in uvicorn npm; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Missing command: $cmd" >&2
    exit 1
  fi
done

if [[ "$RUN_STUDIO" -eq 1 ]] && ! command -v langgraph >/dev/null 2>&1; then
  echo "Missing command in venv: langgraph" >&2
  exit 1
fi

check_port_free() {
  local port="$1"
  if lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "Port $port is already in use. Stop the existing process first." >&2
    return 1
  fi
}

wait_for_http() {
  local url="$1"
  local retries="${2:-40}"
  local delay="${3:-0.5}"
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
if [[ "$RUN_STUDIO" -eq 1 ]]; then
  check_port_free "$LANGGRAPH_PORT"
fi

mkdir -p .run-logs
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKEND_LOG=".run-logs/backend-$STAMP.log"
FRONTEND_LOG=".run-logs/frontend-next-$STAMP.log"
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

echo "Starting Next.js frontend on http://$FRONTEND_HOST:$FRONTEND_PORT ..."
(
  cd "$ROOT_DIR/frontend-next"
  NEXT_PUBLIC_EMAIL_API_BASE="http://$BACKEND_HOST:$BACKEND_PORT" \
    npm run dev -- --hostname "$FRONTEND_HOST" --port "$FRONTEND_PORT" >"$ROOT_DIR/$FRONTEND_LOG" 2>&1
) &
FRONTEND_PID=$!
PIDS+=("$FRONTEND_PID")

if ! wait_for_http "http://$FRONTEND_HOST:$FRONTEND_PORT"; then
  echo "Frontend failed to start. See $FRONTEND_LOG" >&2
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
echo "  Email Backend:  http://$BACKEND_HOST:$BACKEND_PORT"
echo "  Next Frontend:  http://$FRONTEND_HOST:$FRONTEND_PORT"
if [[ "$RUN_STUDIO" -eq 1 ]]; then
  echo "  Studio API:     http://$LANGGRAPH_HOST:$LANGGRAPH_PORT"
fi
echo
echo "Logs:"
echo "  $BACKEND_LOG"
echo "  $FRONTEND_LOG"
if [[ "$RUN_STUDIO" -eq 1 ]]; then
  echo "  $STUDIO_LOG"
fi
echo
echo "Press Ctrl+C to stop all services."

if [[ "$RUN_STUDIO" -eq 1 ]]; then
  wait_for_any "$BACKEND_PID" "$FRONTEND_PID" "$STUDIO_PID"
else
  wait_for_any "$BACKEND_PID" "$FRONTEND_PID"
fi

echo "A service exited. Shutting down the rest..."
