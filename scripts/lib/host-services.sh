#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="${ROOT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
RUNTIME_DIR="$ROOT_DIR/.runtime"
PIDS_DIR="$RUNTIME_DIR/pids"

DEFAULT_HOST_SERVICES=(backend frontend cp)

ensure_runtime_dirs() {
  mkdir -p "$PIDS_DIR"
}

service_pid_file() {
  local service="$1"
  echo "$PIDS_DIR/${service}.pid"
}

read_service_pid() {
  local service="$1"
  local pid_file

  pid_file="$(service_pid_file "$service")"

  if [ -f "$pid_file" ]; then
    tr -d '[:space:]' < "$pid_file"
  fi
}

is_pid_running() {
  local pid="${1:-}"

  [ -n "$pid" ] && kill -0 "$pid" >/dev/null 2>&1
}

write_service_pid() {
  local service="$1"
  local pid="$2"

  ensure_runtime_dirs
  printf '%s\n' "$pid" > "$(service_pid_file "$service")"
}

clear_service_pid() {
  local service="$1"
  rm -f "$(service_pid_file "$service")"
}

start_host_service() {
  local service="$1"
  shift

  local existing_pid
  existing_pid="$(read_service_pid "$service" || true)"

  if is_pid_running "$existing_pid"; then
    echo "⚠️  ${service} already running (pid ${existing_pid})."
    return 0
  fi

  if [ -n "$existing_pid" ]; then
    clear_service_pid "$service"
  fi

  ensure_runtime_dirs

  (
    cd "$ROOT_DIR"
    exec "$@"
  ) > >(sed "s/^/[${service}] /") 2> >(sed "s/^/[${service}] /" >&2) &

  local pid=$!
  write_service_pid "$service" "$pid"
  echo "✅ Started ${service} (pid ${pid})."
}

stop_host_service() {
  local service="$1"
  local pid
  local waited=0

  pid="$(read_service_pid "$service" || true)"

  if [ -z "$pid" ]; then
    echo "ℹ️  ${service} is not running."
    return 0
  fi

  if ! is_pid_running "$pid"; then
    echo "ℹ️  Removing stale PID for ${service} (${pid})."
    clear_service_pid "$service"
    return 0
  fi

  echo "🛑 Stopping ${service} (pid ${pid})..."
  kill "$pid" >/dev/null 2>&1 || true

  while is_pid_running "$pid" && [ "$waited" -lt 10 ]; do
    sleep 1
    waited=$((waited + 1))
  done

  if is_pid_running "$pid"; then
    echo "⚠️  Force-killing ${service} (pid ${pid})..."
    kill -9 "$pid" >/dev/null 2>&1 || true
  fi

  clear_service_pid "$service"
  echo "✅ Stopped ${service}."
}

stop_default_host_services() {
  stop_host_service cp
  stop_host_service frontend
  stop_host_service backend
}

print_host_service_status() {
  local service
  local pid

  for service in "${DEFAULT_HOST_SERVICES[@]}"; do
    pid="$(read_service_pid "$service" || true)"

    if [ -z "$pid" ]; then
      echo "${service}: stopped"
    elif is_pid_running "$pid"; then
      echo "${service}: running (pid=${pid})"
    else
      echo "${service}: stale pid (pid=${pid})"
    fi
  done
}

wait_for_host_services() {
  local service
  local pid

  while true; do
    for service in "${DEFAULT_HOST_SERVICES[@]}"; do
      pid="$(read_service_pid "$service" || true)"

      if [ -z "$pid" ]; then
        echo "❌ Missing PID for ${service}."
        return 1
      fi

      if ! is_pid_running "$pid"; then
        echo "❌ ${service} is no longer running."
        clear_service_pid "$service"
        return 1
      fi
    done

    sleep 1
  done
}