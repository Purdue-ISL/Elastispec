#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  run_auditor_docker.sh \
    --config FIREWALL_CONFIG \
    --inventory INVENTORY_JSON \
    --spec POLICY_FSL \
    --output REPORT_HTML \
    [--title REPORT_TITLE]

Runs the Elastispec Auditor and Batfish images with Docker Compose.
EOF
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 2
}

absolute_file() {
  local path="$1"
  local directory
  local filename

  [[ -f "$path" ]] || die "file not found: $path"
  directory="$(cd "$(dirname "$path")" && pwd -P)"
  filename="$(basename "$path")"
  printf '%s/%s\n' "$directory" "$filename"
}

config=""
inventory=""
spec=""
output=""
title="Elastispec firewall audit"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config)
      [[ $# -ge 2 ]] || die "--config requires a path"
      config="$2"
      shift 2
      ;;
    --inventory)
      [[ $# -ge 2 ]] || die "--inventory requires a path"
      inventory="$2"
      shift 2
      ;;
    --spec)
      [[ $# -ge 2 ]] || die "--spec requires a path"
      spec="$2"
      shift 2
      ;;
    --output)
      [[ $# -ge 2 ]] || die "--output requires a path"
      output="$2"
      shift 2
      ;;
    --title)
      [[ $# -ge 2 ]] || die "--title requires a value"
      title="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

[[ -n "$config" ]] || die "--config is required"
[[ -n "$inventory" ]] || die "--inventory is required"
[[ -n "$spec" ]] || die "--spec is required"
[[ -n "$output" ]] || die "--output is required"
[[ "$output" == *.html ]] || die "--output must end in .html"
[[ ! -d "$output" ]] || die "output path is a directory: $output"

config="$(absolute_file "$config")"
inventory="$(absolute_file "$inventory")"
spec="$(absolute_file "$spec")"

output_parent="$(dirname "$output")"
mkdir -p "$output_parent"
output_dir="$(cd "$output_parent" && pwd -P)"
output_name="$(basename "$output")"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
auditor_dir="$(cd "$script_dir/.." && pwd -P)"
compose_file="$auditor_dir/compose.yaml"

cleanup() {
  docker compose -f "$compose_file" down --volumes >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker compose -f "$compose_file" pull --policy missing

set +e
ELASTISPEC_AUDITOR_CONFIG="$config" \
ELASTISPEC_AUDITOR_INVENTORY="$inventory" \
ELASTISPEC_AUDITOR_SPEC="$spec" \
ELASTISPEC_AUDITOR_OUTPUT_DIR="$output_dir" \
ELASTISPEC_AUDITOR_OUTPUT_NAME="$output_name" \
ELASTISPEC_AUDITOR_TITLE="$title" \
docker compose -f "$compose_file" up \
  --abort-on-container-exit \
  --exit-code-from auditor \
  --attach auditor
status=$?
set -e

if [[ $status -ne 0 ]]; then
  printf 'Batfish logs (last 200 lines):\n' >&2
  docker compose -f "$compose_file" logs \
    --no-color --tail 200 batfish >&2 || true
  exit "$status"
fi

printf 'Report: %s/%s\n' "$output_dir" "$output_name"
