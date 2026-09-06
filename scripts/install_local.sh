#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
config_dir="/home/novaadmin/.config/ark-intel"
env_file="$config_dir/env"
unit_source="$repo_dir/deploy/ark-intel.service"
unit_target="/etc/systemd/system/ark-intel.service"
enable_scans="false"

if [[ "${1:-}" == "--enable-scans" ]]; then
  enable_scans="true"
elif [[ -n "${1:-}" ]]; then
  echo "usage: $0 [--enable-scans]" >&2
  exit 2
fi

install -d -m 700 "$config_dir"
if [[ ! -f "$env_file" ]]; then
  umask 077
  token="$(openssl rand -hex 32)"
  {
    printf 'ARK_INTEL_HOST=127.0.0.1\n'
    printf 'ARK_INTEL_PORT=7010\n'
    printf 'ARK_INTEL_SERVICE_TOKEN=%s\n' "$token"
    printf 'ARK_INTEL_DATABASE_PATH=/var/lib/ark-intel/ark-intel.sqlite3\n'
    printf 'ARK_INTEL_ACTIVE_SCAN_ENABLED=%s\n' "$enable_scans"
    printf 'ARK_INTEL_JOB_RETENTION_DAYS=30\n'
    printf 'ARK_INTEL_BLOCKED_DOMAIN_SUFFIXES=.magaenergy.ai,.internal,.local,.lan,localhost\n'
  } > "$env_file"
else
  sed -i "s/^ARK_INTEL_ACTIVE_SCAN_ENABLED=.*/ARK_INTEL_ACTIVE_SCAN_ENABLED=$enable_scans/" "$env_file"
fi
chmod 600 "$env_file"

# Build before entering the hardened systemd sandbox. Docker Buildx writes
# activity metadata below ~/.docker, which is intentionally read-only inside
# the service unit.
docker compose build

sudo install -m 0644 "$unit_source" "$unit_target"
sudo systemctl daemon-reload
sudo systemctl enable ark-intel.service
# A oneshot unit that is already active will not be started again by
# `enable --now`; restart explicitly so token and feature-flag changes apply.
sudo systemctl restart ark-intel.service
curl \
  --fail \
  --silent \
  --show-error \
  --retry 20 \
  --retry-all-errors \
  --retry-delay 1 \
  --max-time 30 \
  http://127.0.0.1:7010/health
