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

sudo install -m 0644 "$unit_source" "$unit_target"
sudo systemctl daemon-reload
sudo systemctl enable --now ark-intel.service
curl --fail --silent --show-error http://127.0.0.1:7010/health
