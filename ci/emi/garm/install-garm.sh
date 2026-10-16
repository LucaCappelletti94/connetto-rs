#!/usr/bin/env bash
# Installs GARM and its Incus provider for ci-runner on emi, as a systemd user service.
# Runs as ci-runner, needs no root. Re-runnable: it keeps existing secrets and the database.
set -euo pipefail

GARM_VERSION=v0.2.1
PROVIDER_VERSION=v0.1.5
BRIDGE_IP=10.77.0.1
GARM_PORT=9997
home=$HOME/garm

# A private directory, so no other account on emi can swap an archive between its check and its unpacking.
downloads=$(mktemp -d)
trap 'rm -rf "$downloads"' EXIT

fetch() {
  local repo=$1 version=$2 asset=$3 dest=$4
  local base=https://github.com/cloudbase/$repo/releases/download/$version
  curl -fsSL "$base/$asset" -o "$downloads/$asset"
  curl -fsSL "$base/$asset.sha256" -o "$downloads/$asset.sha256"
  (cd "$downloads" && sha256sum -c --status <(awk -v f="$asset" '{ print $1 "  " f }' "$asset.sha256"))
  tar xzf "$downloads/$asset" -C "$dest"
}

mkdir -p "$home/bin" "$home/providers.d" "$HOME/.config/systemd/user"
chmod 0700 "$home"

echo "== GARM $GARM_VERSION, garm-cli and the Incus provider $PROVIDER_VERSION, checksums verified"
fetch garm "$GARM_VERSION" garm-linux-amd64.tgz "$home/bin"
fetch garm "$GARM_VERSION" garm-cli-linux-amd64.tgz "$home/bin"
fetch garm-provider-incus "$PROVIDER_VERSION" garm-provider-incus-linux-amd64.tgz "$home/providers.d"
"$home/bin/garm" -version || true

echo "== secrets, generated once"
[ -f "$home/jwt-secret" ] || head -c 48 /dev/urandom | base64 | tr -d '\n/+=' > "$home/jwt-secret"
[ -f "$home/db-passphrase" ] || head -c 64 /dev/urandom | base64 | tr -d '\n/+=' | head -c 32 > "$home/db-passphrase"
chmod 0600 "$home/jwt-secret" "$home/db-passphrase"

echo "== GARM config: API on the CI bridge only, scale sets, no webhooks"
cat > "$home/config.toml" <<EOF
[default]
enable_webhook_management = false

[logging]
enable_log_streamer = true
log_format = "text"
log_level = "info"
log_source = false
# A system account gets no user journal, so the log goes to a file.
log_file = "$home/garm.log"

[metrics]
enable = false

[jwt_auth]
secret = "$(cat "$home/jwt-secret")"
time_to_live = "8760h"

[apiserver]
  bind = "$BRIDGE_IP"
  port = $GARM_PORT
  use_tls = false
  [apiserver.webui]
    enable = true

[database]
  backend = "sqlite3"
  passphrase = "$(cat "$home/db-passphrase")"
  [database.sqlite3]
    db_file = "$home/garm.db"

[[provider]]
  name = "emi_incus"
  provider_type = "external"
  description = "Incus VMs on emi, project ci"
  [provider.external]
    provider_executable = "$home/providers.d/garm-provider-incus"
    config_file = "$home/garm-provider-incus.toml"
EOF

echo "== Incus provider config: VMs in project ci, default profile plus the flavor's"
cat > "$home/garm-provider-incus.toml" <<EOF
url = "https://127.0.0.1:8443"
client_certificate = "$HOME/incus/client.crt"
client_key = "$HOME/incus/client.key"
tls_server_certificate = "$HOME/incus/server.crt"
project_name = "ci"
instance_type = "virtual-machine"
include_default_profile = true
secure_boot = true
graceful_stop_timeout = 10

# The provider refuses to start with no remote. Runners boot from the local ci-ubuntu-2404 image.
[image_remotes]
  [image_remotes.images]
  addr = "https://images.linuxcontainers.org"
  public = true
  protocol = "simplestreams"
  skip_verify = false
EOF
chmod 0600 "$home/config.toml" "$home/garm-provider-incus.toml"

echo "== systemd user service"
cat > "$HOME/.config/systemd/user/garm.service" <<EOF
[Unit]
Description=GARM, GitHub Actions runner manager for connetto CI
After=network-online.target

[Service]
ExecStart=$home/bin/garm -config $home/config.toml
Restart=always
RestartSec=5s

[Install]
WantedBy=default.target
EOF

echo "== action archive cache, refilled every 10 minutes"
install -m 0755 "$(dirname "$0")/fill-action-cache.sh" "$home/bin/fill-action-cache.sh"
cat > "$HOME/.config/systemd/user/fill-action-cache.service" <<EOF
[Unit]
Description=Download the actions connetto's workflows use into the runner VMs' archive cache

[Service]
Type=oneshot
ExecStart=$home/bin/fill-action-cache.sh
EOF
cat > "$HOME/.config/systemd/user/fill-action-cache.timer" <<EOF
[Unit]
Description=Refill the action archive cache every 10 minutes

[Timer]
OnBootSec=1min
OnUnitActiveSec=10min

[Install]
WantedBy=timers.target
EOF
XDG_RUNTIME_DIR=/run/user/$(id -u)
export XDG_RUNTIME_DIR
systemctl --user daemon-reload
systemctl --user enable garm.service fill-action-cache.timer
systemctl --user restart garm.service fill-action-cache.timer
sleep 3
systemctl --user --no-pager status garm.service | head -n 5
curl -s -o /dev/null -w "GARM API http %{http_code}\n" "http://$BRIDGE_IP:$GARM_PORT/api/v1/"
echo GARM-INSTALL-DONE
