#!/usr/bin/env bash
# Root setup of emi_machine for connetto's self-hosted CI runners.
#
# Installs Incus, gives the CI a confined Incus project with its own storage
# pool, bridge and egress firewall, creates the unprivileged ci-runner account
# that GARM runs as, and prepares the host-side caches every runner VM mounts.
# Every step checks the current state first, so the script can be re-run.
#
# Run once as: sudo bash host-setup.sh
set -euo pipefail

RUNNER_USER=ci-runner
RUNNER_HOME=/srv/ci-runner
CACHE_ROOT=/srv/ci-cache
POOL_DIR=/srv/incus-ci
PROJECT=ci
POOL=ci
BRIDGE=incusbr-ci
BRIDGE_IP=10.77.0.1
BRIDGE_CIDR=10.77.0.1/24
BRIDGE_NET=10.77.0.0/24
ACL=ci-egress
GARM_PORT=9997
MIRROR_PORT=5000
# The runner account inside the golden image, which owns what it writes to the caches.
GUEST_UID=1001
ZABBLY_FINGERPRINT=4EFC590696CB15B87C73A3AD82CC8797C838DCFD

log() { printf '\n== %s\n' "$*"; }

[ "$(id -u)" -eq 0 ] || { echo "run this with sudo" >&2; exit 1; }
[ -n "${SUDO_USER:-}" ] || { echo "run this through sudo from the account whose ssh key ci-runner should accept" >&2; exit 1; }

log "Incus from the Zabbly 7.0 LTS repository"
if ! command -v incus >/dev/null; then
  mkdir -p /etc/apt/keyrings
  curl -fsSL https://pkgs.zabbly.com/key.asc -o /tmp/zabbly.asc
  got=$(gpg --show-keys --with-colons /tmp/zabbly.asc | awk -F: '$1 == "fpr" { print $10; exit }')
  if [ "$got" != "$ZABBLY_FINGERPRINT" ]; then
    echo "Zabbly key fingerprint is $got, expected $ZABBLY_FINGERPRINT" >&2
    exit 1
  fi
  install -m 0644 /tmp/zabbly.asc /etc/apt/keyrings/zabbly.asc
  # shellcheck source=/dev/null
  codename=$(. /etc/os-release && echo "$VERSION_CODENAME")
  cat > /etc/apt/sources.list.d/zabbly-incus-lts-7.0.sources <<EOF
Enabled: yes
Types: deb
URIs: https://pkgs.zabbly.com/incus/lts-7.0
Suites: $codename
Components: main
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/zabbly.asc
EOF
  apt-get update
  apt-get install -y incus
fi
incus version

log "CI storage pool on a btrfs subvolume, so each VM is a copy-on-write clone"
[ -d "$POOL_DIR" ] || btrfs subvolume create "$POOL_DIR"
incus storage show "$POOL" >/dev/null 2>&1 || incus storage create "$POOL" btrfs source="$POOL_DIR"

log "CI bridge $BRIDGE at $BRIDGE_CIDR, IPv4 NAT only"
incus network show "$BRIDGE" >/dev/null 2>&1 \
  || incus network create "$BRIDGE" ipv4.address="$BRIDGE_CIDR" ipv4.nat=true ipv6.address=none

log "Egress firewall: the internet, plus GARM and the image mirror on the host, nothing else local"
if ! incus network acl show "$ACL" >/dev/null 2>&1; then
  incus network acl create "$ACL"
  # 10.0.0.0/8 except 10.77.0.0/16, the CI bridge's own range.
  for cidr in 10.0.0.0/10 10.64.0.0/13 10.72.0.0/14 10.76.0.0/16 10.78.0.0/15 10.80.0.0/12 10.96.0.0/11 10.128.0.0/9 \
      172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 169.254.0.0/16 134.21.0.0/16; do
    incus network acl rule add "$ACL" egress action=drop destination="$cidr"
  done
  # The host itself, every port but GARM's callback and the image mirror (DHCP and DNS are allowed before any ACL).
  incus network acl rule add "$ACL" egress action=drop destination="$BRIDGE_IP" protocol=tcp \
    destination_port="1-$((MIRROR_PORT - 1)),$((MIRROR_PORT + 1))-$((GARM_PORT - 1)),$((GARM_PORT + 1))-65535"
  incus network acl rule add "$ACL" egress action=drop destination="$BRIDGE_IP" protocol=udp destination_port=1-65535
  incus network acl rule add "$ACL" egress action=allow destination=0.0.0.0/0
fi
incus network set "$BRIDGE" security.acls="$ACL"

log "ufw lets the CI bridge reach DHCP, DNS, the mirror and GARM on the host, and route out"
if command -v ufw >/dev/null && ufw status | grep -q '^Status: active'; then
  ufw allow in on "$BRIDGE" to any port 67 proto udp
  ufw allow in on "$BRIDGE" to any port 53
  ufw allow in on "$BRIDGE" to "$BRIDGE_IP" port "$MIRROR_PORT" proto tcp
  ufw allow in on "$BRIDGE" to "$BRIDGE_IP" port "$GARM_PORT" proto tcp
  ufw route allow in on "$BRIDGE" from "$BRIDGE_NET"
fi

log "Docker's FORWARD drop policy must let the CI bridge through"
cat > /etc/systemd/system/ci-incus-docker-forward.service <<EOF
[Unit]
Description=Let Incus CI bridge traffic through Docker's FORWARD policy
After=docker.service incus.service
Wants=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'iptables -C DOCKER-USER -i $BRIDGE -j ACCEPT 2>/dev/null || iptables -I DOCKER-USER -i $BRIDGE -j ACCEPT'
ExecStart=/bin/sh -c 'iptables -C DOCKER-USER -o $BRIDGE -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -I DOCKER-USER -o $BRIDGE -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT'

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now ci-incus-docker-forward.service

log "CI VMs yield the CPU to everyone else on emi"
mkdir -p /etc/systemd/system/incus.service.d
cat > /etc/systemd/system/incus.service.d/ci-cpu-weight.conf <<EOF
[Service]
CPUWeight=10
EOF
systemctl daemon-reload
# No instance exists yet on a first run, so the restart interrupts nothing.
incus list --all-projects --format csv --columns n | grep -q . || systemctl restart incus.service

log "Incus API on localhost only, for ci-runner's confined certificate"
incus config set core.https_address=127.0.0.1:8443

log "Host caches every runner VM mounts"
# Only what is read and written with plain file IO: virtiofs in these VMs refuses shared mmap,
# which libgit2 needs for cargo's git checkouts and rustc for a target directory.
for dir in cargo-registry sccache registry-mirror actions; do
  mkdir -p "$CACHE_ROOT/$dir"
done
chown "$GUEST_UID:$GUEST_UID" "$CACHE_ROOT/cargo-registry" "$CACHE_ROOT/sccache"
chmod 0755 "$CACHE_ROOT"

log "Docker Hub pull-through mirror on $BRIDGE_IP:$MIRROR_PORT"
# Host networking, because a published port DNATs to Docker's 172.17/16, which the CI egress ACL drops.
if [ "$(docker inspect -f '{{.HostConfig.NetworkMode}}' ci-registry-mirror 2>/dev/null)" != host ]; then
  docker rm -f ci-registry-mirror >/dev/null 2>&1 || true
  docker run -d --restart=always --name ci-registry-mirror --network host \
    -v "$CACHE_ROOT/registry-mirror:/var/lib/registry" \
    -e REGISTRY_HTTP_ADDR="$BRIDGE_IP:$MIRROR_PORT" \
    -e REGISTRY_PROXY_REMOTEURL=https://registry-1.docker.io \
    registry:2
fi

log "Project $PROJECT, confined: its own pool and bridge, cache paths only, 256 GiB and 14 VMs at most"
incus project show "$PROJECT" >/dev/null 2>&1 || incus project create "$PROJECT" \
  -c features.images=true -c features.profiles=true -c features.storage.volumes=true -c features.networks=false
incus project set "$PROJECT" \
  restricted=true \
  restricted.devices.disk=allow \
  restricted.devices.disk.paths="$CACHE_ROOT" \
  restricted.networks.access="$BRIDGE" \
  restricted.storage-pools.access="$POOL" \
  limits.memory=256GiB \
  limits.virtual-machines=14 \
  limits.containers=0
# Incus 7.0.1 refuses to launch the project's own published images while this option is set (upstream/incus-restricted-image-servers-blocks-local-images.md).
incus project unset "$PROJECT" restricted.images.servers

log "Profiles: default (disk, network), ci-light and ci-heavy (size and caches)"
incus profile device show default --project "$PROJECT" | grep -q '^root:' \
  || incus profile device add default root disk path=/ pool="$POOL" size=100GiB --project "$PROJECT"
incus profile device show default --project "$PROJECT" | grep -q '^eth0:' \
  || incus profile device add default eth0 nic network="$BRIDGE" name=eth0 --project "$PROJECT"
make_profile() {
  local name=$1 cpus=$2 memory=$3
  incus profile show "$name" --project "$PROJECT" >/dev/null 2>&1 || incus profile create "$name" --project "$PROJECT"
  incus profile set "$name" limits.cpu="$cpus" limits.memory="$memory" limits.cpu.priority=5 --project "$PROJECT"
  for dir in cargo-registry sccache; do
    incus profile device show "$name" --project "$PROJECT" | grep -q "^$dir:" \
      || incus profile device add "$name" "$dir" disk source="$CACHE_ROOT/$dir" path="/srv/cache/$dir" --project "$PROJECT"
  done
  incus profile device show "$name" --project "$PROJECT" | grep -q "^actions:" \
    || incus profile device add "$name" actions disk source="$CACHE_ROOT/actions" path=/srv/cache/actions readonly=true --project "$PROJECT"
  for dir in cargo-git targets; do
    incus profile device remove "$name" "$dir" --project "$PROJECT" >/dev/null 2>&1 || true
  done
}
# 4 vCPUs and 16 GiB, the size of GitHub's hosted Linux runner.
make_profile ci-light 4 16GiB
make_profile ci-heavy 8 32GiB

log "Account $RUNNER_USER, which runs GARM and holds the GitHub App key"
id "$RUNNER_USER" >/dev/null 2>&1 \
  || useradd --system --create-home --home-dir "$RUNNER_HOME" --shell /bin/bash "$RUNNER_USER"
# Action archives, filled by ci-runner with the GitHub App's token and read-only in the VMs.
install -d -m 0755 -o "$RUNNER_USER" -g "$RUNNER_USER" "$CACHE_ROOT/actions"
install -d -m 0700 -o "$RUNNER_USER" -g "$RUNNER_USER" "$RUNNER_HOME/.ssh" "$RUNNER_HOME/incus"
install -m 0600 -o "$RUNNER_USER" -g "$RUNNER_USER" "$(getent passwd "$SUDO_USER" | cut -d: -f6)/.ssh/authorized_keys" \
  "$RUNNER_HOME/.ssh/authorized_keys"
loginctl enable-linger "$RUNNER_USER"

log "Incus client certificate for $RUNNER_USER, valid in project $PROJECT only"
if [ ! -f "$RUNNER_HOME/incus/client.crt" ]; then
  sudo -u "$RUNNER_USER" openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 \
    -days 3650 -subj "/CN=$RUNNER_USER" \
    -keyout "$RUNNER_HOME/incus/client.key" -out "$RUNNER_HOME/incus/client.crt"
fi
incus config trust list --format json | grep -q "\"name\":\"$RUNNER_USER\"" \
  || incus config trust add-certificate "$RUNNER_HOME/incus/client.crt" --name "$RUNNER_USER" --restricted --projects "$PROJECT"
install -m 0644 -o "$RUNNER_USER" -g "$RUNNER_USER" /var/lib/incus/server.crt "$RUNNER_HOME/incus/server.crt"

log "Done"
incus project show "$PROJECT"
incus config trust list
echo "ci-runner can now reach Incus at https://127.0.0.1:8443 with the certificate in $RUNNER_HOME/incus"
