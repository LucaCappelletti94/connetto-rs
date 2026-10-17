#!/usr/bin/env bash
# Root setup of connetto's self-hosted CI hosts, emi_machine and commons_server.
#
# The two hosts form one Incus cluster, and GARM on emi fills it with runner VMs.
# emi bootstraps the cluster and holds the CI's confined project, GARM's account,
# the action archives and the folder jobs hand files through. A WireGuard link
# carries the cluster, that folder and GARM's API to commons. Every step checks
# the current state first, so the script can be re-run.
#
# Run as: sudo bash /home/lucac/host-setup.sh emi         (on emi_machine)
#         sudo bash /home/cappelle/host-setup.sh commons  (on commons_server, from any sudoer)
# A first commons run makes its WireGuard key and stops, the emi run then
# invites commons into the cluster, and a second commons run joins it. Keys
# and the invitation travel through ~/ci-cluster of lucac on emi and cappelle on commons.
set -euo pipefail

MEMBER=${1:-}
RUNNER_USER=ci-runner
RUNNER_HOME=/srv/ci-runner
CACHE_ROOT=/srv/ci-cache
PROJECT=ci
POOL=ci
BRIDGE=incusbr-ci
BRIDGE_IP=10.77.0.1
BRIDGE_CIDR=10.77.0.1/24
BRIDGE_NET=10.77.0.0/24
ACL=ci-egress
GARM_PORT=9997
MIRROR_PORT=5000
WG=wg-ci
WG_PORT=51820
# The runner account inside the golden image, which owns what it writes to the caches.
GUEST_UID=1001
ZABBLY_FINGERPRINT=4EFC590696CB15B87C73A3AD82CC8797C838DCFD
# CI's share of each host. emi fits 18 light and 10 heavy VMs and keeps about 60 GiB of its 503 GiB.
# commons is shared with other people, who keep about 50 GiB of its 251 GiB.
EMI_MEMORY_GIB=440
EMI_VMS=28
COMMONS_MEMORY_GIB=200
COMMONS_VMS=16
# The largest flavor, which a VM still being created is counted as.
LARGEST_GIB=22

case "$MEMBER" in
  emi)
    PEER=commons WG_IP=10.77.254.1 PEER_WG_IP=10.77.254.2 PEER_ADDR=134.21.20.118
    # The ssh account whose key ci-runner accepts, and whose ~/ci-cluster the keys travel through.
    EXCHANGE_USER=lucac
    POOL_DIR=/srv/incus-ci
    ;;
  commons)
    PEER=emi WG_IP=10.77.254.2 PEER_WG_IP=10.77.254.1 PEER_ADDR=134.21.20.58
    # cappelle has no sudo on commons, so another account runs this, and the keys travel through cappelle's home.
    EXCHANGE_USER=cappelle
    # commons' disks are ext4, and a cluster pool has one driver, so its btrfs lives in a loop file.
    POOL_IMAGE=/media/nvme8tb/incus-ci.btrfs
    POOL_FS=/srv/ci-btrfs
    POOL_DIR=$POOL_FS/incus-ci
    ;;
  *)
    echo "usage: sudo bash host-setup.sh emi|commons" >&2
    exit 1
    ;;
esac

log() { printf '\n== %s\n' "$*"; }
clustered() { incus cluster list --format csv >/dev/null 2>&1; }

[ "$(id -u)" -eq 0 ] || { echo "run this with sudo" >&2; exit 1; }
EXCHANGE_HOME=$(getent passwd "$EXCHANGE_USER" | cut -d: -f6)
EXCHANGE=$EXCHANGE_HOME/ci-cluster

log "Incus from the Zabbly 7.0 LTS repository, held so both members upgrade together"
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
# A member that upgrades alone waits for the other, which stalls CI, so upgrade emi and commons back to back.
apt-mark hold incus incus-base incus-client >/dev/null
incus version

log "WireGuard, btrfs and NFS tools"
packages="wireguard-tools jq"
[ "$MEMBER" = emi ] && packages="$packages nfs-kernel-server"
[ "$MEMBER" = commons ] && packages="$packages btrfs-progs nfs-common"
# shellcheck disable=SC2086
dpkg -s $packages >/dev/null 2>&1 || { apt-get update; apt-get install -y $packages; }

log "WireGuard key of $MEMBER, published in $EXCHANGE/$MEMBER.pub"
install -d -m 0700 /etc/wireguard
[ -f /etc/wireguard/$WG.key ] || (umask 077 && wg genkey > /etc/wireguard/$WG.key)
install -d -m 0755 -o "$EXCHANGE_USER" "$EXCHANGE"
wg pubkey < /etc/wireguard/$WG.key > "$EXCHANGE/$MEMBER.pub"
chown "$EXCHANGE_USER" "$EXCHANGE/$MEMBER.pub"
if [ ! -s "$EXCHANGE/$PEER.pub" ]; then
  echo "waiting for $PEER's key: copy $PEER's ~/ci-cluster/$PEER.pub to $EXCHANGE/$PEER.pub and run this again"
  exit 0
fi

log "WireGuard link $WG, $WG_IP to $PEER at $PEER_WG_IP"
conf=$(mktemp)
cat > "$conf" <<EOF
[Interface]
Address = $WG_IP/30
ListenPort = $WG_PORT
PrivateKey = $(cat /etc/wireguard/$WG.key)

[Peer]
PublicKey = $(cat "$EXCHANGE/$PEER.pub")
Endpoint = $PEER_ADDR:$WG_PORT
AllowedIPs = $PEER_WG_IP/32
PersistentKeepalive = 25
EOF
if cmp -s "$conf" /etc/wireguard/$WG.conf; then
  rm "$conf"
  systemctl enable --now wg-quick@$WG.service
else
  install -m 0600 "$conf" /etc/wireguard/$WG.conf
  rm "$conf"
  systemctl enable wg-quick@$WG.service
  systemctl restart wg-quick@$WG.service
fi
if command -v ufw >/dev/null && ufw status | grep -q '^Status: active'; then
  ufw allow from "$PEER_ADDR" to any port "$WG_PORT" proto udp
  # The cluster, the handoff export and GARM's API, from the other host only.
  ufw allow in on "$WG" from "$PEER_WG_IP"
fi
if [ "$MEMBER" = commons ] && ! ping -c 3 -W 2 "$PEER_WG_IP" >/dev/null; then
  echo "emi does not answer on $PEER_WG_IP: run host-setup.sh emi there first" >&2
  exit 1
fi

log "CI storage on a btrfs subvolume, so each VM is a copy-on-write clone"
if [ "$MEMBER" = commons ]; then
  install -d -m 0700 "$POOL_FS"
  if [ ! -f "$POOL_IMAGE" ]; then
    truncate -s 2T "$POOL_IMAGE"
    chmod 0600 "$POOL_IMAGE"
    mkfs.btrfs -q -L incus-ci "$POOL_IMAGE"
  fi
  grep -q " $POOL_FS " /etc/fstab || echo "$POOL_IMAGE $POOL_FS btrfs loop,noatime,nofail 0 0" >> /etc/fstab
  systemctl daemon-reload
  findmnt -n "$POOL_FS" >/dev/null || mount "$POOL_FS"
fi
[ -d "$POOL_DIR" ] || btrfs subvolume create "$POOL_DIR"

log "Incus starts after the link and its storage, and CI VMs yield the CPU to everyone else"
mkdir -p /etc/systemd/system/incus.service.d
cat > /etc/systemd/system/incus.service.d/ci-cluster.conf <<EOF
[Unit]
Wants=wg-quick@$WG.service
After=wg-quick@$WG.service
RequiresMountsFor=$POOL_DIR
EOF
cat > /etc/systemd/system/incus.service.d/ci-cpu-weight.conf <<EOF
[Service]
CPUWeight=10
EOF
systemctl daemon-reload
# No instance exists yet on a first run, so the restart interrupts nothing.
incus list --all-projects --format csv --columns n | grep -q . || systemctl restart incus.service

log "Host caches every runner VM mounts"
# Only what is read and written with plain file IO: virtiofs in these VMs refuses shared mmap,
# which libgit2 needs for cargo's git checkouts and rustc for a target directory.
for dir in cargo-registry sccache handoff registry-mirror actions; do
  mkdir -p "$CACHE_ROOT/$dir"
done
if [ "$MEMBER" = emi ]; then
  chown "$GUEST_UID:$GUEST_UID" "$CACHE_ROOT/cargo-registry" "$CACHE_ROOT/sccache" "$CACHE_ROOT/handoff"
  chmod 0755 "$CACHE_ROOT"
else
  chown "$GUEST_UID:$GUEST_UID" "$CACHE_ROOT/cargo-registry" "$CACHE_ROOT/sccache"
  # uid 1001 is a person on commons, so only root may reach the caches. The VMs reach them through virtiofsd, which runs as root.
  chmod 0700 "$CACHE_ROOT"
fi

if [ "$MEMBER" = emi ]; then
  log "Handoff folder and action archives exported to commons over the link"
  mkdir -p /etc/exports.d
  # virtiofsd sets timestamps as root, so every uid from commons becomes the VMs' runner, which owns everything in handoff.
  squash="all_squash,anonuid=$GUEST_UID,anongid=$GUEST_UID"
  cat > /etc/exports.d/ci-cache.exports <<EOF
$CACHE_ROOT/handoff $PEER_WG_IP(rw,async,no_subtree_check,$squash)
$CACHE_ROOT/actions $PEER_WG_IP(ro,no_subtree_check,$squash)
EOF
  systemctl enable --now nfs-server.service
  exportfs -ra

  log "Daily cleanup of the run folders jobs hand files through"
  cat > /etc/systemd/system/ci-handoff-clean.service <<EOF
[Unit]
Description=Delete CI handoff run folders older than two days

[Service]
Type=oneshot
ExecStart=/usr/bin/find $CACHE_ROOT/handoff -mindepth 1 -maxdepth 1 -mmin +2880 -exec rm -rf {} +
EOF
  cat > /etc/systemd/system/ci-handoff-clean.timer <<'EOF'
[Unit]
Description=Daily cleanup of CI handoff run folders

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable --now ci-handoff-clean.timer
  proxy_listen=$WG_IP proxy_target=$BRIDGE_IP
else
  log "emi's handoff folder and action archives, mounted on first use"
  # virtiofsd asks for POSIX ACLs on every access by a non-owner, which NFSv4 refuses as unsupported and NFSv3 serves. Locks stay local.
  options=vers=3,nolock,_netdev,nofail,noatime,x-systemd.automount,x-systemd.requires=wg-quick@$WG.service
  for dir in handoff actions; do
    mode=rw
    [ "$dir" = actions ] && mode=ro
    line="$PEER_WG_IP:$CACHE_ROOT/$dir $CACHE_ROOT/$dir nfs $mode,$options 0 0"
    grep -qxF "$line" /etc/fstab && continue
    grep -vE " $CACHE_ROOT/$dir nfs4? " /etc/fstab > /etc/fstab.ci-new || true
    echo "$line" >> /etc/fstab.ci-new
    mv /etc/fstab.ci-new /etc/fstab
    # Running VMs keep their own bind of the old mount, and the next access mounts it again with the new options.
    if findmnt -n -t nfs,nfs4 "$CACHE_ROOT/$dir" >/dev/null; then umount -l "$CACHE_ROOT/$dir"; fi
  done
  systemctl daemon-reload
  systemctl restart remote-fs.target
  for dir in handoff actions; do
    ls "$CACHE_ROOT/$dir" >/dev/null
    findmnt -n -t nfs -o TARGET,OPTIONS --target "$CACHE_ROOT/$dir" | cut -c1-120
  done
  proxy_listen=$BRIDGE_IP proxy_target=$PEER_WG_IP
fi

log "GARM's API for the runner VMs on commons, relayed from $proxy_listen to $proxy_target"
cat > /etc/systemd/system/ci-garm-proxy.socket <<EOF
[Unit]
Description=GARM's API for the CI runner VMs on commons

[Socket]
ListenStream=$proxy_listen:$GARM_PORT
FreeBind=true

[Install]
WantedBy=sockets.target
EOF
cat > /etc/systemd/system/ci-garm-proxy.service <<EOF
[Unit]
Description=Relay to GARM's API for the CI runner VMs on commons
Requires=ci-garm-proxy.socket
After=ci-garm-proxy.socket

[Service]
ExecStart=/usr/lib/systemd/systemd-socket-proxyd $proxy_target:$GARM_PORT
DynamicUser=yes
EOF
systemctl daemon-reload
systemctl enable --now ci-garm-proxy.socket

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

if [ "$MEMBER" = emi ]; then
  log "CI pool, bridge $BRIDGE at $BRIDGE_CIDR with IPv4 NAT only, the same on every member"
  incus storage show "$POOL" >/dev/null 2>&1 || incus storage create "$POOL" btrfs source="$POOL_DIR"
  incus network show "$BRIDGE" >/dev/null 2>&1 \
    || incus network create "$BRIDGE" ipv4.address="$BRIDGE_CIDR" ipv4.nat=true ipv6.address=none

  log "Egress firewall: the internet, plus GARM and the image mirror on the host, nothing else local"
  incus network acl show "$ACL" >/dev/null 2>&1 || incus network acl create "$ACL"
  # The whole rule set is written on every run, so a run that stopped halfway or an older rule set is replaced.
  {
    echo "egress:"
    # 10.0.0.0/8 except 10.77.0.0/24, the CI bridge itself, plus the other private, shared and campus ranges.
    for cidr in 10.0.0.0/10 10.64.0.0/13 10.72.0.0/14 10.76.0.0/16 \
        10.77.1.0/24 10.77.2.0/23 10.77.4.0/22 10.77.8.0/21 10.77.16.0/20 10.77.32.0/19 10.77.64.0/18 10.77.128.0/17 \
        10.78.0.0/15 10.80.0.0/12 10.96.0.0/11 10.128.0.0/9 \
        172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 169.254.0.0/16 134.21.0.0/16; do
      printf -- '- action: drop\n  destination: %s\n  state: enabled\n' "$cidr"
    done
    # The host itself, every port but the image mirror and GARM's callback (DHCP and DNS are allowed before any ACL).
    printf -- '- action: drop\n  destination: %s\n  protocol: tcp\n  destination_port: %s\n  state: enabled\n' \
      "$BRIDGE_IP" "1-$((MIRROR_PORT - 1)),$((MIRROR_PORT + 1))-$((GARM_PORT - 1)),$((GARM_PORT + 1))-65535"
    printf -- '- action: drop\n  destination: %s\n  protocol: udp\n  destination_port: 1-65535\n  state: enabled\n' "$BRIDGE_IP"
    printf -- '- action: allow\n  destination: 0.0.0.0/0\n  state: enabled\n'
    echo "ingress: []"
  } | incus network acl edit "$ACL"
  incus network set "$BRIDGE" security.acls="$ACL"

  log "Incus API on localhost only, for ci-runner's confined certificate"
  incus config set core.https_address=127.0.0.1:8443

  log "Project $PROJECT, confined: its own pool and bridge, cache paths only, both hosts' CI shares at most"
  incus project show "$PROJECT" >/dev/null 2>&1 || incus project create "$PROJECT" \
    -c features.images=true -c features.profiles=true -c features.storage.volumes=true -c features.networks=false
  incus project set "$PROJECT" \
    restricted=true \
    restricted.devices.disk=allow \
    restricted.devices.disk.paths="$CACHE_ROOT" \
    restricted.networks.access="$BRIDGE" \
    restricted.storage-pools.access="$POOL" \
    limits.memory="$((EMI_MEMORY_GIB + COMMONS_MEMORY_GIB))GiB" \
    limits.virtual-machines="$((EMI_VMS + COMMONS_VMS))" \
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
    # Setting a profile key updates every VM using it and fails when one is busy, so only a differing value is set.
    local key value
    for key in limits.cpu="$cpus" limits.memory="$memory" limits.cpu.priority=5; do
      value=${key#*=} key=${key%%=*}
      [ "$(incus profile get "$name" "$key" --project "$PROJECT")" = "$value" ] \
        || incus profile set "$name" "$key=$value" --project "$PROJECT"
    done
    for dir in cargo-registry sccache handoff; do
      incus profile device show "$name" --project "$PROJECT" | grep -q "^$dir:" \
        || incus profile device add "$name" "$dir" disk source="$CACHE_ROOT/$dir" path="/srv/cache/$dir" --project "$PROJECT"
    done
    incus profile device show "$name" --project "$PROJECT" | grep -q "^actions:" \
      || incus profile device add "$name" actions disk source="$CACHE_ROOT/actions" path=/srv/cache/actions readonly=true --project "$PROJECT"
  }
  # The largest measured peaks are 9.3 GiB light and 19.1 GiB heavy.
  make_profile ci-light 4 12GiB
  make_profile ci-heavy 8 "${LARGEST_GIB}GiB"

  log "Account $RUNNER_USER, which runs GARM and holds the GitHub App key"
  id "$RUNNER_USER" >/dev/null 2>&1 \
    || useradd --system --create-home --home-dir "$RUNNER_HOME" --shell /bin/bash "$RUNNER_USER"
  # Action archives, filled by ci-runner with the GitHub App's token and read-only in the VMs.
  install -d -m 0755 -o "$RUNNER_USER" -g "$RUNNER_USER" "$CACHE_ROOT/actions"
  install -d -m 0700 -o "$RUNNER_USER" -g "$RUNNER_USER" "$RUNNER_HOME/.ssh" "$RUNNER_HOME/incus"
  install -m 0600 -o "$RUNNER_USER" -g "$RUNNER_USER" "$EXCHANGE_HOME/.ssh/authorized_keys" "$RUNNER_HOME/.ssh/authorized_keys"
  loginctl enable-linger "$RUNNER_USER"

  log "Incus client certificate for $RUNNER_USER, valid in project $PROJECT only"
  if [ ! -f "$RUNNER_HOME/incus/client.crt" ]; then
    sudo -u "$RUNNER_USER" openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 \
      -days 3650 -subj "/CN=$RUNNER_USER" \
      -keyout "$RUNNER_HOME/incus/client.key" -out "$RUNNER_HOME/incus/client.crt"
  fi
  incus config trust list --format json | grep -q "\"name\":\"$RUNNER_USER\"" \
    || incus config trust add-certificate "$RUNNER_HOME/incus/client.crt" --name "$RUNNER_USER" --restricted --projects "$PROJECT"

  log "Cluster bootstrapped on emi, its only database voter, reached by commons over the link"
  if ! clustered; then
    if incus list --project "$PROJECT" --format csv --columns n | grep -q .; then
      echo "project $PROJECT still has instances: drain GARM (max-runners 0) and run this again once they are gone" >&2
      exit 1
    fi
    incus config set cluster.https_address="$WG_IP:8443"
    incus cluster enable emi
  fi
  # Enabling the cluster replaced the API's certificate, which GARM's provider pins.
  cert=/var/lib/incus/cluster.crt
  [ -f "$cert" ] || cert=/var/lib/incus/server.crt
  install -m 0644 -o "$RUNNER_USER" -g "$RUNNER_USER" "$cert" "$RUNNER_HOME/incus/server.crt"
  # ci-runner's own incus remote, which the image build uses, pins it too.
  remote_cert=$RUNNER_HOME/.config/incus/servercerts/emi.crt
  [ -f "$remote_cert" ] && install -m 0644 -o "$RUNNER_USER" -g "$RUNNER_USER" "$cert" "$remote_cert"

  log "Placement: each new CI VM goes to the member with the most CI memory left, within its share"
  incus config set instances.placement.scriptlet="$(cat <<EOF
SHARES = {
    "emi": {"memory": $EMI_MEMORY_GIB, "vms": $EMI_VMS},
    "commons": {"memory": $COMMONS_MEMORY_GIB, "vms": $COMMONS_VMS},
}
LARGEST = $LARGEST_GIB
GIB = 1024 * 1024 * 1024

def memory_gib(instance):
    value = instance.expanded_config.get("limits.memory", "")
    if not value.endswith("GiB"):
        return LARGEST
    return int(value[:-3])

def instance_placement(request, candidate_members):
    if request.project != "$PROJECT" or request.reason != "new":
        return
    wanted = get_instance_resources().memory_size // GIB
    best = None
    best_room = -1
    for member in candidate_members:
        name = member.server_name
        if name not in SHARES:
            continue
        instances = get_instances(project="$PROJECT", location=name)
        # Each creation in flight is an operation, and gets its stopped record soon after, so only the excess has no record yet.
        operations = get_instances_count(project="$PROJECT", location=name, pending=True) - len(instances)
        stopped = len([i for i in instances if i.status == "Stopped"])
        unrecorded = max(0, operations - stopped)
        count = len(instances) + unrecorded
        used = LARGEST * unrecorded
        for instance in instances:
            used += memory_gib(instance)
        room = SHARES[name]["memory"] - used
        if count < SHARES[name]["vms"] and room >= wanted and room > best_room:
            best = name
            best_room = room
    if best == None:
        fail("every member is at its CI share")
    set_target(best)
EOF
)"

  log "Invitation for commons, written to $EXCHANGE/join-token"
  if ! incus cluster list --format csv --columns n | grep -qx "$PEER"; then
    # The join file only provides the pool's source, so refuse a cluster that asks commons for more.
    asked=$(incus query /1.0/cluster | jq -r '.member_config[] | "\(.entity) \(.name) \(.key)"')
    if [ "$asked" != "storage-pool $POOL source" ]; then
      printf 'a member joining this cluster must provide:\n%s\nbut the join file only provides storage-pool %s source\n' "$asked" "$POOL" >&2
      exit 1
    fi
    incus cluster list-tokens --format csv --columns n | grep -qx "$PEER" && incus cluster revoke-token "$PEER"
    (umask 077 && incus cluster add "$PEER" --quiet > "$EXCHANGE/join-token")
    chown "$EXCHANGE_USER" "$EXCHANGE/join-token"
    echo "copy $EXCHANGE/emi.pub and $EXCHANGE/join-token to commons' ~/ci-cluster, then run host-setup.sh commons there"
  fi
else
  log "commons joins the cluster, giving its own pool source"
  if ! clustered; then
    [ -s "$EXCHANGE/join-token" ] || { echo "waiting for the invitation: copy emi's ~/ci-cluster/join-token to $EXCHANGE/join-token" >&2; exit 1; }
    incus admin init --preseed <<EOF
cluster:
  enabled: true
  server_name: commons
  server_address: $WG_IP:8443
  cluster_token: $(cat "$EXCHANGE/join-token")
  member_config:
  - entity: storage-pool
    name: $POOL
    key: source
    value: $POOL_DIR
EOF
    rm "$EXCHANGE/join-token"
  fi
fi

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

log "Done"
incus cluster list 2>/dev/null || true
if [ "$MEMBER" = emi ]; then
  incus project show "$PROJECT"
  incus config trust list
  echo "ci-runner can now reach Incus at https://127.0.0.1:8443 with the certificate in $RUNNER_HOME/incus"
fi
