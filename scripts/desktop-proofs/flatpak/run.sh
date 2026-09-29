#!/usr/bin/env bash
# R71 proof 12 without a screen: the probe as a Flatpak app through the real Secret portal.
# Usage: run.sh PROBE OUT_DIR
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
docker build -q -t connetto-r71-flatpak "$here" >/dev/null
mkdir -p "$2"; chmod 777 "$2"
# bubblewrap needs user namespaces, which Docker's default profile denies.
# flatpak install reaches the system bus, so one runs before the tester's session.
docker run --rm --privileged --user root -v "$1:/probe:ro" -v "$here/scenario.sh:/scenario.sh:ro" -v "$2:/out" connetto-r71-flatpak \
  bash -c 'mkdir -p /run/dbus && dbus-daemon --system --fork && runuser -u tester -- bash -c "export HOME=/home/tester XDG_RUNTIME_DIR=/tmp/runtime; mkdir -m 700 -p \$XDG_RUNTIME_DIR; dbus-run-session -- bash /scenario.sh"'
