#!/usr/bin/env bash
# R71 proof 5 without a screen: KDE Wallet as the Secret Service, its dialogs on a virtual display.
# Usage: run.sh PROBE OUT_DIR
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
docker build -q -t connetto-r71-kde "$here" >/dev/null
mkdir -p "$2"; chmod 777 "$2"
docker run --rm -v "$1:/probe:ro" -v "$here/scenario.sh:/scenario.sh:ro" -v "$2:/out" connetto-r71-kde \
  bash -c 'Xvfb :99 -screen 0 1024x768x24 >/dev/null 2>&1 & export DISPLAY=:99; sleep 1; dbus-run-session -- bash /scenario.sh'
