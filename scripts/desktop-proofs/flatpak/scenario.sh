#!/usr/bin/env bash
# Runs inside the container's session bus: the probe as a Flatpak app, through
# the real Secret portal with gnome-keyring as its backend.
set -uo pipefail
app=org.connetto.R71Probe
printf connetto | gnome-keyring-daemon --unlock --components=secrets >/dev/null
XDG_CURRENT_DESKTOP=GNOME /usr/libexec/xdg-desktop-portal >/out/portal.log 2>&1 &
sleep 1
build=$(mktemp -d)/app
flatpak build-init "$build" $app org.freedesktop.Platform org.freedesktop.Platform 24.08 >/dev/null || exit 1
install -D /probe "$build/files/bin/probe"
flatpak build-finish "$build" --command=probe >/dev/null || exit 1
flatpak build-export /tmp/repo "$build" >/dev/null || exit 1
flatpak remote-add --user --no-gpg-verify local /tmp/repo
flatpak install --user -y --noninteractive local $app >/dev/null || exit 1
for phase in write read; do
  if flatpak run $app "$phase" detected >"/out/probe-$phase.log" 2>&1; then
    echo "PASS $phase: $(tail -1 "/out/probe-$phase.log")"
  else
    echo "FAIL $phase"; cat "/out/probe-$phase.log"; exit 1
  fi
done
keyring="$HOME/.var/app/$app/data/keyrings/default.keyring"
[ -s "$keyring" ] && echo "PASS the secrets live in libsecret's sandbox keyring: $keyring" || { echo "FAIL no keyring at $keyring"; exit 1; }
