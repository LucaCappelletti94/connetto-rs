#!/usr/bin/env bash
# Runs inside the container's session bus: KDE Wallet's ksecretd as the Secret
# Service, its own dialogs answered on a virtual display.
set -uo pipefail
out=/out
mkdir -p ~/.config
printf '[Wallet]\nEnabled=true\nFirst Use=false\n\n[org.freedesktop.secrets]\napiEnabled=true\n' >~/.config/kwalletrc
daemon() {
  pkill -x ksecretd 2>/dev/null; sleep 0.5
  ksecretd >"$out/ksecretd-$1.log" 2>&1 &
  for _ in $(seq 50); do
    dbus-send --session --print-reply --dest=org.freedesktop.DBus / org.freedesktop.DBus.NameHasOwner string:org.freedesktop.secrets 2>/dev/null | grep -q 'boolean true' && return
    sleep 0.1
  done
  echo "ksecretd did not take org.freedesktop.secrets"; exit 1
}
dialog() { for _ in $(seq 150); do w=$(xdotool search --onlyvisible --class . 2>/dev/null | tail -1); [ -n "$w" ] && { echo "$w"; return; }; sleep 0.2; done; return 1; }
probe() { /probe "$@" >"$out/probe-$step.log" 2>&1; echo $? >"$out/probe-$step.status"; }
expect_ok() {
  [ "$(cat "$out/probe-$step.status")" = 0 ] || { echo "FAIL $step"; cat "$out/probe-$step.log"; exit 1; }
  echo "PASS $step: $(tail -1 "$out/probe-$step.log")"
}

step=1-create; daemon $step
probe write secret-service & pid=$!
win=$(dialog) || { echo "FAIL $step: no wallet wizard"; exit 1; }
sleep 1; import -window root "$out/$step-wizard.png"
# The wizard's blowfish choice, which turns Next into Finish.
xdotool mousemove 378 306 click 1; sleep 0.5; xdotool mousemove 614 500 click 1; sleep 2
win=$(dialog) || { echo "FAIL $step: no password dialog"; exit 1; }
xdotool windowfocus --sync "$win" type --delay 50 'connetto-proof'
xdotool key Tab; xdotool type --delay 50 'connetto-proof'; sleep 0.5; import -window "$win" "$out/$step-password.png"
xdotool key Return
wait $pid; expect_ok

# ksecretd writes a wallet to disk 5 s after a change and never on SIGTERM
# (upstream/kwallet-sigterm-loses-recent-writes.md), so the collection is locked,
# which closes and writes the wallet, before the restart below.
dbus-send --session --print-reply --dest=org.freedesktop.secrets /org/freedesktop/secrets \
  org.freedesktop.Secret.Service.Lock array:objpath:/org/freedesktop/secrets/aliases/default >/dev/null

step=2-unlock; daemon $step
probe read secret-service & pid=$!
win=$(dialog) || { echo "FAIL $step: no unlock dialog"; exit 1; }
sleep 1; import -window "$win" "$out/$step-dialog.png"
xdotool windowfocus --sync "$win" type --delay 50 'connetto-proof'; xdotool key Return
wait $pid; expect_ok
