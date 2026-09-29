#!/usr/bin/env bash
# Runs inside the container's session bus: drives gnome-keyring's real dialogs.
set -uo pipefail
out=/out
shot() { import -window root "$out/$1.png"; }
daemon() {
  pkill -x gnome-keyring-d 2>/dev/null; sleep 0.5
  gnome-keyring-daemon --foreground --components=secrets >"$out/daemon-$1.log" 2>&1 &
  for _ in $(seq 50); do
    dbus-send --session --print-reply --dest=org.freedesktop.DBus / org.freedesktop.DBus.NameHasOwner string:org.freedesktop.secrets 2>/dev/null | grep -q 'boolean true' && return
    sleep 0.1
  done
  echo "gnome-keyring did not take org.freedesktop.secrets"; exit 1
}
dialog() {
  xdotool search --sync --onlyvisible --class "$1" | head -1
}
probe() { /probe "$@" >"$out/probe-$step.log" 2>&1; echo $? >"$out/probe-$step.status"; }
expect() {
  local status; status=$(cat "$out/probe-$step.status")
  if [ "$1" = ok ]; then [ "$status" = 0 ] || { echo "FAIL $step: exit $status"; cat "$out/probe-$step.log"; exit 1; }
  else [ "$status" != 0 ] && grep -q "$1" "$out/probe-$step.log" || { echo "FAIL $step: wanted '$1'"; cat "$out/probe-$step.log"; exit 1; }
  fi
  echo "PASS $step: $(tail -1 "$out/probe-$step.log")"
}
class=gcr-prompter

step=1-create; daemon $step
probe write secret-service & pid=$!
win=$(timeout 30 bash -c "$(declare -f dialog); dialog $class") || { echo "FAIL $step: no create dialog"; exit 1; }
sleep 1; shot "$step-dialog"
xdotool windowfocus --sync "$win" type --delay 50 'connetto-proof'
xdotool key Tab; xdotool type --delay 50 'connetto-proof'; shot "$step-typed"; xdotool key Return
wait $pid; expect ok

step=2-unlock; daemon $step
probe read secret-service & pid=$!
win=$(timeout 30 bash -c "$(declare -f dialog); dialog $class") || { echo "FAIL $step: no unlock dialog"; exit 1; }
sleep 1; shot "$step-dialog"
xdotool windowfocus --sync "$win" type --delay 50 'connetto-proof'; xdotool key Return
wait $pid; expect ok

step=3-dismissed; daemon $step
probe read secret-service & pid=$!
win=$(timeout 30 bash -c "$(declare -f dialog); dialog $class") || { echo "FAIL $step: no unlock dialog"; exit 1; }
sleep 1; shot "$step-dialog"
xdotool windowfocus --sync "$win" key Escape
wait $pid; expect dismissed

step=4-bound; daemon $step
start=$(date +%s)
probe read secret-service & pid=$!
timeout 30 bash -c "$(declare -f dialog); dialog $class" >/dev/null || { echo "FAIL $step: no unlock dialog"; exit 1; }
sleep 1; shot "$step-dialog"
wait $pid; expect "did not answer within"
echo "  refused after $(( $(date +%s) - start )) s"
sleep 2; shot "$step-after"
if xdotool search --onlyvisible --class $class >/dev/null; then echo "FAIL $step: the dialog is still open"; exit 1; fi
echo "PASS $step: the dialog closed"
