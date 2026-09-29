#!/usr/bin/env bash
# Runs the R71 Linux secret-store groups a plain test run cannot, under the
# cargo profile CARGO_TEST_PROFILE names (release by default):
#   secret-service  a private session bus with an unlocked gnome-keyring-daemon
#   systemd         transient system services, through passwordless sudo
#   container       Docker under its default seccomp profile
#   desktop         GNOME Keyring's and KDE Wallet's real dialogs and a real
#                   Flatpak, in Docker, screenshots under DESKTOP_PROOF_OUT
set -euo pipefail

profile="${CARGO_TEST_PROFILE:-release}"
nextest=(cargo +stable nextest run --cargo-profile "$profile" --all-features -p connetto-client --run-ignored ignored-only)

# The secret_store_probe example, built under the profile, printed as a path.
build_probe() {
  cargo +stable build --profile "$profile" --all-features -p connetto-client --example secret_store_probe >&2
  local target
  target="$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')"
  echo "$target/$profile/examples/secret_store_probe"
}

case "${1:-}" in
  secret-service)
    exec dbus-run-session -- bash -c '
      set -euo pipefail
      XDG_DATA_HOME="$(mktemp -d)"
      export XDG_DATA_HOME
      printf connetto | gnome-keyring-daemon --unlock --components=secrets >/dev/null
      CONNETTO_R71_PRIVATE_BUS=1 keyctl session - "$@"
    ' _ "${nextest[@]}" -E 'test(=linux_custody::a_fresh_process_reads_what_another_wrote_under_the_secret_service)'
    ;;
  systemd)
    exec keyctl session - "${nextest[@]}" -E 'test(=linux_custody::a_second_transient_service_reads_what_the_first_wrote)'
    ;;
  container)
    probe="$(build_probe)"
    CONNETTO_R71_PROBE="$probe" \
      exec "${nextest[@]}" -E 'test(=linux_custody::a_restarted_container_reads_its_keys_back_through_a_mounted_key_file)'
    ;;
  desktop)
    probe="$(build_probe)"
    out="${DESKTOP_PROOF_OUT:-$(mktemp -d)}"
    here="$(cd "$(dirname "$0")" && pwd)/desktop-proofs"
    for proof in gnome kde flatpak; do
      echo "== $proof"
      "$here/$proof/run.sh" "$probe" "$out/$proof"
    done
    echo "screenshots and logs in $out"
    ;;
  *)
    echo "usage: $0 secret-service|systemd|container|desktop" >&2
    exit 2
    ;;
esac
