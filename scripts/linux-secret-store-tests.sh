#!/usr/bin/env bash
# Runs the R71 Linux secret-store groups a plain test run cannot, under the
# cargo profile CARGO_TEST_PROFILE names (release by default):
#   secret-service  a private session bus with an unlocked gnome-keyring-daemon
#   systemd         transient system services, through passwordless sudo
#   container       Docker under its default seccomp profile
set -euo pipefail

profile="${CARGO_TEST_PROFILE:-release}"
nextest=(cargo +stable nextest run --cargo-profile "$profile" --all-features -p connetto-client --run-ignored ignored-only)

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
    cargo +stable build --profile "$profile" --all-features -p connetto-client --example secret_store_probe
    target="$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')"
    CONNETTO_R71_PROBE="$target/$profile/examples/secret_store_probe" \
      exec "${nextest[@]}" -E 'test(=linux_custody::a_restarted_container_reads_its_keys_back_through_a_mounted_key_file)'
    ;;
  *)
    echo "usage: $0 secret-service|systemd|container" >&2
    exit 2
    ;;
esac
