#!/usr/bin/env bash
# Builds connetto's CI golden image on emi, as ci-runner, and moves the
# ci-ubuntu-2404 alias to it only after a VM booted from it passes a smoke check.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
alias=ci-ubuntu-2404
# One build at a time, since a second one would share the minute stamp, delete this one's VMs and race the alias move.
exec 9>"$here/.build.lock"
flock -n 9 || { echo "another image build is running" >&2; exit 1; }
stamp=$(date -u +%Y%m%d%H%M)
builder=image-build-$stamp
smoke=image-smoke-$stamp

# Every incus call closes stdin, because incus reads instance config from a non-terminal stdin.
inc() { incus "$@" </dev/null; }
wait_agent() {
  for _ in $(seq 1 120); do inc exec "$1" -- true 2>/dev/null && return 0; sleep 2; done
  echo "the VM agent of $1 never answered" >&2
  return 1
}
cleanup() { inc delete --force "$builder" >/dev/null 2>&1 || true; inc delete --force "$smoke" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "== builder VM $builder"
inc launch images:ubuntu/24.04/cloud "$builder" --vm --profile default --profile ci-heavy
wait_agent "$builder"
inc exec "$builder" -- cloud-init status --wait >/dev/null || true
inc file push "$here/provision.sh" "$builder/root/provision.sh"
inc exec "$builder" -- bash /root/provision.sh
inc exec "$builder" -- rm /root/provision.sh
inc stop "$builder"

echo "== publish $alias-$stamp"
inc publish "$builder" --alias "$alias-$stamp"
inc delete --force "$builder"

echo "== smoke VM $smoke"
inc launch "$alias-$stamp" "$smoke" --vm --profile default --profile ci-light
wait_agent "$smoke"
inc exec "$smoke" -- cloud-init status --wait >/dev/null || true
# The variables expand inside the VM, from the runner's own environment.
# shellcheck disable=SC2016
inc exec "$smoke" -- sudo -u runner -H bash -lc '
  set -e
  source ~/.cargo/env
  set -a; source ~/actions-runner/.env; set +a
  cargo --version
  rustup toolchain list
  "$RUSTC_WRAPPER" --version
  wasm-pack --version
  cargo nextest --version
  google-chrome --version
  "$CHROMEWEBDRIVER/chromedriver" --version
  test -x "$ANDROID_NDK_LATEST_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/clang"
  test -x "$ANDROID_HOME/emulator/emulator"
  test -c /dev/kvm
  keyctl session - true >/dev/null
  docker run --rm hello-world | grep -q "Hello from Docker"
  docker image ls --format "{{.Repository}}:{{.Tag}}" | sort
  test -d /srv/cache/sccache
'
inc delete --force "$smoke"

echo "== move $alias to $alias-$stamp"
fingerprint=$(inc image list "$alias-$stamp" --format csv -c f)
inc image alias delete "$alias" >/dev/null 2>&1 || true
inc image alias create "$alias" "$fingerprint"
inc image list --format csv -c lfsu
echo IMAGE-DONE
