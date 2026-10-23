#!/usr/bin/env bash
# Provisions connetto's CI golden image inside a fresh Ubuntu 24.04 VM, as root.
#
# Mirrors what the GitHub-hosted ubuntu-24.04 image gives the workflows (paths,
# environment variables, Chrome and its driver, the Android SDK and NDKs, Java 17,
# Docker), plus what only a self-hosted runner can keep warm: toolchains, the
# test images and sccache pointed at the host cache.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

RUNNER=runner
# Matches the owner of the host caches, set by host-setup.sh.
RUNNER_UID=1001
MIRROR=http://10.77.0.1:5000
SDK=/usr/local/lib/android/sdk
CMDLINE_TOOLS=commandlinetools-linux-13114758_latest.zip
NDK_DEFAULT=27.3.13750724
NDK_LATEST=30.0.16248370
SCCACHE_VERSION=v0.18.0
WASM_PACK_VERSION=0.14.0
CACHE=/srv/cache

echo "== packages"
apt-get update
apt-get install -y --no-install-recommends \
  build-essential pkg-config libssl-dev clang lld cmake git git-lfs curl wget jq unzip zip xz-utils file \
  ca-certificates gnupg sudo openssh-client \
  docker.io docker-buildx docker-compose-v2 \
  keyutils dbus dbus-x11 gnome-keyring libsecret-1-dev \
  libwebkit2gtk-4.1-dev libxdo-dev libayatana-appindicator3-dev librsvg2-dev \
  openjdk-17-jdk-headless python3 python3-pip \
  postgresql
# Installed like GitHub's image, server programs present and the service off.
systemctl disable --now postgresql

echo "== runner account, uid $RUNNER_UID, passwordless sudo, docker and kvm"
id "$RUNNER" >/dev/null 2>&1 || useradd --create-home --uid "$RUNNER_UID" --shell /bin/bash "$RUNNER"
usermod -aG docker,kvm,sudo "$RUNNER"
echo "$RUNNER ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/90-$RUNNER"
chmod 0440 "/etc/sudoers.d/90-$RUNNER"

echo "== Docker pulls through the host mirror, test images pre-pulled"
mkdir -p /etc/docker
printf '{"registry-mirrors":["%s"]}\n' "$MIRROR" > /etc/docker/daemon.json
systemctl restart docker
for image in postgres:16 postgres:18 openfga/openfga:v1.21.0 ghcr.io/navikt/mock-oauth2-server:6.0.2 python:3.12-slim-bookworm; do
  docker pull --quiet "$image"
done

echo "== Google Chrome and the ChromeDriver of the same build"
curl -fsSL https://dl.google.com/linux/linux_signing_key.pub | gpg --dearmor -o /etc/apt/keyrings/google-chrome.gpg
echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/google-chrome.gpg] https://dl.google.com/linux/chrome/deb/ stable main" \
  > /etc/apt/sources.list.d/google-chrome.list
apt-get update
apt-get install -y --no-install-recommends google-chrome-stable
chrome_build=$(google-chrome --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)
driver_url=$(curl -fsSL https://googlechromelabs.github.io/chrome-for-testing/latest-patch-versions-per-build-with-downloads.json \
  | jq -r --arg b "$chrome_build" '.builds[$b].downloads.chromedriver[] | select(.platform == "linux64") | .url')
curl -fsSL "$driver_url" -o /tmp/chromedriver.zip
rm -rf /usr/local/share/chromedriver-linux64
unzip -q /tmp/chromedriver.zip -d /usr/local/share
ln -sf /usr/local/share/chromedriver-linux64/chromedriver /usr/local/bin/chromedriver

echo "== Android SDK at the hosted image's path, API 35 emulator image, NDK $NDK_DEFAULT and $NDK_LATEST"
mkdir -p "$SDK/cmdline-tools"
curl -fsSL "https://dl.google.com/android/repository/$CMDLINE_TOOLS" -o /tmp/cmdline-tools.zip
rm -rf "$SDK/cmdline-tools/latest"
unzip -q /tmp/cmdline-tools.zip -d "$SDK/cmdline-tools"
mv "$SDK/cmdline-tools/cmdline-tools" "$SDK/cmdline-tools/latest"
# A process substitution, because `yes | sdkmanager` ends `yes` with SIGPIPE, which pipefail turns into a failure.
"$SDK/cmdline-tools/latest/bin/sdkmanager" --sdk_root="$SDK" --licenses < <(yes) >/dev/null
"$SDK/cmdline-tools/latest/bin/sdkmanager" --sdk_root="$SDK" \
  "platform-tools" "emulator" "platforms;android-35" "build-tools;35.0.0" \
  "system-images;android-35;google_apis;x86_64" "ndk;$NDK_DEFAULT" "ndk;$NDK_LATEST" >/dev/null
chown -R "$RUNNER:$RUNNER" "$SDK"

echo "== sccache $SCCACHE_VERSION"
curl -fsSL "https://github.com/mozilla/sccache/releases/download/$SCCACHE_VERSION/sccache-$SCCACHE_VERSION-x86_64-unknown-linux-musl.tar.gz" \
  | tar xz -C /tmp
install -m 0755 "/tmp/sccache-$SCCACHE_VERSION-x86_64-unknown-linux-musl/sccache" /usr/local/bin/sccache

echo "== Rust for $RUNNER: stable and nightly, wasm, clippy, rustfmt, llvm-tools, nextest, wasm-pack"
sudo -u "$RUNNER" -H bash -euo pipefail <<EOF
curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable \
  -c clippy -c rustfmt -c llvm-tools-preview -t wasm32-unknown-unknown
source ~/.cargo/env
rustup toolchain install nightly --profile minimal -c clippy -t wasm32-unknown-unknown
curl -fsSL https://get.nexte.st/latest/linux | tar xz -C ~/.cargo/bin
cargo install wasm-pack --locked --version $WASM_PACK_VERSION
# The registry lives on the host, shared by every VM. Git checkouts stay local, because
# libgit2 needs shared mmap, which virtiofs refuses here.
rm -rf ~/.cargo/registry
ln -s $CACHE/cargo-registry ~/.cargo/registry
# Every git dependency main locks, fetched into the image, so a job fetches only what moved since.
git clone -q --depth 1 https://github.com/connetto-rs/connetto-rs /tmp/connetto-rs
for lock in /tmp/connetto-rs/Cargo.lock /tmp/connetto-rs/crates/*/Cargo.lock /tmp/connetto-rs/examples/*/Cargo.lock; do
  (cd "\$(dirname "\$lock")" && CARGO_NET_GIT_FETCH_WITH_CLI=true cargo fetch --locked)
done
rm -rf /tmp/connetto-rs
EOF

echo "== The GitHub Actions runner, extracted where GARM looks for a cached copy"
run_home="/home/$RUNNER/actions-runner"
install -d -o "$RUNNER" -g "$RUNNER" "$run_home"
release=$(curl -fsSL https://api.github.com/repos/actions/runner/releases/latest)
asset=$(jq -r '.assets[] | select(.name | test("^actions-runner-linux-x64-[0-9.]+\\.tar\\.gz$"))' <<<"$release")
curl -fsSL "$(jq -r .browser_download_url <<<"$asset")" -o /tmp/actions-runner.tar.gz
echo "$(jq -r '.digest | sub("^sha256:"; "")' <<<"$asset")  /tmp/actions-runner.tar.gz" | sha256sum -c --status
tar xzf /tmp/actions-runner.tar.gz -C "$run_home"
"$run_home/bin/installdependencies.sh" >/dev/null
chown -R "$RUNNER:$RUNNER" "$run_home"

echo "== Job hooks: the VM's peak memory and sccache's statistics, printed in every job's log"
install -d /opt/ci-hooks
cat > /opt/ci-hooks/job-started.sh <<'EOF'
#!/usr/bin/env bash
# Samples the VM's memory in use until the job-completed hook stops it.
setsid nohup bash -c 'peak=0; while :; do
  used=$(awk "/^MemTotal:/{t=\$2} /^MemAvailable:/{a=\$2} END{print t-a}" /proc/meminfo)
  if [ "$used" -gt "$peak" ]; then peak=$used; echo "$peak" > /tmp/ci-mem-peak-kib; fi
  sleep 2
done' >/dev/null 2>&1 &
echo $! > /tmp/ci-mem-sampler.pid
sccache --zero-stats >/dev/null 2>&1 || true
EOF
cat > /opt/ci-hooks/job-completed.sh <<'EOF'
#!/usr/bin/env bash
# Prints what the speed work measures, each line prefixed so it can be grepped from the log.
kill "$(cat /tmp/ci-mem-sampler.pid 2>/dev/null)" 2>/dev/null || true
echo "ci-measure peak-memory-mib=$(( $(cat /tmp/ci-mem-peak-kib 2>/dev/null || echo 0) / 1024 ))"
sccache --show-stats 2>/dev/null | sed 's/^/ci-measure sccache /' || echo "ci-measure sccache unavailable"
EOF
chmod 0755 /opt/ci-hooks/job-started.sh /opt/ci-hooks/job-completed.sh

echo "== Environment the runner hands every job, the hosted image's names plus the caches"
cat > "$run_home/.env" <<EOF
LANG=C.UTF-8
JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
JAVA_HOME_17_X64=/usr/lib/jvm/java-17-openjdk-amd64
ANDROID_HOME=$SDK
ANDROID_SDK_ROOT=$SDK
ANDROID_NDK=$SDK/ndk/$NDK_DEFAULT
ANDROID_NDK_HOME=$SDK/ndk/$NDK_DEFAULT
ANDROID_NDK_ROOT=$SDK/ndk/$NDK_DEFAULT
ANDROID_NDK_LATEST_HOME=$SDK/ndk/$NDK_LATEST
CHROMEWEBDRIVER=/usr/local/share/chromedriver-linux64
RUSTC_WRAPPER=/usr/local/bin/sccache
SCCACHE_DIR=$CACHE/sccache
SCCACHE_CACHE_SIZE=300G
ACTIONS_RUNNER_ACTION_ARCHIVE_CACHE=$CACHE/actions
CARGO_NET_GIT_FETCH_WITH_CLI=true
CARGO_NET_RETRY=10
SCCACHE_IDLE_TIMEOUT=0
ACTIONS_RUNNER_HOOK_JOB_STARTED=/opt/ci-hooks/job-started.sh
ACTIONS_RUNNER_HOOK_JOB_COMPLETED=/opt/ci-hooks/job-completed.sh
EOF
echo "/home/$RUNNER/.cargo/bin:$SDK/platform-tools:$SDK/cmdline-tools/latest/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
  > "$run_home/.path"
chown "$RUNNER:$RUNNER" "$run_home/.env" "$run_home/.path"

echo "== Trim the image"
apt-get clean
rm -rf /var/lib/apt/lists/* /tmp/* /root/.cache
cloud-init clean --logs --seed
truncate -s 0 /etc/machine-id
echo "PROVISION-DONE"
