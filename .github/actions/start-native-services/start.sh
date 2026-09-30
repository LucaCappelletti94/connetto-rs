#!/usr/bin/env bash
# Starts Postgres, OpenFGA and the mock identity provider as plain processes
# under DIR on a runner that cannot run Linux containers (macOS arm64, and
# Windows x64 under Git Bash), and exports the CONNETTO_STACK_* and
# CONNETTO_POSTGRES_* variables the harness reads, to GITHUB_ENV when set and
# to standard output otherwise. Every PID is written to DIR/pids.
#
#   start.sh DIR
#
# The versions match the images crates/connetto-test-harness starts.
set -euo pipefail

dir=$1
if command -v cygpath > /dev/null; then
  dir=$(cygpath -u "$dir")
fi
here=$(cd "$(dirname "$0")" && pwd)
config="$here/../../../crates/connetto-test-harness/mock-oauth-config.json"

postgres=16.15.0
openfga=1.21.0
mock_oauth=ghcr.io/navikt/mock-oauth2-server:6.0.2
crane=v0.20.3

pg_port=55432
fga_grpc_port=58081
fga_http_port=58080
oauth_port=58090

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64)
    pg_triple=aarch64-apple-darwin fga_os=darwin_arm64 crane_os=Darwin_arm64
    image_platform=linux/arm64 exe='' classpath_separator=:
    ;;
  MINGW64_NT-*-x86_64)
    pg_triple=x86_64-pc-windows-msvc fga_os=windows_amd64 crane_os=Windows_x86_64
    image_platform=linux/amd64 exe=.exe classpath_separator=';'
    ;;
  *)
    echo "start.sh serves macOS arm64 and Windows x64 only" >&2
    exit 1
    ;;
esac

# The harness is a Windows program there, so it needs Windows paths.
native_path() {
  if command -v cygpath > /dev/null; then cygpath -m "$1"; else printf '%s' "$1"; fi
}

mkdir -p "$dir/logs"
cd "$dir"
: > pids

# Download $1 and check it against the checksum line on standard input,
# reporting on standard error so standard output carries only the variables.
fetch_checked() {
  curl -fsSL --retry 3 -o "$(basename "$1")" "$1"
  if command -v shasum > /dev/null; then shasum -a 256 -c >&2; else sha256sum -c >&2; fi
}

pg=postgresql-$postgres-$pg_triple
base=https://github.com/theseus-rs/postgresql-binaries/releases/download/$postgres
curl -fsSL --retry 3 "$base/$pg.tar.gz.sha256" \
  | awk -v file="$pg.tar.gz" '{print $1 "  " file}' \
  | fetch_checked "$base/$pg.tar.gz"
tar xzf "$pg.tar.gz"
"$pg/bin/initdb" -D pgdata -U postgres --auth=trust > logs/initdb.log
"$pg/bin/initdb" -D template -U postgres --auth=trust --no-sync > logs/initdb-template.log
"$pg/bin/pg_ctl" -D pgdata -l logs/postgres.log -w \
  -o "-c wal_level=logical -c fsync=off -c port=$pg_port -c listen_addresses=127.0.0.1" \
  start > /dev/null
head -1 pgdata/postmaster.pid >> pids

fga=openfga_${openfga}_$fga_os.tar.gz
base=https://github.com/openfga/openfga/releases/download/v$openfga
curl -fsSL --retry 3 "$base/checksums.txt" \
  | grep " $fga\$" \
  | fetch_checked "$base/$fga"
mkdir -p openfga
tar xzf "$fga" -C openfga
nohup "openfga/openfga$exe" run \
  --grpc-addr "127.0.0.1:$fga_grpc_port" \
  --http-addr "127.0.0.1:$fga_http_port" \
  --playground-enabled=false \
  --metrics-enabled=false \
  > logs/openfga.log 2>&1 &
echo $! >> pids

# The image's application tree, pulled from the registry without a daemon.
# An empty DOCKER_CONFIG keeps crane anonymous, whatever credential helper the
# machine's own Docker configuration names.
archive=go-containerregistry_$crane_os.tar.gz
base=https://github.com/google/go-containerregistry/releases/download/$crane
curl -fsSL --retry 3 "$base/checksums.txt" \
  | grep " $archive\$" \
  | fetch_checked "$base/$archive"
mkdir -p crane crane-config mock-oauth
tar xzf "$archive" -C crane "crane$exe"
DOCKER_CONFIG="$PWD/crane-config" "crane/crane$exe" export --platform "$image_platform" "$mock_oauth" - \
  | tar x -C mock-oauth app
classpath=mock-oauth/app/resources$classpath_separator
classpath+=mock-oauth/app/classes$classpath_separator
classpath+='mock-oauth/app/libs/*'
JSON_CONFIG=$(cat "$config") SERVER_PORT=$oauth_port nohup "${JAVA_HOME:+$JAVA_HOME/bin/}java" \
  -cp "$classpath" \
  no.nav.security.mock.oauth2.StandaloneMockOAuth2ServerKt \
  > logs/mock-oauth.log 2>&1 &
echo $! >> pids

deadline=$((SECONDS + 120))
until curl -fs "http://127.0.0.1:$fga_http_port/healthz" > /dev/null \
  && curl -fs "http://127.0.0.1:$oauth_port/isalive" > /dev/null; do
  if [ $SECONDS -ge $deadline ]; then
    echo "the services did not answer within 120 s, see $dir/logs" >&2
    exit 1
  fi
  sleep 1
done

variables=(
  "CONNETTO_STACK_POSTGRES_URL=postgres://postgres:postgres@127.0.0.1:$pg_port/postgres"
  "CONNETTO_STACK_OPENFGA_URL=http://127.0.0.1:$fga_grpc_port"
  "CONNETTO_STACK_ISSUER=http://127.0.0.1:$oauth_port/default"
  "CONNETTO_POSTGRES_BIN=$(native_path "$PWD/$pg/bin")"
  "CONNETTO_POSTGRES_TEMPLATE=$(native_path "$PWD/template")"
)
if [ -n "${GITHUB_ENV:-}" ]; then
  printf '%s\n' "${variables[@]}" >> "$GITHUB_ENV"
else
  printf 'export %s\n' "${variables[@]}"
fi
