#!/usr/bin/env bash
# Fills the action archive cache every runner VM reads through ACTIONS_RUNNER_ACTION_ARCHIVE_CACHE.
#
# Each runner VM starts empty, and anonymous action downloads from emi's address
# get rate limited by codeload.github.com (HTTP 429). This downloads every action
# the workflows on main and on open same-repository pull requests use, including
# the ones composite actions call, with the GitHub App's token, into
# <owner>_<repo>/<sha>.tar.gz, the layout the runner looks up.
# Runs as ci-runner. Re-runnable: archives already present are kept.
set -euo pipefail

REPO=LucaCappelletti94/connetto-rs
APP_ID=5319459
INSTALLATION_ID=171457690
KEY=$HOME/garm/github-app.pem
CACHE=/srv/ci-cache/actions

b64() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
now=$(date +%s)
header=$(printf '{"alg":"RS256","typ":"JWT"}' | b64)
payload=$(printf '{"iat":%d,"exp":%d,"iss":"%s"}' $((now - 60)) $((now + 540)) "$APP_ID" | b64)
signature=$(printf '%s.%s' "$header" "$payload" | openssl dgst -sha256 -sign "$KEY" | b64)
token=$(curl -fsS -X POST -H "Authorization: Bearer $header.$payload.$signature" \
  -H "Accept: application/vnd.github+json" \
  "https://api.github.com/app/installations/$INSTALLATION_ID/access_tokens" | jq -r .token)
api() { curl -fsSL -H "Authorization: Bearer $token" -H "Accept: application/vnd.github+json" "$@"; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Every `uses: owner/repo[/path]@ref` in a file, one per line, local and docker references skipped.
uses_in() { grep -hoE '^\s*-?\s*uses:\s*[^ #]+' "$@" 2>/dev/null | sed -E 's/^\s*-?\s*uses:\s*//; s/["'\'']//g' | grep -vE '^(\./|docker://)' | grep '@' || true; }

echo "== workflow files on main and on open same-repository pull requests"
refs=$(api "https://api.github.com/repos/$REPO/commits/main" | jq -r .sha)
refs+=" $(api "https://api.github.com/repos/$REPO/pulls?state=open&per_page=100" \
  | jq -r --arg r "$REPO" '.[] | select(.head.repo.full_name == $r) | .head.sha')"
for sha in $refs; do
  api "https://api.github.com/repos/$REPO/git/trees/$sha?recursive=1" \
    | jq -r '.tree[] | select(.type == "blob") | .path | select(test("^\\.github/(workflows/[^/]+\\.ya?ml|actions/.+/action\\.ya?ml)$"))' \
    | while read -r path; do
        api -H "Accept: application/vnd.github.raw" "https://api.github.com/repos/$REPO/contents/$path?ref=$sha" > "$work/$(echo "$sha-$path" | tr '/' '_')"
      done
done
uses_in "$work"/* | sort -u > "$work/queue"

echo "== archives, nested composite actions included"
: > "$work/seen"
failed=0
while [ -s "$work/queue" ]; do
  next=$(head -n 1 "$work/queue")
  sed -i 1d "$work/queue"
  grep -qxF "$next" "$work/seen" && continue
  echo "$next" >> "$work/seen"
  spec=${next%@*} ref=${next##*@}
  owner_repo=$(cut -d/ -f1-2 <<<"$spec")
  subpath=$(cut -d/ -f3- -s <<<"$spec")
  if [[ $ref =~ ^[0-9a-f]{40}$ ]]; then sha=$ref; else sha=$(api "https://api.github.com/repos/$owner_repo/commits/$ref" | jq -r .sha); fi
  dest="$CACHE/${owner_repo//\//_}/$sha.tar.gz"
  if [ ! -s "$dest" ]; then
    mkdir -p "$(dirname "$dest")"
    # The tarball redirects to codeload without the token, where emi's address meets 429s, so retry and move on.
    if api --retry 5 --retry-delay 30 "https://api.github.com/repos/$owner_repo/tarball/$sha" -o "$dest.part"; then
      mv "$dest.part" "$dest"
      echo "fetched $owner_repo@$sha"
    else
      rm -f "$dest.part"
      echo "could not fetch $owner_repo@$sha" >&2
      failed=$((failed + 1))
      continue
    fi
  fi
  # A composite action's own `uses:` lines need their archives too.
  mkdir -p "$work/x"
  tar -xzf "$dest" -C "$work/x" --wildcards "*/${subpath:+$subpath/}action.y*ml" 2>/dev/null || true
  find "$work/x" -name 'action.y*ml' -print0 | xargs -0 -r cat | uses_in /dev/stdin | sort -u >> "$work/queue" || true
  rm -rf "$work/x"
done
echo "== cache holds $(find "$CACHE" -name '*.tar.gz' | wc -l) archives, $(du -sh "$CACHE" | cut -f1)"
# The next timer run fetches what failed here.
[ "$failed" -eq 0 ] || { echo "$failed archives could not be fetched" >&2; exit 1; }
