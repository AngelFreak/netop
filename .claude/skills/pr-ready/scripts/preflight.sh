#!/usr/bin/env bash
# Local mirror of .github/workflows/build.yml for netop.
# Usage: preflight.sh [--quick]   (--quick skips go test -race)
set -u
cd "$(git rev-parse --show-toplevel)" || exit 2

QUICK=0
[ "${1:-}" = "--quick" ] && QUICK=1

FAIL=0
ok()  { printf '\033[1;32m[PASS]\033[0m %s\n' "$*"; }
bad() { printf '\033[1;31m[FAIL]\033[0m %s\n' "$*"; FAIL=1; }
run() { # run <label> <cmd...>
  local label=$1; shift
  if out=$("$@" 2>&1); then ok "$label"; else bad "$label"; printf '%s\n' "$out" | sed 's/^/    /'; fi
}

branch=$(git branch --show-current)
if [ "$branch" = "master" ] || [ "$branch" = "main" ]; then
  bad "on '$branch' - create a feature branch first (git checkout -b fix/name)"
  exit 1
fi
ok "branch: $branch"

unformatted=$(gofmt -l .)
if [ -n "$unformatted" ]; then
  bad "gofmt (run: gofmt -w $(echo "$unformatted" | tr '\n' ' '))"
  printf '%s\n' "$unformatted" | sed 's/^/    /'
else
  ok "gofmt"
fi

run "go vet ./..."                   go vet ./...
run "go vet -tags integration ./..." go vet -tags integration ./...

# Cross-build matrix from build.yml. darwin catches missing !linux stubs.
for target in linux/amd64 linux/arm64 linux/arm/7 darwin/amd64 darwin/arm64; do
  IFS=/ read -r goos goarch goarm <<<"$target"
  run "build $target" env CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" GOARM="${goarm:-}" \
      go build -ldflags="-s -w" -o /dev/null ./cmd/net
done

if [ "$QUICK" = 1 ]; then
  printf '\033[1;33m[SKIP]\033[0m go test -race ./... (--quick)\n'
else
  run "go test -race ./..." go test -race ./...
fi

echo
if [ "$FAIL" = 0 ]; then
  echo "preflight: all gates passed"
else
  echo "preflight: FAILED - fix the items above before pushing"
fi
exit "$FAIL"
