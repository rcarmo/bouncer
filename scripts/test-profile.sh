#!/usr/bin/env bash
# Run every test workload with allocation evidence. Called only through Make.
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
mode=${1:?test mode required}
root=${PROFILE_ROOT:-artifacts/allocations}
mkdir -p "$root"
run=$(mktemp -d "$root/$(date -u +%Y%m%dT%H%M%SZ)-$mode-XXXXXX")
run=$(cd "$run" && pwd)
echo "Allocation evidence: $run"
{
  printf 'mode=%s\nmemprofilerate=1\nflags=%s\n' "$mode" "${TEST_FLAGS:-}"
  go version
  git rev-parse HEAD
  git diff --stat
} > "$run/run.txt"
read -r -a flags <<< "${TEST_FLAGS:-}"
read -r -a packages <<< "${TEST_PACKAGES:-./...}"
go_flags=()
expected_servers=0
case "$mode" in
  test|coverage|bench) ;;
  race) go_flags+=(-race) ;;
  integration|integration-race)
    packages=(.)
    go_flags+=(-tags=integration)
    flags=(-run TestProcessStreams "${flags[@]}")
    expected_servers=1
    ;;
  browser|browser-tls) expected_servers=2 ;;
  *) echo "Unknown test mode: $mode" >&2; exit 2 ;;
esac
if [[ "$mode" == integration-race ]]; then go_flags+=(-race); fi
if ((expected_servers)); then
  build_flags=(-tags=allocprofile)
  if [[ "$mode" == integration-race ]]; then build_flags+=(-race); fi
  # Keep symbols for allocation analysis; each run retains its own executable.
  go build "${build_flags[@]}" -o "$run/bouncer" .
  export BOUNCER_TEST_BINARY="$run/bouncer"
  export BOUNCER_ALLOC_PROFILE_DIR="$run"
fi
status=0
if [[ "$mode" == browser* ]]; then
  export BOUNCER_TEST_TLS=0
  if [[ "$mode" == browser-tls ]]; then export BOUNCER_TEST_TLS=1; fi
  bun run scripts/browser-smoke.ts 2>&1 | tee "$run/tests.log" || status=$?
else
  go list "${go_flags[@]}" -f '{{if or .TestGoFiles .XTestGoFiles}}{{.ImportPath}}{{end}}' "${packages[@]}" > "$run/packages.txt"
  count=0
  while IFS= read -r pkg; do
    [[ -n "$pkg" ]] || continue
    count=$((count+1))
    name=${pkg//\//_}
    extra=()
    if [[ "$mode" == coverage ]]; then extra+=(-coverprofile="$run/$name.cover"); fi
    if [[ "$mode" == bench ]]; then extra+=(-run '^$' -bench . -benchmem); fi
    go test "${go_flags[@]}" "${extra[@]}" "${flags[@]}" \
      -count=1 -timeout=5m -memprofilerate=1 \
      -memprofile="$run/$name.pprof" -o "$run/$name.test" \
      "$pkg" 2>&1 | tee -a "$run/tests.log" || status=$?
    if [[ ! -s "$run/$name.pprof" ]]; then echo "Missing allocation profile: $pkg" >&2; status=1; fi
  done < "$run/packages.txt"
  if ((count == 0)); then echo 'No test packages selected' >&2; status=1; fi
  if [[ "$mode" == coverage ]]; then
    echo 'mode: set' > "$run/coverage.out"
    for coverage in "$run"/*.cover; do [[ -f "$coverage" ]] && tail -n +2 "$coverage" >> "$run/coverage.out"; done
    go tool cover -func="$run/coverage.out" | tee "$run/coverage.txt" || status=$?
  fi
fi
shopt -s nullglob
server_profiles=("$run"/server-*.pprof)
if ((${#server_profiles[@]} < expected_servers)); then
  echo "Expected at least $expected_servers server profiles, got ${#server_profiles[@]}" >&2
  status=1
fi
profiles=("$run"/*.pprof)
if ((${#profiles[@]} == 0)); then echo 'No allocation profiles written' >&2; status=1; fi
for profile in "${profiles[@]}"; do
  for metric in alloc_space alloc_objects; do
    go tool pprof -top -"$metric" "$profile" > "${profile%.pprof}.$metric.txt" 2>&1 || status=$?
  done
done
printf 'exit_status=%s\nprofiles=%s\n' "$status" "${#profiles[@]}" >> "$run/run.txt"
echo "Allocation profiles and summaries: $run (${#profiles[@]} profiles)"
exit "$status"
