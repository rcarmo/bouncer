#!/usr/bin/env bash
set -euo pipefail
read -r -a engine <<< "${CONTAINER_ENGINE:-docker}"
engine_run() { "${engine[@]}" "$@"; }
image=${CONTAINER_IMAGE:-bouncer:security-local}
profiling=${BOUNCER_PROFILE_CONTAINER:-0}
root=${WORKSPACE_TEST_DIR:?Run through Make to select project-scoped test storage}/container
tags=
profile_dir=
if [[ "$profiling" == 1 ]]; then root=${PROFILE_ROOT:?PROFILE_ROOT required}; tags=allocprofile; profile_dir=/data; fi
mkdir -p "$root"
out=$(mktemp -d "$root/$(date -u +%Y%m%dT%H%M%SZ)-container-XXXXXX")
out=$(cd "$out" && pwd)
name="bouncer-security-$$"
trap 'engine_run rm -fv "$name" >/dev/null 2>&1 || true' EXIT
engine_run build --build-arg GO_BUILD_TAGS="$tags" --build-arg VERSION=security-test -t "$image" . > "$out/build.log" 2>&1
# Use the real entrypoint and image-owned anonymous volume, but disable external
# GeoIP downloads. Container validation must not depend on a live data provider.
cat > "$out/input.yaml" <<'YAML'
ingresses:
  - id: lan
    type: local
    siteIds: [default]
    local: {listen: ":443", tls: local-ca}
  - id: trust
    type: local
    siteIds: [default]
    local: {listen: ":80", tls: "off", bootstrap: true}
onboarding:
  geoip: {enabled: false}
YAML
# This public fixture must be readable before Bouncer atomically replaces it
# with mode-0600 state owned by the non-root process.
chmod 0644 "$out/input.yaml"
engine_run create --name "$name" -e BOUNCER_ALLOC_PROFILE_DIR="$profile_dir" -p 127.0.0.1::443 -p 127.0.0.1::80 "$image" > "$out/container-id.txt"
engine_run cp "$out/input.yaml" "$name":/data/bouncer.yaml
engine_run start "$name" > /dev/null
port=$(engine_run port "$name" 443/tcp | head -1 | sed 's/.*://')
ready=0
for i in $(seq 1 100); do
 if curl -ksSf --max-time 1 -H 'Host: bouncer.local' "https://127.0.0.1:$port/login" > "$out/login.html"; then ready=1;break;fi
 sleep .1
done
[[ "$ready" == 1 ]] || { engine_run logs "$name";exit 1; }
[[ $(engine_run exec "$name" id -u) == 10001 ]]
engine_run exec "$name" sh -c 'test -w /data && test -f /data/bouncer.yaml && test -w /data/bouncer.yaml && test -n "$(getcap /usr/local/bin/bouncer)"'
httpport=$(engine_run port "$name" 80/tcp | head -1 | sed 's/.*://')
curl -sf --max-time 2 -H 'Host: bouncer.local' "http://127.0.0.1:$httpport/login" > /dev/null
engine_run stop --time 10 "$name" > /dev/null
[[ $(engine_run inspect -f '{{.State.ExitCode}}' "$name") == 0 ]]
engine_run logs "$name" > "$out/server.log" 2>&1
if [[ "$profiling" == 1 ]]; then
mkdir -p "$out/state"
engine_run cp "$name":/data/. "$out/state/" > /dev/null
# Profiles may include private identifiers/keys in temporary state; retain locally only.
profile=$(find "$out/state" -name 'server-*.pprof' | head -1)
[[ -s "$profile" ]] || { echo 'Missing allocation profile' >&2;exit 1; }
engine_run cp "$name":/usr/local/bin/bouncer "$out/bouncer.test"
go tool pprof -top -sample_index=alloc_space "$out/bouncer.test" "$profile" > "$out/alloc_space.txt"
go tool pprof -top -sample_index=alloc_objects "$out/bouncer.test" "$profile" > "$out/alloc_objects.txt"
mv "$profile" "$out/"
rm -rf -- "$out/state"
fi
echo "PASS: UID10001, writable state, HTTP:80/TLS:443, graceful shutdown. Evidence: $out"
