#!/usr/bin/env bash
# Disposable two-container restart test. NEVER use a production volume.
set -euo pipefail
if [ "$#" -ne 1 ]; then
  echo "Usage: bash tests/smoke_release_persistence.sh <prebuilt-local-image-tag>" >&2
  exit 2
fi
image="$1"
command -v podman >/dev/null || { echo "Podman is required" >&2; exit 2; }
test "$(podman info --format '{{.Host.Security.Rootless}}')" = "true"
podman image exists "$image"
root="$(mktemp -d /tmp/goreecloud-dns-restart-check.XXXXXXXX)"
cleanup() {
  podman unshare rm -rf -- "$root" 2>/dev/null || true
  rm -rf -- "$root" 2>/dev/null || true
}
trap cleanup EXIT
mkdir "$root/volume"
cat > "$root/inner.sh" <<'INNER'
#!/bin/sh
set -eu
test "$(id -u)" = 1654
test -d /sys/class/net/lo
for item in /sys/class/net/*; do
  test "$(basename "$item")" = lo || exit 33
done
umask 077
if [ "$PHASE" = first ]; then
  mkdir /work/config /work/.dotnet
  od -An -N24 -tx1 /dev/urandom | tr -d '[:space:]' > /work/admin-password
  test "$(wc -c < /work/admin-password)" -eq 48
else
  test -s /work/admin-password
  find /work/config -type f -size +0c | grep -q .
fi
export HOME=/work
export DOTNET_CLI_HOME=/work/.dotnet
export DNS_SERVER_ADMIN_PASSWORD_FILE=/work/admin-password
export DNS_SERVER_WEB_SERVICE_LOCAL_ADDRESSES=127.0.0.1
export DNS_SERVER_WEB_SERVICE_HTTP_PORT=5380
export DNS_SERVER_RECURSION=Deny
dotnet /opt/technitium/dns/DnsServerApp.dll --stop-if-bind-fails --portable-app /work/config >/work/phase-"$PHASE".log 2>&1 &
pid=$!
trap 'kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true' EXIT
ready=no
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25; do
  if curl --silent --fail --noproxy '*' --max-time 1 -o /work/console-"$PHASE".html http://127.0.0.1:5380/; then
    ready=yes
    break
  fi
  sleep 0.5
done
test "$ready" = yes
grep -Fq '<title>GoreeCloud DNS</title>' /work/console-"$PHASE".html
dig @127.0.0.1 -p 53 localhost A +time=1 +tries=1 +noall +comments >/work/refused-"$PHASE".txt
grep -q 'status: REFUSED' /work/refused-"$PHASE".txt
echo "PASS: non-root $PHASE start with disposable persisted configuration"
INNER
podman unshare chown 1654:1654 "$root/volume"
for phase in first second; do
  timeout 55s podman run --rm --pull=never --network=none --user=1654:1654 \
    --cap-drop=ALL --cap-add=NET_BIND_SERVICE \
    --security-opt=no-new-privileges --pids-limit=128 --memory=1g \
    -e "PHASE=$phase" \
    -v "$root/volume:/work:Z" -v "$root/inner.sh:/restart-test.sh:ro,Z" \
    --entrypoint /bin/sh "$image" /restart-test.sh
done
echo "PASS: second disposable non-root container restart succeeded"
