#!/bin/sh
# Runs inside a disposable candidate image; the caller MUST use --network=none.
# This verifies basic container startup, not production readiness.
set -eu

[ "$(id -u)" = "1654" ] || { echo "FAIL: image smoke must run as UID 1654" >&2; exit 1; }
for binary in dotnet curl dig od tr grep; do
    command -v "$binary" >/dev/null 2>&1 || { echo "FAIL: missing $binary" >&2; exit 1; }
done
[ -f /opt/technitium/dns/DnsServerApp.dll ] || { echo "FAIL: published DNS application missing" >&2; exit 1; }
[ -d /work ] && [ -w /work ] || { echo "FAIL: disposable configuration volume not writable" >&2; exit 1; }

umask 077
mkdir /work/config /work/.dotnet
od -An -N24 -tx1 /dev/urandom | tr -d '[:space:]' > /work/admin-password
[ "$(wc -c < /work/admin-password)" -eq 48 ] || { echo "FAIL: temporary secret generation failed" >&2; exit 1; }

export HOME=/work
export DOTNET_CLI_HOME=/work/.dotnet
export DNS_SERVER_ADMIN_PASSWORD_FILE=/work/admin-password
export DNS_SERVER_WEB_SERVICE_LOCAL_ADDRESSES=127.0.0.1
export DNS_SERVER_WEB_SERVICE_HTTP_PORT=5380
export DNS_SERVER_RECURSION=Deny

dotnet /opt/technitium/dns/DnsServerApp.dll --stop-if-bind-fails --portable-app /work/config > /work/service.log 2>&1 &
service_pid=$!
trap 'kill "$service_pid" 2>/dev/null || true; wait "$service_pid" 2>/dev/null || true' EXIT

ready=no
i=0
while [ "$i" -lt 30 ]; do
    if curl --silent --fail --noproxy '*' --max-time 1 \
        --output /work/console.html http://127.0.0.1:5380/; then
        ready=yes
        break
    fi
    i=$((i + 1))
    sleep 0.5
done
[ "$ready" = yes ] || { echo "FAIL: isolated image console not ready" >&2; exit 1; }
grep -Fq '<title>GoreeCloud DNS</title>' /work/console.html ||
    { echo "FAIL: expected branded console missing" >&2; exit 1; }
echo "PASS: non-root candidate image serves branded loopback console"

dig @127.0.0.1 -p 53 localhost A +time=1 +tries=1 +noall +comments > /work/refusal.txt
grep -Fq 'status: REFUSED' /work/refusal.txt ||
    { echo "FAIL: disabled recursion was not refused" >&2; exit 1; }
echo "PASS: non-root candidate image rejects recursion over UDP"

status="$(curl --silent --show-error --noproxy '*' --max-time 4 \
    --output /work/unauth.json --write-out '%{http_code}' \
    http://127.0.0.1:5380/api/settings/get)"
case "$status" in
    401|403) ;;
    200)
        grep -Eq '"status"[[:space:]]*:[[:space:]]*"invalid-token"' /work/unauth.json ||
            { echo "FAIL: unauthenticated settings unexpectedly succeeded" >&2; exit 1; }
        ! grep -Eq '"response"[[:space:]]*:' /work/unauth.json ||
            { echo "FAIL: unauthenticated settings returned sensitive data" >&2; exit 1; }
        ;;
    *)
        echo "FAIL: unexpected unauthenticated settings status $status" >&2
        exit 1
        ;;
esac
echo "PASS: non-root candidate image denies anonymous settings API"
