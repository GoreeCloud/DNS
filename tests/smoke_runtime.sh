#!/usr/bin/env bash
# Offline smoke-test harness. Intentionally never maps host ports or shares host networking.
set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "Usage: bash tests/smoke_runtime.sh /absolute/path/to/DnsServerApp/bin/Release" >&2
    exit 2
fi
for tool in podman realpath mktemp timeout; do
    command -v "$tool" >/dev/null || { echo "Missing required tool: $tool" >&2; exit 2; }
done

if [ "$(podman info --format '{{.Host.Security.Rootless}}')" != "true" ]; then
    echo "Refusing to run: rootless Podman is required." >&2
    exit 2
fi

release="$(realpath "$1")"
test -f "$release/DnsServerApp.dll" || { echo "Build the application before running this test." >&2; exit 2; }

work="$(mktemp -d /tmp/goreecloud-dns-smoke.XXXXXXXX)"
trap 'rm -rf -- "$work"' EXIT
mkdir -p "$work/app" "$work/config"
cp -a -- "$release/." "$work/app/"
cp -- "$(dirname "$0")/smoke_dns_protocol.pl" "$work/smoke_dns_protocol.pl"
cp -- "$(dirname "$0")/smoke_edns_version.pl" "$work/smoke_edns_version.pl"
cp -- "$(dirname "$0")/smoke_auth_session.pl" "$work/smoke_auth_session.pl"
cp -- "$(dirname "$0")/smoke_authoritative.pl" "$work/smoke_authoritative.pl"
cp -- "$(dirname "$0")/smoke_authoritative_negative.pl" "$work/smoke_authoritative_negative.pl"
cp -- "$(dirname "$0")/smoke_doh_tls.pl" "$work/smoke_doh_tls.pl"
cp -- "$(dirname "$0")/smoke_dot_tls.pl" "$work/smoke_dot_tls.pl"
cp -- "$(dirname "$0")/smoke_login_lockout.pl" "$work/smoke_login_lockout.pl"
cp -- "$(dirname "$0")/smoke_dnssec.pl" "$work/smoke_dnssec.pl"

cat > "$work/run-smoke.sh" <<'SMOKE'
#!/usr/bin/env bash
set -euo pipefail
cd /work/app

# Every explicitly configured invalid secret must fail before first-run auth is saved.
# Keep each case in independent, disposable state. Never start the main server first.
: > /work/empty-admin-password-file
printf '%s' '    ' > /work/whitespace-admin-password-file
for scenario in missing empty whitespace; do
    case "$scenario" in
        missing) secret_file=/work/absent-admin-password-file ;;
        empty) secret_file=/work/empty-admin-password-file ;;
        whitespace) secret_file=/work/whitespace-admin-password-file ;;
    esac
    test -n "$secret_file" || { echo "FAIL: invalid secret test setup"; exit 1; }
    test "$scenario" != missing || test ! -e "$secret_file" || { echo "FAIL: missing-secret case exists"; exit 1; }
    mkdir -p "/work/$scenario-admin-config"
    failed_status=0
    timeout 12s env DNS_SERVER_ADMIN_PASSWORD_FILE="$secret_file" \
        dotnet DnsServerApp.dll --stop-if-bind-fails --portable-app "/work/$scenario-admin-config" \
        > "/work/$scenario-admin.log" 2>&1 || failed_status=$?
    if [ "$failed_status" -eq 0 ] || [ "$failed_status" -eq 124 ] ||
       [ "$failed_status" -eq 125 ] || [ "$failed_status" -eq 126 ] ||
       [ "$failed_status" -eq 127 ] || [ "$failed_status" -eq 137 ] ||
       ! grep -Fq "Could not initialize administrator credentials from DNS_SERVER_ADMIN_PASSWORD_FILE." "/work/$scenario-admin.log"; then
        echo "FAIL: $scenario administrator password file did not fail closed (exit $failed_status)" >&2
        exit 1
    fi
    echo "PASS: $scenario admin password file fails closed"
done

umask 077
od -An -N24 -tx1 /dev/urandom | tr -d '[:space:]' > /work/admin-password
[ "$(wc -c < /work/admin-password)" -eq 48 ] || { echo "FAIL: cannot generate temporary administrator secret"; exit 1; }
DNS_SERVER_ADMIN_PASSWORD_FILE=/work/admin-password dotnet DnsServerApp.dll --stop-if-bind-fails --portable-app /work/config > /work/service.log 2>&1 &
service_pid=$!
trap 'kill "$service_pid" 2>/dev/null || true; wait "$service_pid" 2>/dev/null || true' EXIT

ready=false
for i in $(seq 1 25); do
    if curl --fail --silent --max-time 1 -o /work/console.html http://127.0.0.1:5380/; then
        ready=true
        break
    fi
    sleep 0.5
done
if [ "$ready" != true ]; then
    echo "FAIL: DNS console did not respond on the isolated loopback interface." >&2
    exit 1
fi
grep -Fq '<title>GoreeCloud DNS</title>' /work/console.html || { echo "FAIL: console title"; exit 1; }
echo "PASS: GoreeCloud console responds with HTTP 200"

curl --fail --silent --max-time 3 http://127.0.0.1:5380/css/goreecloud.css |
    grep -Fq "gc-skip-link" || { echo "FAIL: GoreeCloud styles unavailable"; exit 1; }
echo "PASS: branded console CSS served"

# A second instance sharing the same isolated loopback listeners must fail quickly.
# Use independent disposable configuration; do not interact with any host ports.
mkdir -p /work/bind-collision-config
collision_status=0
timeout 12s env DNS_SERVER_ADMIN_PASSWORD_FILE=/work/admin-password \
    dotnet DnsServerApp.dll --stop-if-bind-fails --portable-app /work/bind-collision-config \
    > /work/bind-collision.log 2>&1 || collision_status=$?
if [ "$collision_status" -eq 0 ] || [ "$collision_status" -eq 124 ] ||
   [ "$collision_status" -eq 125 ] || [ "$collision_status" -eq 126 ] ||
   [ "$collision_status" -eq 127 ] || [ "$collision_status" -eq 137 ] ||
   ! grep -Eiq 'address already in use|failed to bind|AddressInUse' /work/bind-collision.log; then
    echo "FAIL: duplicate server did not report an unsuccessful listener bind (exit $collision_status)" >&2
    exit 1
fi
curl --fail --silent --max-time 3 -o /dev/null http://127.0.0.1:5380/ ||
    { echo "FAIL: primary DNS console died after bind collision" >&2; exit 1; }
echo "PASS: duplicate listener startup fails without stopping primary service"

perl /work/smoke_dns_protocol.pl udp
perl /work/smoke_dns_protocol.pl tcp
perl /work/smoke_edns_version.pl

status_code="$(curl --silent --show-error --max-time 4 -o /work/unauth-settings.json -w '%{http_code}' http://127.0.0.1:5380/api/settings/get)"
case "$status_code" in
    401|403)
        echo "PASS: settings API rejects unauthenticated access (HTTP $status_code)"
        ;;
    200)
        if grep -Eiq '"status"[[:space:]]*:[[:space:]]*"invalid-token"' /work/unauth-settings.json &&
           ! grep -Eq '"response"[[:space:]]*:' /work/unauth-settings.json; then
            echo "PASS: settings API rejects unauthenticated access in error response"
        else
            echo "FAIL: settings API may expose data without authentication" >&2
            exit 1
        fi
        ;;
    *)
        echo "FAIL: unexpected unauthenticated settings API HTTP status $status_code" >&2
        exit 1
        ;;
esac

perl /work/smoke_auth_session.pl
perl /work/smoke_login_lockout.pl

echo "PASS: isolated runtime smoke tests"
SMOKE

image="mcr.microsoft.com/dotnet/sdk@sha256:9c7b6b263d9d4c2e4718e16dae6d75cd8f4b5ccf206f1e7d48a98eb429981b03"
timeout 55s podman run --rm \
    --network=none --user=0:0 --cap-drop=ALL --cap-add=NET_BIND_SERVICE \
    --security-opt=no-new-privileges --pids-limit=128 --memory=1g \
    -e DOTNET_CLI_HOME=/work/.dotnet \
    -e DNS_SERVER_WEB_SERVICE_LOCAL_ADDRESSES=127.0.0.1 \
    -e DNS_SERVER_WEB_SERVICE_HTTP_PORT=5380 \
    -e DNS_SERVER_RECURSION=Deny \
    -v "$work:/work:Z" -w /work "$image" bash /work/run-smoke.sh
