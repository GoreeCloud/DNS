#!/bin/sh
# Only in a disposable non-root image with --network=none and no host port mappings.
set -eu
[ "$(id -u)" = 1654 ] || { echo "FAIL: expected uid1654";exit 1; }
[ -f /.dockerenv ] || [ -f /run/.containerenv ] || { echo "FAIL: container only";exit 1; }
for link in /sys/class/net/*;do
 case "$link" in /sys/class/net/lo) ;; *) echo "FAIL: external interface";exit 1;; esac
done
[ -f /lab/output/AdvancedBlocking-v2.zip ] && [ -f /opt/technitium/dns/DnsServerApp.dll ] || { echo "FAIL: artifact missing";exit 1; }
expected=74dcaad61ec3ab3835d3d56528fc74bb827efe4b9073a7bd51db26c6f68e75b2
actual="$(sha256sum /lab/output/AdvancedBlocking-v2.zip | cut -d ' ' -f1)"
[ "$actual" = "$expected" ] || { echo "FAIL: synthetic app checksum mismatch";exit 1; }
umask 077
mkdir /work/config /work/.dotnet
cp /lab/output/AdvancedBlocking-v2.zip /work/AdvancedBlocking.zip
cp /lab/tests/smoke_advanced_runtime.pl /work/smoke_advanced_runtime.pl
cp /lab/tests/synthetic_offline_dns_upstream.pl /work/synthetic_offline_dns_upstream.pl
od -An -N24 -tx1 /dev/urandom|tr -d '[:space:]' > /work/admin-password
[ "$(wc -c < /work/admin-password)" -eq 48 ] || { echo "FAIL: password generation";exit 1; }
export HOME=/work DOTNET_CLI_HOME=/work/.dotnet
export DNS_SERVER_ADMIN_PASSWORD_FILE=/work/admin-password
export DNS_SERVER_WEB_SERVICE_LOCAL_ADDRESSES=127.0.0.1 DNS_SERVER_WEB_SERVICE_HTTP_PORT=5380
export DNS_SERVER_RECURSION=Deny
perl /work/synthetic_offline_dns_upstream.pl > /work/offline-upstream.log 2>&1 &
upstream_pid=$!
n=0
until dig +tries=1 +time=1 +short @127.0.0.4 -p 5301 policy-block-1.example A 2>/dev/null |grep -Fxq 192.0.2.53;do
 n=$((n+1));[ "$n" -lt 25 ] || { echo "FAIL: loopback-only synthetic upstream unavailable";exit 1; }
 sleep 0.2
done
echo "PASS: synthetic loopback-only upstream ready"
dotnet /opt/technitium/dns/DnsServerApp.dll --stop-if-bind-fails --portable-app /work/config >/work/service.log 2>&1 &
pid=$!
trap 'kill "$pid" "$upstream_pid" 2>/dev/null || true;wait "$pid" "$upstream_pid" 2>/dev/null || true' EXIT
n=0
until curl --silent --fail --noproxy '*' --max-time 1 --output /work/console.html http://127.0.0.1:5380/;do
 n=$((n+1));[ "$n" -lt 40 ] || { echo "FAIL: isolated DNS did not start";exit 1; }
 sleep 0.5
done
grep -Fq '<title>GoreeCloud DNS</title>' /work/console.html || { echo "FAIL: DNS branding incorrect";exit 1; }
echo "PASS: disposable DNS server ready"
set +e
perl /work/smoke_advanced_runtime.pl
rc=$?
set -e
if [ "$rc" -ne 0 ]; then
 echo "DIAGNOSTIC: synthetic_upstream_valid_query_count=$(grep -c '^SYNTHETIC_A_QUERY$' /work/offline-upstream.log || true)"
 echo "DIAGNOSTIC: plugin_load_error_types_only"
 grep -oE '[A-Za-z0-9_.]+(Exception|Error)' /work/service.log 2>/dev/null |sort |uniq -c|head -n 12 || true
 echo "FAIL: isolated Advanced Blocking runtime test nonzero"
 exit "$rc"
fi
echo "PASS: complete synthetic app runtime session"
