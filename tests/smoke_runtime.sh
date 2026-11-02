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

cat > "$work/run-smoke.sh" <<'SMOKE'
#!/usr/bin/env bash
set -euo pipefail
cd /work/app
dotnet DnsServerApp.dll --stop-if-bind-fails --portable-app /work/config > /work/service.log 2>&1 &
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

perl -MIO::Socket::INET <<'PERL'
use strict;
use warnings;

my $socket = IO::Socket::INET->new(
    PeerAddr => "127.0.0.1",
    PeerPort => 53,
    Proto    => "udp"
) or die "FAIL: DNS UDP socket could not be opened\n";

my $query = pack("n6", 0xBEEF, 0x0100, 1, 0, 0, 0)
          . pack("C", 9) . "localhost" . "\0"
          . pack("n2", 1, 1);

send($socket, $query, 0) == length($query)
    or die "FAIL: could not send DNS UDP query\n";

$SIG{ALRM} = sub { die "FAIL: DNS query timed out\n" };
alarm 4;
my $answer;
my $peer = recv($socket, $answer, 512, 0);
alarm 0;
defined $peer && length($answer) >= 12
    or die "FAIL: missing or malformed DNS UDP response\n";

my ($id, $flags, $questions, $answers) = unpack("n4", $answer);
$id == 0xBEEF or die "FAIL: DNS transaction ID mismatch\n";
($flags & 0x8000) or die "FAIL: DNS response bit missing\n";
$questions == 1 or die "FAIL: DNS question count mismatch\n";
($flags & 15) == 5 or die "FAIL: expected REFUSED (recursion is denied)\n";
print "PASS: UDP DNS replied REFUSED under explicit recursion-denied configuration\n";
PERL

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
