#!/usr/bin/env bash
# Disposable, non-production raw-volume backup/restore check.
set -euo pipefail
if [ "$#" -ne 1 ]; then
    echo "Usage: bash smoke_release_backup_restore.sh <verified-local-image>" >&2
    exit 2
fi
image="$1"
command -v podman >/dev/null
test "$(podman info --format '{{.Host.Security.Rootless}}')" = true
podman image exists "$image"
root="$(mktemp -d /tmp/goreecloud-dns-restore.XXXXXXXX)"
cleanup() {
    podman unshare rm -rf -- "$root" 2>/dev/null || true
    rm -rf -- "$root" 2>/dev/null || true
}
trap cleanup EXIT
mkdir "$root/original" "$root/restored"
cat > "$root/inside.sh" <<'INSIDE'
#!/bin/sh
set -eu
test "$(id -u)" = 1654
test -d /sys/class/net/lo
for nic in /sys/class/net/*; do
    test "$(basename "$nic")" = lo || exit 33
done
umask 077
if [ "$PHASE" = original ]; then
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
dotnet /opt/technitium/dns/DnsServerApp.dll --stop-if-bind-fails --portable-app /work/config >/work/service-"$PHASE".log 2>&1 &
server=$!
trap 'kill "$server" 2>/dev/null || true; wait "$server" 2>/dev/null || true' EXIT
ready=no
counter=0
while [ "$counter" -lt 25 ]; do
    if curl --silent --fail --noproxy '*' --max-time 1 -o /work/console-"$PHASE".html http://127.0.0.1:5380/; then
        ready=yes
        break
    fi
    counter=$((counter+1))
    sleep 0.5
done
test "$ready" = yes
grep -Fq '<title>GoreeCloud DNS</title>' /work/console-"$PHASE".html
dig @127.0.0.1 -p 53 localhost A +time=1 +tries=1 +noall +comments >/work/refusal-"$PHASE".txt
grep -q 'status: REFUSED' /work/refusal-"$PHASE".txt
echo "PASS: $PHASE non-root DNS container functional"
INSIDE
podman unshare chown 1654:1654 "$root/original" "$root/restored"
run_phase() {
    local phase="$1" directory="$2"
    timeout 55s podman run --rm --pull=never --network=none --user=1654:1654 \
        --cap-drop=ALL --cap-add=NET_BIND_SERVICE --security-opt=no-new-privileges \
        --pids-limit=128 --memory=1g -e "PHASE=$phase" \
        -v "$directory:/work:Z" -v "$root/inside.sh:/test.sh:ro,Z" \
        --entrypoint /bin/sh "$image" /test.sh
}
run_phase original "$root/original"
podman unshare tar -C "$root/original" -cf "$root/backup.tar" .
test -s "$root/backup.tar"
sha256sum "$root/backup.tar" > "$root/backup.sha256"
(cd "$root" && sha256sum -c --status backup.sha256)
cp "$root/backup.tar" "$root/altered.tar"
printf 'x' >> "$root/altered.tar"
test "$(sha256sum "$root/altered.tar" | cut -d' ' -f1)" != "$(cut -d' ' -f1 "$root/backup.sha256")"
echo "PASS: raw archive identity recorded and altered bytes detected"
podman unshare tar -C "$root/restored" -xf "$root/backup.tar"
podman unshare tar -C "$root/restored" -df "$root/backup.tar"
run_phase restored "$root/restored"
echo "PASS: disposable config volume restored to distinct non-root container"
