# syntax=docker.io/docker/dockerfile:1

FROM mcr.microsoft.com/dotnet/aspnet:10.0@sha256:de0ee358cdd672f7017a003bed21e9ac9ed48a27c922a59b18175b6e82fa7fee

# Pin the Ubuntu 24.04 Microsoft repo bootstrap bytes (verified package version 1.2-ubuntu24.04).
# Review and update this checksum deliberately when the vendor changes the package.
# This does not pin `apt-get` dependencies or independently attest package provenance.
ADD https://packages.microsoft.com/config/ubuntu/24.04/packages-microsoft-prod.deb /
# Verify the immutable bootstrap checksum *before* executing any package scripts.
# Include `dig` for isolated troubleshooting; OS package versions are not yet pinned.
# Persist DNS config at /etc/dns (mount a private volume for any deployment).
RUN set -eu; \
    echo 'c13f01ac7c3001b51a9281d40dde666db5e037e05512840c319832f7852bfec4  packages-microsoft-prod.deb' | sha256sum --check --status; \
    dpkg -i packages-microsoft-prod.deb; \
    rm packages-microsoft-prod.deb; \
    apt-get update; \
    apt-get install -y libmsquic dnsutils iputils-ping curl; \
    apt-get clean -y; \
    rm -rf /var/lib/apt/lists/*; \
    mkdir -p /etc/dns

# Project is built outside of Docker, copy over the build directory:
WORKDIR /opt/technitium/dns
COPY ./DnsServerApp/bin/Release/publish /opt/technitium/dns

ENTRYPOINT ["/usr/bin/dotnet", "/opt/technitium/dns/DnsServerApp.dll"]
CMD ["/etc/dns"]


## Only append image metadata below this line:
EXPOSE \
  # Standard DNS service
  53/udp 53/tcp      \
  # DNS-over-QUIC (UDP) + DNS-over-TLS (TCP)
  853/udp 853/tcp    \
  # DNS-over-HTTPS (UDP => HTTP/3) (TCP => HTTP/1.1 + HTTP/2)
  443/udp 443/tcp    \
  # DNS-over-HTTP (for when running behind a reverse-proxy that terminates TLS)
  80/tcp 8053/tcp    \
  # Technitium web console + API (HTTP / HTTPS)
  5380/tcp 53443/tcp \
  # DHCP
  67/udp

# https://specs.opencontainers.org/image-spec/annotations/
# https://github.com/opencontainers/image-spec/blob/main/annotations.md
LABEL org.opencontainers.image.title="GoreeCloud DNS"
LABEL org.opencontainers.image.version="15.6.2-gc-dev"
LABEL org.opencontainers.image.vendor="GoreeCloud"
LABEL org.opencontainers.image.source="https://github.com/GoreeCloud/DNS"
LABEL org.opencontainers.image.url="https://github.com/GoreeCloud/DNS"
LABEL org.opencontainers.image.authors="GoreeCloud contributors; based on Technitium DNS Server by Shreyas Zare"

LABEL org.opencontainers.image.licenses="GPL-3.0-or-later"
LABEL org.opencontainers.image.description="Development distribution based on Technitium DNS Server; no production release certification"
