# Development integration. Review and pin upstream packages before production.
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends unbound ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY deploy/unbound/goreecloud.conf /etc/unbound/unbound.conf.d/goreecloud.conf
USER unbound
EXPOSE 5335/udp 5335/tcp
CMD ["/usr/sbin/unbound", "-d", "-c", "/etc/unbound/unbound.conf"]
