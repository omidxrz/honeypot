# The sensor's services in one image: catch-all, decoy backend, nginx, the
# rollup and recent timers, and the operator panel.
#
# What the container does NOT own, in either compose profile:
#
#   * the nftables ruleset -- it belongs to the host's network namespace, it
#     can lock you out of the box, and ops/deploy.sh has never applied it
#     automatically either. Same rule here.
#   * sshd.
#   * certificate issuance. hp-cert needs to open an egress window in the host
#     firewall and writes to /etc/letsencrypt, which is mounted read-only here.
#     Run it on the host; nginx in the container picks the certificate up.
#
# Keeping those three outside is also why this image needs no NET_ADMIN.
FROM debian:bookworm-slim

# nginx-light has everything the decoy uses (no third-party modules); openssl
# is only for generating the catch-all's self-signed terminator certificate.
RUN apt-get update \
 && apt-get install -y --no-install-recommends nginx-light python3 openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && rm -f /etc/nginx/sites-enabled/default

# Same paths as a native install, so catchall.py's hardcoded
# /opt/honeypot/logs/... is identical in both and nothing needs a container
# special case.
WORKDIR /opt/honeypot
RUN mkdir -p /opt/honeypot/logs /opt/honeypot/ops /opt/honeypot/bait /opt/honeypot/tools \
 && chmod 750 /opt/honeypot/logs

COPY opt/catchall.py opt/shim.py                     /opt/honeypot/
COPY ops/rollup.py ops/migrate.py ops/recent.py      /opt/honeypot/ops/
COPY ops/gen-site.sh ops/gen-hostmap.sh              /opt/honeypot/tools/
# The panel is served from /opt/honeypot/ops, which is a persistent volume
# (it holds state.json and the generated stats.json/recent.json beside it).
# A volume would shadow anything baked in at that path, so the pristine copy
# lives here and the entrypoint installs it on every start -- which also means
# rebuilding the image actually updates the panel.
COPY ops/index.html                                  /opt/honeypot/tools/
COPY etc/nginx-honeypot.conf etc/nginx-log-format.conf /opt/honeypot/tools/
COPY docker/entrypoint.sh                            /opt/honeypot/tools/

# ops/assets (the panel's stylesheet, charts and map library) and ops/geo (the
# IP->country tables) are gitignored third-party build output, so they are NOT
# baked in -- a clone does not have them. Both are mounted by compose, and the
# entrypoint refuses to start without them rather than serving a panel whose
# stylesheets 404.

RUN chmod +x /opt/honeypot/tools/*.sh

# Fails while any of the six services is down, so `docker compose ps` and a
# restart policy both see the truth instead of just "the entrypoint is alive".
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD sh /opt/honeypot/tools/entrypoint.sh --health || exit 1

ENTRYPOINT ["sh", "/opt/honeypot/tools/entrypoint.sh"]
