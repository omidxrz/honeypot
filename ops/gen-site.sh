#!/bin/sh
# Generate the nginx site config from etc/nginx-honeypot.conf + etc/names.env.
#
#   sh ops/gen-site.sh [names.env] [out] [letsencrypt-root]
#   sh ops/gen-site.sh --demo
#
# Why this exists: the committed template declares `listen 443 ssl` pointing at
# /etc/letsencrypt/live/<name>/, and on a fresh host that directory does not
# exist yet -- there is no certificate until hp-cert has run, and hp-cert cannot
# run until nginx is serving the ACME webroot on port 80. nginx -t fails, nginx
# does not start, and the install dead-ends. So the TLS half of the server block
# is emitted only when a certificate is actually on disk.
#
# This is the INSTALL-TIME generator: it builds the config from names.env for a
# host that has nothing yet. ops/deploy.sh does the opposite job at UPDATE time
# -- it reads the name hp-cert already substituted on a running box and keeps
# it. Two directions, one file; they are not interchangeable.
set -e

TEMPLATE="${HP_SITE_TEMPLATE:-etc/nginx-honeypot.conf}"

generate() {
  env_file="$1"; out="$2"; le_root="$3"

  [ -f "$TEMPLATE" ] || { echo "gen-site: no template at $TEMPLATE"; exit 2; }
  [ -f "$env_file" ] || { echo "gen-site: no $env_file -- copy etc/names.env.example"; exit 2; }

  # shellcheck disable=SC1090
  . "$env_file"

  # The first Bait Name is the certificate's lineage name (hp-cert passes it as
  # --cert-name); any others are SANs on that same certificate and arrive
  # through the same server block.
  fqdn=$(printf '%s' "$BAIT_NAMES" | awk '{print $1}')

  if [ -n "$fqdn" ] && [ -f "$le_root/$fqdn/fullchain.pem" ]; then
    sed "s/HONEYPOT_FQDN/$fqdn/g" "$TEMPLATE" > "$out"
    echo "gen-site: $out for $fqdn (certificate found, TLS on)"
  else
    # No certificate yet. Drop every line that would make nginx open 443 or
    # read a key, and fall back to the catch-all server_name so the site still
    # answers on 80 -- which is exactly what certbot's webroot challenge needs
    # for the certificate to exist on the next run.
    sed -e '/listen .*443 ssl/d' \
        -e '/ssl_certificate/d' \
        -e 's/^\( *\)server_name .*/\1server_name _;/' \
        "$TEMPLATE" > "$out"
    if [ -n "$fqdn" ]; then
      echo "gen-site: $out HTTP-only (no certificate for $fqdn yet -- run: hp-cert $fqdn)"
    else
      echo "gen-site: $out HTTP-only (BAIT_NAMES is empty in $env_file)"
    fi
  fi
}

demo() {
  d=$(mktemp -d)
  trap 'rm -rf "$d"' EXIT
  printf 'BAIT_NAMES="ops.example.com alt.example.com"\nHOST_ADDR="203.0.113.1"\n' > "$d/names.env"

  # --- no certificate on disk: the config must still be startable ---
  ( generate "$d/names.env" "$d/http.conf" "$d/nonexistent" >/dev/null )
  grep -q '443'               "$d/http.conf" && { echo "FAIL: 443 survived with no certificate"; exit 1; }
  grep -q 'ssl_certificate'   "$d/http.conf" && { echo "FAIL: ssl_certificate survived"; exit 1; }
  grep -q 'HONEYPOT_FQDN'     "$d/http.conf" && { echo "FAIL: placeholder left in output"; exit 1; }
  grep -q 'listen 80'         "$d/http.conf" || { echo "FAIL: nothing listens on 80"; exit 1; }
  # The ACME webroot is served from here. Without it hp-cert can never succeed,
  # so the HTTP-only config would be a dead end rather than a step towards TLS.
  grep -q 'root /opt/honeypot/bait' "$d/http.conf" || { echo "FAIL: no webroot for ACME"; exit 1; }

  # --- certificate on disk: TLS comes back, for the lineage name ---
  mkdir -p "$d/le/ops.example.com"
  : > "$d/le/ops.example.com/fullchain.pem"
  ( generate "$d/names.env" "$d/tls.conf" "$d/le" >/dev/null )
  grep -q 'listen 443 ssl'              "$d/tls.conf" || { echo "FAIL: 443 missing with a certificate"; exit 1; }
  grep -q 'ops.example.com/fullchain'   "$d/tls.conf" || { echo "FAIL: wrong certificate path"; exit 1; }
  grep -q 'alt.example.com/fullchain'   "$d/tls.conf" && { echo "FAIL: used a SAN as the lineage name"; exit 1; }
  grep -q 'HONEYPOT_FQDN'               "$d/tls.conf" && { echo "FAIL: placeholder left in output"; exit 1; }
  grep -q 'server_name ops.example.com' "$d/tls.conf" || { echo "FAIL: server_name not substituted"; exit 1; }

  # A certificate for some OTHER name must not turn TLS on. This is the exact
  # failure the script exists to prevent, one directory along.
  printf 'BAIT_NAMES="unissued.example.com"\n' > "$d/other.env"
  ( generate "$d/other.env" "$d/other.conf" "$d/le" >/dev/null )
  grep -q '443' "$d/other.conf" && { echo "FAIL: another name's certificate enabled TLS"; exit 1; }

  # An empty BAIT_NAMES is a legitimate state -- a sensor with no Bait Name yet
  # still captures. It must not produce a config that refuses to load.
  printf 'BAIT_NAMES=""\n' > "$d/none.env"
  ( generate "$d/none.env" "$d/none.conf" "$d/le" >/dev/null )
  grep -q '443'       "$d/none.conf" && { echo "FAIL: TLS with no Bait Name at all"; exit 1; }
  grep -q 'listen 80' "$d/none.conf" || { echo "FAIL: no listener with no Bait Name"; exit 1; }

  echo "gen-site self-check ok"
}

case "$1" in
  --demo) demo ;;
  *)      generate "${1:-etc/names.env}" "${2:-etc/nginx-site.conf}" "${3:-/etc/letsencrypt/live}" ;;
esac
