#!/bin/sh
# Install the sensor onto this host. Run as root, from the repo root.
#
#   sh install.sh              # install / re-install; safe to run repeatedly
#   sh install.sh --check      # say what would happen, change nothing
#
# This is the FIRST run on a fresh box. ops/deploy.sh is every run after it,
# from your workstation, over ssh.
#
# Two things it deliberately does NOT do, because both can end with no way back
# into the machine and neither is safe to do behind your back:
#
#   * It does not move sshd to port 61022. It writes the drop-in and tells you
#     the command. You run it, then open a SECOND session to prove it worked.
#   * It does not load the nftables ruleset. That ruleset redirects every port
#     to the catch-all; if the SSH port is not in the return set, the next
#     packet you send goes to the honeypot instead of sshd and the box is gone.
#
# Order matters and the script enforces it: sshd is confirmed on the new port
# before the redirect is even offered.
set -e

DEST=/opt/honeypot
CHECK=""
[ "$1" = "--check" ] && CHECK=1

say()  { printf '%s\n' "$*"; }
step() { printf '\n== %s ==\n' "$*"; }
run()  { if [ -n "$CHECK" ]; then say "  would: $*"; else "$@"; fi; }

# ---------------------------------------------------------------- preflight

step "preflight"
[ -f opt/catchall.py ] && [ -f ops/rollup.py ] || {
  say "run this from the repo root (opt/catchall.py not found)"; exit 2; }

[ "$(uname -s)" = "Linux" ] || {
  say "This installs onto Linux. The catch-all needs SO_ORIGINAL_DST and"
  say "nftables, neither of which exists on $(uname -s)."
  say "To try the sensor on this machine instead: docker compose -f docker-compose.demo.yml up"
  exit 2; }

[ "$(id -u)" = 0 ] || { say "must run as root"; exit 2; }
command -v systemctl >/dev/null || { say "systemd is required (the units are systemd units)"; exit 2; }

MISSING=""
for c in python3 nginx nft; do command -v "$c" >/dev/null || MISSING="$MISSING $c"; done
if [ -n "$MISSING" ]; then
  say "missing:$MISSING"
  if command -v apt-get >/dev/null; then
    run apt-get update -qq
    run apt-get install -y -qq python3 nginx-light nftables certbot
  else
    say "no apt-get here -- install python3, nginx, nftables and certbot, then re-run"
    exit 2
  fi
fi

# Both are gitignored third-party output, so a fresh clone has neither. Without
# this check the panel installs referencing stylesheets that are not there and
# the map has no country table -- a sensor that looks installed and is not.
[ -d ops/assets ] && [ -f ops/assets/panel.css ] || {
  say "ops/assets/ missing or incomplete -- run: sh ops/vendor-assets.sh"; exit 2; }
[ -d ops/geo ] && [ -f ops/geo/ip-country-ipv4.csv ] || {
  say "ops/geo/ missing or incomplete -- run: sh ops/vendor-geo.sh"; exit 2; }
[ -f etc/names.env ] || {
  say "etc/names.env missing -- cp etc/names.env.example etc/names.env, then fill it in"; exit 2; }
say "  repo ok; assets, geo table and names.env all present"

step "self-checks (nothing installs if the code is broken)"
for c in "opt/catchall.py" "opt/shim.py" "ops/rollup.py" "ops/migrate.py" "ops/recent.py" "ops/analyze.py"; do
  python3 "$c" --demo >/dev/null || { say "$c --demo FAILED"; exit 1; }
  say "  $c ok"
done
sh ops/gen-site.sh --demo >/dev/null && say "  ops/gen-site.sh ok"
if command -v node >/dev/null; then
  node ops/panel-check.js >/dev/null && say "  ops/panel-check.js ok"
else
  say "  ops/panel-check.js SKIPPED (no node on this host; it runs on your workstation)"
fi

# ------------------------------------------------------------------ payload

step "directories"
for d in "$DEST" "$DEST/ops" "$DEST/logs" "$DEST/bait"; do
  [ -d "$d" ] || run mkdir -p "$d"
done
run chmod 750 "$DEST/logs"          # captured payloads are not world-readable
say "  $DEST"

step "self-signed certificate for the catch-all's TLS terminator"
# Not the Bait Name's certificate -- that one is real, from Let's Encrypt, and
# is what puts the Name into a CT log. This one only exists so the catch-all
# can terminate TLS on the other 65,000 ports and read the plaintext.
if [ -f "$DEST/hp.pem" ]; then
  say "  $DEST/hp.pem exists, keeping it"
elif [ -n "$CHECK" ]; then
  say "  would: generate $DEST/hp.pem"
else
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -subj "/CN=localhost" -keyout "$DEST/hp.pem" -out "$DEST/hp.pem.crt" 2>/dev/null
  cat "$DEST/hp.pem.crt" >> "$DEST/hp.pem"
  rm -f "$DEST/hp.pem.crt"
  chmod 600 "$DEST/hp.pem"
  say "  generated $DEST/hp.pem"
fi

step "programs"
for pair in \
  "opt/catchall.py:$DEST/catchall.py" \
  "opt/shim.py:$DEST/shim.py" \
  "etc/names.env:$DEST/names.env" \
  "ops/rollup.py:$DEST/ops/rollup.py" \
  "ops/migrate.py:$DEST/ops/migrate.py" \
  "ops/recent.py:$DEST/ops/recent.py" \
  "ops/index.html:$DEST/ops/index.html" \
  "opt/hp-cert:/usr/local/sbin/hp-cert" \
  "opt/hp-cert-wait:/usr/local/sbin/hp-cert-wait" \
  "opt/hp-egress:/usr/local/sbin/hp-egress"
do
  run cp "${pair%%:*}" "${pair#*:}"
  say "  ${pair%%:*} -> ${pair#*:}"
done
run chmod +x /usr/local/sbin/hp-cert /usr/local/sbin/hp-cert-wait /usr/local/sbin/hp-egress
run cp -r ops/assets "$DEST/ops/"
run cp -r ops/geo "$DEST/ops/"
say "  ops/assets and ops/geo mirrored"

step "decoy site"
if [ -f bait/index.html ]; then
  run cp -r bait/. "$DEST/bait/"
  say "  bait/ installed from the repo"
elif [ -f "$DEST/bait/index.html" ]; then
  say "  $DEST/bait already populated, keeping it"
elif [ -n "$CHECK" ]; then
  say "  would: write a placeholder $DEST/bait/index.html"
else
  # The real decoy is a built admin template and is not committed (ADR-0006).
  # Something has to be here or nginx serves 404 and, worse, certbot's webroot
  # challenge has nowhere to write -- so no Bait Name can ever be issued.
  cat > "$DEST/bait/index.html" <<'HTML'
<!doctype html><meta charset="utf-8"><title>OpsCenter</title>
<body style="font:14px system-ui;padding:3rem">
<h1>OpsCenter</h1><p>Service is starting.</p>
HTML
  say "  placeholder written -- see README 'Rebuilding the bait' for the real one"
fi

# -------------------------------------------------------------------- nginx

step "nginx"
run sh ops/gen-hostmap.sh etc/names.env etc/nginx-hostmap.conf
run sh ops/gen-site.sh etc/names.env etc/nginx-site.conf /etc/letsencrypt/live
run cp etc/nginx-hostmap.conf   /etc/nginx/conf.d/10-hp-hostmap.conf
run cp etc/nginx-log-format.conf /etc/nginx/conf.d/20-hp-logformat.conf
run cp etc/nginx-site.conf      /etc/nginx/sites-available/honeypot
[ -e /etc/nginx/sites-enabled/honeypot ] || \
  run ln -sf /etc/nginx/sites-available/honeypot /etc/nginx/sites-enabled/honeypot
# Debian's default site is also a `default_server` on 80. Two of them is a
# fatal nginx config error, not a warning.
[ -e /etc/nginx/sites-enabled/default ] && run rm -f /etc/nginx/sites-enabled/default
if [ -z "$CHECK" ]; then
  nginx -t || { say "nginx -t failed -- not reloading"; exit 1; }
  systemctl reload nginx 2>/dev/null || systemctl restart nginx
fi
say "  nginx configured and reloaded"

# ------------------------------------------------------------------ systemd

step "units"
for u in systemd/*.service systemd/*.timer; do
  run cp "$u" "/etc/systemd/system/$(basename "$u")"
done
run systemctl daemon-reload
run systemctl enable --now hp-catchall hp-shim hp-ops
run systemctl enable --now hp-rollup.timer hp-recent.timer hp-certrenew.timer
say "  catchall, shim, panel, and the three timers enabled"

if [ -z "$CHECK" ]; then
  python3 "$DEST/ops/rollup.py" >/dev/null 2>&1 || true
  python3 "$DEST/ops/recent.py" >/dev/null 2>&1 || true
fi

# ------------------------------------------------- the two you do by hand

step "REMAINING STEPS -- these are yours, in this order"

SSH_PORT=$(awk '/^ *Port /{print $2; exit}' etc/sshd-honeypot.conf 2>/dev/null)
SSH_PORT="${SSH_PORT:-61022}"

if ss -tlnp 2>/dev/null | grep -q ":$SSH_PORT "; then
  say ""
  say "1. sshd is already listening on $SSH_PORT. Nothing to do."
  SSH_OK=1
else
  run cp etc/sshd-honeypot.conf /etc/ssh/sshd_config.d/10-honeypot.conf
  say ""
  say "1. Move sshd to port $SSH_PORT. The drop-in is written; apply it:"
  say ""
  say "       systemctl restart ssh   # or sshd"
  say ""
  say "   Then, WITHOUT closing this session, open a second one on the new"
  say "   port and confirm it works:"
  say ""
  say "       ssh -p $SSH_PORT $(id -un)@<this-host>"
  say ""
  SSH_OK=""
fi

run cp etc/nftables.conf /etc/nftables.conf.new
say "2. Load the firewall. /etc/nftables.conf.new is written and NOT applied."
say ""
if [ -n "$SSH_OK" ]; then
  say "       cp /etc/nftables.conf.new /etc/nftables.conf"
  say "       nft -f /etc/nftables.conf && systemctl enable nftables"
else
  say "   Do NOT run this until step 1 is confirmed on a second session."
  say "   The ruleset returns only ports { $SSH_PORT, 80, 443, 8000 } and"
  say "   redirects everything else to the catch-all. If sshd is still on 22,"
  say "   port 22 goes to the honeypot and you are locked out."
fi
say ""
say "3. Point a Name here (DNS-only, no CDN proxy -- see docs/adr/0002), then:"
say ""
say "       hp-cert $(awk -F'\"' '/^BAIT_NAMES=/{print $2}' etc/names.env | awk '{print $1}')"
say ""
say "   That issues the certificate, which is what puts the Name into the"
say "   public CT logs. Everything the sensor is for starts there."
say ""
say "Panel:  ssh -fN -L 8085:127.0.0.1:8085 <this-host>   then http://127.0.0.1:8085"

[ -n "$CHECK" ] && say "" && say "(--check: nothing was changed)"
exit 0
