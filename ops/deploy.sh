#!/bin/sh
# Push this repo to the sensor. Run from the repo root.
#
# Never scp over a running file: catchall.py is open by a live service, and
# overwriting it in place gives ETXTBSY or a half-written program. Everything
# lands as .new and is moved into place in one step.
#
# nftables is copied but never applied: the nat rule redirects every port to the
# catch-all, so a bad ruleset with the wrong return set removes the only way in.
# Apply it yourself, over a session you keep open.
set -e
HOST="${HP_HOST:-honeypot}"

echo "== self-checks (the build step) =="
python3 opt/catchall.py --demo
python3 opt/shim.py --demo
python3 ops/rollup.py --demo
python3 ops/migrate.py --demo
python3 ops/recent.py --demo
python3 ops/analyze.py --demo
sh ops/gen-site.sh --demo
node ops/panel-check.js

# ops/assets and etc/names.env are both gitignored, so a fresh clone has
# neither. Without this check the asset loop below silently uploads nothing
# (find writes to stderr, the pipeline still exits 0, set -e never fires) and
# the panel ships referencing CSS and JS that are not there.
echo "== preflight =="
[ -d ops/assets ] || { echo "ops/assets/ is missing -- run: sh ops/vendor-assets.sh"; exit 1; }
[ -f ops/assets/panel.css ] && [ -f ops/assets/apexcharts.min.js ] || {
  echo "ops/assets/ is incomplete -- run: sh ops/vendor-assets.sh"; exit 1; }
[ -f etc/names.env ] || { echo "etc/names.env is missing -- copy etc/names.env.example and fill it in"; exit 1; }
[ -d ops/geo ] || { echo "ops/geo/ is missing -- run: sh ops/vendor-geo.sh"; exit 1; }
[ -f ops/geo/ip-country-ipv4.csv ] && [ -f ops/geo/country-centroids.csv ] || {
  echo "ops/geo/ is incomplete -- run: sh ops/vendor-geo.sh"; exit 1; }
echo "  ops/assets: $(find ops/assets -type f | wc -l | tr -d ' ') files;" \
     "ops/geo: $(find ops/geo -type f | wc -l | tr -d ' ') files; etc/names.env present"

echo "== regenerate the host map from names.env =="
sh ops/gen-hostmap.sh

# The deployed site config has a real Bait Name substituted into it by hp-cert;
# the repo carries the placeholder. Pushing the placeholder would point
# ssl_certificate at a directory that does not exist and fail nginx -t.
echo "== preserve the live Bait Name in the site config =="
# Anchored to a real directive line: an unanchored match also hits the word
# "server_name" inside a comment, which once substituted the FQDN as "is".
FQDN=$(ssh -n "$HOST" "grep -m1 -E '^[[:space:]]*server_name[[:space:]]' /etc/nginx/sites-available/honeypot 2>/dev/null | awk '{print \$2}' | tr -d ';'" || true)
case "$FQDN" in
  *.*) ;;                                  # must look like a hostname
  *) echo "  ignoring implausible name '$FQDN'"; FQDN="" ;;
esac
# And it must actually have a certificate, or nginx -t fails on the reload.
if [ -n "$FQDN" ] && ! ssh -n "$HOST" "test -f /etc/letsencrypt/live/$FQDN/fullchain.pem"; then
  echo "  no certificate for '$FQDN'"; FQDN=""
fi
SITE=etc/nginx-honeypot.conf
if [ -n "$FQDN" ] && [ "$FQDN" != "_" ] && [ "$FQDN" != "HONEYPOT_FQDN" ]; then
  SITE=$(mktemp)
  sed "s/HONEYPOT_FQDN/$FQDN/g" etc/nginx-honeypot.conf > "$SITE"
  echo "  keeping $FQDN"
else
  echo "  no substituted name on the box; shipping the placeholder"
fi

# local path -> remote path. ops/assets/* mirrors 1:1 onto the box (see the
# loop below) rather than being hand-listed here -- a directory that must be
# listed twice, once as files and once as a mirror, is a list someone forgets
# to update. Everything else is named individually since the mapping isn't
# 1:1 (etc/names.env -> a different path, $SITE is computed, etc).
set -- \
  "opt/catchall.py:/opt/honeypot/catchall.py" \
  "opt/shim.py:/opt/honeypot/shim.py" \
  "etc/names.env:/opt/honeypot/names.env" \
  "ops/rollup.py:/opt/honeypot/ops/rollup.py" \
  "ops/migrate.py:/opt/honeypot/ops/migrate.py" \
  "ops/recent.py:/opt/honeypot/ops/recent.py" \
  "ops/analyze.py:/opt/honeypot/ops/analyze.py" \
  "ops/index.html:/opt/honeypot/ops/index.html" \
  "opt/hp-cert:/usr/local/sbin/hp-cert" \
  "opt/hp-cert-wait:/usr/local/sbin/hp-cert-wait" \
  "opt/hp-egress:/usr/local/sbin/hp-egress" \
  "etc/nginx-hostmap.conf:/etc/nginx/conf.d/10-hp-hostmap.conf" \
  "etc/nginx-log-format.conf:/etc/nginx/conf.d/20-hp-logformat.conf" \
  "$SITE:/etc/nginx/sites-available/honeypot" \
  "etc/nftables.conf:/etc/nftables.conf.new"
# etc/sshd-honeypot.conf is deliberately not deployed: the box already carries it
# as 10-honeypot.conf, a second drop-in would duplicate Port, and a bad sshd
# config on this host is the one failure with no way back in.

echo "== upload =="
# ops/assets and ops/geo mirror 1:1 onto the box. They are ~11 MB together and
# almost never change, so every file's remote checksum is fetched in ONE round
# trip and only what actually differs is sent -- re-uploading 11 MB on every
# deploy is minutes of scp for nothing.
MIRROR_DIRS="ops/assets ops/geo"

if command -v sha256sum >/dev/null; then SHA="sha256sum"; else SHA="shasum -a 256"; fi
REMOTE_SUMS=$(ssh -n "$HOST" "cd /opt/honeypot && find $MIRROR_DIRS -type f -exec sha256sum {} \; 2>/dev/null" || true)

for d in $MIRROR_DIRS; do
  find "$d" -type d | sed "s#^#/opt/honeypot/#" | xargs -n1 -I{} ssh -n "$HOST" "mkdir -p '{}'"
done

for d in $MIRROR_DIRS; do
  # ssh -n: without it ssh reads this loop's stdin and swallows the filenames
  # find has not yet handed to `read`, so the loop silently processes a
  # fraction of the files and still reports success. This bit once.
  find "$d" -type f | while read -r f; do
    dst="/opt/honeypot/$f"
    local_sum=$($SHA "$f" | cut -d" " -f1)
    remote_sum=$(printf '%s\n' "$REMOTE_SUMS" | awk -v k="$f" '$2 == k {print $1; exit}')
    if [ "$local_sum" = "$remote_sum" ] && [ -n "$remote_sum" ]; then
      echo "  = $f (unchanged)"
    else
      scp -q "$f" "$HOST:$dst.new"
      ssh -n "$HOST" "mv -f '$dst.new' '$dst'"
      echo "  + $f -> $dst"
    fi
  done
done

# The loop above runs in a pipeline subshell, so it cannot report a count back.
# Compare what is actually on the box against what is here -- the check that
# would have caught the stdin bug the first time.
for d in $MIRROR_DIRS; do
  want=$(find "$d" -type f | wc -l | tr -d " ")
  got=$(ssh -n "$HOST" "find /opt/honeypot/$d -type f 2>/dev/null | wc -l" | tr -d " ")
  [ "$want" = "$got" ] || { echo "$d: $got of $want files on the box -- mirror incomplete"; exit 1; }
  echo "  $d: $got/$want files present"
done
for pair; do
  src=${pair%%:*}; dst=${pair#*:}
  case "$dst" in *.new) tmp=$dst ;; *) tmp=$dst.new ;; esac
  scp -q "$src" "$HOST:$tmp"
  [ "$tmp" = "$dst" ] || ssh -n "$HOST" "mv -f '$tmp' '$dst'"
  echo "  $src -> $dst"
done
for u in systemd/*.service systemd/*.timer; do
  scp -q "$u" "$HOST:/etc/systemd/system/$(basename "$u").new"
  ssh -n "$HOST" "mv -f /etc/systemd/system/$(basename "$u").new /etc/systemd/system/$(basename "$u")"
done

echo "== reload =="
ssh "$HOST" 'set -e
  # superseded by 20-hp-logformat.conf; leaving it duplicates log_format hp,
  # which nginx rejects outright
  rm -f /etc/nginx/conf.d/00-hp-log.conf
  chmod +x /usr/local/sbin/hp-cert /usr/local/sbin/hp-cert-wait /usr/local/sbin/hp-egress
  systemctl daemon-reload
  nginx -t

  # migrate is authoritative for hosts/contacts, so the timer goes down first.
  systemctl stop hp-rollup.timer
  python3 /opt/honeypot/ops/migrate.py

  # Only now reload nginx. migrate replaces web.jsonl, and an nginx that was
  # reloaded before that keeps its fd on the unlinked inode -- every access log
  # line after it would be written to a deleted file.
  systemctl reload nginx
  systemctl restart hp-catchall hp-shim hp-ops

  python3 /opt/honeypot/ops/rollup.py
  systemctl start hp-rollup.timer
  systemctl enable --now hp-recent.timer
  python3 /opt/honeypot/ops/recent.py'
echo "done. /etc/nftables.conf.new is uploaded but NOT applied."
