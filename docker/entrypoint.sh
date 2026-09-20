#!/bin/sh
# Start every sensor service and stay up as long as they all do.
#
#   entrypoint.sh            run (the container's default)
#   entrypoint.sh --check    validate the mounts and config, start nothing
#   entrypoint.sh --health   one probe, for HEALTHCHECK
#
# There is no systemd in here, so this is the supervisor. Its one real job is
# the failure mode: if any service dies, the whole container exits non-zero so
# the restart policy brings everything back together. A supervisor that keeps
# running with a dead catch-all is a sensor that looks healthy and is capturing
# nothing -- the worst outcome available, because you only find out later when
# the data has a hole in it.
set -e

DEST=/opt/honeypot
TOOLS="$DEST/tools"
PANEL_BIND="${HP_PANEL_BIND:-127.0.0.1}"
PANEL_PORT="${HP_PANEL_PORT:-8085}"
ROLLUP_EVERY="${HP_ROLLUP_EVERY:-300}"
RECENT_EVERY="${HP_RECENT_EVERY:-10}"

say() { printf '%s\n' "$*"; }

# ----------------------------------------------------------------- health

if [ "$1" = "--health" ]; then
  # Check that each service is LISTENING, by reading /proc/net/tcp directly.
  #
  # Not by process name: procps is not in the base image, so pgrep and ps do
  # not exist here and a healthcheck built on them reports "down" forever while
  # everything works -- which is the same class of lie as reporting healthy
  # while the capture is dead, just inverted.
  #
  # And not by connecting either: a probe that dials the catch-all every 30s
  # writes a synthetic record into the capture, and the capture is the one
  # thing here that must stay exactly what arrived from outside.
  CATCHALL_PORT=$(printf '%s' "${HP_BIND_PORTS:-8000}" | cut -d, -f1)
  python3 - "$CATCHALL_PORT" "$PANEL_PORT" <<'PY' || exit 1
import sys

LISTEN = "0A"
listening = set()
for path in ("/proc/net/tcp", "/proc/net/tcp6"):
    try:
        with open(path) as f:
            next(f, None)
            for line in f:
                col = line.split()
                if len(col) > 3 and col[3] == LISTEN:
                    listening.add(int(col[1].rsplit(":", 1)[1], 16))
    except OSError:
        pass

want = [(int(sys.argv[1]), "catch-all"), (80, "nginx"),
        (8099, "decoy shim"), (int(sys.argv[2]), "operator panel")]
down = [name for port, name in want if port not in listening]
if down:
    print("down: " + ", ".join(down))
    sys.exit(1)
print("ok")
PY
  exit 0
fi

# --------------------------------------------------------------- preflight

say "== preflight =="
[ -f "$DEST/names.env" ] || {
  say "no $DEST/names.env -- mount it:"
  say "  cp etc/names.env.example etc/names.env   (then fill it in)"
  exit 2; }
[ -f "$DEST/ops/assets/panel.css" ] || {
  say "ops/assets/ not mounted or incomplete -- run on the host: sh ops/vendor-assets.sh"
  exit 2; }
[ -f "$DEST/ops/geo/ip-country-ipv4.csv" ] || {
  say "ops/geo/ not mounted or incomplete -- run on the host: sh ops/vendor-geo.sh"
  exit 2; }
say "  names.env, assets and geo tables present"

mkdir -p "$DEST/logs" "$DEST/bait" "$DEST/ops"
chmod 750 "$DEST/logs"

# $DEST/ops is a persistent volume, so the image's index.html is shadowed by
# it. Install the pristine copy on every start or a rebuilt image would ship a
# panel nobody ever sees.
cp "$TOOLS/index.html" "$DEST/ops/index.html"

# The catch-all terminates TLS on every port that is not 80/443 using this
# self-signed certificate. It is not the Bait Name's certificate -- that one is
# real, issued on the host, and is the thing that lands in the CT logs.
if [ ! -f "$DEST/hp.pem" ]; then
  say "  generating $DEST/hp.pem (catch-all TLS terminator, self-signed)"
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=localhost" \
    -keyout "$DEST/hp.pem" -out "$DEST/hp.pem.crt" 2>/dev/null
  cat "$DEST/hp.pem.crt" >> "$DEST/hp.pem"
  rm -f "$DEST/hp.pem.crt"
  chmod 600 "$DEST/hp.pem"
fi

if [ ! -f "$DEST/bait/index.html" ]; then
  # Something must be here or certbot's webroot challenge has nowhere to write
  # and no Bait Name can ever be issued. See README, "Rebuilding the bait".
  cat > "$DEST/bait/index.html" <<'HTML'
<!doctype html><meta charset="utf-8"><title>OpsCenter</title>
<body style="font:14px system-ui;padding:3rem">
<h1>OpsCenter</h1><p>Service is starting.</p>
HTML
  say "  placeholder decoy written (no bait/ mounted)"
fi

say "== nginx config =="
sh "$TOOLS/gen-hostmap.sh" "$DEST/names.env" /etc/nginx/conf.d/10-hp-hostmap.conf
cp "$TOOLS/nginx-log-format.conf" /etc/nginx/conf.d/20-hp-logformat.conf
# TLS goes in only when the certificate is really mounted at
# /etc/letsencrypt/live/<name>/. Otherwise nginx refuses to start and takes the
# whole container with it.
HP_SITE_TEMPLATE="$TOOLS/nginx-honeypot.conf" \
  sh "$TOOLS/gen-site.sh" "$DEST/names.env" /etc/nginx/sites-enabled/honeypot /etc/letsencrypt/live
nginx -t

if [ "$1" = "--check" ]; then
  say ""
  say "--check: config is valid, nothing started."
  exit 0
fi

# ------------------------------------------------------------------- run

PIDS=""
spawn() {
  label="$1"; shift
  "$@" &
  PIDS="$PIDS $!"
  say "  $label (pid $!)"
}

cleanup() {
  code="${1:-0}"
  trap - TERM INT
  [ -n "$SLEEP_PID" ] && kill "$SLEEP_PID" 2>/dev/null
  # shellcheck disable=SC2086
  [ -n "$PIDS" ] && kill $PIDS 2>/dev/null
  nginx -s quit 2>/dev/null || true
  exit "$code"
}
SLEEP_PID=""
# A signal is an orderly stop (docker stop): exit 0. A dead service is not.
trap 'cleanup 0' TERM INT

say "== start =="
nginx -g 'daemon off;' &
PIDS="$PIDS $!"
say "  nginx (pid $!)"

spawn "catch-all"  python3 "$DEST/catchall.py"
spawn "decoy shim" python3 "$DEST/shim.py"
spawn "panel on $PANEL_BIND:$PANEL_PORT" \
  python3 -m http.server "$PANEL_PORT" --bind "$PANEL_BIND" --directory "$DEST/ops"

# The two timers. Each run is independent and a failure is not fatal -- a
# rollup that throws once must not take the capture down with it, because the
# capture is the thing that cannot be recreated.
spawn "rollup every ${ROLLUP_EVERY}s" sh -c \
  "while :; do python3 $DEST/ops/rollup.py >/dev/null 2>&1 || true; sleep $ROLLUP_EVERY; done"
spawn "recent every ${RECENT_EVERY}s" sh -c \
  "while :; do python3 $DEST/ops/recent.py >/dev/null 2>&1 || true; sleep $RECENT_EVERY; done"

say "== up =="

# Supervise. dash has no `wait -n`, so poll -- at this interval it costs
# nothing and the semantics are the ones that matter: first death ends it.
#
# The sleep is backgrounded and waited on rather than run in the foreground.
# A shell blocked in a foreground `sleep` defers its signal handlers until the
# command returns, so `docker stop` would time out and SIGKILL the container --
# every service dying at once, mid-write, and an exit code of 137 that looks
# like a crash every single time it is stopped normally. `wait` returns the
# moment a signal arrives, so the trap runs immediately.
while :; do
  for p in $PIDS; do
    kill -0 "$p" 2>/dev/null || {
      say "service pid $p exited -- bringing the container down so it restarts whole"
      cleanup 1
    }
  done
  sleep 5 &
  SLEEP_PID=$!
  wait "$SLEEP_PID" 2>/dev/null || true
  SLEEP_PID=""
done
