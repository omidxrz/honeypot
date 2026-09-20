#!/usr/bin/env python3
"""Roll the raw honeypot logs into ops/stats.json.

One streaming pass, no record list. State (counters + per-file byte offsets)
persists in ops/state.json, so each run reads only what was appended since the
last one. Read-only on the logs, one direction.

The headline signal is the Contact: an Actor reaching this host by a Name it
could not derive from the address. See CONTEXT.md and docs/adr/0001.
"""
import bisect, calendar, json, os, re, sys, time
from array import array
from collections import Counter

LOGS = ["/opt/honeypot/logs/hp.jsonl", "/opt/honeypot/logs/web.jsonl"]
OUT = "/opt/honeypot/ops/stats.json"
STATE = "/opt/honeypot/ops/state.json"
NAMES = "/opt/honeypot/names.env"
GEO_DIR = "/opt/honeypot/ops/geo"
HOUR = 3600
DAY = 86400

NOVEL_SHOWN = 40      # sample size in the panel; the count in totals is never sliced
CONTACTS_SHOWN = 50
HOSTS_SHOWN = 20
NOVEL_MAX_SEEN = 3    # a shape seen more than this is not novel, so its sample is dropped
HOURS_KEPT = 48
CONTACTS_KEPT = 5000  # ~8 months at the observed rate; pruned by age, never by count
KEEP = {"paths": 2000, "uas": 500, "users": 500, "hosts": 200}
# ips and ports are never pruned: both are headline counts.

HEX = re.compile(r"[0-9a-f]{6,}", re.I)
NUM = re.compile(r"\d+")
WS = re.compile(r"\s+")
USERFIELD = re.compile(r"(?:user(?:name)?|login|email)=([^&\s]{1,40})", re.I)
ACME = "/.well-known/acme-challenge"
IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
LOCAL = re.compile(r"^(127\.|::1$|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)")

EMPTY = {
    "offsets": {}, "ports": {}, "ips": {}, "paths": {},
    "uas": {}, "users": {}, "hourly": {}, "contacts_hourly": {}, "shapes": {},
    "shape_first": {}, "shape_sample": {}, "hosts": {}, "contacts": {}, "contact_n": {},
    "tls": 0, "events": 0, "web": 0, "tcp": 0, "first_ts": 0,
}


def blank():
    """A fresh state. Not EMPTY.copy(): that shares the nested dicts with EMPTY."""
    return json.loads(json.dumps(EMPTY))


def read_env(path=NAMES):
    """Parse etc/names.env into a dict. Shell syntax, but only NAME="value"
    lines matter. Values are lowercased -- every key here is a hostname, an
    address or a number, none of which is case-sensitive."""
    env = {}
    try:
        text = open(path).read()
    except OSError:
        return env
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        env[k.strip()] = v.strip().strip('"').strip("'").lower()
    return env


def read_names(path=NAMES):
    """Parse etc/names.env. Shell syntax, but only NAME="value" lines matter."""
    env = read_env(path)
    bait = {n for n in env.get("BAIT_NAMES", "").split() if n}
    control = {n for n in env.get("CONTROL_NAMES", "").split() if n}
    return bait, control, env.get("HOST_ADDR", "")


def norm_host(h):
    """Lowercase, drop the port and any IPv6 brackets. '' when there is no Name."""
    h = (h or "").strip().lower()
    if h.startswith("["):            # [::1]:443
        return h.split("]", 1)[0][1:]
    if h.count(":") == 1:            # name:443 -- an unbracketed IPv6 has more
        h = h.split(":", 1)[0]
    return h


def classify(host, names):
    """bait | control | foreign | derived. See CONTEXT.md for what each means."""
    bait, control, addr = names
    h = norm_host(host)
    if not h:
        return "derived"
    if h in bait:
        return "bait"
    if h in control:
        return "control"
    if IPV4.match(h) or ":" in h:
        return "derived"
    if addr and addr.replace(".", "-") in h:
        return "derived"
    return "foreign"


def is_actor(ip):
    """A Contact needs a remote Actor. Loopback is the operator testing the box,
    and this is an internet-facing sensor, so a private source is not a finding."""
    return bool(ip) and not LOCAL.match(ip)


def contact_key(ip, host):
    """The one place a Contact's identity is packed into a state-dict key."""
    return ip + "|" + host


def split_contact_key(key):
    """The inverse of contact_key(). Also the one place that unpacks it."""
    ip, host = key.split("|", 1)
    return ip, host


def record_to_contact(r, names):
    """What Name (if any) an Actor used in this record, and whether it is a
    Contact. Returns (host, is_contact) -- host is "" when the record carries
    no Name at all, so callers can still tally Names-asked-for without a
    Contact. The whole point of concentrating this here: absorb()'s
    incremental path and migrate.py's rebuild path must agree on it, and once
    already didn't (the rebuild forgot the SNI branch and silently dropped
    every Contact made on a port nginx never sees)."""
    ip = r.get("ip")
    if r.get("src") == "web":
        name = r.get("h")
        # Let's Encrypt validates HTTP-01 from several vantage points, by Bait
        # Name, on every issuance and renewal -- our own certificate request
        # arriving back at us, not a discovery. See docs/adr/0004.
        if (r.get("u") or "").startswith(ACME):
            name = None
    else:
        name = r.get("sni")   # forward-only: catchall started extracting SNI later

    host = norm_host(name)
    if not host or not is_actor(ip):
        return "", False
    return host, classify(host, names) in ("bait", "control")


def ip_to_num(ip):
    """Dotted IPv4 -> int, or None for anything that is not one (IPv6 included)."""
    parts = (ip or "").split(".")
    if len(parts) != 4:
        return None
    n = 0
    for p in parts:
        if not p.isdigit():
            return None
        o = int(p)
        if o > 255:
            return None
        n = (n << 8) | o
    return n


# Loaded once, lazily: the table is ~9 MB and a routine incremental run looks
# up only a handful of new addresses, so it must not be parsed when there is
# nothing to look up. _GEO is None = not tried yet, () = tried and unavailable.
_GEO = None


def load_geo_index(path):
    """(starts, ends, ccs) from the packed index vendor-geo.sh builds, or None.

    Layout: one JSON header line, then three arrays -- uint32 starts, uint32
    ends, uint16 country-code indices. The header carries the byte order it
    was written with, because it is built on one machine and read on another."""
    try:
        with open(path, "rb") as f:
            header = json.loads(f.readline().decode())
            n = header["n"]
            codes = header["codes"]
            starts, ends, ccix = array("I"), array("I"), array("H")
            starts.fromfile(f, n)
            ends.fromfile(f, n)
            ccix.fromfile(f, n)
    except (OSError, ValueError, KeyError, EOFError):
        return None
    if header.get("little") != (sys.byteorder == "little"):
        starts.byteswap(); ends.byteswap(); ccix.byteswap()
    return (starts, ends, [codes[i] for i in ccix])


def load_geo(path=None):
    """(starts, ends, ccs) parallel lists, sorted by start, for bisect.

    Missing files are not fatal: the sensor's job is capture, and it should
    keep counting if the geo table was never vendored. country_of() then
    returns "" for everything and the map is empty rather than the rollup
    being broken."""
    global _GEO
    if _GEO is not None:
        return _GEO
    # Prefer the binary index. Parsing the CSV costs ~1.0s, and hp-recent runs
    # every 10 seconds -- that is a tenth of a core, permanently, to look up a
    # hundred addresses. The index loads in milliseconds.
    if path is None:
        idx = load_geo_index(os.path.join(GEO_DIR, "ip-country.idx"))
        if idx is not None:
            _GEO = idx
            return _GEO

    p = path or os.path.join(GEO_DIR, "ip-country-ipv4.csv")
    starts, ends, ccs = [], [], []
    try:
        with open(p) as f:
            for line in f:
                parts = line.rstrip("\n").split(",")
                if len(parts) != 3:
                    continue
                a, b = ip_to_num(parts[0]), ip_to_num(parts[1])
                if a is None or b is None:
                    continue
                starts.append(a); ends.append(b); ccs.append(parts[2])
    except OSError:
        _GEO = ([], [], [])
        return _GEO
    _GEO = (starts, ends, ccs)
    return _GEO


def country_of(ip, geo=None):
    """ISO-3166 alpha-2 for an address, or "" when unknown.

    IPv4 only. The catch-all binds AF_INET so v6 can only arrive via nginx,
    and the v6 table is a separate 16 MB file not worth carrying for that."""
    n = ip_to_num(ip)
    if n is None:
        return ""
    starts, ends, ccs = geo if geo is not None else load_geo()
    if not starts:
        return ""
    # Rightmost range whose start is <= n; it matches only if n is also within
    # that range's end, since the table has gaps.
    i = bisect.bisect_right(starts, n) - 1
    if i < 0 or n > ends[i]:
        return ""
    return ccs[i]


def load_centroids(path=None):
    """{cc: (lat, lon, name)} for placing a country on the map."""
    p = path or os.path.join(GEO_DIR, "country-centroids.csv")
    out = {}
    try:
        with open(p) as f:
            for line in f:
                parts = line.rstrip("\n").split(",", 3)
                if len(parts) != 4:
                    continue
                try:
                    out[parts[0]] = (float(parts[1]), float(parts[2]), parts[3])
                except ValueError:
                    continue
    except OSError:
        pass
    return out


def shape(s):
    """Normalize a payload so novel structure surfaces instead of novel randomness."""
    s = HEX.sub("H", s.strip().lower())
    s = NUM.sub("#", s)
    return WS.sub(" ", s)[:120]


def parse_ts(t):
    """Epoch seconds from a log timestamp. Both logs are UTC: catchall.py
    writes time.gmtime with no offset, nginx writes $time_iso8601 which the
    [:19] slice trims to the same shape.

    calendar.timegm, not time.mktime: mktime reads the struct as LOCAL time.
    On the sensor (Etc/UTC) the two agree, which is why this was invisible --
    but run the same analysis on a workstation in CEST and every timestamp
    moves two hours, silently. Hour-of-day buckets and issuance-to-Contact
    latencies are exactly the figures that would be wrong, and they are the
    ones the paper reports. Output is formatted with gmtime and labelled Z,
    so the input has to be read as UTC for that label to be true."""
    try:
        return calendar.timegm(time.strptime(t[:19], "%Y-%m-%dT%H:%M:%S"))
    except Exception:
        return 0.0


def resume_at(mark, ino, size):
    """Where to start reading. A rotated or truncated file restarts at zero."""
    if not mark:
        return 0
    if mark.get("ino") != ino or size < mark.get("pos", 0):
        return 0
    return mark.get("pos", 0)


def prune(st, now):
    """Bound the state. Anything that can no longer reach a 24h window is dropped."""
    day = now - DAY
    st["shape_first"] = {k: v for k, v in st["shape_first"].items() if v >= day}
    st["shapes"] = {k: v for k, v in st["shapes"].items() if k in st["shape_first"]}
    st["shape_sample"] = {k: v for k, v in st["shape_sample"].items() if k in st["shape_first"]}
    st["hourly"] = dict(sorted(st["hourly"].items())[-HOURS_KEPT:])
    st["contacts_hourly"] = dict(sorted(st["contacts_hourly"].items())[-HOURS_KEPT:])

    # Contacts are the headline, and the rarest ones matter most, so they are
    # pruned by age rather than by count.
    if len(st["contacts"]) > CONTACTS_KEPT:
        st["contacts"] = dict(sorted(st["contacts"].items(), key=lambda kv: -kv[1])[:CONTACTS_KEPT])
    st["contact_n"] = {k: v for k, v in st["contact_n"].items() if k in st["contacts"]}

    for key, keep in KEEP.items():
        if len(st[key]) > keep:
            st[key] = dict(sorted(st[key].items(), key=lambda kv: -kv[1])[:keep])
    return st


def absorb(st, r, ts, names):
    """Fold one record into the running counters."""
    st["events"] += 1
    bucket = str(int(ts // HOUR) * HOUR)
    st["hourly"][bucket] = st["hourly"].get(bucket, 0) + 1
    if ts and (not st["first_ts"] or ts < st["first_ts"]):
        st["first_ts"] = ts

    ip = r.get("ip")
    # Only Actors are counted here. CONTEXT.md defines an Actor as a *remote*
    # source; unique_ips is read as "actors total" by the panel and as the
    # Actor denominator by docs/paper.md, so counting the operator's own
    # loopback probes here would inflate exactly the ratio the sensor exists
    # to report. Events themselves are still counted -- the sensor did see
    # them -- it is only the Actor population that excludes us.
    if is_actor(ip):
        st["ips"][ip] = st["ips"].get(ip, 0) + 1
    if r.get("tls"):
        st["tls"] += 1

    if r.get("src") == "web":
        st["web"] += 1
        port = 443 if r.get("scheme") == "https" else 80
        u = r.get("u") or "/"
        p = u.split("?", 1)[0][:80]
        st["paths"][p] = st["paths"].get(p, 0) + 1
        ua = (r.get("ua") or "")[:120]
        if ua:
            st["uas"][ua] = st["uas"].get(ua, 0) + 1
        body = r.get("body") or ""
        m = USERFIELD.search(body)
        if m:
            st["users"][m.group(1)] = st["users"].get(m.group(1), 0) + 1
        payload = (r.get("m", "") + " " + u + " " + body).strip()
    else:
        st["tcp"] += 1
        port = r.get("dport") or 0
        payload = r.get("preview") or ""

    host, is_contact = record_to_contact(r, names)
    if host:
        st["hosts"][host] = st["hosts"].get(host, 0) + 1
        if is_contact:
            key = contact_key(ip, host)
            if key not in st["contacts"]:
                st["contacts"][key] = ts
                st["contacts_hourly"][bucket] = st["contacts_hourly"].get(bucket, 0) + 1
            st["contact_n"][key] = st["contact_n"].get(key, 0) + 1

    k = str(port)
    st["ports"][k] = st["ports"].get(k, 0) + 1

    if payload:
        sk = shape(payload)
        n = st["shapes"].get(sk, 0) + 1
        st["shapes"][sk] = n
        if sk not in st["shape_first"]:
            st["shape_first"][sk] = ts
            st["shape_sample"][sk] = payload[:200]
        elif n > NOVEL_MAX_SEEN:
            st["shape_sample"].pop(sk, None)   # it can never be novel again, so drop the sample
    return st


def main():
    names = read_names()
    st = blank()
    try:
        st.update(json.load(open(STATE)))
    except (OSError, ValueError):
        pass
    for k, v in EMPTY.items():          # a state file written before a key existed
        st.setdefault(k, json.loads(json.dumps(v)))
    st.pop("port_first", None)          # retired with new_ports_24h; see docs/adr/0001
    # ips once counted loopback and private sources, which are not Actors.
    st["ips"] = {ip: n for ip, n in st["ips"].items() if is_actor(ip)}

    read = 0
    for path in LOGS:
        try:
            info = os.stat(path)
        except OSError:
            continue
        start = resume_at(st["offsets"].get(path), info.st_ino, info.st_size)
        with open(path, errors="replace") as f:
            f.seek(start)
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except ValueError:
                    continue
                absorb(st, r, parse_ts(r.get("t", "")), names)
                read += 1
            st["offsets"][path] = {"pos": f.tell(), "ino": info.st_ino}

    now = time.time()
    prune(st, now)
    day = now - DAY

    def iso(ts):
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts)) if ts else ""

    ports = Counter({int(k): v for k, v in st["ports"].items()})
    novel_all = sorted(
        [{"shape": k, "n": st["shapes"][k], "first": iso(t), "sample": st["shape_sample"].get(k, "")}
         for k, t in st["shape_first"].items()
         if t >= day and st["shapes"].get(k, 0) <= NOVEL_MAX_SEEN],
        key=lambda x: x["first"], reverse=True)

    contacts_all = sorted(
        [{"ip": ip, "name": host, "first": iso(t), "n": st["contact_n"].get(k, 0),
          "class": classify(host, names)}
         for k, t in st["contacts"].items()
         for ip, host in (split_contact_key(k),)],
        key=lambda x: x["first"], reverse=True)
    contacts_24h = [c for c in st["contacts"].values() if c >= day]

    hosts_all = sorted(
        [{"host": h, "n": n, "class": classify(h, names)} for h, n in st["hosts"].items()],
        key=lambda x: -x["n"])

    # Countries are derived here rather than counted in absorb(): st["ips"]
    # already holds every Actor and its event count and is never pruned, so
    # this is exactly equivalent, needs no migration for history absorbed
    # before geo existed, cannot drift out of sync, and re-attributes for free
    # when the geo table is re-vendored. ~18k bisect lookups, measured at 0.08s.
    cent = load_centroids()
    ev, act = {}, {}
    unknown_events = unknown_actors = 0
    for ip, n in st["ips"].items():
        cc = country_of(ip)
        if not cc:
            unknown_events += n; unknown_actors += 1
            continue
        ev[cc] = ev.get(cc, 0) + n
        act[cc] = act.get(cc, 0) + 1
    countries_all = sorted(
        [{"cc": cc, "name": cent.get(cc, (0, 0, cc))[2], "n": n, "actors": act.get(cc, 0),
          "lat": cent.get(cc, (None, None, ""))[0],
          "lon": cent.get(cc, (None, None, ""))[1]}
         for cc, n in ev.items()],
        key=lambda x: -x["n"])
    # Anything the centroid table cannot place would silently vanish from the
    # map, so it is reported rather than dropped.
    unplaced = sum(c["n"] for c in countries_all if c["lat"] is None)

    env = read_env()
    host_cc = country_of(env.get("HOST_ADDR", ""))
    hlat, hlon, hname = cent.get(host_cc, (None, None, host_cc))
    # names.env may override: a datacenter's registered country is often right
    # while its centroid is a thousand km from the actual rack.
    try:
        if env.get("HOST_LAT") and env.get("HOST_LON"):
            hlat, hlon = float(env["HOST_LAT"]), float(env["HOST_LON"])
    except ValueError:
        pass
    sensor = {"cc": host_cc, "name": hname, "lat": hlat, "lon": hlon}

    top = lambda d, n: Counter(d).most_common(n)
    stats = {
        "generated": iso(now),
        "window_start": iso(st["first_ts"]),
        "totals": {
            "events": st["events"], "web": st["web"], "tcp": st["tcp"],
            "unique_ips": len(st["ips"]), "ports_seen": len(st["ports"]), "tls": st["tls"],
            "contacts": len(st["contacts"]), "contacts_24h": len(contacts_24h),
            "novel_24h": len(novel_all), "countries_seen": len(countries_all),
        },
        "hourly": [{"h": iso(int(h)), "n": n} for h, n in sorted(st["hourly"].items(), key=lambda kv: int(kv[0]))],
        "contacts_hourly": [{"h": iso(int(h)), "n": n}
                             for h, n in sorted(st["contacts_hourly"].items(), key=lambda kv: int(kv[0]))],
        "contacts": contacts_all[:CONTACTS_SHOWN],
        "hosts": hosts_all[:HOSTS_SHOWN],
        "top_ports": [{"port": p, "n": n} for p, n in ports.most_common(15)],
        "top_ips": [{"ip": i, "n": n} for i, n in top(st["ips"], 15)],
        "top_paths": [{"path": p, "n": n} for p, n in top(st["paths"], 15)],
        "top_agents": [{"ua": u, "n": n} for u, n in top(st["uas"], 10)],
        "credentials": [{"user": u, "n": n} for u, n in top(st["users"], 10)],
        "novel": novel_all[:NOVEL_SHOWN],
        "countries": countries_all,
        "countries_unplaced": unplaced,
        "countries_unknown_events": unknown_events,
        "countries_unknown_actors": unknown_actors,
        "sensor": sensor,
    }

    for path, data in ((OUT, stats), (STATE, st)):
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f, separators=(",", ":"))
        os.replace(tmp, path)
    print("%d new lines, %d events, %d contacts -> %s"
          % (read, st["events"], len(st["contacts"]), OUT))


def demo():
    """Self-check: normalization, Name classification, Contacts, resume, bounds."""
    assert shape("GET /a?id=8841 sess=deadbeefcafe") == "get /a?id=# sess=H"
    assert shape("GET /a?id=9 ") == "get /a?id=#"
    assert len(shape("z" * 300)) == 120
    assert parse_ts("2026-09-09T07:36:42+00:00") > 0
    assert parse_ts("garbage") == 0.0

    # Timestamps are UTC in both logs and must parse as UTC REGARDLESS of the
    # host's timezone. With time.mktime this passed only on a UTC box and
    # shifted every hour bucket and latency elsewhere -- including in any
    # re-analysis someone runs on their own machine.
    _known = 1789539026   # 2026-09-16T06:10:26Z, the Bait Name's first SCT
    assert parse_ts("2026-09-16T06:10:26") == _known, parse_ts("2026-09-16T06:10:26")
    assert parse_ts("2026-09-16T06:10:26+00:00") == _known, "the offset suffix must not shift it"
    assert time.strftime("%H:%M:%S", time.gmtime(parse_ts("2026-09-16T06:10:26"))) == "06:10:26", \
        "parse_ts/gmtime round-trip is not identity -- timestamps are being read as local time"

    # blank() must not hand out EMPTY's own nested dicts
    b = blank()
    b["ips"]["1.1.1.1"] = 1
    assert EMPTY["ips"] == {}, "blank() leaked a reference into EMPTY"

    # names.env parsing
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".env", delete=False) as f:
        f.write('# comment\nBAIT_NAMES="a.example b.example"\n'
                'CONTROL_NAMES="old.example"\nHOST_ADDR="203.0.113.9"\n')
        envp = f.name
    names = read_names(envp)
    os.unlink(envp)
    assert names[0] == {"a.example", "b.example"} and names[1] == {"old.example"}
    assert names[2] == "203.0.113.9"

    # host normalization
    assert norm_host("A.Example:443") == "a.example"
    assert norm_host("[2001:db8::1]:443") == "2001:db8::1"
    assert norm_host("2001:db8::1") == "2001:db8::1"
    assert norm_host(None) == ""

    # classification: the whole point is that a Derived Name is not a Contact
    assert classify("a.example", names) == "bait"
    assert classify("A.EXAMPLE:80", names) == "bait"
    assert classify("old.example", names) == "control"
    assert classify("203.0.113.9", names) == "derived"
    assert classify("api.203-0-113-9.nip.io", names) == "derived", "IP-derived name is not targeting"
    assert classify("[2001:db8::1]", names) == "derived"
    assert classify("", names) == "derived"
    assert classify("someone-else.example", names) == "foreign"

    # --- geo: address parsing -------------------------------------------
    assert ip_to_num("0.0.0.0") == 0
    assert ip_to_num("255.255.255.255") == 4294967295
    assert ip_to_num("1.2.3.4") == 16909060
    for bad in ("", None, "1.2.3", "1.2.3.4.5", "1.2.3.256", "1.2.3.-1",
                "2001:db8::1", "a.b.c.d", "1.2.3.x"):
        assert ip_to_num(bad) is None, bad

    # --- geo: the bisect lookup -----------------------------------------
    # Deliberate gap between the second and third range: the table does not
    # cover the whole address space, so "start <= n" alone is not a match.
    fake = (
        [ip_to_num("1.0.0.0"), ip_to_num("2.0.0.0"), ip_to_num("9.0.0.0")],
        [ip_to_num("1.0.0.255"), ip_to_num("2.255.255.255"), ip_to_num("9.0.0.0")],
        ["AU", "CN", "ZZ"],
    )
    assert country_of("1.0.0.0", fake) == "AU", "first address of a range is inside it"
    assert country_of("1.0.0.255", fake) == "AU", "last address of a range is inside it"
    assert country_of("1.0.0.7", fake) == "AU"
    assert country_of("2.0.0.1", fake) == "CN"
    assert country_of("9.0.0.0", fake) == "ZZ", "a single-address range still matches"
    assert country_of("0.255.255.255", fake) == "", "below the first range"
    assert country_of("1.0.1.0", fake) == "", "in the gap after a range end"
    assert country_of("5.5.5.5", fake) == "", "in the gap between ranges"
    assert country_of("200.0.0.1", fake) == "", "above the last range"
    assert country_of("2001:db8::1", fake) == "", "IPv6 is not looked up"
    assert country_of("", fake) == ""

    # a missing table is not fatal -- capture keeps working, the map is empty
    global _GEO
    saved, _GEO = _GEO, None
    assert load_geo("/nonexistent/ip-country.csv") == ([], [], [])
    assert country_of("1.0.0.1") == "", "no table means no country, not a crash"
    _GEO = saved

    # --- geo: the packed index must answer exactly like the CSV ----------
    with tempfile.NamedTemporaryFile(suffix=".idx", delete=False) as f:
        ipath = f.name
    hdr = {"v": 1, "n": 3, "codes": ["AU", "CN", "ZZ"], "little": sys.byteorder == "little"}
    with open(ipath, "wb") as f:
        f.write((json.dumps(hdr) + "\n").encode())
        array("I", fake[0]).tofile(f)
        array("I", fake[1]).tofile(f)
        array("H", [0, 1, 2]).tofile(f)
    packed = load_geo_index(ipath)
    os.unlink(ipath)
    assert packed is not None, "the packed index failed to load"
    assert list(packed[0]) == list(fake[0]) and list(packed[2]) == list(fake[2])
    for probe in ("1.0.0.0", "1.0.0.255", "2.0.0.1", "9.0.0.0", "5.5.5.5", "200.0.0.1"):
        assert country_of(probe, packed) == country_of(probe, fake), \
            "index and CSV disagree on " + probe
    assert load_geo_index("/nonexistent/x.idx") is None, "a missing index is not fatal"
    with tempfile.NamedTemporaryFile(suffix=".idx", delete=False) as f:
        f.write(b"not a header\n")
        bad = f.name
    assert load_geo_index(bad) is None, "a corrupt index falls back, it does not raise"
    os.unlink(bad)

    # --- geo: centroids --------------------------------------------------
    with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as f:
        f.write("AU,-25.0,133.0,Australia\nCN,35.0,103.0,China\nBAD,notanumber,1,X\n")
        cp = f.name
    cent = load_centroids(cp)
    os.unlink(cp)
    assert cent["AU"] == (-25.0, 133.0, "Australia")
    assert "BAD" not in cent, "an unparseable centroid row is skipped, not fatal"
    assert load_centroids("/nonexistent/centroids.csv") == {}

    # the operator curling the box must not become a Contact
    assert is_actor("203.0.113.7")
    assert not is_actor("127.0.0.1") and not is_actor("::1")
    assert not is_actor("10.0.0.5") and not is_actor("192.168.1.9") and not is_actor("172.16.0.1")
    assert is_actor("172.15.0.1") and is_actor("11.0.0.1"), "only the real private ranges"
    assert not is_actor("") and not is_actor(None)

    # absorb keeps no records, only counters
    now = time.time()
    st = blank()
    absorb(st, {"src": "hp", "ip": "1.2.3.4", "dport": 23, "preview": "login: 1234"}, now, names)
    absorb(st, {"src": "web", "ip": "1.2.3.4", "scheme": "https", "u": "/a?id=1",
                "ua": "curl", "body": "username=admin&password=x"}, now, names)
    assert st["events"] == 2 and st["tcp"] == 1 and st["web"] == 1
    assert st["users"]["admin"] == 1 and len(st["ips"]) == 1
    assert st["ports"]["23"] == 1 and st["ports"]["443"] == 1
    assert st["contacts"] == {}, "no Name was used, so no Contact"

    # contact_key / split_contact_key round-trip -- the one place the format lives
    assert contact_key("9.9.9.9", "a.example") == "9.9.9.9|a.example"
    assert split_contact_key("9.9.9.9|a.example") == ("9.9.9.9", "a.example")

    # record_to_contact is what absorb() and migrate.backfill() both call --
    # this is the seam that broke once (the rebuild forgot the SNI branch)
    assert record_to_contact({"src": "web", "ip": "9.9.9.9", "h": "a.example"}, names) == ("a.example", True)
    assert record_to_contact({"src": "hp", "ip": "9.9.9.9", "sni": "a.example"}, names) == ("a.example", True), \
        "SNI must carry a Name exactly like the HTTP Host does"
    assert record_to_contact({"src": "web", "ip": "9.9.9.9", "h": "203.0.113.9"}, names) == ("203.0.113.9", False), \
        "a Derived Name is a host, never a Contact"
    assert record_to_contact({"src": "web", "ip": "127.0.0.1", "h": "a.example"}, names) == ("", False), \
        "loopback carries no host at all, not just no Contact"
    assert record_to_contact(
        {"src": "web", "ip": "1.1.1.1", "h": "a.example", "u": "/.well-known/acme-challenge/x"}, names
    ) == ("", False), "ACME validation carries no host either"

    # a Contact is one Actor under one Name, however many requests follow
    st = blank()
    for _ in range(5):
        absorb(st, {"src": "web", "ip": "9.9.9.9", "h": "a.example", "u": "/"}, now, names)
    absorb(st, {"src": "web", "ip": "9.9.9.9", "h": "203.0.113.9", "u": "/"}, now, names)
    absorb(st, {"src": "web", "ip": "8.8.8.8", "h": "a.example", "u": "/"}, now, names)
    absorb(st, {"src": "web", "ip": "7.7.7.7", "h": "someone-else.example", "u": "/"}, now, names)
    absorb(st, {"src": "web", "ip": "127.0.0.1", "h": "a.example", "u": "/"}, now, names)
    assert len(st["contacts"]) == 2, st["contacts"]
    assert "127.0.0.1|a.example" not in st["contacts"], "loopback is not an Actor"
    assert st["contact_n"]["9.9.9.9|a.example"] == 5
    assert "7.7.7.7|someone-else.example" not in st["contacts"], "Foreign Name is not a Contact"
    assert st["hosts"]["203.0.113.9"] == 1, "a Derived Name is still counted as a host"
    assert "127.0.0.1" not in st["ips"], "loopback is not an Actor, so it is not in ips"
    assert st["events"] == 9, "the loopback request is still an event -- only the Actor count excludes it"
    bucket = str(int(now // HOUR) * HOUR)
    assert st["contacts_hourly"][bucket] == 2, "one bump per NEW Contact, not per request"

    # --- geo attribution is derived from ips, not counted in absorb() ----
    saved2, _GEO = _GEO, fake
    st = blank()
    for _ in range(3):
        absorb(st, {"src": "hp", "ip": "1.0.0.5", "dport": 23}, now, names)   # AU
    absorb(st, {"src": "hp", "ip": "1.0.0.6", "dport": 23}, now, names)       # AU, 2nd actor
    absorb(st, {"src": "hp", "ip": "2.0.0.9", "dport": 23}, now, names)       # CN
    absorb(st, {"src": "hp", "ip": "5.5.5.5", "dport": 23}, now, names)       # in a gap
    absorb(st, {"src": "hp", "ip": "127.0.0.1", "dport": 23}, now, names)     # not an Actor
    assert "countries" not in st, "countries are derived at emit time, not stored"
    ev, act, unk = {}, {}, 0
    for ip, n in st["ips"].items():
        cc = country_of(ip)
        if not cc:
            unk += 1; continue
        ev[cc] = ev.get(cc, 0) + n
        act[cc] = act.get(cc, 0) + 1
    assert ev == {"AU": 4, "CN": 1}, ev
    assert act == {"AU": 2, "CN": 1}, "distinct Actors per country, however many events each sends"
    assert unk == 1, "the Actor in a gap is counted as unknown, not dropped silently"
    assert "127.0.0.1" not in st["ips"], "a non-Actor never reaches the geo step at all"
    _GEO = saved2

    # our own ACME validation must never register as a Contact
    st = blank()
    for ip in ("23.178.112.213", "18.218.240.225", "51.21.169.175"):
        absorb(st, {"src": "web", "ip": ip, "h": "a.example",
                    "u": "/.well-known/acme-challenge/tokentokentoken"}, now, names)
    assert st["contacts"] == {}, "ACME validation is not a Contact"
    assert st["hosts"] == {}, "nor does it count as a Name asked for"
    absorb(st, {"src": "web", "ip": "23.178.112.213", "h": "a.example", "u": "/"}, now, names)
    assert len(st["contacts"]) == 1, "the same host asking for / is a Contact"

    # SNI carries a Name on any port, not just 80/443
    st = blank()
    absorb(st, {"src": "hp", "ip": "5.5.5.5", "dport": 8443, "sni": "a.example"}, now, names)
    assert list(st["contacts"]) == ["5.5.5.5|a.example"]

    # resume: fresh file, steady growth, truncation, rotation
    assert resume_at(None, 7, 100) == 0
    assert resume_at({"pos": 80, "ino": 7}, 7, 100) == 80
    assert resume_at({"pos": 80, "ino": 7}, 7, 40) == 0, "truncated file must restart"
    assert resume_at({"pos": 80, "ino": 7}, 9, 100) == 0, "rotated file must restart"

    # a shape past the novelty threshold loses its sample
    st2 = blank()
    for _ in range(NOVEL_MAX_SEEN + 1):
        absorb(st2, {"src": "hp", "ip": "9.9.9.9", "dport": 1, "preview": "same payload"}, now, names)
    assert st2["shapes"]["same payload"] == NOVEL_MAX_SEEN + 1
    assert "same payload" not in st2["shape_sample"], "sample must be dropped once it cannot be novel"

    # prune drops what can no longer reach the 24h window, and caps every series
    st3 = blank()
    st3["shape_first"] = {"old": now - 2 * DAY, "new": now}
    st3["shapes"] = {"old": 1, "new": 1}
    st3["shape_sample"] = {"old": "x", "new": "y"}
    st3["hourly"] = {str(i * HOUR): 1 for i in range(HOURS_KEPT + 20)}
    st3["contacts_hourly"] = {str(i * HOUR): 1 for i in range(HOURS_KEPT + 20)}
    st3["paths"] = {"/p%d" % i: i for i in range(KEEP["paths"] + 50)}
    st3["hosts"] = {"h%d.example" % i: i for i in range(KEEP["hosts"] + 50)}
    st3["contacts"] = {"ip%d|a.example" % i: now - i for i in range(CONTACTS_KEPT + 50)}
    st3["contact_n"] = {k: 1 for k in st3["contacts"]}
    prune(st3, now)
    assert list(st3["shape_first"]) == ["new"] and list(st3["shapes"]) == ["new"]
    assert list(st3["shape_sample"]) == ["new"]
    assert len(st3["hourly"]) == HOURS_KEPT
    assert len(st3["contacts_hourly"]) == HOURS_KEPT
    assert len(st3["paths"]) == KEEP["paths"]
    assert len(st3["hosts"]) == KEEP["hosts"]
    assert len(st3["contacts"]) == CONTACTS_KEPT
    assert len(st3["contact_n"]) == CONTACTS_KEPT, "contact_n must follow contacts"
    assert "ip0|a.example" in st3["contacts"], "pruning keeps the most recent Contacts"

    # every key prune touches is one prune() actually knows about
    for key in KEEP:
        assert key in EMPTY, key
    print("rollup self-check ok")


if __name__ == "__main__":
    if "--demo" in sys.argv:
        demo()
    else:
        main()
