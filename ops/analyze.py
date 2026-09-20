#!/usr/bin/env python3
"""Every figure docs/paper.md cites, computed from the raw logs in ONE pass.

    python3 ops/analyze.py                  # full pass, Markdown to stdout
    python3 ops/analyze.py --json           # same numbers, machine-readable
    python3 ops/analyze.py --demo           # offline self-check

Why this exists, and why it is not rollup.py:

rollup.py keeps FORWARD-ONLY counters in ops/state.json. It never recomputes
them, it prunes its tables to bounded sizes (KEEP, CONTACTS_KEPT, HOURS_KEPT),
and the raw capture rotates one generation at 512 MiB. So a published figure
that came from stats.json cannot be re-derived later, and several of the
paper's figures -- the hour-by-hour Contact histogram above all -- had already
aged out of the 48-hour window stats.json keeps by the time they were quoted.
They came from a one-off script that was never committed, which meant no reader
could reproduce §4.4 at all.

This program is that script, committed and self-checked. It holds no state,
writes nothing, and reads the logs from the beginning every time, so the same
logs always give the same answer.

The definitions are NOT reimplemented here. is_actor, record_to_contact,
norm_host, classify, country_of and parse_ts are imported from rollup, per
ADR-0005: one function decides what a Contact is, and everything else asks it.
A second opinion in here is how the paper and the panel start disagreeing.

THE MATCHED WINDOW. The sensor ran for ~10.6 days but the Bait Name only
existed for the last ~3.6 of them, so there are two populations and they are
not interchangeable. An earlier draft divided Contacts observed in the Bait
window by Actors observed over the WHOLE run, which understates the rate by
counting ~7 days of addresses that never had a Bait Name to find. Every rate
here is computed over one stated window, and the denominator is named.
"""
import base64, collections, json, os, re, sys


def io_read(p):
    with open(p, errors="replace") as f:
        return f.read()

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rollup   # the definitions live there and are not copied

PCTL = (50, 90, 99)

# Known-exploitation signatures. Deliberately coarse and deliberately public:
# this is NOT a detector, it is the LABEL SET that separates "we have seen this
# before" from the residue. The residue is the interesting part, and its size
# is only meaningful if the label set is stated rather than tuned.
#
# A miss here is not a bug, it is the measurement: /SDK/webLanguage (Hikvision
# CVE-2021-36260) matches nothing below and is a known CVE, which is exactly
# why "matched no signature" must never be reported as "unknown vulnerability".
SIGNATURES = [
    ("log4j-jndi",       rb"\$\{jndi:"),
    ("path-traversal",   rb"\.\./\.\./|%2e%2e%2f|\.\.\\"),
    ("shellshock",       rb"\(\)\s*\{\s*:;\s*\}"),
    ("sqli",             rb"(?i)union\s+select|' or '1'='1|sleep\(\d+\)"),
    ("cmd-injection",    rb"(?i);\s*(wget|curl|nc|bash|sh)\s|\|\s*(wget|curl)\s"),
    ("webshell-funcs",   rb"(?i)eval\(|base64_decode\(|system\(|passthru\("),
    ("xxe",              rb"(?i)<!entity|<!doctype[^>]*system"),
    ("ssti",             rb"\{\{.+\}\}"),
    ("java-deserialize", rb"\xac\xed\x00\x05|rO0AB"),
    ("php-wrapper",      rb"(?i)php://|data://|expect://"),
    ("cve-2017-9841",    rb"(?i)eval-stdin\.php"),
    ("config-hunting",   rb"(?i)/\.env|/\.git/|/config\.json|/\.aws"),
    ("cloud-metadata",   rb"169\.254\.169\.254"),
    ("cgi-bin",          rb"(?i)/cgi-bin/"),
    ("actuator-admin",   rb"(?i)/actuator|/druid/|/solr/"),
    ("xmlrpc",           rb"(?i)xmlrpc\.php"),
    ("script-exec",      rb"(?i)\.php\?|\.jsp\?|cmd=|exec="),
]
_SIG = [(n, re.compile(p)) for n, p in SIGNATURES]


def sig_hits(blob):
    """Signature names matching this record's attacker-controlled bytes.

    Pattern-matching only. Nothing here decodes into a shell, resolves a URL
    or evaluates anything -- captured bytes are data, never instructions."""
    return [n for n, rx in _SIG if rx.search(blob)]


def proto_shape(d):
    """What protocol the opening bytes look like. Coarse on purpose -- this
    says how much of the corpus is protocol handshake noise versus something
    with application content in it, which is what decides how big the real
    analysable surface is."""
    if d[:4] in (b"GET ", b"POST", b"HEAD", b"PUT ") or d[:7] == b"OPTIONS":
        return "http"
    if d[:3] == b"SSH":
        return "ssh"
    if d[:3] == b"RFB":
        return "vnc"
    if d[:1] == b"\x16":
        return "tls"
    if d[:1] == b"\xff":
        return "telnet"
    if all(32 <= c < 127 or c in (9, 10, 13) for c in d[:32]):
        return "other-text"
    return "binary"


def log_inventory(log_dir=None, read=None):
    """Every file in the log directory, and whether the analysis reads it.

    A dataset that silently omits a file on disk is not a complete dataset.
    The backups in particular are NOT read -- they are pre-migrate copies, and
    at least one has held records the live log no longer contains."""
    read = set(read or rollup.LOGS)
    log_dir = log_dir or os.path.dirname(rollup.LOGS[0])
    rows = []
    try:
        entries = sorted(os.listdir(log_dir))
    except OSError:
        return rows
    for name in entries:
        p = os.path.join(log_dir, name)
        if not os.path.isfile(p):
            continue
        lines = 0
        try:
            with open(p, errors="replace") as f:
                for _ in f:
                    lines += 1
        except OSError:
            pass
        rows.append({"file": name, "bytes": os.path.getsize(p), "records": lines,
                     "in_analysis": p in read})
    return rows


def pct(sorted_vals, p):
    """The p-th percentile by nearest-rank. Empty input is 0, not an error:
    an empty category is a real state here (no TLS yet, no bodies yet)."""
    if not sorted_vals:
        return 0
    k = max(0, min(len(sorted_vals) - 1, int(round(p / 100.0 * len(sorted_vals) + 0.5)) - 1))
    return sorted_vals[k]


def scan(logs, names, geo=None, bait_start=None):
    """One pass over every record. Returns a dict of plain numbers.

    bait_start is the SCT timestamp as epoch seconds; everything at or after
    it is inside the Bait-Name window. Passing None means the whole run is the
    window, which is what a sensor with no Bait Name yet should report."""
    st = {
        "events": 0, "web": 0, "tcp": 0, "tls": 0, "malformed": 0,
        "first_ts": None, "last_ts": None,
        "actors": set(), "actors_bait": set(),
        "actor_tcp": collections.Counter(),   # for the concentration figure
        "ports": collections.Counter(),
        "countries": collections.Counter(),
        "country_actors": collections.defaultdict(set),
        "unlocated": set(),
        "contacts": {},            # "ip|host" -> first ts (epoch)
        "contact_n": collections.Counter(),
        "payloads": [],
        "methods": collections.Counter(),
        "statuses": collections.Counter(),
        "acme": set(),
        "sig": collections.Counter(),          # signature -> records matched
        "sig_src": collections.defaultdict(collections.Counter),
        "sig_records": collections.Counter(),  # source log -> records with >=1 hit
        "payload_records": collections.Counter(),
        "proto": collections.Counter(),        # opening-byte protocol shape
        "sni_port": collections.defaultdict(collections.Counter),  # port -> class
        "sni_values": set(),
    }

    for path in logs:
        try:
            fh = open(path, errors="replace")
        except OSError:
            continue
        with fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except ValueError:
                    st["malformed"] += 1
                    continue

                # parse_ts returns 0.0, not None, for anything it cannot read.
                # Letting that through would put a record at the epoch and
                # drag first_ts back to 1970, silently reporting a 20,000-day
                # observation window.
                ts = rollup.parse_ts(r.get("t", ""))
                if not ts:
                    st["malformed"] += 1
                    continue
                if st["first_ts"] is None or ts < st["first_ts"]:
                    st["first_ts"] = ts
                if st["last_ts"] is None or ts > st["last_ts"]:
                    st["last_ts"] = ts

                st["events"] += 1
                web = r.get("src") == "web"
                if web:
                    st["web"] += 1
                    st["methods"][r.get("m") or "?"] += 1
                    st["statuses"][str(r.get("st") or "?")] += 1
                else:
                    st["tcp"] += 1
                    if r.get("tls"):
                        st["tls"] += 1
                    if r.get("dport") is not None:
                        st["ports"][r["dport"]] += 1
                    n = r.get("n")
                    if isinstance(n, int) and n > 0:
                        st["payloads"].append(n)

                ip = r.get("ip")
                if not rollup.is_actor(ip):
                    continue

                st["actors"].add(ip)
                if not web:
                    st["actor_tcp"][ip] += 1
                if bait_start is not None and ts >= bait_start:
                    st["actors_bait"].add(ip)

                cc = rollup.country_of(ip, geo)
                if cc:
                    st["countries"][cc] += 1
                    st["country_actors"][cc].add(ip)
                else:
                    st["unlocated"].add(ip)

                # ACME validation is the CA fetching its own challenge file
                # under the Bait Name. It is not a Contact (ADR-0004), but it
                # IS worth counting -- it is the sanity check that says the
                # pre-SCT traffic really was validation and not an observer.
                if web and (r.get("u") or "").startswith(rollup.ACME):
                    st["acme"].add(ip)

                # --- exploitation labelling and protocol shape -------------
                # Both logs, because they hold different halves of the same
                # picture: nginx sees HTTP on 80/443, the catch-all sees
                # everything else including HTTP on non-standard ports.
                src = "web" if web else "hp"
                blob = b""
                if web:
                    blob = (" ".join(str(r.get(k) or "")
                                     for k in ("u", "ua", "ref", "body", "ct"))).encode(
                                         "utf-8", "replace")
                    st["payload_records"][src] += 1
                else:
                    b64 = r.get("b64")
                    if b64:
                        try:
                            blob = base64.b64decode(b64)
                        except Exception:
                            blob = b""
                        if blob:
                            st["payload_records"][src] += 1
                            st["proto"][proto_shape(blob)] += 1

                if blob:
                    hits = sig_hits(blob)
                    if hits:
                        st["sig_records"][src] += 1
                        for h in hits:
                            st["sig"][h] += 1
                            st["sig_src"][h][src] += 1

                # --- Names arriving by SNI, per port ------------------------
                # The catch-all extracts SNI on every port, which nothing in
                # the prior literature does. The question it answers: does CT
                # discovery reach past 443, or is it web-shaped?
                sni = rollup.norm_host(r.get("sni")) if not web else ""
                if sni:
                    st["sni_values"].add(sni)
                    st["sni_port"][r.get("dport")][rollup.classify(sni, names)] += 1

                host, is_contact = rollup.record_to_contact(r, names)
                if is_contact:
                    key = rollup.contact_key(ip, host)
                    st["contact_n"][key] += 1
                    if key not in st["contacts"] or ts < st["contacts"][key]:
                        st["contacts"][key] = ts

    return st


def summarize(st, bait_start=None):
    """Turn the scan into the numbers the paper quotes. No I/O."""
    import time

    def iso(t):
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t)) if t else ""

    span = (st["last_ts"] - st["first_ts"]) / 86400.0 if st["first_ts"] else 0.0
    firsts = sorted(st["contacts"].values())

    # Contacts whose FIRST arrival falls inside the Bait window. A Contact
    # first seen before it cannot be attributed to the certificate.
    in_win = [t for t in firsts if bait_start is None or t >= bait_start]

    # Gaps between successive new Contacts -- the shape of discovery, not of
    # traffic. A burst then a long tail shows up here and nowhere else.
    gaps = sorted((in_win[i] - in_win[i - 1]) / 60.0 for i in range(1, len(in_win)))

    hourly = collections.Counter()
    for t in in_win:
        hourly[iso(t)[:13]] += 1

    reqs = sorted(st["contact_n"].values())
    pays = sorted(st["payloads"])
    tcp = st["tcp"] or 1

    denom = len(st["actors_bait"]) if bait_start is not None else len(st["actors"])
    out = {
        "window": {
            "first": iso(st["first_ts"]), "last": iso(st["last_ts"]),
            "days": round(span, 2),
            "bait_start": iso(bait_start) if bait_start else "",
            "bait_days": round((st["last_ts"] - bait_start) / 86400.0, 2) if bait_start else None,
        },
        "totals": {
            "events": st["events"], "tcp": st["tcp"], "web": st["web"],
            "tls": st["tls"], "malformed": st["malformed"],
            "actors_all": len(st["actors"]),
            "actors_in_bait_window": len(st["actors_bait"]),
            "ports_seen": len(st["ports"]),
        },
        "contacts": {
            "total": len(firsts),
            "in_bait_window": len(in_win),
            "denominator": denom,
            "denominator_is": ("Actors seen in the Bait-Name window"
                               if bait_start else "Actors seen in the whole run"),
            "rate_pct": round(100.0 * len(in_win) / denom, 4) if denom else 0.0,
            "first": iso(in_win[0]) if in_win else "",
            "acme_validators": len(st["acme"]),
            "singleton_pct": round(100.0 * sum(1 for n in reqs if n == 1) / len(reqs), 1) if reqs else 0.0,
            "requests_p50": pct(reqs, 50), "requests_p90": pct(reqs, 90),
            "requests_max": reqs[-1] if reqs else 0,
            "gap_min_p50": round(pct(gaps, 50), 1), "gap_min_p90": round(pct(gaps, 90), 1),
            "busiest_hour": hourly.most_common(1)[0] if hourly else ("", 0),
            "hourly": hourly.most_common(8),
        },
        "background": {
            "top_ports": [(p, n, round(100.0 * n / tcp, 2)) for p, n in st["ports"].most_common(12)],
            "payload_p50": pct(pays, 50), "payload_p90": pct(pays, 90),
            "payload_p99": pct(pays, 99), "payload_n": len(pays),
            "top_methods": st["methods"].most_common(4),
            "top_statuses": st["statuses"].most_common(4),
        },
        "geography": {
            "countries": len(st["countries"]),
            "located_pct": round(100.0 * sum(st["countries"].values()) /
                                 max(1, sum(st["countries"].values()) + len(st["unlocated"])), 2),
            "unlocated_actors": len(st["unlocated"]),
            "top": [(cc, n, len(st["country_actors"][cc])) for cc, n in st["countries"].most_common(10)],
        },
    }

    # VNC is the headline of the background section and is spread over a
    # display range, so it has to be summed rather than read off one port.
    vnc = sum(n for p, n in st["ports"].items() if 5900 <= p <= 5910)
    out["background"]["vnc_events"] = vnc
    out["background"]["vnc_pct"] = round(100.0 * vnc / tcp, 2)

    # Concentration: how much of the raw-TCP flood comes from how few Actors.
    # This is what makes the background "generic scanning" rather than many
    # independent parties, and it is the contrast the Contact rate is against.
    ranked = [n for _, n in st["actor_tcp"].most_common()]
    total_actor_tcp = sum(ranked) or 1
    running, conc = 0, {}
    for k in (10, 12, 100):
        conc["top%d_pct" % k] = round(100.0 * sum(ranked[:k]) / total_actor_tcp, 2)
    for i, n in enumerate(ranked):
        running += n
        if running >= total_actor_tcp / 2.0:
            conc["actors_for_half"] = i + 1
            conc["actors_for_half_pct_of_all"] = round(
                100.0 * (i + 1) / max(1, len(st["actors"])), 3)
            break
    out["background"]["concentration"] = conc
    return out


def render(d):
    """Markdown, so the output can be pasted into docs/paper-data.md."""
    w, t, c, b, g = d["window"], d["totals"], d["contacts"], d["background"], d["geography"]
    L = []
    L.append("## Window\n")
    L.append("| | |\n|---|---|")
    L.append("| Sensor first record | `%s` |" % w["first"])
    L.append("| Snapshot (last record) | `%s` |" % w["last"])
    L.append("| Total operation | %.2f days |" % w["days"])
    if w["bait_start"]:
        L.append("| Bait Name in CT since | `%s` |" % w["bait_start"])
        L.append("| Bait-Name observation | %.2f days |" % w["bait_days"])

    L.append("\n## Totals\n")
    L.append("| | |\n|---|---|")
    L.append("| Events | %s |" % f"{t['events']:,}")
    L.append("| Raw TCP | %s |" % f"{t['tcp']:,}")
    L.append("| HTTP | %s |" % f"{t['web']:,}")
    L.append("| TLS connections | %s |" % f"{t['tls']:,}")
    L.append("| Distinct Actors, whole run | %s |" % f"{t['actors_all']:,}")
    L.append("| Distinct Actors, Bait window | %s |" % f"{t['actors_in_bait_window']:,}")
    L.append("| Ports touched | %s |" % f"{t['ports_seen']:,}")
    L.append("| Malformed log lines | %s |" % f"{t['malformed']:,}")

    L.append("\n## Contacts\n")
    L.append("| | |\n|---|---|")
    L.append("| Contacts, all time | %s |" % f"{c['total']:,}")
    L.append("| Contacts, Bait window | %s |" % f"{c['in_bait_window']:,}")
    L.append("| Denominator | %s (%s) |" % (f"{c['denominator']:,}", c["denominator_is"]))
    L.append("| **Rate** | **%.3f%%** |" % c["rate_pct"])
    L.append("| First Contact | `%s` |" % c["first"])
    L.append("| ACME validators excluded | %d |" % c["acme_validators"])
    L.append("| Single-request Contacts | %.1f%% |" % c["singleton_pct"])
    L.append("| Requests per Contact | p50 %d, p90 %d, max %s |"
             % (c["requests_p50"], c["requests_p90"], f"{c['requests_max']:,}"))
    L.append("| Gap between new Contacts | p50 %.1f min, p90 %.1f min |"
             % (c["gap_min_p50"], c["gap_min_p90"]))
    L.append("| Busiest hour | `%s` with %d |" % c["busiest_hour"])
    L.append("\nFirst arrivals by hour (top 8):\n")
    L.append("| Hour (UTC) | Contacts |\n|---|---|")
    for h, n in c["hourly"]:
        L.append("| `%s` | %d |" % (h, n))

    L.append("\n## Background scanning\n")
    L.append("| Port | Events | Share of raw TCP |\n|---|---|---|")
    for p, n, share in b["top_ports"]:
        L.append("| %d | %s | %.2f%% |" % (p, f"{n:,}", share))
    L.append("\nVNC (5900-5910) combined: **%s events, %.2f%% of raw TCP**."
             % (f"{b['vnc_events']:,}", b["vnc_pct"]))
    cn = b["concentration"]
    L.append("\nConcentration: the top 10 Actors account for %.2f%% of raw TCP, the top 12 for "
             "%.2f%%. Half of all raw TCP comes from %d Actors (%.3f%% of all connecting "
             "addresses)." % (cn["top10_pct"], cn["top12_pct"],
                              cn.get("actors_for_half", 0), cn.get("actors_for_half_pct_of_all", 0)))
    L.append("\nOpening-byte payload sizes (n=%s): p50 %d B, p90 %d B, p99 %d B."
             % (f"{b['payload_n']:,}", b["payload_p50"], b["payload_p90"], b["payload_p99"]))
    L.append("\nHTTP methods: %s." % ", ".join("%s %s" % (m, f"{n:,}") for m, n in b["top_methods"]))

    L.append("\n## Geography\n")
    L.append("| | |\n|---|---|")
    L.append("| Countries seen | %d |" % g["countries"])
    L.append("| Events located | %.2f%% |" % g["located_pct"])
    L.append("| Actors not located | %d |" % g["unlocated_actors"])
    L.append("\n| Country | Events | Actors |\n|---|---|---|")
    for cc, n, a in g["top"]:
        L.append("| %s | %s | %s |" % (cc, f"{n:,}", f"{a:,}"))
    return "\n".join(L)


def anon(ip):
    """An address truncated to its /24 (or /48 for v6).

    Contacts are the unit of analysis, so the dataset has to carry one row per
    Contact -- but a full address identifies a specific machine, and the whole
    reason the raw capture is unpublishable is that it points at third parties.
    A /24 keeps what the analysis needs (are these the same network, how many
    distinct networks) and drops what it does not."""
    if not ip:
        return ""
    if ":" in ip:
        return ":".join(ip.split(":")[:3]) + "::/48"
    parts = ip.split(".")
    if len(parts) != 4:
        return ""
    return ".".join(parts[:3]) + ".0/24"


def export(st, out_dir, bait_start=None):
    """Write the publishable dataset: aggregates plus per-Contact rows with
    addresses truncated. Never payloads, bodies, credentials or full addresses.
    The self-check asserts all of that."""
    import time

    os.makedirs(out_dir, exist_ok=True)
    written = {}

    def cell(x):
        """One CSV field, safe to open in a spreadsheet.

        Some of these strings are attacker-controlled. A field starting with
        =, +, - or @ is executed as a formula by Excel and Sheets, so a
        published dataset carrying one is a payload aimed at whoever opens it.
        Prefix with an apostrophe and quote anything structural."""
        s = str(x)
        if s[:1] in ("=", "+", "-", "@", "\t", "\r"):
            s = "'" + s
        if any(c in s for c in ',"\n\r'):
            s = '"' + s.replace('"', '""') + '"'
        return s

    def csv(name, header, rows):
        path = os.path.join(out_dir, name)
        with open(path, "w") as f:
            f.write(",".join(header) + "\n")
            for r in rows:
                f.write(",".join(cell(x) for x in r) + "\n")
        written[name] = len(rows)

    iso = lambda t: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))

    rows = []
    for key, first in sorted(st["contacts"].items(), key=lambda kv: kv[1]):
        ip, host = rollup.split_contact_key(key)
        rows.append((iso(first), anon(ip), host, st["contact_n"][key],
                     "in_window" if (bait_start is None or first >= bait_start) else "before_window"))
    csv("contacts.csv", ["first_seen_utc", "actor_net", "name", "requests", "window"], rows)

    hourly = collections.Counter()
    for t in st["contacts"].values():
        if bait_start is None or t >= bait_start:
            hourly[iso(t)[:13]] += 1
    csv("contacts-hourly.csv", ["hour_utc", "first_contacts"], sorted(hourly.items()))

    csv("ports.csv", ["port", "events"], st["ports"].most_common())
    csv("countries.csv", ["cc", "events", "actors"],
        [(cc, n, len(st["country_actors"][cc])) for cc, n in st["countries"].most_common()])
    csv("http-status.csv", ["status", "count"], st["statuses"].most_common())
    csv("http-method.csv", ["method", "count"], st["methods"].most_common())

    # Exploitation labelling. Counts and category names only -- no captured
    # bytes, so the residue can be sized without republishing the payloads.
    # EVERY signature, including the ones with zero hits. A zero is a result:
    # "no Log4j JNDI attempts in 11 days" is a finding about campaign decay,
    # and a table that omits the row leaves a reader unable to tell whether it
    # was searched for and absent, or never searched for at all.
    csv("signatures.csv", ["signature", "hits", "in_hp_jsonl", "in_web_jsonl"],
        sorted(((n, st["sig"].get(n, 0), st["sig_src"][n].get("hp", 0),
                 st["sig_src"][n].get("web", 0)) for n, _ in SIGNATURES),
               key=lambda r: (-r[1], r[0])))

    csv("corpus.csv", ["source", "records_with_content", "records_matching_a_signature"],
        [(s, st["payload_records"][s], st["sig_records"][s])
         for s in sorted(st["payload_records"])])

    csv("payload-protocol.csv", ["opening_bytes_look_like", "records"],
        st["proto"].most_common())

    # Names by SNI, per port: the all-port view no prior CT honeypot has.
    rows = []
    for port in sorted(st["sni_port"], key=lambda p: (p is None, p)):
        c = st["sni_port"][port]
        rows.append((port if port is not None else "", c.get("bait", 0), c.get("control", 0),
                     c.get("derived", 0), c.get("foreign", 0), sum(c.values())))
    csv("sni-by-port.csv",
        ["port", "bait", "control", "derived", "foreign", "total"], rows)

    inv = log_inventory()
    csv("log-inventory.csv", ["file", "bytes", "records", "included_in_this_analysis"],
        [(r["file"], r["bytes"], r["records"], "yes" if r["in_analysis"] else "no")
         for r in inv])

    with open(os.path.join(out_dir, "summary.json"), "w") as f:
        json.dump(summarize(st, bait_start), f, indent=2, sort_keys=True)
    written["summary.json"] = 1
    return written


def demo():
    """Self-check: the matched window, and that no secret can reach the output."""
    import tempfile, shutil, time

    d = tempfile.mkdtemp()
    names = ({"bait.example"}, {"retired.example"}, "203.0.113.9")
    saved = rollup._GEO
    rollup._GEO = ([rollup.ip_to_num("1.0.0.0")], [rollup.ip_to_num("1.255.255.255")], ["AU"])

    def ts(s):
        return "2026-09-16T%s" % s

    bait = rollup.parse_ts(ts("06:10:26"))
    log = os.path.join(d, "web.jsonl")
    with open(log, "w") as f:
        w = lambda o: f.write(json.dumps(o) + "\n")
        # BEFORE the Bait Name existed: an Actor that can never be a Contact.
        # It belongs in the all-run denominator and NOT in the matched one.
        w({"t": "2026-09-15T00:00:00", "src": "web", "ip": "1.0.0.1", "h": "203.0.113.9", "u": "/"})
        # ACME validation, under the Bait Name, before the SCT. Not a Contact.
        w({"t": ts("06:10:22"), "src": "web", "ip": "1.0.0.2",
           "h": "bait.example", "u": "/.well-known/acme-challenge/xyz"})
        # Two real Contacts inside the window, one of them repeating.
        w({"t": ts("06:10:29"), "src": "web", "ip": "1.0.0.3", "h": "bait.example", "u": "/",
           "auth": "Bearer topsecret", "ck": "sid=abc", "body": "password=hunter2"})
        w({"t": ts("06:11:00"), "src": "web", "ip": "1.0.0.3", "h": "bait.example", "u": "/x"})
        w({"t": ts("07:00:00"), "src": "web", "ip": "1.0.0.4", "h": "bait.example", "u": "/"})
        # An Actor inside the window that never used the Name: denominator only.
        w({"t": ts("06:30:00"), "src": "web", "ip": "1.0.0.5", "h": "203.0.113.9", "u": "/"})
        # Loopback is not an Actor and must not reach any population.
        w({"t": ts("06:31:00"), "src": "web", "ip": "127.0.0.1", "h": "bait.example", "u": "/"})
        # A Contact by a RETIRED Name, arriving before this certificate was
        # issued. It is a genuine Contact (a Control Name still counts) but it
        # cannot be attributed to this issuance, so it must be inside
        # contacts.total and outside contacts.in_bait_window. Without a row
        # like this the window filter has nothing to exclude and the check
        # passes whether or not the filter exists.
        w({"t": "2026-09-15T12:00:00", "src": "web", "ip": "1.0.0.6",
           "h": "retired.example", "u": "/"})
        # An unparseable timestamp. parse_ts answers 0.0, and admitting that
        # would put the record at the epoch and report a 20,000-day window.
        w({"t": "not-a-timestamp", "src": "web", "ip": "1.0.0.7",
           "h": "bait.example", "u": "/"})

    st = scan([log], names, bait_start=bait)
    out = summarize(st, bait_start=bait)

    assert out["totals"]["actors_all"] == 6, out["totals"]["actors_all"]
    # The garbage-timestamp record is dropped whole, so its address never
    # joins any population and the window still starts at the real first row.
    assert out["totals"]["malformed"] == 1, out["totals"]["malformed"]
    assert out["window"]["first"].startswith("2026-09-15"), out["window"]["first"]
    assert out["window"]["days"] < 2, "epoch-0 record dragged the window open: %s" % out["window"]
    # The matched window holds 1.0.0.3, .4 and .5. Two are excluded for
    # different reasons, and both reasons matter:
    #   1.0.0.1 arrived a day before the Bait Name existed.
    #   1.0.0.2 is the ACME validator, which arrives BEFORE the SCT -- exactly
    #           as it does in the real capture. Pre-SCT traffic cannot have
    #           learned the Name from a log that does not yet contain it.
    assert out["totals"]["actors_in_bait_window"] == 3, out["totals"]["actors_in_bait_window"]
    assert "127.0.0.1" not in st["actors"], "loopback is not an Actor"

    # Three Contacts exist; only two fall inside the window this certificate
    # created. The retired-Name Contact from the day before is real and is
    # counted in the total, but attributing it to this issuance would be the
    # same error as the mismatched denominator, from the other side.
    assert out["contacts"]["total"] == 3, out["contacts"]["total"]
    assert out["contacts"]["in_bait_window"] == 2, out["contacts"]
    assert out["contacts"]["denominator"] == 3, "must divide by the MATCHED window"
    assert abs(out["contacts"]["rate_pct"] - 66.6667) < 1e-3, out["contacts"]["rate_pct"]
    # The bug this program exists to prevent: dividing by the all-run count.
    assert out["contacts"]["denominator"] != out["totals"]["actors_all"], \
        "the denominator fell back to the whole run -- this is the mismatched-window bug"
    assert out["contacts"]["acme_validators"] == 1, "ACME validation must be counted, not silent"
    assert out["contacts"]["first"] == "2026-09-16T06:10:29Z", out["contacts"]["first"]
    assert out["contacts"]["requests_max"] == 2, out["contacts"]["requests_max"]

    # Nothing captured may reach a document that gets published.
    blob = json.dumps(out) + render(out)
    for leak in ("hunter2", "Bearer", "topsecret", "sid=abc", "1.0.0.3"):
        assert leak not in blob, "analysis output leaked %r" % leak

    # --- the publishable export ---
    ed = os.path.join(d, "dataset")
    written = export(st, ed, bait_start=bait)
    assert written["contacts.csv"] == 3, written
    dump = ""
    for fn in sorted(os.listdir(ed)):
        dump += io_read(os.path.join(ed, fn))

    # Addresses are truncated and payloads never appear. If either fails, the
    # dataset is not publishable and this is the only thing standing between a
    # captured credential and an archive.
    # RFC 5737 documentation range, not a real address out of the capture:
    # a test fixture is not a place to write down somebody's IP.
    assert anon("203.0.113.208") == "203.0.113.0/24", anon("203.0.113.208")
    assert anon("2001:db8:abcd:1::5") == "2001:db8:abcd::/48", anon("2001:db8:abcd:1::5")
    assert anon("") == "" and anon("garbage") == ""
    for leak in ("hunter2", "Bearer", "topsecret", "sid=abc", "password"):
        assert leak not in dump, "the exported dataset leaked %r" % leak
    for full in ("1.0.0.3", "1.0.0.4", "1.0.0.6"):
        assert full not in dump, "the exported dataset carries a full address (%s)" % full
    assert "1.0.0.0/24" in dump, "Contact rows lost their (truncated) address entirely"
    # The window column has to distinguish them, or the matched-window rule is
    # unreproducible from the dataset alone.
    assert "before_window" in dump and "in_window" in dump, "window labelling missing"

    # Signature labelling reached both logs, and reports the residue.
    assert sig_hits(b"GET /.env HTTP/1.1") == ["config-hunting"], sig_hits(b"GET /.env HTTP/1.1")
    assert "log4j-jndi" in sig_hits(b"User-Agent: ${jndi:ldap://x/a}")
    assert sig_hits(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n") == [], "a plain GET is not exploitation"
    # The point of the whole exercise: a known CVE the label set misses lands
    # in the residue, and must never be called an unknown vulnerability.
    assert sig_hits(b"GET /SDK/webLanguage HTTP/1.1") == [], \
        "if this ever matches, update the paper -- the residue claim depends on it"
    assert "signatures.csv" in written and "corpus.csv" in written
    # A zero-hit signature must still appear, or "we found no Log4j" is
    # indistinguishable from "we never looked for Log4j".
    assert written["signatures.csv"] == len(SIGNATURES), \
        "signatures.csv dropped the zero-hit rows (%d of %d)" % (
            written["signatures.csv"], len(SIGNATURES))
    assert "log4j-jndi" in io_read(os.path.join(ed, "signatures.csv")), \
        "a signature with no hits vanished from the table"
    assert "sni-by-port.csv" in written and "log-inventory.csv" in written

    assert proto_shape(b"GET / HTTP/1.1") == "http"
    assert proto_shape(b"RFB 003.008\n") == "vnc"
    assert proto_shape(b"\x16\x03\x01") == "tls"
    assert proto_shape(b"\x00\x01\x02\xff\xfe") == "binary"

    # Spreadsheet formula injection: these strings are attacker-controlled and
    # a published CSV carrying one is a payload aimed at whoever opens it.
    ed2 = os.path.join(d, "inject")
    st2 = dict(st)
    st2["statuses"] = collections.Counter({"=cmd|'/c calc'!A1": 3, "+1": 1, "@SUM(1)": 1})
    export(st2, ed2, bait_start=bait)
    inj = io_read(os.path.join(ed2, "http-status.csv"))
    for line in inj.splitlines()[1:]:
        assert not line[:1] in ("=", "+", "@"), "CSV formula injection survived: %r" % line

    assert pct([], 50) == 0, "an empty category is a state, not a crash"
    assert pct([1, 2, 3, 4], 50) == 2
    assert scan([os.path.join(d, "nope.jsonl")], names)["events"] == 0, "a missing log is not fatal"

    rollup._GEO = saved
    shutil.rmtree(d)
    print("analyze self-check ok")


def main():
    names = rollup.read_names()
    bait = None
    for i, a in enumerate(sys.argv):
        if a == "--since" and i + 1 < len(sys.argv):
            bait = rollup.parse_ts(sys.argv[i + 1])
    st = scan(rollup.LOGS, names, rollup.load_geo(), bait_start=bait)
    out = summarize(st, bait_start=bait)
    for i, a in enumerate(sys.argv):
        if a == "--export" and i + 1 < len(sys.argv):
            w = export(st, sys.argv[i + 1], bait_start=bait)
            for k in sorted(w):
                print("  %-22s %d row(s)" % (k, w[k]))
            return
    if "--json" in sys.argv:
        json.dump(out, sys.stdout, indent=2, sort_keys=True)
        print()
    else:
        print(render(out))


if __name__ == "__main__":
    if "--demo" in sys.argv:
        demo()
    else:
        main()
