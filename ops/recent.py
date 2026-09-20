#!/usr/bin/env python3
"""Write ops/recent.json: the last few arrivals, located, for the panel's map.

Deliberately tiny and stateless. It holds no counters, writes no state file and
never touches ops/state.json, so a bug in here cannot corrupt the numbers that
took eleven days to accumulate -- the worst it can do is produce a stale or
empty feed. rollup.py remains the only thing that owns state.

It reads only the TAIL of each log. hp.jsonl is ~350 MB and grows ~34 MB/day;
reading it whole every ten seconds would be absurd.

What it emits is deliberately narrower than what the logs hold: a timestamp,
the address, where that address is, and whether the arrival used one of our
Names. No payload, no body, no auth, no cookie -- nothing the panel does not
already show, and nothing that would put captured credentials into a second
file. The self-check asserts that.

    python3 recent.py            # write the feed once
    python3 recent.py --demo     # offline self-check
"""
import json, os, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rollup   # same directory, no packaging; the Name rules must not be copied

OUT = "/opt/honeypot/ops/recent.json"
TAIL_BYTES = 256 * 1024   # a few hundred records at the observed line length
SHOWN = 120               # arcs the panel could ever draw at once


def tail_lines(path, nbytes=TAIL_BYTES):
    """The last complete lines of a file, reading at most nbytes from the end.

    The first line after a mid-file seek is almost always a partial record, so
    it is discarded rather than handed to json.loads to fail on."""
    try:
        size = os.path.getsize(path)
    except OSError:
        return []
    try:
        with open(path, errors="replace") as f:
            start = max(0, size - nbytes)
            f.seek(start)
            if start:
                f.readline()
            return f.read().splitlines()
    except OSError:
        return []


def arrivals(logs, names, cent, limit=SHOWN):
    """Recent located arrivals, oldest first. Anything we cannot place is
    dropped -- this feed exists to draw arcs, and an arc needs two ends."""
    out = []
    for path in logs:
        for line in tail_lines(path):
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except ValueError:
                continue
            ip = r.get("ip")
            if not rollup.is_actor(ip):
                continue
            cc = rollup.country_of(ip)
            pos = cent.get(cc)
            if not pos:
                continue
            host, named = rollup.record_to_contact(r, names)
            out.append({
                "t": r.get("t", ""),
                "ip": ip,
                "cc": cc,
                "lat": pos[0],
                "lon": pos[1],
                # "named" is not "Contact": a Contact is the FIRST arrival by a
                # Name, and this program has no state with which to know that.
                # This says only that the arrival used one of our Names.
                "named": bool(named),
            })
    out.sort(key=lambda e: e["t"])
    return out[-limit:]


def main():
    names = rollup.read_names()
    cent = rollup.load_centroids()
    events = arrivals(rollup.LOGS, names, cent)
    doc = {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "events": events,
    }
    tmp = OUT + ".tmp"
    with open(tmp, "w") as f:
        json.dump(doc, f, separators=(",", ":"))
    os.replace(tmp, OUT)
    print("%d arrivals (%d by name) -> %s"
          % (len(events), sum(1 for e in events if e["named"]), OUT))


def demo():
    """Self-check: tail bounding, what is emitted, and what must never be."""
    import tempfile, shutil

    d = tempfile.mkdtemp()
    names = ({"a.example"}, set(), "203.0.113.9")
    cent = {"AU": (-25.0, 133.0, "Australia"), "CN": (35.0, 103.0, "China")}

    # a fake geo table so country_of resolves without the real 9 MB file
    saved = rollup._GEO
    # 127/8 is deliberately in this table and mapped to a real centroid, so
    # the only thing that can exclude loopback is the is_actor() gate. With a
    # table that could not place it, this test would pass for the wrong reason.
    rollup._GEO = (
        [rollup.ip_to_num("1.0.0.0"), rollup.ip_to_num("2.0.0.0"), rollup.ip_to_num("127.0.0.0")],
        [rollup.ip_to_num("1.0.0.255"), rollup.ip_to_num("2.255.255.255"), rollup.ip_to_num("127.255.255.255")],
        ["AU", "CN", "AU"],
    )

    web = os.path.join(d, "web.jsonl")
    with open(web, "w") as f:
        f.write(json.dumps({"t": "2026-09-20T01:00:00", "src": "web", "ip": "1.0.0.9",
                            "h": "a.example", "u": "/",
                            "body": "password=hunter2", "auth": "Bearer secret",
                            "ck": "sid=abc"}) + "\n")
        f.write(json.dumps({"t": "2026-09-20T01:00:01", "src": "web", "ip": "2.0.0.9",
                            "h": "203.0.113.9", "u": "/"}) + "\n")
        f.write(json.dumps({"t": "2026-09-20T01:00:02", "src": "web", "ip": "127.0.0.1",
                            "h": "a.example", "u": "/"}) + "\n")
        f.write(json.dumps({"t": "2026-09-20T01:00:03", "src": "web", "ip": "9.9.9.9",
                            "h": "a.example", "u": "/"}) + "\n")   # not in the geo table

    ev = arrivals([web], names, cent)
    assert len(ev) == 2, ev
    assert [e["ip"] for e in ev] == ["1.0.0.9", "2.0.0.9"], "oldest first"
    assert ev[0]["cc"] == "AU" and ev[0]["lat"] == -25.0
    assert ev[0]["named"] is True, "arrived by a Bait Name"
    assert ev[1]["named"] is False, "a Derived Name is not one of our Names"
    assert all("127.0.0.1" != e["ip"] for e in ev), "loopback is not an Actor"
    assert all(e["cc"] for e in ev), "an unlocatable arrival has no arc to draw"

    # the whole point: captured secrets must not reach a second file
    blob = json.dumps(ev)
    for leak in ("hunter2", "Bearer", "secret", "sid=abc", "password"):
        assert leak not in blob, "recent.json leaked %r from the capture" % leak
    assert set(ev[0]) == {"t", "ip", "cc", "lat", "lon", "named"}, set(ev[0])

    # tail bounding: a big file must not be read whole
    big = os.path.join(d, "big.jsonl")
    with open(big, "w") as f:
        for i in range(20000):
            f.write(json.dumps({"t": "2026-09-20T02:00:00", "src": "hp",
                                "ip": "1.0.0.5", "dport": 23, "pad": "x" * 200}) + "\n")
    size = os.path.getsize(big)
    assert size > 4 * TAIL_BYTES, "test file is not big enough to prove bounding"
    lines = tail_lines(big)
    assert len(lines) < 20000, "tail_lines read the whole file"
    assert sum(len(x) for x in lines) <= TAIL_BYTES, "tail_lines exceeded its budget"
    for line in lines:
        json.loads(line)   # every returned line is whole, incl. after the seek

    # A seek into the middle of a file lands mid-record. That first partial
    # line must be discarded: every line handed back has to be whole JSON.
    frag = os.path.join(d, "frag.jsonl")
    with open(frag, "w") as f:
        for i in range(50):
            f.write(json.dumps({"t": "2026-09-20T03:00:%02d" % (i % 60),
                                "src": "hp", "ip": "1.0.0.7", "pad": "y" * 120}) + "\n")
    # a budget that cannot align with a line boundary, so the seek always
    # lands inside a record
    got = tail_lines(frag, nbytes=777)
    assert got, "expected some lines back"
    for line in got:
        json.loads(line)   # fails loudly if the partial first line survived

    assert tail_lines("/nonexistent/x.jsonl") == [], "a missing log is not fatal"
    assert arrivals(["/nonexistent/x.jsonl"], names, cent) == []

    rollup._GEO = saved
    shutil.rmtree(d)
    print("recent self-check ok")


if __name__ == "__main__":
    if "--demo" in sys.argv:
        demo()
    else:
        main()
