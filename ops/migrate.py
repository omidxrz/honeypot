#!/usr/bin/env python3
"""One-shot: redact Foreign-Name credentials already on disk, backfill Contacts.

Three things that have to happen together, or the counters break:

1. web.jsonl already holds requests that arrived under a Foreign Name, with
   their auth, cookie and body. nginx blanks those at capture from now on; this
   removes the ones already written.
2. With --rebuild, hosts/contacts/contact_n are cleared and replayed from BOTH
   logs. That is a one-time correction, not routine: it is how a counter that
   never existed gets backfilled, or how a changed definition gets applied to
   history. It is off by default because it is destructive -- it can only
   reconstruct what the current log files still contain, so anything already
   rotated away is lost, and it must read hp.jsonl or it drops every Contact
   that arrived by TLS SNI rather than by HTTP Host.
3. Rewriting the file changes its inode, which makes resume_at() restart at
   zero and re-absorb all of it. So the offset is repointed at the new file in
   the same step.

Run with hp-rollup.timer stopped. Keeps a .bak.

    systemctl stop hp-rollup.timer
    python3 /opt/honeypot/ops/migrate.py
    systemctl start hp-rollup.timer
"""
import json, os, shutil, sys, tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rollup   # same directory, no packaging; the classification rule must not be copied

REDACT = ("auth", "ck", "body")


def scrub_line(r, names):
    """Blank the credentials of a record that arrived under a Foreign Name."""
    if rollup.classify(r.get("h"), names) != "foreign":
        return r, False
    hit = False
    for k in REDACT:
        if r.get(k):        # count what was actually removed, so a second run reports 0
            r[k] = ""
            hit = True
    return r, hit


def backfill(st, r, names):
    """Count the Name and the Contact. Deliberately nothing else.

    Calls rollup.record_to_contact() rather than re-deriving the rule: that
    function is the one place the host-field-by-src branch, the ACME
    exclusion and the is_actor gate live, precisely because this function once
    re-derived it independently and got it wrong (forgot the SNI branch,
    silently dropped every Contact made on a port nginx never sees). See
    docs/adr/0005."""
    host, is_contact = rollup.record_to_contact(r, names)
    if not host:
        return
    st["hosts"][host] = st["hosts"].get(host, 0) + 1
    if is_contact:
        ip = r.get("ip")
        key = rollup.contact_key(ip, host)
        if key not in st["contacts"]:
            st["contacts"][key] = rollup.parse_ts(r.get("t", ""))
        st["contact_n"][key] = st["contact_n"].get(key, 0) + 1


def rebuild_names_and_contacts(st, names, logs):
    """Clear hosts/contacts and replay them from every log. Destructive: see the
    module docstring. Reads hp.jsonl too, or SNI-derived Contacts vanish."""
    st["hosts"], st["contacts"], st["contact_n"] = {}, {}, {}
    seen = 0
    for path in logs:
        try:
            f = open(path, errors="replace")
        except OSError:
            continue
        with f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except ValueError:
                    continue
                backfill(st, r, names)
                seen += 1
    return seen


def run(web_path, state_path, names, rebuild=False, logs=None):
    st = rollup.blank()
    try:
        st.update(json.load(open(state_path)))
    except (OSError, ValueError):
        pass
    for k, v in rollup.EMPTY.items():
        st.setdefault(k, json.loads(json.dumps(v)))
    st.pop("port_first", None)

    if not os.path.exists(web_path):
        return {"lines": 0, "redacted": 0, "contacts": 0}


    shutil.copy2(web_path, web_path + ".bak")
    d = os.path.dirname(os.path.abspath(web_path))
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".migrate-")
    lines = redacted = 0
    with os.fdopen(fd, "w") as out, open(web_path, errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except ValueError:
                out.write(line + "\n")   # keep what we cannot read, unchanged
                lines += 1
                continue
            r, hit = scrub_line(r, names)
            redacted += hit
            out.write(json.dumps(r, separators=(",", ":")) + "\n")
            lines += 1
    os.replace(tmp, web_path)

    if rebuild:
        rebuild_names_and_contacts(st, names, logs or [rollup.LOGS[0], web_path])

    info = os.stat(web_path)
    st["offsets"][web_path] = {"pos": info.st_size, "ino": info.st_ino}

    t = state_path + ".tmp"
    with open(t, "w") as f:
        json.dump(st, f, separators=(",", ":"))
    os.replace(t, state_path)
    return {"lines": lines, "redacted": redacted, "contacts": len(st["contacts"])}


def demo():
    """Self-check: redaction, the counters that must not move, and the offset."""
    names = ({"a.example"}, {"old.example"}, "203.0.113.9")
    d = tempfile.mkdtemp()
    web = os.path.join(d, "web.jsonl")
    state = os.path.join(d, "state.json")

    recs = [
        {"t": "2026-09-09T07:00:00", "src": "web", "ip": "1.1.1.1", "h": "a.example",
         "auth": "Bearer ours", "ck": "s=1", "body": "x=1"},
        {"t": "2026-09-09T07:00:01", "src": "web", "ip": "1.1.1.1", "h": "a.example"},
        {"t": "2026-09-09T07:00:02", "src": "web", "ip": "2.2.2.2", "h": "theirs.example",
         "auth": "Bearer theirs", "ck": "sid=abc", "body": "password=hunter2"},
        {"t": "2026-09-09T07:00:03", "src": "web", "ip": "3.3.3.3", "h": "203.0.113.9"},
        {"t": "2026-09-09T07:00:04", "src": "web", "ip": "4.4.4.4", "h": "old.example"},
        {"t": "2026-09-09T07:00:05", "src": "web", "ip": "127.0.0.1", "h": "a.example"},
        {"t": "2026-09-09T07:00:06", "src": "web", "ip": "5.5.5.5", "h": "a.example",
         "u": "/.well-known/acme-challenge/tok"},
    ]
    with open(web, "w") as f:
        for r in recs:
            f.write(json.dumps(r) + "\n")
    before = rollup.blank()
    before["events"] = 999          # a counter migrate must not touch
    before["hosts"] = {"a.example": 77}          # as if a rollup had run first
    before["contacts"] = {"1.1.1.1|a.example": 1}
    before["contact_n"] = {"1.1.1.1|a.example": 77}
    before["offsets"][web] = {"pos": 10, "ino": 1}
    json.dump(before, open(state, "w"))

    hp = os.path.join(d, "hp.jsonl")
    with open(hp, "w") as f:                    # a Contact made by TLS SNI, not HTTP
        f.write(json.dumps({"t": "2026-09-09T07:00:07", "src": "hp", "ip": "6.6.6.6",
                            "dport": 8443, "sni": "a.example"}) + "\n")

    # --- default: scrub only, never touch the Contacts -------------------
    out = run(web, state, names)
    assert out["lines"] == 7 and out["redacted"] == 1, out

    got = [json.loads(l) for l in open(web)]
    assert got[0]["auth"] == "Bearer ours", "our own Name keeps its capture"
    assert got[2]["auth"] == "" and got[2]["ck"] == "" and got[2]["body"] == "", \
        "a Foreign Name must lose its credentials"
    assert got[2]["h"] == "theirs.example", "the fact of it is still signal"
    assert len(got) == 7, "no record is dropped"

    st = json.load(open(state))
    assert st["events"] == 999, "migrate must not re-absorb: events moved"
    assert st["contacts"] == {"1.1.1.1|a.example": 1}, \
        "a routine run must leave accumulated Contacts exactly alone"
    assert st["hosts"] == {"a.example": 77}

    info = os.stat(web)
    assert st["offsets"][web] == {"pos": info.st_size, "ino": info.st_ino}, \
        "offset must point past the rewritten file or every counter doubles"
    assert os.path.exists(web + ".bak")

    out2 = run(web, state, names)
    assert out2["redacted"] == 0, out2

    # --- --rebuild: clear and replay from every log ----------------------
    out3 = run(web, state, names, rebuild=True, logs=[hp, web])
    st3 = json.load(open(state))
    assert st3["events"] == 999, "a rebuild still must not re-absorb the totals"
    assert st3["contact_n"]["1.1.1.1|a.example"] == 2, "replayed, not inherited"
    assert "6.6.6.6|a.example" in st3["contacts"], \
        "a rebuild that skips hp.jsonl drops every SNI Contact"
    assert "2.2.2.2|theirs.example" not in st3["contacts"], "Foreign Name is not a Contact"
    assert "3.3.3.3|203.0.113.9" not in st3["contacts"], "Derived Name is not a Contact"
    assert "4.4.4.4|old.example" in st3["contacts"], "Control Name still counts"
    assert "127.0.0.1|a.example" not in st3["contacts"], "loopback is not an Actor"
    assert "5.5.5.5|a.example" not in st3["contacts"], "ACME validation is not a Contact"
    assert st3["hosts"]["203.0.113.9"] == 1
    assert out3["contacts"] == 3, out3

    out4 = run(web, state, names, rebuild=True, logs=[hp, web])
    st4 = json.load(open(state))
    for k in ("hosts", "contacts", "contact_n"):
        assert st4[k] == st3[k], "rebuild must be idempotent in " + k
    shutil.rmtree(d)
    print("migrate self-check ok")


if __name__ == "__main__":
    if "--demo" in sys.argv:
        demo()
    else:
        rb = "--rebuild" in sys.argv
        r = run("/opt/honeypot/logs/web.jsonl", rollup.STATE, rollup.read_names(),
                rebuild=rb, logs=rollup.LOGS)
        print("%d lines, %d redacted, %d contacts %s"
              % (r["lines"], r["redacted"], r["contacts"],
                 "(rebuilt from every log)" if rb else "(left alone)"))
