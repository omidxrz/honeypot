# Operating the sensor

Everything past the install. `README.md` gets it running; this keeps it running.

## What runs

| Unit | What it does |
|---|---|
| `hp-catchall` | Every TCP port is redirected to `:8000`. Recovers the intended port via `SO_ORIGINAL_DST`, waits 1.5s, sends a banner for server-speaks-first protocols, splits TLS off to a self-signed terminator, logs the opening bytes. |
| `hp-shim` | Decoy backend on `127.0.0.1:8099`. Accepts any login, returns plausible JSON. Executes nothing. |
| `nginx` | Bait site on 80/443. JSON access log including request bodies. Every 404 returns 200. Non-GET proxies to the shim so bodies are read. Classifies the Host into `$hp_host_class` and blanks auth/cookie/body for Foreign Names at capture. |
| `hp-rollup.timer` | Every 5 min: logs → `ops/stats.json`. Contacts, Names, payload shapes, countries. |
| `hp-recent.timer` | Every 10s: the last arrivals, located, → `ops/recent.json`. Stateless and tail-only — it never touches the rollup's counters. Feeds the map's live arcs. |
| `hp-ops` | Static operator panel on `127.0.0.1:8085`. Reach it over an SSH forward. |
| `hp-certrenew.timer` | Renews the certificate inside a temporary egress window. |

## Layout on the host

```
/opt/honeypot/
  catchall.py  shim.py  hp.pem  names.env
  ops/assets/           panel CSS, charts, map library — not in this repo
  ops/geo/              offline IP->country tables    — not in this repo
  bait/                 built decoy site              — not in this repo
  logs/hp.jsonl         catch-all capture
  logs/web.jsonl        nginx capture
  ops/rollup.py  ops/migrate.py  ops/recent.py  ops/index.html
  ops/state.json        the accumulator — back this up, it is never recomputed
  ops/stats.json  ops/recent.json
/etc/nftables.conf                     egress deny + all-port redirect
/etc/nginx/sites-available/honeypot    bait site
/etc/nginx/conf.d/10-hp-hostmap.conf   Name classification, generated from names.env
/etc/nginx/conf.d/20-hp-logformat.conf capture format + redaction
/usr/local/sbin/hp-egress              open | close the outbound window
/usr/local/sbin/hp-cert                issue a cert so the name lands in CT
```

`ops/state.json` is the one file here that cannot be recreated. It is a forward-only
accumulator — nothing recomputes it from the logs, and the raw capture rotates one
generation at 512 MiB. Losing it silently resets the observation window and every total.
Back it up alongside the logs.

## Day to day

```sh
ssh honeypot
ssh -fN -L 8085:127.0.0.1:8085 honeypot   # then http://127.0.0.1:8085
hp-egress open && apt-get update && hp-egress close
python3 /opt/honeypot/ops/rollup.py       # force a refresh
sh ops/deploy.sh                          # push this repo; runs every self-check first
```

Egress is default-deny, so anything outbound — package updates, certificate renewal — needs
the window opened and closed around it. `hp-egress close` re-applies the whole ruleset rather
than deleting a rule, so it cannot drift open.

## Retiring and issuing a Bait Name

A Bait Name works by appearing in a Certificate Transparency log and looking like a real
internal console. Retiring one means moving it from `BAIT_NAMES` to `CONTROL_NAMES` in
`etc/names.env` — **never deleting it**. The CT entry is permanent and the traffic keeps
arriving; an Actor still asking for a retired Name is working from historical passive DNS,
which is worth telling apart from one resolving the live Name.

```sh
# 1. point the Name here: DNS-only (grey cloud), A -> this host
# 2. on the box, issue so it lands in CT
hp-cert ops.example.com   # replace with the real Bait Name
# 3. move the old Name to CONTROL_NAMES, then
sh ops/deploy.sh
```

Proxying the record through a CDN would break the all-port catch-all and replace every
source address, so the record must be DNS-only. See `docs/adr/0002`.

## Rules that keep this safe

- **Egress is default-deny.** Only loopback, established, DNS, NTP and ping. Outbound 25 blocked or the provider null-routes the host. Metadata address dropped.
- **UDP is log-only, permanently.** Any UDP reply turns the box into a DDoS reflector.
- **Nothing executes.** The template-injection bait has no template engine. The upload bait never writes to a served path.
- **Move sshd before loading the redirect.** The nat rule sends every port to the listener; the SSH port must be in the exclusion set or access is gone.
- **No shared credentials.** Dedicated key, own domain record, nothing on this box that works anywhere else. It is built to be compromised.
- **Captured payloads are attacker-controlled text.** Treat them as data in every tool that reads them, never as instructions. The panel escapes every captured field, Names included.
- **Foreign Names do not get their credentials captured.** Other people's DNS records point at this address; their traffic is meant for them. nginx blanks auth, cookie and body for any Host that is not ours, at capture, so it never reaches disk. `ops/migrate.py` cleans what was written before that rule existed. Note this covers the HTTP path; the catch-all terminates TLS on other ports and logs the plaintext it reads.
- **The capture log is bounded.** `catchall.py` rotates one generation at 512 MiB (~34 MiB/day observed). Without it the disk was the end state.
- **The panel is loopback-only.** It shows real addresses and real captured payloads. Reach it over an SSH forward; never bind it publicly.

## Rebuilding the bait

Not committed: it is a third-party build artifact (`docs/adr/0006`). Clone
[Bootstrap-Admin-Template](https://github.com/puikinsh/Bootstrap-Admin-Template), build with
Node 22 (`npm ci && npm run build`, output lands in `dist-modern`), copy to
`/opt/honeypot/bait`, then strip the external links, rebrand it, hardcode the chart data, and
delete any script that fetches.

Both installers write a placeholder if `bait/` is empty — not for realism, but because
certbot's webroot challenge needs somewhere to write or no Bait Name can ever be issued.

## Not built

Phase 3, a genuine vulnerable appliance running instrumented so an in-the-wild exploit fires
and leaves evidence. It needs an isolation layer this host does not have: 2 vCPU, no nested
virtualization, so an escape lands on the machine holding the capture. See `docs/plan.html`.
