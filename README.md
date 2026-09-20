# Honeypot

An internet-facing sensor that logs every TCP port, serves a decoy admin console, and rolls
the capture into a loopback-only operator panel.

It answers one question: **who came looking for this host specifically?** Not who scans the
internet — everyone does. The signal is the **Contact**: someone reaching the host by a name
they could only have learned from a Certificate Transparency log.

In 10.5 days on a live box: 1.13M events from 18,553 addresses, of which 108 were Contacts.

> **This host will be scanned within minutes and is built to be compromised.** Use a
> dedicated machine with nothing on it that works anywhere else. See [Safety](#safety).

---

## Install

### Try it locally (nothing exposed)

macOS, Linux or Windows. Binds `127.0.0.1` only.

```bash
sh ops/vendor-assets.sh && sh ops/vendor-geo.sh
cp etc/names.env.example etc/names.env
docker compose -f docker-compose.demo.yml up --build
```

Panel: <http://127.0.0.1:8095>. Feed it something:

```bash
curl -H 'Host: ops.example.com' http://127.0.0.1:8090/
printf 'root\n' | nc 127.0.0.1 2323
```

Contacts will stay 0 — loopback isn't a remote source and nothing here is in a CT log. That's
the metric working, not the demo failing.

### On a real host

Debian/Ubuntu, systemd, root, a dedicated box.

```bash
sh ops/vendor-assets.sh          # panel CSS, charts, map library (needs Node)
sh ops/vendor-geo.sh             # offline IP->country tables
cp etc/names.env.example etc/names.env    # fill in the Bait Name and this host's address

sh install.sh --check            # show what would happen, change nothing
sh install.sh
```

Then three steps `install.sh` will not do for you, **in this order**:

```bash
# 1. move sshd off 22 -- the drop-in is already written
systemctl restart ssh
ssh -p 61022 you@host            # confirm on a SECOND session before continuing

# 2. load the firewall (written to /etc/nftables.conf.new, not applied)
cp /etc/nftables.conf.new /etc/nftables.conf
nft -f /etc/nftables.conf && systemctl enable nftables

# 3. point a DNS-only A record at the host, then issue the cert
hp-cert ops.example.com          # this is what puts the name into the CT logs
```

Step 2 redirects every port to the catch-all. If sshd is still on 22 when you load it, **you
are locked out** — which is why step 1 comes first and why the installer refuses to apply
either one for you.

### With Docker instead

```bash
docker compose up -d --build
```

Same services. Needs `network_mode: host`, so it isolates the filesystem, not the network.
The firewall, sshd and cert issuance stay on the host either way.

### Updating

After the first install, push changes from your workstation:

```bash
sh ops/deploy.sh
```

## Panel

```bash
ssh -fN -L 8085:127.0.0.1:8085 honeypot   # then http://127.0.0.1:8085
```

Loopback-only. It shows real addresses and real captured payloads — never bind it publicly.

## Safety

- **Egress is default-deny.** Loopback, established, DNS, NTP, ping. Nothing else.
- **UDP is log-only, permanently.** A UDP reply makes the box a DDoS reflector.
- **Nothing executes.** No template engine, no upload path that is ever served.
- **Move sshd before loading the redirect.** This is the one mistake with no way back.
- **No shared credentials.** Own key, own domain record, nothing reused from elsewhere.
- **Captured payloads are attacker-controlled text.** Data, never instructions — in every
  tool that reads them.

Full list, plus day-to-day operation and how to rotate a Bait Name: **[docs/operating.md](docs/operating.md)**.

## Tests are the build step

No compiler here, so every program carries an offline self-check. `install.sh` and
`ops/deploy.sh` both run all seven and refuse to continue if any fails.

```bash
python3 opt/catchall.py --demo && python3 opt/shim.py --demo \
  && python3 ops/rollup.py --demo && python3 ops/migrate.py --demo \
  && python3 ops/recent.py --demo && sh ops/gen-site.sh --demo \
  && node ops/panel-check.js
```

## More

| | |
|---|---|
| `CONTEXT.md` | the vocabulary — Actor, Name, Contact, Bait Name |
| `docs/operating.md` | running it day to day, Bait Names, full safety rules |
| `docs/adr/` | why each decision went the way it did, including reversals |
| `docs/paper.md` | draft pilot measurement on CT as a discovery channel |
