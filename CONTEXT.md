# Honeypot

An internet-facing sensor. It answers on every TCP port, serves a decoy internal
console, and rolls the capture into an operator panel. The question it exists to
answer is not "who scans the internet" — everyone does — but **who came looking
for this host specifically**.

## Language

### Arrival

**Actor**:
The remote source address of a connection. One IP, however many connections it
opens. Loopback and private ranges are not Actors: on an internet-facing sensor
those are the operator, and counting them inflates the only metric that matters.
_Avoid_: attacker, client, source, peer.

**Name**:
The hostname an Actor used to reach this host — the HTTP `Host` header, or the
SNI in a TLS ClientHello. Distinct from the address it resolves to.
_Avoid_: domain, vhost, FQDN.

**Derived Name**:
A Name that can be constructed from this host's address without knowing anything
else: the address itself, or a wildcard-DNS label that encodes it
(`api.204-11-2-208.nip.io`). Carries no information about how the Actor found us.
_Avoid_: IP host, literal host.

**Contact**:
The first time an Actor reaches this host by a Bait Name or a Control Name. The
unit of the targeting signal: one Actor arriving under one Name, counted once
however many requests follow. An Actor that only ever used a Derived Name has
made no Contact.
_Avoid_: hit, visit, session, connection.

### Names we publish

**Bait Name**:
A Name we placed in a certificate so it would appear in a Certificate
Transparency log, and which currently resolves here. The instrument that
produces Contacts.
_Avoid_: canary, decoy domain.

**Control Name**:
A retired Bait Name that no longer resolves. Still counted: an Actor asking for
one is working from historical passive DNS rather than live resolution, which is
worth telling apart.
_Avoid_: dead name, old domain.

**Foreign Name**:
A Name that is neither ours nor Derived — someone else's DNS record pointing at
this address. The traffic is meant for them, not us. Its credentials are not
ours to keep, so `Authorization`, `Cookie` and request bodies are dropped at
capture for these.
_Avoid_: third-party host, stray vhost.

### Presentation

**Operator Panel**:
The loopback-only dashboard showing real captured data — Contacts, Names, Actors,
raw-TCP and payload statistics — reached over an SSH tunnel. Distinct from the
Console below: this one is never exposed and never shows fabricated data.
_Avoid_: admin panel, dashboard (too generic — this is the specific internal one).

**Console**:
The decoy internal admin interface served publicly on the Bait Name, built to look
like a real internal tool to an Actor who connects to it. Its data is fabricated —
never real Capture — precisely because it is public. Distinct from the Operator
Panel above: same visual language is fine, real data crossing from one to the
other is not.
_Avoid_: bait site (still fine informally, but "Console" is the noun when contrasting
with "Operator Panel").

### Capture

**Shape**:
A payload with its hex runs, digits and whitespace normalized away, so that
novel structure surfaces instead of novel randomness.
_Avoid_: signature, fingerprint, pattern.

**Capture**:
What a single connection yielded: the opening bytes, whether TLS was offered,
the ClientHello if it was, and the port the Actor intended.
_Avoid_: event, record, sample.
