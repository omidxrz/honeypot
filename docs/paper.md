---
status: draft
type: short paper / work-in-progress report
as-of: 2026-09-20T06:58:09Z (single consistent snapshot; see docs/paper-data.md)
regenerate: python3 ops/analyze.py --since 2026-09-16T06:10:26
---

# Certificate Transparency as a Real-Time Discovery Channel: A Pilot Measurement

**Status of this document.** This is a draft short paper / work-in-progress report, not a
finished submission. Its headline timing result rests on a single certificate issuance
(n=1) and a 4.0-day observation window. It is honest about that limitation throughout and
proposes the controlled experiment that would turn it into a full paper (§8). Treat every
number here as a pilot measurement, not a settled finding.

**Correction to an earlier draft.** A previous version reported the Contact rate as 0.58%,
dividing Contacts observed during the Bait-Name window by Actors observed over the *entire*
sensor deployment — two different observation periods. Corrected to a matched window, the
rate is **1.14%**. The error understated the effect by roughly a factor of two. §3.4 states
the denominator rule that now prevents it, and §6 records the correction. Two §5.2 figures
also changed; §6 explains why.

## Abstract

We instrument an internet-facing sensor with a domain name ("Bait Name") published solely
via TLS certificate issuance, and measure the time between the certificate's appearance in
public Certificate Transparency (CT) logs and the first connection that uses the name. In
our single observed issuance, the first genuine, non-self-generated connection arrived 3
seconds after the certificate's Signed Certificate Timestamp (SCT) — faster than the 73–197
second DNS-query latency reported by the closest prior measurement [Scheitle et al., 2018],
though the two studies measure different points in the discovery pipeline (DNS lookup vs.
arrival by name at the application layer) and are not directly comparable without further
controls. Over a 4.0-day window the Bait Name produced 112 distinct Actor×Name arrivals
("Contacts") from 9,802 Actors observed in that same window (**1.14%**), with 36 of 112
first arrivals in the single hour following issuance. We report our sensor's design, a
measurement-hygiene finding (two of our own instrumentation channels — our certificate
renewal traffic and our own loopback testing — initially registered as false Contacts,
requiring explicit exclusion), and identify an open question in the existing literature that
neither of the two closest prior studies addresses: whether a Bait Name's *semantic
plausibility* affects whether CT-monitoring adversaries act on it. We propose a four-arm
controlled design to answer it.

## 1. Introduction

Certificate Transparency requires every publicly-trusted TLS certificate to be logged in an
append-only, publicly queryable ledger before browsers will accept it [RFC 6962]. This closes
a real trust gap — mis-issued and rogue certificates become detectable — but it has a
side effect that is now well documented: the same logs are a public, real-time feed of newly
provisioned hostnames, and third parties monitor them. Prior work has shown that CT logs are
used both for legitimate purposes (asset discovery, attack-surface monitoring) and for
reconnaissance by parties probing for vulnerable software immediately after a name appears
[Pletinckx et al., 2023; Kondracki et al., 2022].

What is less established is the *shape* of that reconnaissance from the target's point of
view: how fast is fast, does it look like scanning we would see anyway, and — the question we
found no prior measurement of — does what the name looks like change whether anyone acts on
it. We built a sensor to observe this directly rather than infer it, and this paper reports
what a single instrumented issuance and 4.0 days of observation actually looked like.

## 2. Related work

*Scope of this review.* We identified related work by following citations from the CT
measurement literature and searching the major measurement and security venues (IMC, PAM,
USENIX Security, NDSS, EuroS&P) for CT-based honeypot deployments. We did not run a
systematic review protocol, so "closest prior work" below means closest among what we found,
not a claim of exhaustiveness.

**Scheitle et al. (2018)**, "The Rise of Certificate Transparency and Its Implications on the
Internet Ecosystem" (IMC '18), ran the CT honeypot closest in design to ours: 11
randomly-named (12-character, content-free) subdomains, certificates issued in three batches
over 18 days, DNS and packet capture from 2018-04-12 to 2018-05-15. They report the first DNS
queries for their subdomains appearing **73 seconds to ≈3 minutes** after the corresponding
precertificate was published in CT logs, and the first "suspicious" connections 85–122 minutes
later. Their names were deliberately random and unguessable — the paper does not analyze, and
by its own design could not analyze, whether a name's plausibility changes scanner behavior.

**Kondracki, So, and Nikiforakis (2022)**, "Uninvited Guests: Analyzing the Identity and
Behavior of Certificate Transparency Bots" (USENIX Security '22), built CTPOT, a
distributed CT honeypot operated at much larger scale: 4,657 certificates over ten weeks,
attracting 1.5 million requests from 31,898 unique IP addresses, resolved into 105 distinct
malicious campaigns (including automated Log4j exploitation attempts). They report that CT-bot
IP addresses overlap with traditional host-scanning bot populations by less than 2% — CT-driven
traffic is a materially different population, not simply "scanning, but faster." They also
found that varying the *content* served at decoy domains changed which bot populations engaged
— a finding adjacent to, but not the same as, the question of whether the domain *name itself*
matters.

**Pletinckx et al. (2023)**, "Certifiably Vulnerable: Using Certificate Transparency Logs for
Target Reconnaissance" (EuroS&P '23), ran a 200-day honeypot deployment to measure attackers
using CT logs to find likely-vulnerable software by pattern-matching on certificate subject
names (e.g., names suggesting a specific CMS or admin panel). This is closer to our question
than the other two — it is about what a name *signals* — but it studies signals of software
identity, not signals of plausibility-as-a-real-service versus obvious deception.

**The gap.** None of the three measures whether a name that reads as a real internal service
(what we call a Bait Name, plausible) draws different treatment than a name that reads as
identifiably fake, or than a name with no semantic content at all (Scheitle et al.'s random
strings). Scheitle et al. state explicitly that they do not analyze naming effects. This is the
question our sensor is built to eventually answer (§8); the present paper reports the sensor
and a first, uncontrolled observation of it in operation.

## 3. Method

### 3.1 Apparatus

A single internet-facing host with one IPv4 address, running:

- **An all-port TCP catch-all.** A netfilter rule redirects every TCP port to one listener,
  which recovers the originally-intended port via `SO_ORIGINAL_DST`. Server-speaks-first
  protocols receive a static banner; TLS is terminated with a self-signed certificate so the
  plaintext can be read. At most 4,096 opening bytes are recorded per connection.
- **A decoy HTTP console** on 80/443 served under the Bait Name, backed by a stub that accepts
  any credential, returns plausible JSON and executes nothing.
- **SNI extraction on every port**, via a raw ClientHello parser rather than only on 80/443, so
  a Name used against a non-web port (e.g. a raw TLS probe on 8443) is still observed.

Outbound traffic is default-deny. The host is dedicated to this measurement and shares no
credentials or DNS records with any other system.

### 3.2 Vocabulary

Terms are capitalized where they are the project's defined vocabulary (`CONTEXT.md`).

- **Actor**: the remote source address of a connection. Loopback and RFC 1918 private
  addresses are excluded by construction — on an internet-facing sensor those are the
  operator, and counting them inflates the metric that matters.
- **Name**: the hostname an Actor used to reach the sensor — the HTTP `Host` header, or the
  SNI field of a TLS ClientHello.
- **Derived Name**: a Name mechanically constructable from the sensor's IP address alone (the
  address itself, or a wildcard-DNS label like `api.<ip-with-dashes>.nip.io`). Carries no
  information about discovery method and is excluded from the Contact metric.
- **Bait Name**: a Name we placed in a TLS certificate specifically so it would appear in CT
  logs, and which resolves to the sensor. The instrument that produces Contacts.
- **Control Name**: a retired Bait Name. It no longer resolves, but its CT entry is permanent
  and traffic keeps arriving; an Actor still asking for one is working from historical passive
  DNS or a log mirror rather than live resolution, which is worth distinguishing. Control
  Names still count as Contacts. At this snapshot the sensor has none (§7).
- **Contact**: the first time a given Actor reaches the sensor using a given Bait or Control
  Name, counted once regardless of how many requests follow. This is the paper's primary
  dependent variable.

### 3.3 Measurement hygiene: two self-contamination channels found and excluded

Two channels of the sensor's own operation initially satisfied our own definition of a Contact
and had to be explicitly excluded — we report both because they are easy to miss and would
silently inflate results in any similarly-built instrument.

1. **ACME domain validation.** Requesting a certificate for the Bait Name causes the issuing CA
   to fetch an HTTP-01 challenge file *under that exact Name*, from multiple vantage points, on
   every issuance and renewal. At the observed issuance this produced 5 requests from 5
   distinct addresses, arriving 06:10:22–06:10:23 UTC — 3 to 4 seconds *before* the earlier
   SCT. Requests under `/.well-known/acme-challenge/` are excluded from the Contact count.
   Across the full deployment, including subsequent renewals, 10 distinct addresses have been
   excluded on this rule.
2. **Operator verification traffic.** Testing the deployed redaction and classification logic
   from the sensor's own loopback address registered as Contacts under the same definition.
   Loopback and private-range sources are excluded (the Actor definition above).

Both are reported as a methodological note for future CT-honeypot builders: an instrument that
watches for "anyone who used this name" will, by default, watch itself. The pre-SCT arrival
time of the ACME traffic is itself a useful check — it confirms those requests are validation
rather than observers, since nothing could have read the Name from a log that did not yet
contain it.

### 3.4 Windows and denominators

The sensor has been running longer than the Bait Name has existed, so there are two
observation windows and they are **not** interchangeable:

| Window | From | Duration | What it is for |
|---|---|---|---|
| Deployment | 2026-09-09T07:35:26Z | 10.97 days | background scanning context (§5.4) |
| Bait-Name | 2026-09-16T06:10:26Z (first SCT) | 4.03 days | everything about Contacts (§5.1–5.3) |

**Any rate involving Contacts is computed over the Bait-Name window on both sides.** The
numerator is Contacts whose first arrival falls at or after the first SCT; the denominator is
distinct Actors seen in that same period. Mixing them — 112 Contacts over 4 days against
19,123 Actors over 11 days — is the error corrected in this draft, and it halves the apparent
rate by counting seven days of addresses that had no Bait Name to find.

### 3.5 Reproducibility

Every figure in §5 is produced by one committed program, `ops/analyze.py`, in a single pass
over the raw logs:

```
python3 ops/analyze.py --since 2026-09-16T06:10:26
```

It holds no state and writes nothing, so the same logs always yield the same output. It
imports its definitions (`is_actor`, `record_to_contact`, `country_of`, `parse_ts`) from the
sensor's own pipeline rather than reimplementing them, so the paper and the live instrument
cannot disagree about what a Contact is. It carries an offline self-check (`--demo`) that
asserts the matched-window rule above, and that check is mutation-tested.

This replaces an uncommitted one-off script used for the previous draft, which is why two
§5.2 figures changed (§6).

**Timestamp base.** Both logs are UTC. An earlier version of the shared timestamp parser read
them as *local* time; on the sensor (`Etc/UTC`) this was a no-op, but any re-analysis on a
machine in another timezone would have shifted every hour bucket and latency figure silently.
The parser now uses `calendar.timegm` and a self-check asserts the UTC round-trip. Published
figures are unaffected, because they were computed on a UTC host.

## 4. Data availability

The sensor's full source, including the analysis program, is available. We do **not** publish
the raw capture: it contains unredacted request bodies and credentials sent by third parties
to hostnames that are not ours (§9). What can be published without that hazard — per-Contact
first-arrival times and request counts with addresses truncated, the hourly histograms, and
the port and country distributions — is derivable from `ops/analyze.py --json` and we intend
to archive that derived dataset alongside a future revision. At present a reader can reproduce
every figure given the logs, and can inspect the exact definitions that produce them, but
cannot independently re-derive them from published data. This is a real limitation (§7).

## 5. Results

All figures are a single consistent snapshot at **2026-09-20T06:58:09Z**, regenerated in one
pass. Deployment: 10.97 days, 1,167,304 events (1,141,695 raw TCP; 25,609 HTTP), 180,672 TLS
connections, 19,123 distinct Actors, 65,493 of 65,535 ports touched, 0 malformed log lines.

### 5.1 Time from CT log entry to first Contact

The certificate carried two embedded SCTs, timestamped 06:10:26 and 06:10:27 UTC on
2026-09-16 — proof of submission to two independent CT logs at issuance. After excluding the
ACME-validation requests (§3.3, all arriving *before* the SCT), the first non-self-generated
request using the Bait Name arrived at **06:10:29 UTC — 3 seconds after the earlier SCT.** It
was a full browser-shaped fetch (`GET /`, followed immediately by requests for the page's own
asset bundle: favicon, several JS chunks), not a bare TCP probe.

This is a single observation (n=1 issuance) and should not be read as a general latency
distribution — we report it because it is the fact the sensor was built to produce, and because
it is fast enough, relative to Scheitle et al.'s reported 73–197 second *DNS-query* latency, to
be worth flagging rather than fast enough to be quietly believed. The two numbers measure
different things: Scheitle et al. instrument DNS resolution of a name that must first be
resolved before any connection can occur; our number is the arrival of an HTTP request that
already carries a resolved connection. A request arriving faster than typical DNS-query latency
after CT log entry is unusual enough that we flag the mechanism as an **open question** — it is
consistent with (but not proof of) a scanner that reads the certificate's Subject/SAN directly
from the CT log stream and connects to an already-known or concurrently-resolved address,
bypassing an independent DNS lookup of the name entirely. We did not instrument DNS query
observation on this pass and cannot distinguish these mechanisms; doing so is listed in §8.

### 5.2 Contact volume and temporal clustering

Over the 4.03-day Bait-Name window: **112 Contacts** from **9,802** Actors observed in that
same window — **1.14%**. Every Contact recorded in the deployment falls inside this window;
none predate the first SCT.

Of the 112, **36 (32%) registered their first Contact within the single UTC hour containing
the issuance** (06:00–07:00 on 2026-09-16), and 50 (45%) within the first two hours. The
remainder arrived at a median gap of 2.9 minutes and a 90th-percentile gap of 141.5 minutes
between successive new Contacts — consistent with an initial scraper-driven burst followed by
slower, more diffuse re-discovery (via CT-log mirrors, passive-DNS feeds, or search indexing
of the certificate) over the following days. A secondary cluster of 6 appears at 22:00 the
same day and another 5 at 06:00 the next, which is suggestive of scheduled re-scraping but is
far too small a sample to claim periodicity.

### 5.3 Per-Contact engagement

Request counts per Contact are heavily right-skewed: median 1 request (55.4% of Contacts are
single-shot — one request, never seen again), 90th percentile 43 requests, maximum 554 from a
single Actor. This shape — a large population of one-shot verifiers alongside a small number of
sustained engagers — is qualitatively consistent with Kondracki et al.'s finding that CT-bot
traffic is behaviorally distinct from generic scanning, though we have not attempted to
replicate their IP-population-overlap methodology at our much smaller scale.

### 5.4 Background scanning context

Over the full 10.97-day deployment the catch-all received 1,141,695 raw TCP events across
65,493 ports. Traffic is extremely concentrated: **the top 10 Actors account for 48.5% of all
raw TCP, and 13 Actors — 0.068% of connecting addresses — account for half of it.**

The most-targeted ports were not the ones we anticipated. VNC, summed over 5900 and its
display range 5901–5910, accounts for **43.3%** of all raw-TCP events (494,101), the single
largest category by a wide margin and well ahead of Telnet (23, 4.7%) and SSH (22, ~1%). Port
5900 alone is 21.6%. Opening-byte payload sizes are small and protocol-handshake-shaped
(median 19 bytes, 90th percentile 220, 99th percentile 588, n=607,282) rather than
exploit-payload-shaped.

At the HTTP layer, 24,172 of 25,609 requests (94.4%) are GET and 24,680 (96.4%) returned 200 —
the decoy returns 200 for every path by design, so this reflects the instrument, not the
traffic.

This background is the population the Bait Name's 1.14% is distinguished from, and it is
dominated by generic, name-independent scanning from a handful of high-volume sources rather
than anything resembling targeted reconnaissance.

### 5.5 Geographic distribution

Offline country attribution covers **100.0% of located events across 132 countries**; exactly
one Actor in the deployment could not be placed. The distribution is dominated by hosting
infrastructure rather than by end-user geography: the United States accounts for 463,619
events from 8,206 Actors, followed by France (132,593 / 552), Singapore (89,348 / 899) and the
Netherlands (84,945 / 406).

The events-to-Actors ratio is the more interesting column. Sweden shows 64,467 events from
just **40** Actors and Mexico 61,100 from **65**, against the United Kingdom's 46,783 from
1,999. Concentrated, high-volume scanning from a small number of hosts is a different
phenomenon from diffuse low-volume traffic from many, and country totals alone would hide
that. We report this as description only: country attribution of datacenter address space
reflects the registrant, not necessarily the operator or the physical machine, and we draw no
inference about origin from it.

## 6. Corrections to the previous draft

Recorded explicitly rather than silently amended.

| Figure | Previous | Now | Why |
|---|---|---|---|
| Contact rate | 0.58% | **1.14%** | numerator and denominator now share one window (§3.4) |
| Denominator | 18,553 (11 days) | 9,802 (4 days) | matched to the Bait-Name window |
| First-hour Contacts | 42 of 108 (39%) | 36 of 112 (32%) | see below |
| Actors for half of raw TCP | "top 12, 0.1%" | 13, 0.068% | recomputed, not re-estimated |
| VNC share | "over half" → 43.3% | 43.3% | an earlier draft said "over half"; that was wrong |

The first-hour count is the one we cannot fully reconcile. The previous figure came from a
script that was never committed and no longer exists, so the difference cannot be traced
directly. The most likely explanation is that it predated the §3.3 exclusions — 42 − 36 = 6 is
close to the 5 ACME validators plus operator traffic in that same hour, all of which are
excluded now. We state the current, reproducible number and flag the discrepancy rather than
assume the tidy explanation is the true one.

## 7. Threats to validity and limitations

**Construct validity — does a Contact measure what we claim?**

- **Actor is an IP address.** NAT, CGNAT, cloud egress pools and shared proxies mean one
  address may be many parties and one party may use many addresses. All Actor counts, and
  therefore the 1.14% rate, inherit this. We follow prior CT-honeypot work in this choice but
  it is a genuine limitation, not a convention that removes the problem.
- **The instrument shapes the traffic it measures.** The catch-all sends banners on 23 and
  5900 — the two highest-volume ports in §5.4 — and the decoy returns 200 for every path. A
  silent host would see different follow-on behavior. The §5.4 distribution is therefore
  "what this instrument attracts", not "what the internet sends".
- **Low interactivity.** Static banners, no session continuation, at most 4,096 opening bytes,
  a stub that executes nothing. We observe reconnaissance, not exploitation or
  post-exploitation.

**Internal validity — could the effect be something else?**

- **No control arms.** We cannot separate CT-log presence from the mere existence of a DNS
  record, or from generic scanning of the sensor's address that would have found the name
  eventually. The four-arm design in §8 exists precisely to close this.
- **The pre-issuance baseline is zero by construction, not by observation.** A previous Bait
  Name on a different domain was dropped rather than retired when that domain was abandoned,
  which reclassified its Contacts away (`docs/adr/0003`). The deployment therefore has no
  measured "before" period for Contacts. This is the weakest link in reading the post-issuance
  burst as caused by issuance.
- **n=1 issuance.** One certificate, one CA (Let's Encrypt), one log pair, one hour of day.
  A single issuance cannot separate "CT monitoring is generally this fast" from "this
  particular log, CA, hour or name produced a fast hit."
- **The Bait Name is a subdomain of the operator's primary domain** (`docs/adr/0003`). Anyone
  enumerating that domain from CT finds the sensor for reasons unrelated to the bait, which is
  a confound on who arrives and why.

**External validity — does it generalize?**

- **Single host, single address, single AS, single country, single CA.** Scanner behavior
  toward other CAs, address ranges or geographies is not observed.
- **Short window.** 4.03 days of Bait-Name observation against Kondracki et al.'s 10 weeks and
  Pletinckx et al.'s 200 days.
- **No naming-semantics test yet.** One Bait Name tests one point on the plausibility
  spectrum, not the spectrum.

**Data validity — is the capture complete?**

- **Events are dropped under load.** The listener sheds connections above 300 concurrent
  without recording them. We do not currently instrument the shed counter, so the magnitude is
  unknown; it is a known gap rather than an estimated one.
- **The raw capture is bounded.** The catch-all log rotates one generation at 512 MiB
  (~34 MiB/day), so the deployment currently fits but a longer run would lose its own tail.
  Counters in the live pipeline are forward-only and are not recomputed from logs; the figures
  here come from a full re-read instead, which is why they differ slightly from the panel's.
- **DNS-layer instrumentation absent.** We observe arrival by HTTP/SNI, not DNS queries, so we
  cannot compare our 3-second figure to Scheitle et al.'s DNS-query latency on the same metric.
- **Geolocation is a point-in-time table.** Country attribution is recomputed at display time
  from a table that is re-vendored periodically, so historical attribution can shift. §5.5
  should be read as attribution under one table version, recorded in the companion data file.

## 8. Proposed follow-on design

To turn §5.1's single observation into a defensible result and to close the gap identified in
§2, we propose:

**Repetition.** Thirty-plus staggered issuances (following Scheitle et al.'s batching approach)
to produce a real latency distribution — median, tail, and whether latency varies by hour of
day, issuing CA, or log operator. Staggering must break the confound between issuance hour and
arm.

**A four-arm design isolating CT as the channel:**

| Arm | DNS record | Certificate issued | Isolates |
|---|---|---|---|
| Treatment | present | yes | the effect observed in §5.1 |
| DNS-only | present | no | passive DNS / zone enumeration as an alternate channel |
| CT-only | absent | yes | whether scrapers connect from the cert alone, with no resolvable A record |
| Neither | absent | no | the background scanning floor (§5.4) |

The CT-only arm is the sharp test: if names that never resolve still draw connection attempts,
that traffic can only be explained by scrapers reading the certificate itself (SAN/CN) rather
than by DNS-based discovery — directly resolving the open question in §5.1.

**DNS instrumentation.** Running our own authoritative nameserver for the bait zone would make
our latency figure directly comparable to Scheitle et al.'s and would settle whether the
3-second arrival bypassed DNS resolution entirely. This is the single highest-value addition.

**A measured baseline.** Operating a Bait Name's zone and certificate on a *fresh* address for
a period before issuance, so the pre-issuance Contact rate is observed rather than zero by
construction (§7).

**The naming-semantics arm — closing the literature gap.** Matched pairs of Bait Names
differing only in plausibility: `ops.`, `console.`, `vpn.`-style names (reads as a real internal
service) against `honeypot.`, `canary.`, `decoy.`-style names (self-identifying) and
Scheitle-style random strings (semantically empty), all otherwise identical (same domain, same
TLS configuration, same hosting). If plausible names draw more or different Contacts than
self-identifying ones, that is a measurable finding with a direct defensive implication: it
tells defenders whether CT-based deception is detectable by adversaries at zero cost, which
neither Scheitle et al. (random names only) nor Kondracki et al. (varied content, not name
semantics) nor Pletinckx et al. (vulnerability-signaling names, not plausibility) has measured.

## 9. Discussion

The central methodological point this pilot supports is that **a Bait Name is measurable and
discriminates against background noise even at n=1**: 1.14% of Actors seen while the Name
existed used a name they could only have learned from the certificate, and that population's
temporal signature (a sharp post-issuance burst, then a long tail) looks nothing like the
flat, concentrated, IP-driven background traffic in §5.4. That much survives the small sample,
and the corrected denominator strengthens rather than weakens it.

What does not survive it is any claim about *why* the 3-second figure looks the way it does, or
whether it would replicate. Scheitle et al.'s own multi-batch design (11 domains across three
issuance batches) is the minimum bar for treating a latency figure as a distribution rather
than an anecdote, and we have not yet cleared it.

The correction in §6 is itself a small methodological point worth stating plainly: the
mismatched denominator survived several readings of the draft because both numbers were
individually correct and separately reported. It was caught by writing the analysis as a
program whose self-check has to state the denominator rule out loud, not by re-reading prose.

## 10. Ethics

The sensor operates on infrastructure the authors control and interacts with no third-party
systems beyond passively logging inbound connections that attackers or scanners initiate
against it. It is a dedicated host sharing no credentials with any other system, its outbound
traffic is default-deny, and it serves no content that could act on a third party.

Where a connection arrives over HTTP under a hostname the sensor does not own — a third
party's DNS record pointing at the sensor's address, unrelated to this study —
credential-bearing fields (`Authorization`, `Cookie`, request bodies) are blanked at the point
of capture and never written to disk, since that traffic belongs to whoever that hostname's
actual operator is, not to this study.

**That redaction covers the HTTP path only.** The all-port catch-all terminates TLS on other
ports with a self-signed certificate and records the opening plaintext of whatever it reads,
without classifying the hostname. A client that ignores certificate validation on a non-web
port therefore has its opening bytes captured in full, and those bytes may contain credentials.
We state this rather than imply blanket redaction; narrowing it is a change to the instrument,
not to the paper. It is also the reason the raw capture is not published (§4).

No connecting party is identified beyond IP address and country, consistent with prior
published CT-honeypot work [Scheitle et al. 2018; Kondracki et al. 2022]. No attempt is made
to interact with, attribute, or report any connecting party.

## References

Scheitle, Q., Gasser, O., Nolte, T., Amann, J., Brent, L., Carle, G., Holz, R., Schmidt, T. C.,
& Wählisch, M. (2018). The Rise of Certificate Transparency and Its Implications on the
Internet Ecosystem. In *Proceedings of the Internet Measurement Conference (IMC '18)*, 343–349.
ACM. https://doi.org/10.1145/3278532.3278562

Kondracki, B., So, J., & Nikiforakis, N. (2022). Uninvited Guests: Analyzing the Identity and
Behavior of Certificate Transparency Bots. In *Proceedings of the 31st USENIX Security
Symposium*, 53–70. USENIX Association.
https://www.usenix.org/conference/usenixsecurity22/presentation/kondracki

Pletinckx, S., Nguyen, T.-D., Fiebig, T., Kruegel, C., & Vigna, G. (2023). Certifiably
Vulnerable: Using Certificate Transparency Logs for Target Reconnaissance. In *Proceedings of
the IEEE European Symposium on Security and Privacy (EuroS&P '23)*, 817–831.

RFC 6962: Laurie, B., Langley, A., & Kasper, E. (2013). Certificate Transparency. IETF.
https://www.rfc-editor.org/rfc/rfc6962

---

*Companion data snapshot: `docs/paper-data.md`, regenerated in one pass by `ops/analyze.py`.
See `CONTEXT.md` for the vocabulary and `docs/adr/` for the decisions this paper relies on.*
