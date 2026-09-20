---
status: accepted
supersedes: ADR-0002
---

# Bait Names move to the operator's primary domain

ADR-0002 put Bait Names on a domain unconnected to the operator, so that a
permanent public Certificate Transparency entry would not join the primary
domain to a host built to be compromised. That separate domain has been dropped
outright, and Bait Names now live under the operator's primary domain.

The trade-off ADR-0002 described has not gone away; it has been accepted. A CT
entry for a Bait Name permanently and publicly associates the operator's primary
domain with this sensor, and because the record must be DNS-only for the
all-port catch-all to see real source addresses, it publishes the host's address
under that domain too. Anyone enumerating the primary domain from CT will find
the sensor. This is a confound on who arrives and why, and the paper records it
as such.

## Consequences

The old domain was removed rather than retired, so it is not a Control Name and
its traffic is Foreign from here on: credentials arriving under it are redacted
at capture, and the 148 Contacts attributed to it are no longer Contacts. Until
the new Bait Name resolved and held a certificate, the Contact count was zero by
construction — the sensor had no live Bait Name. That is why the deployment has
no *measured* pre-issuance baseline, only a constructed one.

The label is `ops`, not `honeypot`: a Bait Name that says what it is gets
filtered by the CT scrapers that produce the signal, which is the reasoning
ADR-0002 gave and the one part of it that still holds.

The concrete Names and the host address live in `etc/names.env`, which is
gitignored and never committed. Nothing in this repository names them.
