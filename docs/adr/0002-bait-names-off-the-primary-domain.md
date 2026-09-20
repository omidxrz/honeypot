---
status: superseded by ADR-0003
---

# Bait Names live on a domain unconnected to the operator

A Bait Name only works if a Certificate Transparency scraper reads it and
decides it is worth connecting to, so the Name must not describe what it is:
`honeypot.example` is filtered by anyone doing this seriously, and the signal
dies with it. A retired Bait Name that read as a real internal console pulled
1,261 by-Name requests, which is the evidence this rests on.

Certificate issuance is also permanent and public. A Bait Name under the
operator's primary domain would join that domain, in a public log, to a host
this repo describes as built to be compromised — and because the record must be
DNS-only for the all-port catch-all to see real source addresses, it would
publish the host's address there too. So Bait Names go on a domain that is not
used for anything else.

## Consequences

Retiring a Bait Name does not retract it: the CT entry is permanent and the Name
keeps drawing traffic from passive DNS. That is why retired names become Control
Names instead of being deleted — the traffic arrives whether or not we count it.
