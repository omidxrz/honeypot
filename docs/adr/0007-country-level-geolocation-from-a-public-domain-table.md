---
status: accepted
---

# Country-level geolocation, from a public-domain table

The Operator Panel needed to answer "where does this come from", which means
attributing 18,000+ Actor addresses to places. Two constraints ruled out the
usual approaches before any were evaluated on merit:

The sensor's egress is default-deny (`etc/nftables.conf` permits loopback,
established, DNS, NTP and ICMP — no outbound 80/443), so a geolocation API call
at runtime is impossible. And ADR-0006 committed the panel to making no
third-party requests at all, which also rules out looking addresses up from the
operator's browser — that would hand the list of addresses we are watching to
whoever runs the API.

So the lookup is an offline table, on the box.

**Dataset: `user-country` from sapics/ip-location-db, PDDL v1.0.** Its own
SOURCES.md states the terms plainly: *"free use without attribution"*. It is
built from RIR delegated statistics, Route Views / RIPE RIS BGP archives, and
RFC 8805 geofeeds — sources chosen upstream specifically to avoid commercial
and redistribution restrictions. Measured against this sensor's real capture it
resolves **99.99% of Actors and 99.99% of events** across 132 countries.

Rejected:

- **MaxMind GeoLite2** — the most common choice, and the worst fit here. It
  needs an account and license key to download, its EULA incorporates CC BY-SA
  terms requiring downstream recipients be bound to substantially similar terms,
  and it obliges the licensee to destroy superseded versions within 30 days.
  None of that survives contact with a public git repository, which this one is
  headed for.
- **DB-IP Lite city-level (CC BY 4.0)** — redistributable, but ~134–197 MB, and
  city precision on datacenter ranges is largely false precision: a scanner's
  VPS resolves to a datacenter or a country centroid anyway, so a city dot would
  imply accuracy the data does not have. It also pins individual addresses to
  cities, a heavier privacy footprint for a repo intended to be published.
- **IP2Location LITE** — redistribution is explicitly prohibited.

**Centroids** come from gavinr/world-countries-centroids (MIT, derived from
public-domain Natural Earth), using the centroid of each country's largest
landmass rather than a bounding-box centre.

## Consequences

The table is ~9 MB of gitignored third-party data, fetched by
`ops/vendor-geo.sh` and mirrored to the box by `deploy.sh` — the same treatment
`ops/assets/` already gets, and `deploy.sh` refuses to run without it rather
than shipping a panel with an empty map.

Countries are **derived at emit time** in `rollup.py` from `st["ips"]`, not
counted incrementally in `absorb()`. `ips` already holds every Actor and its
event count and is never pruned, so deriving is exactly equivalent, needs no
migration for the 1.1M events absorbed before geo existed, cannot drift out of
sync with the Actor counts, and re-attributes everything for free when the table
is re-vendored. It costs ~18k bisect lookups per run, measured at 0.08s.

Seven country codes the IP table uses have no centroid upstream — including
Hong Kong, which is ~10k events in the live capture. They are supplemented
explicitly in `vendor-geo.sh`, and the script asserts that >99.5% of ranges are
drawable so a future upstream change cannot silently reopen that hole.

Lookups are IPv4-only. The catch-all binds `AF_INET`, so IPv6 can only arrive
via nginx, and carrying the separate 16 MB v6 table is not worth it for that.
Unresolvable addresses are reported as `countries_unknown_*` rather than
silently dropped.
