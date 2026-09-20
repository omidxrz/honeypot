# Companion data for docs/paper.md

Every table below is the **verbatim output of one command**, run in a single pass over the
raw logs on the sensor:

```sh
python3 ops/analyze.py --since 2026-09-16T06:10:26
```

`--since` is the Bait Name's first SCT, which is what makes the Contact rate a matched-window
figure (paper §3.4). Machine-readable form: add `--json`.

Do not assemble this file from separate reads. An earlier version of this snapshot mixed a
port breakdown taken at 09:11 UTC with a totals read from 21:11 UTC the same day; that
mismatch is why the whole file is now one program's output.

**No raw records appear here** — no request bodies, no credentials, no per-Contact addresses.
Aggregates only. The paper explains why the raw capture is not published (§4, §10).

Regenerated: **2026-09-20T06:58:09Z**.

---

## Window

| | |
|---|---|
| Sensor first record | `2026-09-09T07:35:26Z` |
| Snapshot (last record) | `2026-09-20T06:58:09Z` |
| Total operation | 10.97 days |
| Bait Name in CT since | `2026-09-16T06:10:26Z` |
| Bait-Name observation | 4.03 days |

## Totals

| | |
|---|---|
| Events | 1,167,304 |
| Raw TCP | 1,141,695 |
| HTTP | 25,609 |
| TLS connections | 180,672 |
| Distinct Actors, whole run | 19,123 |
| Distinct Actors, Bait window | 9,802 |
| Ports touched | 65,493 |
| Malformed log lines | 0 |

## Contacts

| | |
|---|---|
| Contacts, all time | 112 |
| Contacts, Bait window | 112 |
| Denominator | 9,802 (Actors seen in the Bait-Name window) |
| **Rate** | **1.143%** |
| First Contact | `2026-09-16T06:10:29Z` |
| ACME validators excluded | 10 |
| Single-request Contacts | 55.4% |
| Requests per Contact | p50 1, p90 43, max 554 |
| Gap between new Contacts | p50 2.9 min, p90 141.5 min |
| Busiest hour | `2026-09-16T06` with 36 |

First arrivals by hour (top 8):

| Hour (UTC) | Contacts |
|---|---|
| `2026-09-16T06` | 36 |
| `2026-09-16T07` | 14 |
| `2026-09-16T08` | 6 |
| `2026-09-16T22` | 6 |
| `2026-09-17T06` | 5 |
| `2026-09-17T09` | 4 |
| `2026-09-16T09` | 3 |
| `2026-09-17T02` | 3 |

## Background scanning

| Port | Events | Share of raw TCP |
|---|---|---|
| 5900 | 246,745 | 21.61% |
| 23 | 53,960 | 4.73% |
| 5902 | 36,754 | 3.22% |
| 5901 | 31,267 | 2.74% |
| 5908 | 23,704 | 2.08% |
| 5906 | 23,666 | 2.07% |
| 5909 | 23,448 | 2.05% |
| 5910 | 23,448 | 2.05% |
| 5905 | 23,085 | 2.02% |
| 5907 | 23,065 | 2.02% |
| 5904 | 19,694 | 1.72% |
| 5903 | 19,225 | 1.68% |

VNC (5900-5910) combined: **494,101 events, 43.28% of raw TCP**.

Concentration: the top 10 Actors account for 48.50% of raw TCP, the top 12 for 49.92%. Half of all raw TCP comes from 13 Actors (0.068% of all connecting addresses).

Opening-byte payload sizes (n=607,282): p50 19 B, p90 220 B, p99 588 B.

HTTP methods: GET 24,172, POST 863, ? 500, HEAD 23.

## Geography

| | |
|---|---|
| Countries seen | 132 |
| Events located | 100.00% |
| Actors not located | 1 |

| Country | Events | Actors |
|---|---|---|
| US | 463,619 | 8,206 |
| FR | 132,593 | 552 |
| SG | 89,348 | 899 |
| NL | 84,945 | 406 |
| SE | 64,467 | 40 |
| MX | 61,100 | 65 |
| DE | 51,193 | 586 |
| GB | 46,783 | 1,999 |
| CA | 35,099 | 86 |
| BE | 25,557 | 472 |

---

## Provenance and known caveats

- **Geolocation table version.** Country attribution is recomputed at display time from
  `ops/geo/ip-country-ipv4.csv` (PDDL, from `sapics/ip-location-db`, `user-country`). The
  vendoring script fetches the upstream branch tip and is not pinned to a commit, so
  re-vendoring can shift historical attribution. §5.5 is attribution under the table as
  vendored at this snapshot.
- **Timestamps are UTC.** Both logs are written in UTC and the shared parser reads them as
  UTC (`calendar.timegm`), asserted by a self-check. An earlier parser read them as host-local
  time, which was a no-op on the sensor (`Etc/UTC`) but would have shifted every hour bucket
  in any off-box re-analysis.
- **Forward-only counters are not used here.** The live pipeline (`ops/rollup.py`) keeps
  bounded, never-recomputed counters in `ops/state.json`; this file does not read them. Small
  differences against the operator panel are expected and are the panel's pruning, not an
  error here.
- **The catch-all log rotates** one generation at 512 MiB (~34 MiB/day). The current
  deployment fits inside one generation; a longer run would lose its earliest records and
  these totals would stop being re-derivable.
