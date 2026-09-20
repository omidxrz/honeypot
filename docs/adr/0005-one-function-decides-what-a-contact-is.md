---
status: accepted
---

# One function decides what a Contact is

`ops/rollup.py`'s `absorb()` (the incremental path, run every 5 minutes) and
`ops/migrate.py`'s `backfill()` (the rebuild path, run on demand) both had to
know the same five-step rule to recognise a Contact: pick the Name field by
record source (`h` for web, `sni` for the catch-all), exclude ACME validation
traffic, exclude non-Actor sources, classify the Name, and pack the Contact
key. Each function re-derived it independently.

That duplication already broke once: `backfill()`'s rebuild forgot the SNI
branch and silently dropped every Contact made on a port nginx never sees,
on every deploy, until an independent recount caught a one-record discrepancy.

`rollup.record_to_contact(r, names)` is now the one place the rule lives.
`absorb()` and `backfill()` both call it and apply the result to their own
state dict; neither re-derives the sequence. `contact_key()` /
`split_contact_key()` do the same for the key format, which had been
hand-rolled in three separate places.

## Consequences

Adding a new Contact-derived aggregate (`contacts_hourly`, added in the same
change) now touches one function's call site, not two independently-written
copies. The self-check (`rollup.py --demo`) asserts `record_to_contact`
directly, so the rule's behaviour is tested once rather than through two
different call paths that could silently diverge again.
