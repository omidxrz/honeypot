# Targeting is the signal, not payload novelty

The sensor originally treated novelty as the signal: first-seen ports, and
payload Shapes not seen before. After seven days both metrics had saturated in
opposite directions — 65,371 of 65,535 ports had been hit, so `new_ports_24h`
had fallen to 7 and was still falling; and 1,725 of 1,858 Shapes had been seen
exactly once, so "novel" described almost every payload. Neither number
discriminated any more.

We replaced both with the Contact: an Actor arriving by a Name that cannot be
derived from this host's address. Over the same seven days, 148 of 14,259
Actors had made Contact — 1% — which is a number that still means something,
and which gets sharper rather than duller as the host ages.

## Consequences

`port_first` is deleted rather than retained. It existed only to feed
`new_ports_24h`, and it was 1.49 MB of a 3.7 MB state file that `prune()`
claimed to bound and did not. Per-port first-seen times are not recoverable
afterwards; `top_ports` keeps the port counts, which are still worth reading as
"what they were reaching for".
