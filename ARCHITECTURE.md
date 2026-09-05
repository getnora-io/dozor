# Architecture

Dozor is the companion to [NORA](https://github.com/getnora-io/nora) and inherits
its temperament — one binary, files as the source of truth, no database — but not
its shape. NORA is a server that must stay up. Dozor is a compiler that must be
right, and must be unable to take NORA down.

```
snapshots/npm-<date>-<sha>.zip   immutable input, content-addressed, carriable on a USB stick
inventory.jsonl                  what the registry actually holds
policy.toml                      the only human-authored input, reviewed in a PR
        │
        ▼  dozor build   (streaming, stateless, deterministic)
blocklist.json                   NORA reads it · git is the journal
openvex.json                     (0.2) Trivy/Grype read it
```

## Decisions

### D-ADR-1: A compiler, not a service

No daemon, no port, no controller loop, no state between runs. Dozor is invoked
by CI, cron, or a person. **Consequence: it is physically incapable of failing a
download.** This is the direct answer to the risk that sinks an in-registry
vulnerability feed — a stale feed plus fail-closed semantics turns the registry
into a build breaker.

### D-ADR-2: Determinism is a feature, not tidiness

Identical inputs produce byte-identical output. No timestamps live in the body;
the canonical form is key-sorted JSON, hashed with SHA-256. Two consequences:
a verdict is reproducible a year later, and the daily job opens a pull request
only when something actually changed instead of churning a diff every night.

### D-ADR-3: The file is the interface

The only contract with NORA is `blocklist.json` in the schema NORA already reads
(`curation.rs::BlocklistFile`). No network between the two, no protocol version,
no plugin. Dozor writes a *superset* — extra `x-dozor` keys are ignored by NORA's
deserializer — so it works with released NORA versions and needs no core change.
Delete Dozor and the blocklist keeps working.

### D-ADR-4: The intersection, not the database

The feed is never materialised. Zip entries are decompressed one at a time,
projected to the few percent that decides a verdict (name, ranges, id, severity,
kind), and dropped. Nothing is unpacked to disk — 25k tiny JSON files cost 122 MB
of block padding for 68 MB of content.

### D-ADR-5: Layout is the feature

The first cut used idiomatic `HashMap<String, Vec<Entry>>` with `Option<String>`
bounds and peaked at **720 MB** on the npm feed. The data was never the problem:
~1.2M individual allocations were. One string arena plus flat CSR vectors brought
the same index to **24.9 MB retained / 173 MB peak** and cut build time from 6.3 s
to 2.5 s. Structures are chosen for allocation count, not for prettiness.

### D-ADR-6: One place knows what a version is

All ecosystem version semantics live in `dozor-vers`: pure, no I/O, borrowed
inputs. It returns `Affected | NotAffected | **Unknown**` — and `Unknown` is
load-bearing. The matcher never guesses; an undecidable version is reported in
`x-dozor-unmatched`, a visible hole rather than a silent "safe".

### D-ADR-7: Exceptions expire

Every exception carries a `reason` and an `expires` date. An expired exception
fails the build with exit 4. There are no permanent exceptions, because a
permanent exception is how a security policy quietly dies.

### D-ADR-8: Fail-open on data, fail-closed on policy

A feed that could not be fetched is a hard stop with a non-zero exit — the
existing blocklist is left exactly as it was. Dozor never rewrites a blocklist
with a thinner one. A silently emptied control is worse than a missing one.

### D-ADR-9: One policy, two outputs

The same policy drives what NORA blocks and (from 0.2) an OpenVEX document that
silences Trivy/Grype on the same accepted exceptions. Today "what we block" and
"what we accept" live in two systems and drift apart.

## Malicious packages are the main event

The npm OSV feed is **228,684 advisories, of which 221,365 are `MAL-*`** —
malicious-package reports with no severity at all. A policy expressed only as a
severity threshold would discard 96.8% of the payload. Hence a separate
`malicious` switch.

Of those, **197,314 are "the whole package, forever"** (`introduced: 0`, no fix,
no version list). Those collapse into a single `version: "*"` rule per package —
and that rule is preventive: the package is refused before its first download,
whether or not any version was ever cached.

## Crates

| crate | job |
|---|---|
| `dozor-vers` | version-range semantics per ecosystem · pure · property-tested |
| `dozor-osv` | streaming OSV reader · arena + CSR index · `peak_rss_kb()` |
| `dozor-core` | inventory sources, policy, rule collapse, canonical serialisation, derivation |
| `dozor` | the CLI: `inventory` · `build` · `verify` · `explain` · `stats` |

## The inventory is read from files too

`dozor inventory` takes it from a NORA data directory — the layout is
`storage/npm/<package>/tarballs/<base>-<version>.tgz` for proxied packages and
`storage/npm/<package>/versions/<version>.json` for hosted ones, with scoped
packages nesting — or from an npm lockfile, for gating a project rather than a
cache. No API call, nothing to authenticate, works on a cold copy of the data
directory. Output is sorted and deduplicated, so the inventory file is itself
deterministic and diffs cleanly.

## Known limits (accepted, not "by design")

- **Scan-on-publish** (contract D-7) — a synchronous verdict on push would need a resident
  service with an in-memory index. That is a different product; out of scope, not
  denied. Workaround: post-hoc build plus version withdrawal.
- **Peak RSS 173 MB vs 24.9 MB retained** (contract D-6, OPEN) — the gap is transient build allocation
  and allocator behaviour, not data. Reserving capacity up front and streaming the
  output writer are the open items.
- **Proactive mode costs NORA latency** — 197,314 rules make NORA's linear
  blocklist scan cost **+3.8 ms per download** (5.4 ms → 9.3 ms, measured on a
  cached tarball). Nearly every Dozor rule is an exact name, so bucketing exact
  names in a hash map upstream removes it. Tracked as a NORA issue.
- **npm only** in 0.1. Every other ecosystem answers `Unknown` and is reported.
