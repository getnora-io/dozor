# Dozor

[![ci](https://github.com/getnora-io/dozor/actions/workflows/ci.yml/badge.svg)](https://github.com/getnora-io/dozor/actions/workflows/ci.yml)
[![nora-parity](https://github.com/getnora-io/dozor/actions/workflows/nora-parity.yml/badge.svg)](https://github.com/getnora-io/dozor/actions/workflows/nora-parity.yml)
[![crates.io](https://img.shields.io/crates/v/dozor.svg)](https://crates.io/crates/dozor)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Dozor** /ˈdoʊ.zɔːr/ — Slavic: *the watch, the patrol sent ahead*.

The watch that walks ahead of your registry. Dozor compiles the OSV vulnerability
feed and your registry's inventory into a blocklist that [NORA](https://github.com/getnora-io/nora)
enforces at the door.

**Dozor scouts. NORA holds the door.**

```
osv.dev snapshot   ─┐
registry inventory ─┼─►  dozor build  ─►  blocklist.json  ─►  git PR  ─►  NORA
policy.toml        ─┘
```

Dozor is not a daemon, not a service, not a scanner and not a database. It is a
compiler: three files in, one file out, deterministic. It never sits on the
download path, so it can never take your registry down.

## Why it exists

A registry proxy caches whatever upstream hands it. The npm OSV feed currently
carries **228,684 advisories**, and **96.8% of them are `MAL-*` — malicious
packages**, not CVEs: typosquats, hijacked maintainers, poisoned releases. A CI
scanner finds those *after* the package is already cached and served to the whole
team. The registry is the only place where refusing them is prevention.

NORA already blocks by file (`curation.blocklist_path`). Nobody can hand-maintain
that file against thousands of advisories a week. Dozor writes it.

## Unix philosophy, on purpose

| | |
|---|---|
| **One job** | Turn advisories + inventory into a blocklist. Nothing else. |
| **Text in, text out** | Reads a zip snapshot, JSONL and TOML; writes JSON. No API, no socket, no daemon. |
| **Exit codes are the interface** | `0` ok · `2` feed unreadable · `3` empty inventory · `4` expired exception · `5` bad policy · `6` drift |
| **Composes** | `dozor build && git commit` · `dozor verify` in CI · `jq` over the output · cron or a GitLab job, your choice |
| **No state** | Nothing survives the run. Delete everything but the inputs and re-derive. |
| **Do nothing silently** | A version the matcher cannot decide is reported as `x-dozor-unmatched`, never as "safe". |

## GitOps native

The output is an artifact, not a controller's opinion:

- **Declarative** — the blocklist is a file, reviewed in a pull request, with `git log -S` as its audit trail.
- **Reproducible** — identical inputs give byte-identical output. Two runs, same SHA-256. The daily job opens a PR only when something actually changed.
- **Verifiable** — every output carries `x-dozor-derivation`: digests of the feed snapshot, the inventory, the policy and the body itself. `dozor verify` re-derives it. You can prove a year later why a build was blocked in March.
- **No operator, no CRD, no reconcile loop.** A Job that writes a file. Your existing GitOps stack does the rest.

## Measured, not claimed

On the live npm feed, 2026-09-05 (32-core box, single-threaded run):

| | |
|---|---|
| feed | 222 MB zip · 360 MB raw JSON · 228,684 advisories · 224,545 packages |
| index build | **2.5 s**, retained index **24.9 MB**, peak RSS **173 MB** |
| wholly-malicious packages | **197,314** |
| proactive blocklist | 197,314 rules · 78 MB (4.2 MB gzipped) |
| determinism | two runs → identical bytes, `verify` green |
| NORA loading it | `Blocklist filter loaded rules=197314`, NORA RSS **58 MB** |
| blocked download | **HTTP 403 in 1.5 ms**, reason string carries the MAL id and the osv.dev link |

The feed is never unpacked to disk: entries are decompressed one at a time,
projected to the ~4% that decides a verdict, and dropped.

## Install

```bash
cargo install dozor
```

Or take a static binary from the [releases page](https://github.com/getnora-io/dozor/releases)
— `x86_64` and `aarch64`, musl, no runtime dependencies.

## Quick start

```bash
# 1. snapshot the feed (or copy the zip in, for air-gapped sites)
curl -o snapshots/npm.zip https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip

# 2. take an inventory of what your registry actually holds
dozor inventory --nora-data /var/lib/nora -o inventory.jsonl
#   ...or gate a project instead of a cache:
# dozor inventory --lockfile package-lock.json -o inventory.jsonl

# 3. compile a blocklist: everything malicious, plus CVEs affecting what you cache
dozor build \
  --feed-npm snapshots/npm.zip \
  --inventory inventory.jsonl \
  --policy policy.toml \
  --proactive \
  -o blocklist.json

# 4. hand it to NORA — no NORA changes required, any released version
NORA_CURATION_MODE=enforce \
NORA_CURATION_BLOCKLIST_PATH=/etc/nora/blocklist.json \
nora serve
```

The inventory is one JSON object per line, sorted and deduplicated so it diffs
cleanly in git:

```json
{"registry":"npm","name":"lodash","version":"4.17.20"}
```

`dozor inventory` reads it from a NORA data directory (both proxied tarballs and
hosted versions, scoped packages included) or from an npm lockfile. Anything that
can emit those lines works — it is a text format on purpose.

## Commands

```
dozor inventory  --nora-data DIR | --lockfile FILE   what the registry holds
dozor build      feed x inventory x policy -> blocklist.json
dozor verify     re-derive the digest from the file itself
dozor explain    what the feed says about one package version
dozor stats      index size and peak RSS, measured
```

## Policy

The only human-authored input. It lives in git.

```toml
version = 1

[defaults]
severity_threshold = "high"   # critical | high | moderate | low | off
malicious = "block"           # MAL-* reports carry no severity — own switch

[[exception]]
registry = "npm"
name = "lodash"
version = "4.17.20"
reason = "pinned by legacy build, tracked in JIRA-42"
expires = "2026-12-31"        # required. expired exception = exit 4, not silent renewal
```

## What Dozor is not

- **Not a scanner.** It does not open your artifacts. Trivy and Grype do that, and they do it well.
- **Not an SCA tool for your project.** It looks at what your *registry* holds, not at your dependency tree.
- **Not a service.** No port, no daemon, no controller. It cannot be on the download path, by design.
- **Not a database.** Nothing persists between runs but the files you keep on purpose.
- **Not a replacement for NORA's curation.** It writes curation input; NORA decides and enforces.

## Status

v0.1 — **npm only**. The matcher answers `Unknown` for every other ecosystem, and
`Unknown` never becomes "safe": those versions are counted and sampled in
`x-dozor-unmatched` in the output.

Next: PyPI (PEP 440), then Maven, Go and RPM/deb version semantics; an OpenVEX
output so the same policy that blocks in NORA also silences Trivy and Grype on
the same accepted exceptions; and `dozor sync` for content-addressed snapshots.
None of that exists yet — this section is the whole roadmap.

## Crates

| crate | |
|---|---|
| [`dozor`](https://crates.io/crates/dozor) | the CLI |
| [`dozor-core`](https://crates.io/crates/dozor-core) | inventory, policy, rule collapse, canonical output |
| [`dozor-osv`](https://crates.io/crates/dozor-osv) | streaming OSV reader, arena + CSR index |
| [`dozor-vers`](https://crates.io/crates/dozor-vers) | version-range semantics per ecosystem, pure, no I/O |

## License

MIT.

OSV data is published by [osv.dev](https://osv.dev) under CC-BY-4.0.
