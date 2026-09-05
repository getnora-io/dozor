# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] — 2026-09-05

First release. npm only.

### Added
- `dozor build` — compiles `(OSV feed snapshot × registry inventory × policy)`
  into a blocklist NORA reads as-is. Deterministic: identical inputs give
  byte-identical output.
- `dozor inventory` — takes an inventory from a NORA data directory (proxied
  tarballs and hosted versions, scoped packages included) or an npm lockfile.
- `dozor verify` — re-derives the output digest from the file itself, so a
  verdict can be checked long after the run.
- `dozor explain` — what the feed says about one package version.
- `dozor stats` — index size and peak RSS, measured rather than claimed.
- `--proactive` — blocks every wholly-malicious package in the feed, cached or
  not, so a package is refused before its first download.
- Policy (`policy.toml`): per-severity threshold, a separate `malicious` switch,
  and exceptions that must carry a `reason` and an `expires` date.
- Contract registry (`contracts.json`) with `scripts/contract-gate.sh`: a
  contract may be CLOSED only if every proof it names exists in the tree.
- `nora-parity` workflow: every push runs the published NORA image against a
  generated blocklist and asserts a 403 carrying Dozor's reason string.

### Notes
- The npm OSV feed is 228,684 advisories of which 96.8% are `MAL-*` malicious
  package reports carrying no severity — hence the separate `malicious` switch.
  197,314 of them are "the whole package, forever" and collapse to a single
  `version: "*"` rule each.
- Peak RSS on the full npm feed is 173 MB against a 100 MB target
  (contract D-6, OPEN). The retained index is 24.9 MB; the gap is transient
  build allocation.

[Unreleased]: https://github.com/getnora-io/dozor/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/getnora-io/dozor/releases/tag/v0.1.0
