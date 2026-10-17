# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- **Closed by default** (D-ADR-10). A policy that sets nothing blocks as much as the feed
  allows; every setting that blocks less is a line in the policy:
  - every wholly-malicious package is blocked unless the policy says `proactive = false`;
    `--proactive` stays for existing jobs and can only ask for more;
  - for a package in the inventory, every version a malicious report lists is blocked,
    cached or not; `malicious_versions = "cached"` limits it to the inventory's versions.
    A release NORA holds back with `min_release_age` is never downloaded, so it was never
    in the inventory and never blocked.
- A policy value or key Dozor does not know fails the build with exit 5. `malicious`
  takes `block` or `audit`: any other value used to turn malicious blocking off. A
  misspelt key used to be ignored.
- An empty inventory stops the build with exit 3 even when proactive rules could be
  written; the previous file stays. It used to be replaced with the proactive rules alone.

### Fixed
- A malicious report whose ranges cover every version is a whole-package rule even when
  it also lists versions: 9,100 such reports in the npm feed of 2026-10-17 were not
  blocked proactively.
- A malicious report listing more than 64 versions keeps them, as does any report without
  ranges: six reports in the same feed were dropped and blocked nothing.

### Notes
- Measured on the npm feed of 2026-10-17: the default build holds 206,466 rules where
  0.1.0 with `--proactive` held 197,393, and every 0.1.0 rule is still there. Index
  25.2 MB, `dozor stats` peak RSS 142 MB, as before. NORA (1.4.0 release candidate) with
  that file: startup 0.9 s, RSS 91 MB (peak 172 MB), download latency unchanged.

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
