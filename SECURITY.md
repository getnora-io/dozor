# Security Policy

## Reporting a vulnerability

Report privately through
[GitHub Security Advisories](https://github.com/getnora-io/dozor/security/advisories/new).
Please do not open a public issue for a vulnerability.

Expect an acknowledgement within 72 hours and an assessment within seven days.

## Threat model

Dozor decides what a registry refuses to serve. Two failure directions matter,
and they are not symmetric:

- **False negative — a malicious package is not blocked.** The likeliest causes
  are a stale feed snapshot, a version the matcher cannot parse, or an
  over-broad exception. Dozor counts undecidable versions in
  `x-dozor-unmatched` rather than treating them as safe, and every exception
  expires. Report anything that makes a rule silently disappear.
- **False positive — a good package is blocked.** Annoying, not dangerous;
  Dozor is never on the download path, so it cannot itself fail a request.

Dozor consumes third-party data (the OSV feed). It parses that data, never
executes it, and never opens package contents. Treat a crash or excessive memory
use on a crafted feed entry as a security issue and report it as one.

## What is not a vulnerability

- Advisories missing from OSV upstream — report those to
  [osv.dev](https://osv.dev).
- A blocked package you disagree with: that is policy, and policy is your file.
