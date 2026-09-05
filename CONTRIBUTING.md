# Contributing

## The short version

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
./scripts/contract-gate.sh
```

All four are merge gates. CI runs exactly these.

## The rule that matters most

**A contract in `contracts.json` may be marked `CLOSED` only when every proof it
names exists in the tree.** `scripts/contract-gate.sh` enforces that, and it
is deliberately the check that guards the register of checks: a claim with no
test behind it is a claim, not a control.

If you fix a bug that a test would have caught, add the contract as well as the
fix. Every incident is worth one more contract.

## Where things live

| crate | job |
|---|---|
| `dozor-vers` | version-range semantics per ecosystem · pure, no I/O |
| `dozor-osv` | streaming OSV reader · arena + CSR index |
| `dozor-core` | inventory, policy, rule collapse, canonical output |
| `dozor` | the CLI |

## Adding an ecosystem

This is the most useful thing you can do right now, and it is well isolated:

1. Add the variant to `Ecosystem` in `dozor-vers`.
2. Implement its comparison. It must return `Unknown` rather than guess — an
   undecidable version is reported, never assumed safe.
3. Test the edges: pre-releases, epochs, missing bounds, garbage input.
4. If you have a reference implementation to compare against (`npm semver`,
   `packaging` for PEP 440), a differential test over a corpus is worth more
   than a dozen hand-written cases.

## Style

Match the surrounding code. Comments explain *why* a shape was chosen, not what
the line does — the memory note in `dozor-osv` is the model: it records the
measurement that forced the layout.
