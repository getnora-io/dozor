#!/usr/bin/env bash
# A contract may be marked CLOSED only if every proof it names actually exists
# in the tree. This is the check that guards the register of checks, because
# documented is not the same as enforced.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 - <<'PY'
import json, pathlib, sys

contracts = json.loads(pathlib.Path("contracts.json").read_text())["contracts"]
failures, closed = [], 0

for c in contracts:
    state, cid = c["state"], c["id"]
    proofs = c.get("proof", [])
    if state != "CLOSED":
        if proofs:
            failures.append(f"{cid}: state={state} but names proofs — either close it or drop them")
        continue
    closed += 1
    if not proofs:
        failures.append(f"{cid}: CLOSED with no proof — documented is not enforced")
        continue
    for proof in proofs:
        path, _, symbol = proof.partition("::")
        p = pathlib.Path(path)
        if not p.exists():
            failures.append(f"{cid}: proof file missing: {path}")
        elif symbol and symbol not in p.read_text():
            failures.append(f"{cid}: proof '{symbol}' not found in {path}")

print(f"contract gate: {len(contracts)} contracts, {closed} CLOSED")
for f in failures:
    print(f"  RED  {f}")
if failures:
    sys.exit(1)
print("  all CLOSED contracts have living proofs")
PY
