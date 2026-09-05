//! Contract enforcement. Each test names the contract it upholds; `contracts.json`
//! points back here and `scripts/contract-gate.sh` refuses a CLOSED contract
//! whose proof does not exist.

use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    // crates/dozor-cli -> repo root
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn testdata(name: &str) -> PathBuf {
    repo_root().join("testdata").join(name)
}

fn tmp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("dozor-it-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join(name)
}

fn dozor() -> Command {
    Command::new(env!("CARGO_BIN_EXE_dozor"))
}

fn build_to(out: &Path, policy: &str, extra: &[&str]) -> std::process::Output {
    let mut cmd = dozor();
    cmd.arg("build")
        .arg("--feed-npm")
        .arg(testdata("mini-npm.zip"))
        .arg("--inventory")
        .arg(testdata("inventory.jsonl"))
        .arg("--policy")
        .arg(testdata(policy))
        .arg("--today")
        .arg("2026-09-05")
        .arg("-o")
        .arg(out);
    cmd.args(extra);
    cmd.output().expect("run dozor")
}

fn rules_of(path: &Path) -> serde_json::Value {
    let text = std::fs::read_to_string(path).expect("read output");
    serde_json::from_str(&text).expect("parse output")
}

/// D-1: identical inputs produce byte-identical output.
#[test]
fn determinism_two_builds_identical() {
    let a = tmp("det-a.json");
    let b = tmp("det-b.json");
    assert!(build_to(&a, "policy.toml", &[]).status.success());
    assert!(build_to(&b, "policy.toml", &[]).status.success());
    let (ba, bb) = (std::fs::read(&a).unwrap(), std::fs::read(&b).unwrap());
    assert_eq!(
        ba, bb,
        "two builds from the same inputs must be byte-identical"
    );

    // ...and the stored derivation digest must re-derive from the file itself.
    let out = dozor().arg("verify").arg(&a).output().unwrap();
    assert!(
        out.status.success(),
        "verify failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// D-3: an unreadable feed stops the run and leaves the existing file alone.
#[test]
fn missing_feed_exits_2_and_leaves_output_untouched() {
    let out = tmp("guard-feed.json");
    std::fs::write(&out, b"PREVIOUS CONTENT").unwrap();
    let res = dozor()
        .arg("build")
        .arg("--feed-npm")
        .arg(testdata("does-not-exist.zip"))
        .arg("--inventory")
        .arg(testdata("inventory.jsonl"))
        .arg("--policy")
        .arg(testdata("policy.toml"))
        .arg("-o")
        .arg(&out)
        .output()
        .unwrap();
    assert_eq!(res.status.code(), Some(2));
    assert_eq!(std::fs::read(&out).unwrap(), b"PREVIOUS CONTENT");
}

/// D-3: an empty inventory is a signal, not a result — the file survives.
#[test]
fn empty_inventory_exits_3_and_leaves_output_untouched() {
    let empty = tmp("empty.jsonl");
    std::fs::write(&empty, b"").unwrap();
    let out = tmp("guard-inv.json");
    std::fs::write(&out, b"PREVIOUS CONTENT").unwrap();
    let res = dozor()
        .arg("build")
        .arg("--feed-npm")
        .arg(testdata("mini-npm.zip"))
        .arg("--inventory")
        .arg(&empty)
        .arg("--policy")
        .arg(testdata("policy.toml"))
        .arg("-o")
        .arg(&out)
        .output()
        .unwrap();
    assert_eq!(res.status.code(), Some(3));
    assert_eq!(std::fs::read(&out).unwrap(), b"PREVIOUS CONTENT");
}

/// D-5: an expired exception fails the build instead of renewing itself.
#[test]
fn expired_exception_exits_4() {
    let out = tmp("expired.json");
    let res = build_to(&out, "policy-expired.toml", &[]);
    assert_eq!(res.status.code(), Some(4));
    assert!(String::from_utf8_lossy(&res.stderr).contains("expired"));
}

#[test]
fn unusable_policy_exits_5() {
    let out = tmp("badpolicy.json");
    let res = build_to(&out, "policy-bad.toml", &[]);
    assert_eq!(res.status.code(), Some(5));
}

/// D-4: a version the matcher cannot decide is reported, never assumed safe.
#[test]
fn undecidable_version_is_reported_not_silently_allowed() {
    let out = tmp("unmatched.json");
    assert!(build_to(&out, "policy.toml", &[]).status.success());
    let doc = rules_of(&out);
    let unmatched = &doc["x-dozor-unmatched"];
    assert_eq!(
        unmatched["count"], 1,
        "weird-pkg@not-a-semver must be counted"
    );
    assert!(
        unmatched["sample"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s == "weird-pkg@not-a-semver"),
        "the undecidable version must be named in the sample"
    );
}

/// Policy semantics, in one pass over the fixture.
#[test]
fn policy_decides_what_the_fixture_expects() {
    let out = tmp("policy-shape.json");
    assert!(build_to(&out, "policy.toml", &[]).status.success());
    let doc = rules_of(&out);
    let rules = doc["rules"].as_array().unwrap();
    let keys: Vec<(String, String)> = rules
        .iter()
        .map(|r| {
            (
                r["name"].as_str().unwrap().into(),
                r["version"].as_str().unwrap().into(),
            )
        })
        .collect();

    // wholly malicious package -> one "*" rule, both cached versions collapsed
    assert!(keys.contains(&("evil-pkg".into(), "*".into())));
    assert_eq!(keys.iter().filter(|(n, _)| n == "evil-pkg").count(), 1);
    // malicious in one version only -> that version, not the package
    assert!(keys.contains(&("partly-evil".into(), "1.0.1".into())));
    assert!(!keys.contains(&("partly-evil".into(), "1.0.2".into())));
    // HIGH inside range blocks, the fixed version does not
    assert!(keys.contains(&("vuln-pkg".into(), "1.0.0".into())));
    assert!(!keys.contains(&("vuln-pkg".into(), "2.0.0".into())));
    // LOW under a HIGH threshold does not block
    assert!(!keys.iter().any(|(n, _)| n == "low-pkg"));
    // a package with no advisory is untouched
    assert!(!keys.iter().any(|(n, _)| n == "clean-pkg"));
    // PyPI advisories never leak into an npm blocklist
    assert!(!keys.iter().any(|(n, _)| n == "django"));
}

/// The reason string is what NORA puts in the 403 body — it must carry the id.
#[test]
fn reason_carries_advisory_id_and_link() {
    let out = tmp("reason.json");
    assert!(build_to(&out, "policy.toml", &[]).status.success());
    let doc = rules_of(&out);
    let evil = doc["rules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "evil-pkg")
        .expect("evil-pkg rule");
    let reason = evil["reason"].as_str().unwrap();
    assert!(
        reason.contains("MAL-0001"),
        "reason must name the advisory: {reason}"
    );
    assert!(
        reason.contains("osv.dev"),
        "reason must link to the advisory: {reason}"
    );
}

/// Proactive mode blocks a malicious package that is not in the inventory.
#[test]
fn proactive_blocks_packages_never_cached() {
    let out = tmp("proactive.json");
    let res = dozor()
        .arg("build")
        .arg("--feed-npm")
        .arg(testdata("mini-npm.zip"))
        .arg("--policy")
        .arg(testdata("policy.toml"))
        .arg("--proactive")
        .arg("--today")
        .arg("2026-09-05")
        .arg("-o")
        .arg(&out)
        .output()
        .unwrap();
    assert!(res.status.success());
    let doc = rules_of(&out);
    let rules = doc["rules"].as_array().unwrap();
    assert!(rules
        .iter()
        .any(|r| r["name"] == "evil-pkg" && r["version"] == "*"));
    assert_eq!(doc["x-dozor-derivation"]["mode"], "proactive");
}

/// `dozor inventory` must round-trip into `dozor build`.
#[test]
fn inventory_from_lockfile_feeds_build() {
    let lock = tmp("package-lock.json");
    std::fs::write(
        &lock,
        r#"{"lockfileVersion":3,"packages":{"":{"name":"app"},
            "node_modules/evil-pkg":{"version":"1.2.3"},
            "node_modules/clean-pkg":{"version":"1.0.0"}}}"#,
    )
    .unwrap();
    let inv = tmp("from-lock.jsonl");
    let res = dozor()
        .arg("inventory")
        .arg("--lockfile")
        .arg(&lock)
        .arg("-o")
        .arg(&inv)
        .output()
        .unwrap();
    assert!(
        res.status.success(),
        "{}",
        String::from_utf8_lossy(&res.stderr)
    );

    let out = tmp("from-lock-blocklist.json");
    let res = dozor()
        .arg("build")
        .arg("--feed-npm")
        .arg(testdata("mini-npm.zip"))
        .arg("--inventory")
        .arg(&inv)
        .arg("--policy")
        .arg(testdata("policy.toml"))
        .arg("--today")
        .arg("2026-09-05")
        .arg("-o")
        .arg(&out)
        .output()
        .unwrap();
    assert!(res.status.success());
    let doc = rules_of(&out);
    assert!(doc["rules"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["name"] == "evil-pkg"));
}
