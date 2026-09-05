//! The derivation: (feed snapshot x inventory x policy) -> blocklist.
//!
//! D-ADR-1: a compiler, not a service. Nothing survives the run.
//! D-ADR-2: identical inputs produce byte-identical output.
//! D-ADR-3: the output is a plain NORA blocklist — a superset NORA reads as-is,
//!          because `curation.rs` does not use `deny_unknown_fields`.
#![forbid(unsafe_code)]

pub mod inventory;
pub mod policy;

use dozor_osv::{Index, Kind, Severity};
use dozor_vers::{Ecosystem, Match};
use policy::Policy;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::BufRead;

/// One line of the inventory: what the registry actually holds.
#[derive(Debug, Deserialize)]
pub struct InvItem {
    pub registry: String,
    pub name: String,
    pub version: String,
}

/// A NORA blocklist rule. The first four fields are NORA's schema
/// (`curation.rs::BlocklistRule`); `x-dozor` is ours and NORA ignores it.
#[derive(Debug, Serialize)]
pub struct Rule {
    pub registry: String,
    pub name: String,
    pub version: String,
    pub reason: String,
    #[serde(rename = "x-dozor")]
    pub meta: RuleMeta,
}

#[derive(Debug, Serialize)]
pub struct RuleMeta {
    pub osv: Vec<String>,
    pub severity: String,
    pub kind: String,
    pub purl: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fixed_in: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Derivation {
    pub dozor: String,
    pub matcher: String,
    pub policy: String,
    pub inventory: String,
    pub mode: String,
    pub snapshots: BTreeMap<String, String>,
    pub output: String,
}

#[derive(Debug, Serialize, Default)]
pub struct Unmatched {
    pub count: usize,
    pub sample: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct Output {
    pub version: u32,
    pub rules: Vec<Rule>,
    #[serde(rename = "x-dozor-derivation")]
    pub derivation: Derivation,
    #[serde(rename = "x-dozor-unmatched")]
    pub unmatched: Unmatched,
}

#[derive(Debug, Default)]
pub struct Stats {
    pub inventory_items: usize,
    pub whole_package_rules: usize,
    pub version_rules: usize,
    pub excepted: usize,
    pub unknown: usize,
}

/// Aggregation key: registry, name, version (`"*"` for a whole package).
type Key = (String, String, String);

#[derive(Default)]
struct Hit {
    ids: Vec<String>,
    severity: Severity,
    malicious: bool,
    fixed_in: Option<String>,
}

/// Accumulates hits and collapses them into the smallest correct rule set.
#[derive(Default)]
pub struct Builder {
    hits: BTreeMap<Key, Hit>,
    /// Packages already covered by a `version: "*"` rule — per-version rules
    /// for these are redundant and must not be emitted.
    whole: std::collections::BTreeSet<(String, String)>,
    unknown_samples: Vec<String>,
    pub stats: Stats,
}

impl Builder {
    fn record(
        &mut self,
        registry: &str,
        name: &str,
        version: &str,
        idx: &Index,
        e: &dozor_osv::Entry,
    ) {
        let key = (registry.to_string(), name.to_string(), version.to_string());
        if version == "*" {
            self.whole.insert((registry.to_string(), name.to_string()));
        }
        let id = idx.id_str(e).to_string();
        let hit = self.hits.entry(key).or_default();
        if !hit.ids.contains(&id) {
            hit.ids.push(id);
        }
        if e.severity() > hit.severity {
            hit.severity = e.severity();
        }
        if e.kind() == Kind::Malicious {
            hit.malicious = true;
        }
        if hit.fixed_in.is_none() && !e.fixed_in.is_empty() {
            hit.fixed_in = Some(idx.arena.get(e.fixed_in).to_string());
        }
    }

    /// Emit every whole-package malicious rule in the feed, with no regard for
    /// what is currently cached. This is what makes Dozor preventive rather
    /// than reactive: the package is refused before its first download.
    pub fn add_proactive(&mut self, idx: &Index, eco: Ecosystem, pol: &Policy) {
        if !pol.blocks_malicious() {
            return;
        }
        let registry = eco.registry();
        for (name, e) in idx.iter_named() {
            if e.kind() != Kind::Malicious || !idx.is_whole_package(e) {
                continue;
            }
            if pol.excepted(registry, name, "*") {
                self.stats.excepted += 1;
                continue;
            }
            self.record(registry, name, "*", idx, e);
        }
    }

    /// Match the registry inventory against the feed.
    pub fn add_inventory<R: BufRead>(
        &mut self,
        inventory: R,
        idx: &Index,
        eco: Ecosystem,
        pol: &Policy,
    ) -> std::io::Result<()> {
        let threshold = pol.threshold().ok().flatten();
        let block_malicious = pol.blocks_malicious();
        let registry = eco.registry();

        for line in inventory.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let item: InvItem = match serde_json::from_str(&line) {
                Ok(i) => i,
                Err(_) => continue,
            };
            self.stats.inventory_items += 1;
            if item.registry != registry {
                continue;
            }

            for e in idx.lookup(&item.name) {
                let gated = match e.kind() {
                    Kind::Malicious => block_malicious,
                    Kind::Vulnerability => threshold.is_some_and(|t| e.severity() >= t),
                };
                if !gated {
                    continue;
                }

                // A wholly-malicious package is one rule, not one per version.
                if e.kind() == Kind::Malicious && idx.is_whole_package(e) {
                    if pol.excepted(registry, &item.name, "*") {
                        self.stats.excepted += 1;
                        continue;
                    }
                    self.record(registry, &item.name, "*", idx, e);
                    continue;
                }

                match version_verdict(idx, eco, &item.version, e) {
                    Match::NotAffected => continue,
                    Match::Unknown => {
                        self.stats.unknown += 1;
                        if self.unknown_samples.len() < 20 {
                            self.unknown_samples
                                .push(format!("{}@{}", item.name, item.version));
                        }
                        continue;
                    }
                    Match::Affected => {}
                }
                if pol.excepted(registry, &item.name, &item.version) {
                    self.stats.excepted += 1;
                    continue;
                }
                self.record(registry, &item.name, &item.version, idx, e);
            }
        }
        Ok(())
    }

    /// Collapse, sort and render. Per-version rules shadowed by a `*` rule for
    /// the same package are dropped — they can never change a decision.
    pub fn finish(mut self) -> (Vec<Rule>, Unmatched, Stats) {
        let whole = std::mem::take(&mut self.whole);
        let mut rules = Vec::with_capacity(self.hits.len());
        for ((registry, name, version), mut hit) in std::mem::take(&mut self.hits) {
            if version != "*" && whole.contains(&(registry.clone(), name.clone())) {
                continue;
            }
            if version == "*" {
                self.stats.whole_package_rules += 1;
            } else {
                self.stats.version_rules += 1;
            }
            hit.ids.sort();
            let purl = format!("pkg:{registry}/{name}@{version}");
            let reason = reason_line(&hit);
            rules.push(Rule {
                registry,
                name,
                version,
                reason,
                meta: RuleMeta {
                    osv: hit.ids,
                    severity: hit.severity.as_str().to_string(),
                    kind: if hit.malicious {
                        "malicious".into()
                    } else {
                        "vulnerability".into()
                    },
                    purl,
                    fixed_in: hit.fixed_in,
                },
            });
        }
        let unmatched = Unmatched {
            count: self.stats.unknown,
            sample: std::mem::take(&mut self.unknown_samples),
        };
        (rules, unmatched, self.stats)
    }
}

fn version_verdict(idx: &Index, eco: Ecosystem, version: &str, e: &dozor_osv::Entry) -> Match {
    if idx.versions_of(e).any(|v| v == version) {
        return Match::Affected;
    }
    let mut saw_unknown = false;
    for b in idx.bounds_of(e) {
        match dozor_vers::matches(eco, version, &b) {
            Match::Affected => return Match::Affected,
            Match::Unknown => saw_unknown = true,
            Match::NotAffected => {}
        }
    }
    if saw_unknown {
        Match::Unknown
    } else {
        Match::NotAffected
    }
}

/// The text a developer sees in NORA's 403 body. Self-contained on purpose:
/// what, how bad, where to read more, and what to upgrade to.
fn reason_line(hit: &Hit) -> String {
    let ids = hit.ids.join(", ");
    let first = hit.ids.first().map(String::as_str).unwrap_or("");
    if hit.malicious {
        format!(
            "MALICIOUS package ({ids}) — blocked by dozor · https://osv.dev/vulnerability/{first}"
        )
    } else {
        let fix = match &hit.fixed_in {
            Some(f) => format!(" · fix: {f}"),
            None => " · no fixed version published".to_string(),
        };
        format!(
            "{} severity vulnerability ({ids}){fix} · https://osv.dev/vulnerability/{first}",
            hit.severity.as_str()
        )
    }
}

/// Canonical serialisation of the NORA-visible body, and its digest.
/// No timestamps live in here — that is what makes two runs byte-identical and
/// keeps the daily PR empty when nothing changed.
pub fn canonical_body(rules: &[Rule]) -> (String, String) {
    #[derive(Serialize)]
    struct Body<'a> {
        version: u32,
        rules: &'a [Rule],
    }
    // Through Value first: serde_json's Map is a BTreeMap, so keys come out
    // sorted. That is what lets `dozor verify` re-derive the same bytes from a
    // parsed file instead of trusting struct declaration order.
    let value = serde_json::to_value(Body { version: 1, rules }).expect("to value");
    let body = serde_json::to_string(&value).expect("serialize body");
    let digest = format!("sha256:{:x}", Sha256::digest(body.as_bytes()));
    (body, digest)
}

/// Re-derive the canonical body digest from an already-parsed blocklist file.
/// `verify` must not trust struct order — it rebuilds from the JSON itself.
pub fn digest_of_parsed(file: &serde_json::Value) -> Option<String> {
    let mut map = serde_json::Map::new();
    map.insert("version".to_string(), file.get("version")?.clone());
    map.insert("rules".to_string(), file.get("rules")?.clone());
    let body = serde_json::to_string(&serde_json::Value::Object(map)).ok()?;
    Some(format!("sha256:{:x}", Sha256::digest(body.as_bytes())))
}

/// SHA-256 of a small text input (the policy file).
pub fn text_digest(s: &str) -> String {
    format!("sha256:{:x}", Sha256::digest(s.as_bytes()))
}

/// Days -> `YYYY-MM-DD` (civil_from_days, Howard Hinnant). No date dependency,
/// and `--today` can override it so a build stays reproducible.
pub fn today_utc() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    civil_from_days(secs / 86_400)
}

pub fn civil_from_days(days: i64) -> String {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_dates_are_right() {
        assert_eq!(civil_from_days(0), "1970-01-01");
        assert_eq!(civil_from_days(19_723), "2024-01-01");
    }

    #[test]
    fn canonical_body_is_stable_and_hashes() {
        let rules = vec![Rule {
            registry: "npm".into(),
            name: "lodash".into(),
            version: "4.17.20".into(),
            reason: "r".into(),
            meta: RuleMeta {
                osv: vec!["GHSA-x".into()],
                severity: "HIGH".into(),
                kind: "vulnerability".into(),
                purl: "pkg:npm/lodash@4.17.20".into(),
                fixed_in: Some("4.17.21".into()),
            },
        }];
        let (a, da) = canonical_body(&rules);
        let (b, db) = canonical_body(&rules);
        assert_eq!(a, b);
        assert_eq!(da, db);
        // keys are sorted, so `rules` precedes `version` at the top level
        assert!(a.starts_with(r#"{"rules":[{"name":"lodash""#), "{a}");
    }
}
