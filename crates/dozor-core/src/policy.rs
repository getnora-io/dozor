//! Policy: the only human-authored input. Lives in git, reviewed in a PR.
//!
//! D-ADR-7: every exception carries `reason` and `expires`. An expired
//! exception fails the build — silent renewal is how security policy dies.
//!
//! D-ADR-10: closed by default. With no `[defaults]` at all the policy blocks
//! as much as the feed allows; every setting that blocks less is a line someone
//! wrote in this file, reviewed in a PR. A value or a key the policy does not
//! know fails the build: a typo must not open anything.

use dozor_osv::Severity;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: u32,
    #[serde(default)]
    pub defaults: Defaults,
    #[serde(default, rename = "exception")]
    pub exceptions: Vec<Exception>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Defaults {
    /// `critical` | `high` | `moderate` | `low` | `off`
    #[serde(default = "default_threshold")]
    pub severity_threshold: String,
    /// `block` | `audit` — applies to MAL-* reports, which carry no severity.
    /// `audit` blocks no malicious package.
    #[serde(default = "default_malicious")]
    pub malicious: String,
    /// `true`: every wholly-malicious package in the feed is blocked, cached or
    /// not. `false` limits malicious-package rules to the inventory.
    #[serde(default = "default_proactive")]
    pub proactive: bool,
    /// `listed`: for a package in the inventory, every version a malicious
    /// report lists is blocked, cached or not. `cached`: only the versions in
    /// the inventory, so a listed release the registry has not downloaded yet
    /// is not blocked.
    #[serde(default = "default_malicious_versions")]
    pub malicious_versions: String,
}

impl Default for Defaults {
    fn default() -> Self {
        Defaults {
            severity_threshold: default_threshold(),
            malicious: default_malicious(),
            proactive: default_proactive(),
            malicious_versions: default_malicious_versions(),
        }
    }
}

fn default_threshold() -> String {
    "high".to_string()
}

fn default_malicious() -> String {
    "block".to_string()
}

fn default_proactive() -> bool {
    true
}

fn default_malicious_versions() -> String {
    "listed".to_string()
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Exception {
    pub registry: String,
    pub name: String,
    /// Exact version or `*`.
    pub version: String,
    pub reason: String,
    /// ISO date `YYYY-MM-DD`. Required — there are no permanent exceptions.
    pub expires: String,
}

#[derive(Debug)]
pub enum PolicyError {
    Parse(String),
    UnsupportedVersion(u32),
    Expired(Vec<String>),
    BadThreshold(String),
    BadMalicious(String),
    BadMaliciousVersions(String),
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyError::Parse(e) => write!(f, "policy parse error: {e}"),
            PolicyError::UnsupportedVersion(v) => {
                write!(f, "unsupported policy version {v} (expected 1)")
            }
            PolicyError::Expired(list) => write!(
                f,
                "expired exceptions (renew or drop them): {}",
                list.join(", ")
            ),
            PolicyError::BadThreshold(s) => write!(f, "unknown severity_threshold '{s}'"),
            PolicyError::BadMalicious(s) => {
                write!(f, "unknown malicious '{s}' (expected block or audit)")
            }
            PolicyError::BadMaliciousVersions(s) => {
                write!(
                    f,
                    "unknown malicious_versions '{s}' (expected listed or cached)"
                )
            }
        }
    }
}

impl Policy {
    pub fn load(text: &str) -> Result<Self, PolicyError> {
        let p: Policy = toml::from_str(text).map_err(|e| PolicyError::Parse(e.to_string()))?;
        if p.version != 1 {
            return Err(PolicyError::UnsupportedVersion(p.version));
        }
        p.threshold()?;
        if !["block", "audit"].contains(&p.defaults.malicious.to_ascii_lowercase().as_str()) {
            return Err(PolicyError::BadMalicious(p.defaults.malicious.clone()));
        }
        if !["listed", "cached"]
            .contains(&p.defaults.malicious_versions.to_ascii_lowercase().as_str())
        {
            return Err(PolicyError::BadMaliciousVersions(
                p.defaults.malicious_versions.clone(),
            ));
        }
        Ok(p)
    }

    /// `None` means "severity gating is off" — malicious reports still apply.
    pub fn threshold(&self) -> Result<Option<Severity>, PolicyError> {
        match self
            .defaults
            .severity_threshold
            .to_ascii_lowercase()
            .as_str()
        {
            "off" => Ok(None),
            "low" => Ok(Some(Severity::Low)),
            "moderate" | "medium" => Ok(Some(Severity::Moderate)),
            "high" => Ok(Some(Severity::High)),
            "critical" => Ok(Some(Severity::Critical)),
            other => Err(PolicyError::BadThreshold(other.to_string())),
        }
    }

    pub fn blocks_malicious(&self) -> bool {
        self.defaults.malicious.eq_ignore_ascii_case("block")
    }

    /// Whether every wholly-malicious package in the feed is blocked, cached or not.
    pub fn proactive(&self) -> bool {
        self.defaults.proactive
    }

    /// Whether every version a malicious report lists is blocked for a package
    /// in the inventory, not only the versions the inventory holds.
    pub fn blocks_listed_versions(&self) -> bool {
        self.defaults
            .malicious_versions
            .eq_ignore_ascii_case("listed")
    }

    /// Fails if any exception is past its date on `today` (ISO `YYYY-MM-DD`).
    pub fn check_expiry(&self, today: &str) -> Result<(), PolicyError> {
        let expired: Vec<String> = self
            .exceptions
            .iter()
            .filter(|e| e.expires.as_str() < today)
            .map(|e| {
                format!(
                    "{}/{}@{} (expired {})",
                    e.registry, e.name, e.version, e.expires
                )
            })
            .collect();
        if expired.is_empty() {
            Ok(())
        } else {
            Err(PolicyError::Expired(expired))
        }
    }

    pub fn excepted(&self, registry: &str, name: &str, version: &str) -> bool {
        self.exceptions.iter().any(|e| {
            e.registry == registry && e.name == name && (e.version == "*" || e.version == version)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
version = 1
[defaults]
severity_threshold = "high"
malicious = "block"

[[exception]]
registry = "npm"
name = "lodash"
version = "4.17.20"
reason = "pinned by legacy build, tracked in JIRA-42"
expires = "2026-12-31"
"#;

    #[test]
    fn loads_and_reads_threshold() {
        let p = Policy::load(SAMPLE).unwrap();
        assert_eq!(p.threshold().unwrap(), Some(Severity::High));
        assert!(p.blocks_malicious());
        assert!(p.excepted("npm", "lodash", "4.17.20"));
        assert!(!p.excepted("npm", "lodash", "4.17.19"));
    }

    #[test]
    fn expired_exception_is_an_error() {
        let p = Policy::load(SAMPLE).unwrap();
        assert!(p.check_expiry("2026-01-01").is_ok());
        assert!(p.check_expiry("2027-01-01").is_err());
    }

    #[test]
    fn an_empty_policy_blocks_as_much_as_the_feed_allows() {
        let p = Policy::load("version = 1\n").unwrap();
        assert_eq!(p.threshold().unwrap(), Some(Severity::High));
        assert!(p.blocks_malicious());
        assert!(p.proactive());
        assert!(p.blocks_listed_versions());
    }

    #[test]
    fn blocking_less_is_a_line_in_the_policy() {
        let p = Policy::load(
            "version = 1\n[defaults]\nmalicious = \"audit\"\nproactive = false\nmalicious_versions = \"cached\"\n",
        )
        .unwrap();
        assert!(!p.blocks_malicious());
        assert!(!p.proactive());
        assert!(!p.blocks_listed_versions());
    }

    #[test]
    fn an_unknown_value_or_key_is_rejected_at_load() {
        for bad in [
            "malicious = \"blcok\"",
            "malicious = \"\"",
            "malicious_versions = \"all\"",
            "malicous = \"audit\"",
            "proactive = \"no\"",
        ] {
            let text = format!("version = 1\n[defaults]\n{bad}\n");
            assert!(Policy::load(&text).is_err(), "{bad}");
        }
        assert!(Policy::load("version = 1\nexceptions = []\n").is_err());
        // A key next to every required one: only deny_unknown_fields refuses it.
        let extra = SAMPLE.replace(
            "expires = \"2026-12-31\"",
            "expires = \"2026-12-31\"\nscope = \"all\"",
        );
        assert!(Policy::load(&extra).is_err());
    }

    #[test]
    fn unknown_threshold_is_rejected_at_load() {
        let bad = SAMPLE.replace("\"high\"", "\"kinda-bad\"");
        assert!(Policy::load(&bad).is_err());
    }
}
