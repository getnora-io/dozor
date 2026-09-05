//! Policy: the only human-authored input. Lives in git, reviewed in a PR.
//!
//! D-ADR-7: every exception carries `reason` and `expires`. An expired
//! exception fails the build — silent renewal is how security policy dies.

use dozor_osv::Severity;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Policy {
    pub version: u32,
    #[serde(default)]
    pub defaults: Defaults,
    #[serde(default, rename = "exception")]
    pub exceptions: Vec<Exception>,
}

#[derive(Debug, Deserialize)]
pub struct Defaults {
    /// `critical` | `high` | `moderate` | `low` | `off`
    #[serde(default = "default_threshold")]
    pub severity_threshold: String,
    /// `block` | `audit` — applies to MAL-* reports, which carry no severity.
    #[serde(default = "default_malicious")]
    pub malicious: String,
}

impl Default for Defaults {
    fn default() -> Self {
        Defaults {
            severity_threshold: default_threshold(),
            malicious: default_malicious(),
        }
    }
}

fn default_threshold() -> String {
    "high".to_string()
}

fn default_malicious() -> String {
    "block".to_string()
}

#[derive(Debug, Deserialize, Clone)]
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
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyError::Parse(e) => write!(f, "policy parse error: {e}"),
            PolicyError::UnsupportedVersion(v) => write!(f, "unsupported policy version {v} (expected 1)"),
            PolicyError::Expired(list) => write!(f, "expired exceptions (renew or drop them): {}", list.join(", ")),
            PolicyError::BadThreshold(s) => write!(f, "unknown severity_threshold '{s}'"),
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
        Ok(p)
    }

    /// `None` means "severity gating is off" — malicious reports still apply.
    pub fn threshold(&self) -> Result<Option<Severity>, PolicyError> {
        match self.defaults.severity_threshold.to_ascii_lowercase().as_str() {
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

    /// Fails if any exception is past its date on `today` (ISO `YYYY-MM-DD`).
    pub fn check_expiry(&self, today: &str) -> Result<(), PolicyError> {
        let expired: Vec<String> = self
            .exceptions
            .iter()
            .filter(|e| e.expires.as_str() < today)
            .map(|e| format!("{}/{}@{} (expired {})", e.registry, e.name, e.version, e.expires))
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
    fn unknown_threshold_is_rejected_at_load() {
        let bad = SAMPLE.replace("\"high\"", "\"kinda-bad\"");
        assert!(Policy::load(&bad).is_err());
    }
}
