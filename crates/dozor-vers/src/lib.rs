//! Version-range matching.
//!
//! D-ADR-6: all ecosystem version semantics live here. Pure functions, no I/O,
//! and no ownership — [`Bound`] borrows, so the caller can keep every version
//! string in one arena instead of a million small allocations.
//!
//! The load-bearing type is [`Match`]: the matcher NEVER guesses. When it cannot
//! decide it says [`Match::Unknown`] and the caller reports a visible hole
//! instead of silently emitting "not affected".
#![forbid(unsafe_code)]

/// Ecosystem as named by OSV, mapped to the registry name NORA uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ecosystem {
    Npm,
    PyPI,
    Other,
}

impl Ecosystem {
    /// Parse an OSV ecosystem string (`"npm"`, `"PyPI"`, `"Go"`, ...).
    pub fn parse(s: &str) -> Self {
        match s {
            "npm" => Ecosystem::Npm,
            "PyPI" => Ecosystem::PyPI,
            _ => Ecosystem::Other,
        }
    }

    /// The registry identifier NORA's curation layer matches on.
    pub fn registry(&self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::PyPI => "pypi",
            Ecosystem::Other => "*",
        }
    }
}

/// One OSV range flattened to the bounds that decide the verdict.
/// Borrowed on purpose — see the module note.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Bound<'a> {
    pub introduced: Option<&'a str>,
    pub fixed: Option<&'a str>,
    pub last_affected: Option<&'a str>,
}

impl Bound<'_> {
    /// A range that starts at zero and never ends: the whole package is affected.
    /// 89% of the npm malicious-package feed looks like this, and it is the
    /// difference between one `version: "*"` rule and one rule per version.
    pub fn is_whole_package(&self) -> bool {
        self.introduced == Some("0") && self.fixed.is_none() && self.last_affected.is_none()
    }
}

/// Result of a match attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Match {
    /// The version falls inside the advisory's range.
    Affected,
    /// The version is provably outside the range.
    NotAffected,
    /// The matcher cannot decide (unsupported ecosystem or unparsable version).
    /// Never treat this as "safe" — it is a reportable hole.
    Unknown,
}

/// Decide whether `version` is covered by `bound` under `eco` semantics.
pub fn matches(eco: Ecosystem, version: &str, bound: &Bound<'_>) -> Match {
    match eco {
        Ecosystem::Npm => npm_match(version, bound),
        // PEP 440 and the rest land in 0.2 — until then, honest Unknown.
        Ecosystem::PyPI | Ecosystem::Other => Match::Unknown,
    }
}

fn npm_match(version: &str, b: &Bound<'_>) -> Match {
    let v = match semver::Version::parse(version) {
        Ok(v) => v,
        Err(_) => return Match::Unknown,
    };

    // OSV uses the literal "0" to mean "from the beginning of time".
    if let Some(i) = b.introduced {
        if i != "0" {
            match semver::Version::parse(i) {
                Ok(iv) if v < iv => return Match::NotAffected,
                Ok(_) => {}
                Err(_) => return Match::Unknown,
            }
        }
    }

    if let Some(f) = b.fixed {
        return match semver::Version::parse(f) {
            Ok(fv) if v < fv => Match::Affected,
            Ok(_) => Match::NotAffected,
            Err(_) => Match::Unknown,
        };
    }

    if let Some(l) = b.last_affected {
        return match semver::Version::parse(l) {
            Ok(lv) if v <= lv => Match::Affected,
            Ok(_) => Match::NotAffected,
            Err(_) => Match::Unknown,
        };
    }

    // Introduced, never fixed.
    Match::Affected
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b<'a>(introduced: &'a str, fixed: Option<&'a str>) -> Bound<'a> {
        Bound { introduced: Some(introduced), fixed, last_affected: None }
    }

    #[test]
    fn npm_inside_range_is_affected() {
        assert_eq!(matches(Ecosystem::Npm, "4.17.20", &b("0", Some("4.17.21"))), Match::Affected);
    }

    #[test]
    fn npm_at_fix_is_not_affected() {
        assert_eq!(matches(Ecosystem::Npm, "4.17.21", &b("0", Some("4.17.21"))), Match::NotAffected);
    }

    #[test]
    fn npm_before_introduced_is_not_affected() {
        assert_eq!(matches(Ecosystem::Npm, "1.0.0", &b("2.0.0", Some("3.0.0"))), Match::NotAffected);
    }

    #[test]
    fn npm_open_ended_range_is_affected() {
        assert_eq!(matches(Ecosystem::Npm, "9.9.9", &b("0", None)), Match::Affected);
    }

    #[test]
    fn npm_last_affected_is_inclusive() {
        let bound = Bound { introduced: Some("0"), fixed: None, last_affected: Some("1.2.3") };
        assert_eq!(matches(Ecosystem::Npm, "1.2.3", &bound), Match::Affected);
        assert_eq!(matches(Ecosystem::Npm, "1.2.4", &bound), Match::NotAffected);
    }

    #[test]
    fn prerelease_orders_below_release() {
        assert_eq!(matches(Ecosystem::Npm, "4.17.21-beta.1", &b("0", Some("4.17.21"))), Match::Affected);
    }

    #[test]
    fn unparsable_version_is_unknown_not_safe() {
        assert_eq!(matches(Ecosystem::Npm, "not-a-version", &b("0", Some("1.0.0"))), Match::Unknown);
    }

    #[test]
    fn unsupported_ecosystem_is_unknown_not_safe() {
        assert_eq!(matches(Ecosystem::PyPI, "1.0.0", &b("0", Some("2.0.0"))), Match::Unknown);
    }

    #[test]
    fn whole_package_is_detected() {
        assert!(b("0", None).is_whole_package());
        assert!(!b("0", Some("1.0.0")).is_whole_package());
        assert!(!b("1.0.0", None).is_whole_package());
    }
}
