//! Streaming reader for OSV.dev bulk exports.
//!
//! D-ADR-4: the feed is never materialised. Entries are decompressed one at a
//! time, projected down to the few percent that decides a verdict (name, ranges,
//! id, severity, kind) and dropped. Prose — `details`, `references`, `credits` —
//! is skipped by serde without ever being allocated.
//!
//! Everything retained lives in three flat vectors plus one string arena. The
//! first cut of this crate used idiomatic `HashMap<String, Vec<Entry>>` with
//! `Option<String>` bounds and peaked at 720 MB on the npm feed: the data is
//! small, but ~1.2M individual allocations are not. Layout is the feature.
#![forbid(unsafe_code)]

use dozor_vers::{Bound, Ecosystem};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;

/// A slice of the arena. 8 bytes, `Copy`, no allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Str {
    off: u32,
    len: u32,
}

impl Str {
    pub const EMPTY: Str = Str { off: 0, len: 0 };
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// One append-only string buffer for every name, id and version in the feed.
#[derive(Debug, Default)]
pub struct Arena {
    buf: String,
}

impl Arena {
    pub fn push(&mut self, s: &str) -> Str {
        if s.is_empty() {
            return Str::EMPTY;
        }
        let off = self.buf.len() as u32;
        self.buf.push_str(s);
        Str { off, len: s.len() as u32 }
    }

    pub fn get(&self, r: Str) -> &str {
        if r.is_empty() {
            return "";
        }
        &self.buf[r.off as usize..(r.off + r.len) as usize]
    }

    pub fn opt(&self, r: Str) -> Option<&str> {
        if r.is_empty() {
            None
        } else {
            Some(self.get(r))
        }
    }

    pub fn bytes(&self) -> usize {
        self.buf.len()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Malicious,
    Vulnerability,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum Severity {
    #[default]
    Unknown,
    Low,
    Moderate,
    High,
    Critical,
}

impl Severity {
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_uppercase().as_str() {
            "LOW" => Severity::Low,
            "MODERATE" | "MEDIUM" => Severity::Moderate,
            "HIGH" => Severity::High,
            "CRITICAL" => Severity::Critical,
            _ => Severity::Unknown,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Unknown => "UNKNOWN",
            Severity::Low => "LOW",
            Severity::Moderate => "MODERATE",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }

    fn from_u8(v: u8) -> Self {
        match v {
            1 => Severity::Low,
            2 => Severity::Moderate,
            3 => Severity::High,
            4 => Severity::Critical,
            _ => Severity::Unknown,
        }
    }

    fn to_u8(self) -> u8 {
        match self {
            Severity::Unknown => 0,
            Severity::Low => 1,
            Severity::Moderate => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }
}

/// A flattened OSV range. 24 bytes, arena-referencing.
#[derive(Debug, Clone, Copy, Default)]
pub struct BoundRef {
    pub introduced: Str,
    pub fixed: Str,
    pub last_affected: Str,
}

/// One advisory as it touches one package. 32 bytes.
#[derive(Debug, Clone, Copy)]
pub struct Entry {
    /// Index into [`Index::ids`].
    pub id: u32,
    /// Bit 7 = malicious, bits 0..3 = severity.
    packed: u8,
    /// `[bounds_start, bounds_start + bounds_len)` into [`Index::bounds`].
    bounds_start: u32,
    bounds_len: u32,
    /// `[versions_start, versions_start + versions_len)` into [`Index::versions`].
    versions_start: u32,
    versions_len: u32,
    /// First `fixed` bound, for the human-readable reason. Empty = none.
    pub fixed_in: Str,
}

impl Entry {
    pub fn kind(&self) -> Kind {
        if self.packed & 0x80 != 0 {
            Kind::Malicious
        } else {
            Kind::Vulnerability
        }
    }

    pub fn severity(&self) -> Severity {
        Severity::from_u8(self.packed & 0x0f)
    }
}

/// The compact index. Sorted names + CSR offsets: no per-name allocation.
#[derive(Debug, Default)]
pub struct Index {
    pub arena: Arena,
    pub ids: Vec<Str>,
    /// Unique package names, sorted. Binary search entry point.
    names: Vec<Str>,
    /// `entries[starts[i]..starts[i+1]]` belong to `names[i]`.
    starts: Vec<u32>,
    entries: Vec<Entry>,
    bounds: Vec<BoundRef>,
    versions: Vec<Str>,
    /// Staging area used while streaming, drained by [`Index::finish`].
    staging: Vec<(Str, Entry)>,
    pub advisories: usize,
    pub skipped: usize,
}

impl Index {
    pub fn names(&self) -> usize {
        self.names.len()
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Resident bytes of the retained structures — reported, not guessed.
    pub fn footprint(&self) -> usize {
        self.arena.bytes()
            + self.ids.len() * std::mem::size_of::<Str>()
            + self.names.len() * std::mem::size_of::<Str>()
            + self.starts.len() * 4
            + self.entries.len() * std::mem::size_of::<Entry>()
            + self.bounds.len() * std::mem::size_of::<BoundRef>()
            + self.versions.len() * std::mem::size_of::<Str>()
    }

    /// Sort the staging area and build the CSR layout. Call once, after all
    /// feeds are streamed in.
    pub fn finish(&mut self) {
        let mut staging = std::mem::take(&mut self.staging);
        staging.sort_by(|a, b| self.arena.get(a.0).cmp(self.arena.get(b.0)));

        self.names.reserve(staging.len() / 2);
        self.entries.reserve(staging.len());
        let mut last: Option<Str> = None;
        for (name, entry) in staging.drain(..) {
            let is_new = match last {
                Some(prev) => self.arena.get(prev) != self.arena.get(name),
                None => true,
            };
            if is_new {
                self.names.push(name);
                self.starts.push(self.entries.len() as u32);
                last = Some(name);
            }
            self.entries.push(entry);
        }
        self.starts.push(self.entries.len() as u32);
        self.names.shrink_to_fit();
        self.starts.shrink_to_fit();
        self.entries.shrink_to_fit();
    }

    /// Advisories touching `name`, or an empty slice.
    pub fn lookup(&self, name: &str) -> &[Entry] {
        match self.names.binary_search_by(|probe| self.arena.get(*probe).cmp(name)) {
            Ok(i) => &self.entries[self.starts[i] as usize..self.starts[i + 1] as usize],
            Err(_) => &[],
        }
    }

    /// Every (name, entry) pair, in sorted name order. Used by proactive mode.
    pub fn iter_named(&self) -> impl Iterator<Item = (&str, &Entry)> {
        self.names.iter().enumerate().flat_map(move |(i, name)| {
            let s = self.starts[i] as usize;
            let e = self.starts[i + 1] as usize;
            self.entries[s..e].iter().map(move |entry| (self.arena.get(*name), entry))
        })
    }

    pub fn bounds_of(&self, e: &Entry) -> impl Iterator<Item = Bound<'_>> {
        let s = e.bounds_start as usize;
        let n = e.bounds_len as usize;
        self.bounds[s..s + n].iter().map(move |b| Bound {
            introduced: self.arena.opt(b.introduced),
            fixed: self.arena.opt(b.fixed),
            last_affected: self.arena.opt(b.last_affected),
        })
    }

    pub fn versions_of(&self, e: &Entry) -> impl Iterator<Item = &str> {
        let s = e.versions_start as usize;
        let n = e.versions_len as usize;
        self.versions[s..s + n].iter().map(move |v| self.arena.get(*v))
    }

    /// True when every bound says "the whole package, forever".
    pub fn is_whole_package(&self, e: &Entry) -> bool {
        e.versions_len == 0
            && e.bounds_len > 0
            && self.bounds_of(e).all(|b| b.is_whole_package())
    }

    pub fn id_str(&self, e: &Entry) -> &str {
        self.arena.get(self.ids[e.id as usize])
    }
}

// --- wire structs: only the fields that decide a verdict ------------------

#[derive(serde::Deserialize)]
struct RawAdvisory {
    id: String,
    #[serde(default)]
    affected: Vec<RawAffected>,
    #[serde(default)]
    database_specific: Option<RawDbSpecific>,
}

#[derive(serde::Deserialize)]
struct RawDbSpecific {
    #[serde(default)]
    severity: Option<String>,
}

#[derive(serde::Deserialize)]
struct RawAffected {
    #[serde(default)]
    package: Option<RawPackage>,
    #[serde(default)]
    ranges: Vec<RawRange>,
    #[serde(default)]
    versions: Vec<String>,
}

#[derive(serde::Deserialize)]
struct RawPackage {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    ecosystem: Option<String>,
}

#[derive(serde::Deserialize)]
struct RawRange {
    #[serde(default)]
    events: Vec<RawEvent>,
}

#[derive(serde::Deserialize)]
struct RawEvent {
    #[serde(default)]
    introduced: Option<String>,
    #[serde(default)]
    fixed: Option<String>,
    #[serde(default)]
    last_affected: Option<String>,
}

/// Explicit affected-version lists above this length are dropped in favour of
/// the ranges. Counted in [`Index::skipped`], never silent.
const MAX_EXPLICIT_VERSIONS: usize = 64;

/// Stream one OSV export zip into `index`, keeping only `eco`.
/// Call [`Index::finish`] when all feeds are in.
pub fn index_zip(path: &Path, eco: Ecosystem, index: &mut Index) -> std::io::Result<()> {
    let file = std::fs::File::open(path)?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

    let mut buf = String::with_capacity(32 * 1024);
    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        if !entry.name().ends_with(".json") {
            continue;
        }
        buf.clear();
        entry.read_to_string(&mut buf)?;

        match serde_json::from_str::<RawAdvisory>(&buf) {
            Ok(raw) => fold(raw, eco, index),
            Err(_) => index.skipped += 1,
        }
    }
    Ok(())
}

fn fold(raw: RawAdvisory, want: Ecosystem, index: &mut Index) {
    let malicious = raw.id.starts_with("MAL-");
    let severity = raw
        .database_specific
        .as_ref()
        .and_then(|d| d.severity.as_deref())
        .map(Severity::parse)
        .unwrap_or(Severity::Unknown);
    let packed = (if malicious { 0x80 } else { 0 }) | severity.to_u8();

    let mut id_slot: Option<u32> = None;
    index.advisories += 1;

    for aff in raw.affected {
        let pkg = match aff.package {
            Some(p) => p,
            None => continue,
        };
        let name = match pkg.name {
            Some(n) => n,
            None => continue,
        };
        if Ecosystem::parse(pkg.ecosystem.as_deref().unwrap_or("")) != want {
            continue;
        }

        let bounds_start = index.bounds.len() as u32;
        let mut fixed_in = Str::EMPTY;
        for r in aff.ranges {
            let mut cur = BoundRef::default();
            let mut open = false;
            for ev in r.events {
                if let Some(i) = ev.introduced {
                    // A new `introduced` starts a new interval.
                    if open {
                        index.bounds.push(cur);
                        cur = BoundRef::default();
                    }
                    cur.introduced = index.arena.push(&i);
                    open = true;
                }
                if let Some(f) = ev.fixed {
                    let s = index.arena.push(&f);
                    if fixed_in.is_empty() {
                        fixed_in = s;
                    }
                    cur.fixed = s;
                }
                if let Some(l) = ev.last_affected {
                    cur.last_affected = index.arena.push(&l);
                }
            }
            if open || !cur.fixed.is_empty() || !cur.last_affected.is_empty() {
                index.bounds.push(cur);
            }
        }
        let bounds_len = index.bounds.len() as u32 - bounds_start;

        let versions_start = index.versions.len() as u32;
        if aff.versions.len() <= MAX_EXPLICIT_VERSIONS {
            for v in &aff.versions {
                let s = index.arena.push(v);
                index.versions.push(s);
            }
        } else {
            index.skipped += 1;
        }
        let versions_len = index.versions.len() as u32 - versions_start;

        if bounds_len == 0 && versions_len == 0 {
            continue;
        }

        let id = *id_slot.get_or_insert_with(|| {
            let s = index.arena.push(&raw.id);
            index.ids.push(s);
            (index.ids.len() - 1) as u32
        });

        let name_ref = index.arena.push(&name);
        index.staging.push((
            name_ref,
            Entry { id, packed, bounds_start, bounds_len, versions_start, versions_len, fixed_in },
        ));
    }
}

/// SHA-256 of a file, streamed. Pins feed snapshots in the derivation.
pub fn file_digest(path: &Path) -> std::io::Result<String> {
    let mut f = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

/// Peak resident set size of this process, from the kernel. Linux only;
/// `None` elsewhere. Makes the memory budget a testable number, not a claim.
pub fn peak_rss_kb() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status
        .lines()
        .find(|l| l.starts_with("VmHWM:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn index_of(json: &str, eco: Ecosystem) -> Index {
        let raw: RawAdvisory = serde_json::from_str(json).unwrap();
        let mut idx = Index::default();
        fold(raw, eco, &mut idx);
        idx.finish();
        idx
    }

    #[test]
    fn mal_prefix_is_malicious_and_whole_package() {
        let idx = index_of(
            r#"{"id":"MAL-2026-1","affected":[{"package":{"name":"evil","ecosystem":"npm"},
                "ranges":[{"events":[{"introduced":"0"}]}]}]}"#,
            Ecosystem::Npm,
        );
        let e = &idx.lookup("evil")[0];
        assert_eq!(e.kind(), Kind::Malicious);
        assert_eq!(e.severity(), Severity::Unknown);
        assert!(idx.is_whole_package(e));
    }

    #[test]
    fn prose_fields_are_ignored_not_rejected() {
        let idx = index_of(
            r#"{"id":"GHSA-x","details":"long prose","references":[{"url":"http://x"}],
                "credits":[{"name":"someone"}],"database_specific":{"severity":"HIGH"},
                "affected":[{"package":{"name":"lodash","ecosystem":"npm"},
                "ranges":[{"events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}"#,
            Ecosystem::Npm,
        );
        let e = &idx.lookup("lodash")[0];
        assert_eq!(e.severity(), Severity::High);
        assert_eq!(idx.arena.get(e.fixed_in), "4.17.21");
        assert_eq!(idx.bounds_of(e).count(), 1);
        assert!(!idx.is_whole_package(e));
    }

    #[test]
    fn other_ecosystem_is_dropped() {
        let idx = index_of(
            r#"{"id":"GHSA-y","affected":[{"package":{"name":"django","ecosystem":"PyPI"},
                "ranges":[{"events":[{"introduced":"0"}]}]}]}"#,
            Ecosystem::Npm,
        );
        assert_eq!(idx.names(), 0);
        assert!(idx.lookup("django").is_empty());
    }

    #[test]
    fn lookup_finds_the_right_bucket() {
        let mut idx = Index::default();
        for (id, name) in [("MAL-1", "aaa"), ("MAL-2", "zzz"), ("MAL-3", "mmm"), ("MAL-4", "aaa")] {
            let raw: RawAdvisory = serde_json::from_str(&format!(
                r#"{{"id":"{id}","affected":[{{"package":{{"name":"{name}","ecosystem":"npm"}},
                    "ranges":[{{"events":[{{"introduced":"0"}}]}}]}}]}}"#
            ))
            .unwrap();
            fold(raw, Ecosystem::Npm, &mut idx);
        }
        idx.finish();
        assert_eq!(idx.names(), 3);
        assert_eq!(idx.lookup("aaa").len(), 2);
        assert_eq!(idx.lookup("mmm").len(), 1);
        assert!(idx.lookup("nope").is_empty());
    }

    #[test]
    fn explicit_versions_survive() {
        let idx = index_of(
            r#"{"id":"MAL-2026-9","affected":[{"package":{"name":"pkg","ecosystem":"npm"},
                "versions":["1.0.0","1.0.1"]}]}"#,
            Ecosystem::Npm,
        );
        let e = &idx.lookup("pkg")[0];
        assert_eq!(idx.versions_of(e).collect::<Vec<_>>(), vec!["1.0.0", "1.0.1"]);
        assert!(!idx.is_whole_package(e));
    }
}
