//! `dozor` — the watch that walks ahead of your registry.
//!
//! A compiler, not a service: it reads a feed snapshot, a registry inventory
//! and a policy, and writes a blocklist NORA already knows how to read.
#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use dozor_core::{canonical_body, policy::Policy, Builder, Derivation, Output};
use dozor_osv::{file_digest, index_zip, peak_rss_kb, Index};
use dozor_vers::Ecosystem;
use std::collections::BTreeMap;
use std::io::BufReader;
use std::path::PathBuf;
use std::process::ExitCode;

/// Exit codes are part of the contract: CI branches on them.
mod exit {
    pub const OK: u8 = 0;
    pub const FEED: u8 = 2;
    pub const EMPTY_INVENTORY: u8 = 3;
    pub const EXPIRED_EXCEPTION: u8 = 4;
    pub const POLICY: u8 = 5;
    pub const DRIFT: u8 = 6;
}

#[derive(Parser)]
#[command(name = "dozor", version, about = "Compile OSV + registry inventory into a NORA blocklist")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Derive a blocklist from (feed snapshot x inventory x policy)
    Build {
        /// OSV export zip for npm (as downloaded — never unpacked)
        #[arg(long)]
        feed_npm: PathBuf,
        /// Registry inventory, one JSON object per line
        #[arg(long)]
        inventory: Option<PathBuf>,
        /// Policy file (TOML)
        #[arg(long)]
        policy: PathBuf,
        /// Output blocklist path
        #[arg(short, long, default_value = "blocklist.json")]
        out: PathBuf,
        /// Also block every wholly-malicious package in the feed, cached or not
        #[arg(long)]
        proactive: bool,
        /// Pin "today" for reproducible builds (YYYY-MM-DD)
        #[arg(long)]
        today: Option<String>,
    },
    /// Re-derive the digest of an existing blocklist and compare
    Verify { blocklist: PathBuf },
    /// Explain what the feed says about one package version
    Explain {
        #[arg(long)]
        feed_npm: PathBuf,
        /// `name@version`
        package: String,
    },
    /// Index the feed and report size only — the memory budget, measured
    Stats {
        #[arg(long)]
        feed_npm: PathBuf,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("dozor: {e}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<u8, Box<dyn std::error::Error>> {
    match Cli::parse().cmd {
        Cmd::Build { feed_npm, inventory, policy, out, proactive, today } => {
            build(feed_npm, inventory, policy, out, proactive, today)
        }
        Cmd::Verify { blocklist } => verify(blocklist),
        Cmd::Explain { feed_npm, package } => explain(feed_npm, package),
        Cmd::Stats { feed_npm } => stats(feed_npm),
    }
}

fn load_index(feed: &PathBuf) -> Result<(Index, f64), Box<dyn std::error::Error>> {
    let t0 = std::time::Instant::now();
    let mut index = Index::default();
    index_zip(feed, Ecosystem::Npm, &mut index)?;
    index.finish();
    Ok((index, t0.elapsed().as_secs_f64()))
}

fn build(
    feed_npm: PathBuf,
    inventory: Option<PathBuf>,
    policy_path: PathBuf,
    out: PathBuf,
    proactive: bool,
    today: Option<String>,
) -> Result<u8, Box<dyn std::error::Error>> {
    let policy_text = std::fs::read_to_string(&policy_path)?;
    let pol = match Policy::load(&policy_text) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("dozor: {e}");
            return Ok(exit::POLICY);
        }
    };
    let today = today.unwrap_or_else(dozor_core::today_utc);
    if let Err(e) = pol.check_expiry(&today) {
        eprintln!("dozor: {e}");
        return Ok(exit::EXPIRED_EXCEPTION);
    }

    // D-ADR-8: a feed we could not read is a hard stop. The existing blocklist
    // is never rewritten with a thinner one — a silently emptied blocklist is
    // how a control disappears with nobody noticing.
    if !feed_npm.exists() {
        eprintln!("dozor: feed not found: {}", feed_npm.display());
        return Ok(exit::FEED);
    }

    let (index, t_index) = load_index(&feed_npm)?;

    let mut builder = Builder::default();
    if proactive {
        builder.add_proactive(&index, Ecosystem::Npm, &pol);
    }
    let inventory_digest = match &inventory {
        Some(path) => {
            let f = std::fs::File::open(path)?;
            builder.add_inventory(BufReader::with_capacity(1 << 16, f), &index, Ecosystem::Npm, &pol)?;
            if builder.stats.inventory_items == 0 && !proactive {
                eprintln!("dozor: inventory is empty — refusing to overwrite {}", out.display());
                return Ok(exit::EMPTY_INVENTORY);
            }
            file_digest(path)?
        }
        None => {
            if !proactive {
                eprintln!("dozor: need --inventory or --proactive");
                return Ok(exit::EMPTY_INVENTORY);
            }
            "none".to_string()
        }
    };

    let (rules, unmatched, stats) = builder.finish();
    let (_body, output_digest) = canonical_body(&rules);
    let mut snapshots = BTreeMap::new();
    snapshots.insert("npm".to_string(), file_digest(&feed_npm)?);

    let doc = Output {
        version: 1,
        rules,
        derivation: Derivation {
            dozor: env!("CARGO_PKG_VERSION").to_string(),
            matcher: format!("dozor-vers {}", env!("CARGO_PKG_VERSION")),
            policy: dozor_core::text_digest(&policy_text),
            inventory: inventory_digest,
            mode: if proactive { "proactive".into() } else { "inventory".into() },
            snapshots,
            output: output_digest,
        },
        unmatched,
    };

    let json = serde_json::to_string_pretty(&doc)?;
    std::fs::write(&out, format!("{json}\n"))?;

    eprintln!(
        "dozor: {} advisories / {} names / {} entries indexed in {:.1}s · index {:.1} MB · inventory {} · rules {}+{} · excepted {} · unknown {} · peak RSS {} MB",
        index.advisories,
        index.names(),
        index.entry_count(),
        t_index,
        index.footprint() as f64 / 1_048_576.0,
        stats.inventory_items,
        stats.whole_package_rules,
        stats.version_rules,
        stats.excepted,
        stats.unknown,
        peak_rss_kb().unwrap_or(0) / 1024,
    );
    Ok(exit::OK)
}

fn stats(feed_npm: PathBuf) -> Result<u8, Box<dyn std::error::Error>> {
    let (index, t) = load_index(&feed_npm)?;
    let whole = index
        .iter_named()
        .filter(|(_, e)| e.kind() == dozor_osv::Kind::Malicious && index.is_whole_package(e))
        .count();
    println!("advisories        : {}", index.advisories);
    println!("names             : {}", index.names());
    println!("entries           : {}", index.entry_count());
    println!("whole-package MAL : {whole}");
    println!("arena             : {:.1} MB", index.arena.bytes() as f64 / 1_048_576.0);
    println!("index footprint   : {:.1} MB", index.footprint() as f64 / 1_048_576.0);
    println!("peak RSS          : {} MB", peak_rss_kb().unwrap_or(0) / 1024);
    println!("index time        : {t:.1} s");
    Ok(exit::OK)
}

fn verify(path: PathBuf) -> Result<u8, Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(&path)?;
    let value: serde_json::Value = serde_json::from_str(&text)?;
    let stored = value
        .get("x-dozor-derivation")
        .and_then(|d| d.get("output"))
        .and_then(|o| o.as_str())
        .ok_or("no x-dozor-derivation.output in file")?;
    let recomputed = dozor_core::digest_of_parsed(&value).ok_or("malformed blocklist body")?;
    if stored == recomputed {
        println!("ok: {} matches its derivation ({stored})", path.display());
        Ok(exit::OK)
    } else {
        eprintln!("DRIFT: stored {stored}, recomputed {recomputed}");
        Ok(exit::DRIFT)
    }
}

fn explain(feed_npm: PathBuf, package: String) -> Result<u8, Box<dyn std::error::Error>> {
    let (name, version) = package.rsplit_once('@').ok_or("expected name@version")?;
    let (index, _) = load_index(&feed_npm)?;
    let entries = index.lookup(name);
    if entries.is_empty() {
        println!("{name}: no advisories in this snapshot");
        return Ok(exit::OK);
    }
    println!("{name}@{version} — {} advisories touch this package", entries.len());
    for e in entries {
        let verdict = if index.is_whole_package(e) {
            "WholePackage".to_string()
        } else {
            let m = index
                .bounds_of(e)
                .map(|b| dozor_vers::matches(Ecosystem::Npm, version, &b))
                .find(|m| *m == dozor_vers::Match::Affected)
                .unwrap_or(dozor_vers::Match::NotAffected);
            format!("{m:?}")
        };
        println!(
            "  {:<24} {:<9} {:<14} {:<13} fix={}",
            index.id_str(e),
            e.severity().as_str(),
            format!("{:?}", e.kind()),
            verdict,
            index.arena.opt(e.fixed_in).unwrap_or("-")
        );
    }
    Ok(exit::OK)
}
