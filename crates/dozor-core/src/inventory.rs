//! Where the inventory comes from.
//!
//! Two sources, both files, no API required:
//!
//! * a NORA data directory — the layout is
//!   `<data>/storage/npm/<package>/tarballs/<base>-<version>.tgz` for proxied
//!   packages and `<data>/storage/npm/<package>/versions/<version>.json` for
//!   hosted ones. Scoped packages nest: `npm/@types/node/…`.
//! * an npm lockfile, for people who want to gate a project rather than a cache.
//!
//! Output is sorted and deduplicated, so the inventory file is itself
//! deterministic and diffs cleanly in git.

use crate::InvItem;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Walk `dir` recursively, calling `f` for every file.
fn walk(dir: &Path, f: &mut impl FnMut(&Path)) -> std::io::Result<()> {
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let rd = match std::fs::read_dir(&d) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        for entry in rd {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                stack.push(path);
            } else {
                f(&path);
            }
        }
    }
    Ok(())
}

/// Locate the npm storage root, accepting either a NORA data directory,
/// its `storage/` subdirectory, or the `storage/npm` directory itself.
fn npm_root(root: &Path) -> PathBuf {
    for candidate in [
        root.join("storage").join("npm"),
        root.join("npm"),
        root.to_path_buf(),
    ] {
        if candidate.is_dir() {
            return candidate;
        }
    }
    root.join("storage").join("npm")
}

/// Read a NORA data directory and report every npm package version it holds.
pub fn scan_nora_storage(root: &Path) -> std::io::Result<Vec<InvItem>> {
    let base = npm_root(root);
    let mut out = BTreeSet::new();

    walk(&base, &mut |path| {
        let rel = match path.strip_prefix(&base) {
            Ok(r) => r,
            Err(_) => return,
        };
        let parts: Vec<&str> = rel.iter().filter_map(|c| c.to_str()).collect();
        if parts.len() < 3 {
            return;
        }
        // `<package…>/tarballs/<base>-<version>.tgz`
        // `<package…>/versions/<version>.json`
        let kind = parts[parts.len() - 2];
        let file = parts[parts.len() - 1];
        let package = parts[..parts.len() - 2].join("/");
        if package.is_empty() {
            return;
        }
        let version = match kind {
            "versions" => file.strip_suffix(".json").map(str::to_string),
            // The tarball is named after the unscoped package basename.
            "tarballs" => file.strip_suffix(".tgz").and_then(|stem| {
                let basename = package.rsplit('/').next().unwrap_or(package.as_str());
                stem.strip_prefix(&format!("{basename}-"))
                    .map(str::to_string)
            }),
            _ => None,
        };
        if let Some(version) = version {
            if !version.is_empty() {
                out.insert((package, version));
            }
        }
    })?;

    Ok(out
        .into_iter()
        .map(|(name, version)| InvItem {
            registry: "npm".to_string(),
            name,
            version,
        })
        .collect())
}

/// Read an npm lockfile (v1 `dependencies` or v2/v3 `packages`).
pub fn from_npm_lockfile(text: &str) -> Result<Vec<InvItem>, serde_json::Error> {
    let root: serde_json::Value = serde_json::from_str(text)?;
    let mut out = BTreeSet::new();

    if let Some(packages) = root.get("packages").and_then(|p| p.as_object()) {
        for (path, spec) in packages {
            // "" is the project itself; everything else is "node_modules/<name>"
            // possibly nested: "node_modules/a/node_modules/b".
            let name = match path.rsplit_once("node_modules/") {
                Some((_, n)) if !n.is_empty() => n,
                _ => continue,
            };
            if let Some(v) = spec.get("version").and_then(|v| v.as_str()) {
                out.insert((name.to_string(), v.to_string()));
            }
        }
    }

    if let Some(deps) = root.get("dependencies").and_then(|d| d.as_object()) {
        collect_v1(deps, &mut out);
    }

    Ok(out
        .into_iter()
        .map(|(name, version)| InvItem {
            registry: "npm".to_string(),
            name,
            version,
        })
        .collect())
}

fn collect_v1(
    deps: &serde_json::Map<String, serde_json::Value>,
    out: &mut BTreeSet<(String, String)>,
) {
    for (name, spec) in deps {
        if let Some(v) = spec.get("version").and_then(|v| v.as_str()) {
            out.insert((name.clone(), v.to_string()));
        }
        if let Some(nested) = spec.get("dependencies").and_then(|d| d.as_object()) {
            collect_v1(nested, out);
        }
    }
}

/// Serialise as JSONL in a stable field order.
pub fn write_jsonl(items: &[InvItem], mut w: impl std::io::Write) -> std::io::Result<()> {
    for item in items {
        writeln!(
            w,
            r#"{{"registry":{},"name":{},"version":{}}}"#,
            serde_json::to_string(&item.registry).unwrap_or_default(),
            serde_json::to_string(&item.name).unwrap_or_default(),
            serde_json::to_string(&item.version).unwrap_or_default(),
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lockfile_v3_packages() {
        let items = from_npm_lockfile(
            r#"{"lockfileVersion":3,"packages":{
                "":{"name":"app","version":"1.0.0"},
                "node_modules/lodash":{"version":"4.17.20"},
                "node_modules/@types/node":{"version":"20.1.0"},
                "node_modules/a/node_modules/b":{"version":"0.1.0"}}}"#,
        )
        .unwrap();
        let got: Vec<(String, String)> = items
            .iter()
            .map(|i| (i.name.clone(), i.version.clone()))
            .collect();
        assert_eq!(
            got,
            vec![
                ("@types/node".to_string(), "20.1.0".to_string()),
                ("b".to_string(), "0.1.0".to_string()),
                ("lodash".to_string(), "4.17.20".to_string()),
            ]
        );
    }

    #[test]
    fn lockfile_v1_dependencies_nested() {
        let items = from_npm_lockfile(
            r#"{"lockfileVersion":1,"dependencies":{
                "lodash":{"version":"4.17.20","dependencies":{"tiny":{"version":"0.0.1"}}}}}"#,
        )
        .unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].name, "lodash");
        assert_eq!(items[1].name, "tiny");
    }

    #[test]
    fn storage_scan_reads_tarballs_and_scoped_packages() {
        let dir = std::env::temp_dir().join(format!("dozor-inv-{}", std::process::id()));
        let npm = dir.join("storage").join("npm");
        std::fs::create_dir_all(npm.join("lodash").join("tarballs")).unwrap();
        std::fs::create_dir_all(npm.join("@types").join("node").join("tarballs")).unwrap();
        std::fs::create_dir_all(npm.join("hosted-pkg").join("versions")).unwrap();
        std::fs::write(npm.join("lodash/tarballs/lodash-4.17.21.tgz"), b"x").unwrap();
        std::fs::write(npm.join("lodash/tarballs/lodash-4.17.21.tgz.sha256"), b"x").unwrap();
        std::fs::write(npm.join("lodash/metadata.json"), b"{}").unwrap();
        std::fs::write(npm.join("@types/node/tarballs/node-20.1.0.tgz"), b"x").unwrap();
        std::fs::write(npm.join("hosted-pkg/versions/1.2.3.json"), b"{}").unwrap();

        let mut items = scan_nora_storage(&dir).unwrap();
        items.sort_by(|a, b| a.name.cmp(&b.name));
        let got: Vec<(String, String)> = items
            .iter()
            .map(|i| (i.name.clone(), i.version.clone()))
            .collect();
        std::fs::remove_dir_all(&dir).ok();

        assert_eq!(
            got,
            vec![
                ("@types/node".to_string(), "20.1.0".to_string()),
                ("hosted-pkg".to_string(), "1.2.3".to_string()),
                ("lodash".to_string(), "4.17.21".to_string()),
            ],
            "sha256 sidecars and metadata.json must not become inventory entries"
        );
    }
}
