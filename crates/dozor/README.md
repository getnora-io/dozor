# dozor

The watch that walks ahead of your registry.

Dozor compiles the [OSV](https://osv.dev) advisory feed together with an
inventory of what your artifact registry actually holds into a blocklist that
[NORA](https://github.com/getnora-io/nora) enforces at the door.

It is a compiler, not a service: three files in, one file out, deterministic.
It never sits on the download path, so it cannot fail a build.

```bash
dozor inventory --nora-data /var/lib/nora -o inventory.jsonl
dozor build --feed-npm snapshots/npm.zip --inventory inventory.jsonl \
            --policy policy.toml --proactive -o blocklist.json
dozor verify blocklist.json
```

The npm OSV feed is 228,684 advisories, of which **96.8% are malicious-package
reports** carrying no severity at all — typosquats, hijacked maintainers,
poisoned releases. A CI scanner sees those only after the registry has already
cached and served them. The registry is the one place where refusing them is
prevention.

Full documentation, architecture decisions and measured numbers:
**https://github.com/getnora-io/dozor**

npm only in 0.1. Every other ecosystem answers `Unknown`, and `Unknown` never
becomes "safe" — those versions are reported, not assumed.

MIT. OSV data is published by osv.dev under CC-BY-4.0.
