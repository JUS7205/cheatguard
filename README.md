# cheatguard

> Engine-agnostic anti-cheat **detection primitives** — a *defensive* process-integrity
> scanner and deterministic heuristic risk scorer. Part of the *runtime defense of
> autonomous systems* toolbox (the anti-cheat facet).

`cheatguard` is **not** a cheat or evasion tool. It is a blue-team scanner that
inspects a target process's loaded modules and scores how likely that process is
running cheating software, based on a **data-driven** ruleset (signatures are JSON,
not code).

```text
cheatguard scan <pid>  ->  JSON report { matches, score (0-100), verdict }
```

---

## Features

| Module | Purpose | Status |
| --- | --- | --- |
| `cheatguard::rules` | Serde-deserializable JSON ruleset (weights, thresholds, locations, name patterns, known-cheat list, baseline counts). | ✅ Real |
| `cheatguard::scoring` | Deterministic, weighted 0–100 scorer + `CLEAN`/`SUSPICIOUS`/`MALICIOUS` verdict. Pure functions, fully unit-tested. | ✅ Real |
| `cheatguard::process` | Process-integrity scan: enumerate a target process's loaded modules, match against the ruleset. | ⚠️ Windows real / non-Windows honest stub |
| `cheatguard::report` | JSON scan-report shape + builder (the CLI output schema). | ✅ Real |
| CLI `cheatguard scan <pid>` | Prints a JSON report to stdout. | ✅ Real |
| Authenticode signature verification (`is_signed`) | Raw signature bit. Currently reported as `None` (unknown) on all platforms — an honest integration seam, **not** a fake verifier. | ⛔ Not implemented (documented) |

### Platform support (honest)

| Platform | Module enumeration | `is_signed` |
| --- | --- | --- |
| Windows (x86_64 / Win32) | ✅ Real — `K32EnumProcessModules` (Psapi) + `GetModuleFileNameExW` | `None` (seam, not faked) |
| Linux / macOS / other | ⚠️ Returns empty, `supported: false` — **no fabricated data** | n/a |

On non-Windows the scanner reports `supported: false` and an empty module list so
callers/tests can distinguish "nothing found" from "platform unsupported".

---

## Install / build

```bash
cargo build --release      # binary at target/release/cheatguard.exe
cargo test                 # all unit + integration tests
```

Requires Rust 2021. Dependencies: `serde`, `serde_json`, and (Windows only)
`windows-sys` 0.52.

---

## Usage

```bash
# Scan a process by PID; prints a JSON report to stdout.
cheatguard scan 1234

# Override the bundled ruleset with your own JSON.
cheatguard scan 1234 --rules my_rules.json

# Show version / help
cheatguard --version
cheatguard --help
```

Example report (abridged):

```json
{
  "pid": 1234,
  "engine": "cheatguard",
  "module_count": 42,
  "matches": [
    {
      "module": "aimbot.dll",
      "module_path": "C:\\Temp\\aimbot.dll",
      "signal": "known_cheat_name",
      "reason": "basename matches known cheat: aimbot.dll"
    }
  ],
  "active_signals": ["known_cheat_name", "unexpected_path"],
  "score": 75,
  "verdict": "MALICIOUS",
  "supported": true,
  "error": null
}
```

### Verdict thresholds

Defaults (configurable per-ruleset via `thresholds`):

* `0 .. 25`  → `CLEAN`
* `25 .. 70` → `SUSPICIOUS`
* `70 .. 100` → `MALICIOUS`

Scores are clamped to `0..=100`. Each active signal contributes its weight;
duplicate signals are de-duplicated before summing.

---

## Ruleset format

`rules/default.rules.json` is the shipped default and is used by the test-suite
and as the CLI's built-in ruleset. You can supply your own:

```json
{
  "version": 1,
  "name": "cheatguard-default",
  "weights": {
    "unsigned_module": 30,
    "unexpected_path": 15,
    "known_cheat_name": 60,
    "suspicious_name": 25,
    "count_anomaly": 10
  },
  "thresholds": { "suspicious": 25, "malicious": 70 },
  "expected_locations": ["C:\\Windows\\", "C:\\Program Files\\"],
  "suspicious_name_patterns": ["cheat", "hack", "inject", "aimbot"],
  "known_cheat_names": ["aimbot.dll", "cheatengine.dll"],
  "baseline_module_count": null,
  "module_count_tolerance": 0
}
```

Signals in a ruleset:
* `known_cheat_name` — basename exactly matches a known cheat.
* `suspicious_name` — name contains a configured suspicious substring.
* `unexpected_path` — module loaded from a path outside `expected_locations`.
* `unsigned_module` — `is_signed == Some(false)` (currently only reachable if you
  wire up Authenticode verification into the `is_signed` field).
* `count_anomaly` — loaded module count deviates from `baseline_module_count`
  beyond `module_count_tolerance`.

---

## Library use

```rust
use cheatguard::{rules, process, report, scoring};

let rs = rules::Ruleset::from_json(include_str!("../rules/default.rules.json"))?;
let (matches, signals, count, supported, err) = process::scan_process(pid, &rs);
let rep = report::build(pid, matches, &signals, count, &rs, supported, err);
println!("{}", serde_json::to_string_pretty(&rep)?);
```

---

## Status / honesty

This crate ships **real, compiling, tested** detection logic. The only intentionally
non-functional seam is raw Authenticode signature verification (`is_signed` is always
`None`): implementing a correct `WinVerifyTrust` integration is left as a documented
integration point rather than shipped half-correct. Everything else — module
enumeration (Windows), rule matching, scoring, and report generation — is fully
implemented and exercised by `cargo test`.

## License

MIT OR Apache-2.0
