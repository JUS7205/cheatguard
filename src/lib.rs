//! `cheatguard` — engine-agnostic anti-cheat *detection primitives*.
//!
//! This is a DEFENSIVE scanner, not a cheat or evasion tool. It provides:
//!
//! * [`rules`] — a serde-deserializable JSON ruleset so signatures are data, not code.
//! * [`scoring`] — a deterministic, weighted heuristic scorer (CLEAN/SUSPICIOUS/MALICIOUS).
//! * [`process`] — process-integrity scanning (Windows: real Win32 module enumeration +
//!   Authenticode verification; non-Windows: honest empty stub).
//! * [`report`] — the JSON scan report shape.
//!
//! The CLI (`src/main.rs`) exposes `cheatguard scan <pid>` which prints a JSON report.

pub mod process;
pub mod report;
pub mod rules;
pub mod scoring;

pub use process::{analyze_module, count_anomaly, enumerate_modules, ModuleInfo, ScanError, scan_process};
pub use report::{build, RuleMatch, ScanReport};
pub use rules::{Ruleset, Weights};
pub use scoring::{score_signals, verdict_for, Signal, Verdict};
