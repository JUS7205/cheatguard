//! JSON scan-report shape and builder.
//!
//! [`ScanReport`] is the serializable output of `cheatguard scan <pid>`. It is
//! built by [`build`] from a process scan result, a ruleset, and the active
//! signals. Keeping the report a plain `serde` struct guarantees the CLI always
//! emits well-formed, parseable JSON.

use crate::rules::Ruleset;
use crate::scoring::{score_signals, verdict_for, Signal, Verdict};
use serde::{Deserialize, Serialize};

/// One triggered rule / signal against a specific module.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleMatch {
    pub module: String,
    pub module_path: String,
    /// Which signal fired for this module.
    pub signal: String,
    /// Human-readable reason for the match.
    pub reason: String,
}

/// The full JSON report emitted by the scanner.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanReport {
    pub pid: u32,
    pub engine: String,
    pub scanned_at: String,
    pub module_count: usize,
    pub matches: Vec<RuleMatch>,
    pub active_signals: Vec<String>,
    pub score: u32,
    pub verdict: String,
    pub error: Option<String>,
    /// On non-Windows or unsupported targets, true; signals are honesty markers.
    pub supported: bool,
}

/// Build a [`ScanReport`] from scan inputs.
///
/// * `matches` — the per-module rule matches (may be empty).
/// * `signals` — the deduplicated set of active signals driving the score.
/// * `module_count` — number of modules enumerated (0 when unsupported).
/// * `supported` — whether real module enumeration ran on this platform.
pub fn build(
    pid: u32,
    matches: Vec<RuleMatch>,
    signals: &[Signal],
    module_count: usize,
    ruleset: &Ruleset,
    supported: bool,
    error: Option<String>,
) -> ScanReport {
    let score = score_signals(signals, ruleset);
    let verdict: Verdict = verdict_for(score, &ruleset.thresholds);
    ScanReport {
        pid,
        engine: env!("CARGO_PKG_NAME").to_string(),
        scanned_at: now_rfc3339(),
        module_count,
        matches,
        active_signals: signals.iter().map(signal_name).collect(),
        score,
        verdict: verdict.as_str().to_string(),
        error,
        supported,
    }
}

/// Stable machine name for a signal (used in the report / CLI).
pub fn signal_name(s: &Signal) -> String {
    match s {
        Signal::UnsignedModule => "unsigned_module".to_string(),
        Signal::UnexpectedPath => "unexpected_path".to_string(),
        Signal::KnownCheatName => "known_cheat_name".to_string(),
        Signal::SuspiciousName => "suspicious_name".to_string(),
        Signal::CountAnomaly => "count_anomaly".to_string(),
    }
}

/// Best-effort UTC timestamp; never fails the scan if the clock misbehaves.
fn now_rfc3339() -> String {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => format!("{}", d.as_secs()),
        Err(_) => "unknown".to_string(),
    }
}

/// Convenience constructor used in tests to avoid depending on the clock format.
#[cfg(test)]
pub(crate) fn build_test(
    pid: u32,
    matches: Vec<RuleMatch>,
    signals: &[Signal],
    module_count: usize,
    ruleset: &Ruleset,
    supported: bool,
) -> ScanReport {
    let score = score_signals(signals, ruleset);
    let verdict: Verdict = verdict_for(score, &ruleset.thresholds);
    ScanReport {
        pid,
        engine: "cheatguard".to_string(),
        scanned_at: "test".to_string(),
        module_count,
        matches,
        active_signals: signals.iter().map(signal_name).collect(),
        score,
        verdict: verdict.as_str().to_string(),
        error: None,
        supported,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scoring::Signal;

    #[test]
    fn report_with_known_cheat_is_malicious() {
        let rs = Ruleset::default();
        let m = RuleMatch {
            module: "aimbot.dll".to_string(),
            module_path: "C:\\Temp\\aimbot.dll".to_string(),
            signal: "known_cheat_name".to_string(),
            reason: "known cheat name".to_string(),
        };
        let r = build_test(1234, vec![m], &[Signal::KnownCheatName], 5, &rs, true);
        assert_eq!(r.score, rs.weights.known_cheat_name);
        assert_eq!(r.verdict, "MALICIOUS");
        assert_eq!(r.module_count, 5);
        assert_eq!(r.active_signals, vec!["known_cheat_name"]);
    }

    #[test]
    fn report_with_no_signals_is_clean() {
        let rs = Ruleset::default();
        let r = build_test(99, vec![], &[], 3, &rs, true);
        assert_eq!(r.score, 0);
        assert_eq!(r.verdict, "CLEAN");
        assert!(r.matches.is_empty());
    }

    #[test]
    fn report_serializes_to_valid_json() {
        let rs = Ruleset::default();
        let r = build_test(1234, vec![], &[Signal::UnsignedModule], 2, &rs, true);
        let json = serde_json::to_string(&r).unwrap();
        // round-trips back to an equivalent report
        let back: ScanReport = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn unsupported_report_is_honest() {
        let rs = Ruleset::default();
        let r = build_test(1, vec![], &[], 0, &rs, false);
        assert!(!r.supported);
        assert_eq!(r.module_count, 0);
    }
}
