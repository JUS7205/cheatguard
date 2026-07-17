//! Deterministic, weighted heuristic risk scorer.
//!
//! [`score_signals`] combines a set of [`Signal`]s into a 0..=100 risk score using
//! a [`WeightedRuleset`] (weights + verdict thresholds). It is intentionally a
//! pure function — no I/O, no randomness — so its behaviour is fully unit-tested.
//!
//! Verdict tiers (see [`Verdict`]): `CLEAN` (0 .. suspicious), `SUSPICIOUS`
//! (`suspicious` .. `malicious`), `MALICIOUS` (`malicious` ..= 100).

use crate::rules::{Ruleset, Thresholds, Weights};
use serde::{Deserialize, Serialize};

/// A single boolean detection signal produced by the process-integrity scan.
///
/// All signals are mutually combinable; the scorer sums the weight of every
/// *active* signal and clamps the total to `0..=100`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Signal {
    /// A loaded module carries no (verified) Authenticode signature.
    UnsignedModule,
    /// A module was loaded from an unexpected location (e.g. `%TEMP%`/`%APPDATA%`).
    UnexpectedPath,
    /// A module basename exactly matches a known-cheat name.
    KnownCheatName,
    /// A module name matches a suspicious-naming pattern.
    SuspiciousName,
    /// The process loaded an anomalous number of modules vs. baseline.
    CountAnomaly,
}

impl Signal {
    /// The ruleset weight associated with this signal.
    pub fn weight(self, w: &Weights) -> u32 {
        match self {
            Signal::UnsignedModule => w.unsigned_module,
            Signal::UnexpectedPath => w.unexpected_path,
            Signal::KnownCheatName => w.known_cheat_name,
            Signal::SuspiciousName => w.suspicious_name,
            Signal::CountAnomaly => w.count_anomaly,
        }
    }
}

/// Verdict tier derived from the final score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Clean,
    Suspicious,
    Malicious,
}

impl Verdict {
    /// Stable, uppercase machine label (e.g. for JSON/`println!`).
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Clean => "CLEAN",
            Verdict::Suspicious => "SUSPICIOUS",
            Verdict::Malicious => "MALICIOUS",
        }
    }
}

/// Map a clamped score to a verdict using configured thresholds.
pub fn verdict_for(score: u32, t: &Thresholds) -> Verdict {
    if score >= t.malicious {
        Verdict::Malicious
    } else if score >= t.suspicious {
        Verdict::Suspicious
    } else {
        Verdict::Clean
    }
}

/// Sum the weights of all active signals and clamp to `0..=100`.
///
/// `signals` is a slice of active signals (a given signal present multiple times
/// is only scored once — duplicates are ignored via a `HashSet`).
pub fn score_signals(signals: &[Signal], ruleset: &Ruleset) -> u32 {
    use std::collections::HashSet;
    let mut seen = HashSet::new();
    let mut raw: u32 = 0;
    for s in signals {
        if seen.insert(*s) {
            raw = raw.saturating_add(s.weight(&ruleset.weights));
        }
    }
    raw.min(100)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ruleset() -> Ruleset {
        Ruleset::default()
    }

    #[test]
    fn empty_signals_score_zero_and_clean() {
        let s = score_signals(&[], &ruleset());
        assert_eq!(s, 0);
        assert_eq!(verdict_for(s, &ruleset().thresholds), Verdict::Clean);
    }

    #[test]
    fn unsigned_module_signal_weight() {
        let rs = ruleset();
        let s = score_signals(&[Signal::UnsignedModule], &rs);
        assert_eq!(s, rs.weights.unsigned_module);
        assert_eq!(verdict_for(s, &rs.thresholds), Verdict::Suspicious);
    }

    #[test]
    fn unexpected_path_signal_weight() {
        let rs = ruleset();
        let s = score_signals(&[Signal::UnexpectedPath], &rs);
        assert_eq!(s, rs.weights.unexpected_path);
        assert_eq!(verdict_for(s, &rs.thresholds), Verdict::Clean);
    }

    #[test]
    fn known_cheat_name_signal_weight() {
        let rs = ruleset();
        let s = score_signals(&[Signal::KnownCheatName], &rs);
        assert_eq!(s, rs.weights.known_cheat_name);
        assert_eq!(verdict_for(s, &rs.thresholds), Verdict::Malicious);
    }

    #[test]
    fn suspicious_name_signal_weight() {
        let rs = ruleset();
        let s = score_signals(&[Signal::SuspiciousName], &rs);
        assert_eq!(s, rs.weights.suspicious_name);
        assert_eq!(verdict_for(s, &rs.thresholds), Verdict::Suspicious);
    }

    #[test]
    fn count_anomaly_signal_weight() {
        let rs = ruleset();
        let s = score_signals(&[Signal::CountAnomaly], &rs);
        assert_eq!(s, rs.weights.count_anomaly);
        assert_eq!(verdict_for(s, &rs.thresholds), Verdict::Clean);
    }

    #[test]
    fn duplicate_signals_deduplicated() {
        let rs = ruleset();
        let s = score_signals(
            &[
                Signal::UnsignedModule,
                Signal::UnsignedModule,
                Signal::UnsignedModule,
            ],
            &rs,
        );
        assert_eq!(s, rs.weights.unsigned_module);
    }

    #[test]
    fn combined_score_sums_and_clamps_to_100() {
        let rs = ruleset();
        // All signals sum to 30+15+60+25+10 = 140 -> clamped to 100.
        let s = score_signals(
            &[
                Signal::UnsignedModule,
                Signal::UnexpectedPath,
                Signal::KnownCheatName,
                Signal::SuspiciousName,
                Signal::CountAnomaly,
            ],
            &rs,
        );
        assert_eq!(s, 100);
        assert_eq!(verdict_for(s, &rs.thresholds), Verdict::Malicious);
    }

    #[test]
    fn combined_score_partial_sum() {
        let rs = ruleset();
        // unsigned(30) + suspicious_name(25) = 55 -> SUSPICIOUS
        let s = score_signals(&[Signal::UnsignedModule, Signal::SuspiciousName], &rs);
        assert_eq!(s, 55);
        assert_eq!(verdict_for(s, &rs.thresholds), Verdict::Suspicious);
    }

    #[test]
    fn custom_thresholds_change_verdict_boundaries() {
        let mut rs = ruleset();
        rs.thresholds = Thresholds {
            suspicious: 10,
            malicious: 14,
        };
        let s = score_signals(&[Signal::UnexpectedPath], &rs); // 15
        assert_eq!(verdict_for(s, &rs.thresholds), Verdict::Malicious);
    }

    #[test]
    fn verdict_boundaries_inclusive() {
        let t = Thresholds {
            suspicious: 25,
            malicious: 70,
        };
        assert_eq!(verdict_for(0, &t), Verdict::Clean);
        assert_eq!(verdict_for(24, &t), Verdict::Clean);
        assert_eq!(verdict_for(25, &t), Verdict::Suspicious); // inclusive
        assert_eq!(verdict_for(69, &t), Verdict::Suspicious);
        assert_eq!(verdict_for(70, &t), Verdict::Malicious); // inclusive
        assert_eq!(verdict_for(100, &t), Verdict::Malicious);
    }
}
