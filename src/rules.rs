//! Data-driven detection ruleset.
//!
//! Signatures are **data, not code**. A [`Ruleset`] is a serde-deserializable
//! JSON document describing:
//!
//! * [`Weights`] — how strongly each signal contributes to the risk score.
//! * [`Thresholds`] — score cut-offs for the SUSPICIOUS / MALICIOUS verdicts.
//! * `expected_locations` — module path prefixes that are considered normal
//!   (anything loaded elsewhere, e.g. `%TEMP%` / `%APPDATA%`, is "unexpected").
//! * `suspicious_name_patterns` — case-insensitive substrings matching known
//!   cheat-DLL naming conventions.
//! * `known_cheat_names` — case-insensitive exact module basenames of known cheats.
//! * `baseline_module_count` / `module_count_tolerance` — for the module-count
//!   anomaly signal.
//!
//! The crate ships a bundled default ruleset (`rules/default.rules.json`) which
//! is also used by the test-suite and by the CLI when no `--rules` path is given.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// How strongly each signal contributes to the 0..=100 risk score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Weights {
    pub unsigned_module: u32,
    pub unexpected_path: u32,
    pub known_cheat_name: u32,
    pub suspicious_name: u32,
    pub count_anomaly: u32,
}

impl Default for Weights {
    fn default() -> Self {
        Weights {
            unsigned_module: 30,
            unexpected_path: 15,
            known_cheat_name: 80,
            suspicious_name: 25,
            count_anomaly: 10,
        }
    }
}

/// Score cut-offs (inclusive lower bound) for each verdict tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Thresholds {
    pub suspicious: u32,
    pub malicious: u32,
}

impl Default for Thresholds {
    fn default() -> Self {
        Thresholds {
            suspicious: 25,
            malicious: 70,
        }
    }
}

/// A fully-described detection ruleset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ruleset {
    pub version: u32,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub weights: Weights,
    #[serde(default)]
    pub thresholds: Thresholds,
    /// Module path prefixes considered "expected"/trusted.
    #[serde(default)]
    pub expected_locations: Vec<String>,
    /// Case-insensitive substrings of suspicious module names.
    #[serde(default)]
    pub suspicious_name_patterns: Vec<String>,
    /// Case-insensitive exact module basenames of known cheats.
    #[serde(default)]
    pub known_cheat_names: Vec<String>,
    /// Expected number of loaded modules for a clean process (optional).
    #[serde(default)]
    pub baseline_module_count: Option<u32>,
    /// How many modules above/below baseline are tolerated before scoring.
    #[serde(default)]
    pub module_count_tolerance: u32,
}

impl Default for Ruleset {
    /// Built-in default ruleset (mirrors `rules/default.rules.json`).
    fn default() -> Self {
        Ruleset {
            version: 1,
            name: "cheatguard-default".to_string(),
            weights: Weights::default(),
            thresholds: Thresholds::default(),
            expected_locations: vec![
                "C:\\Windows\\".to_string(),
                "C:\\Program Files\\".to_string(),
                "C:\\Program Files (x86)\\".to_string(),
            ],
            suspicious_name_patterns: vec![
                "cheat".to_string(),
                "hack".to_string(),
                "inject".to_string(),
                "aimbot".to_string(),
                "wallhack".to_string(),
                "trainer".to_string(),
                "speeder".to_string(),
                "bypass".to_string(),
            ],
            known_cheat_names: vec![
                "cheatengine.dll".to_string(),
                "csgo-cheat.dll".to_string(),
                "xhack.dll".to_string(),
                "aimbot.dll".to_string(),
                "overwolf_hook.dll".to_string(),
            ],
            baseline_module_count: None,
            module_count_tolerance: 0,
        }
    }
}

impl Ruleset {
    /// Parse a ruleset from a JSON string.
    pub fn from_json(json: &str) -> Result<Ruleset, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Load and parse a ruleset from a file path.
    pub fn load_path(path: &Path) -> Result<Ruleset, std::io::Error> {
        let text = std::fs::read_to_string(path)?;
        Ruleset::from_json(&text)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    /// Does `name` match a known-cheat basename (case-insensitive exact match)?
    pub fn matches_known_cheat(&self, name: &str) -> bool {
        let lower = name.to_lowercase();
        self.known_cheat_names
            .iter()
            .any(|k| k.to_lowercase() == lower)
    }

    /// Does `name` contain any suspicious-naming substring (case-insensitive)?
    pub fn matches_suspicious_pattern(&self, name: &str) -> bool {
        let lower = name.to_lowercase();
        self.suspicious_name_patterns
            .iter()
            .any(|p| lower.contains(&p.to_lowercase()))
    }

    /// Is `path` loaded from an expected/trusted location?
    ///
    /// Returns `true` when `path` starts with any configured `expected_locations`
    /// prefix (case-insensitive). An empty `path` is treated as unexpected.
    pub fn is_expected_location(&self, path: &str) -> bool {
        if path.is_empty() {
            return false;
        }
        let lower = path.to_lowercase();
        self.expected_locations
            .iter()
            .any(|p| lower.starts_with(&p.to_lowercase()))
    }

    /// Signed-delta of a module count against the configured baseline.
    ///
    /// Returns the absolute deviation beyond `module_count_tolerance`, i.e. the
    /// number of "anomalous" modules. Returns `0` when no baseline is configured.
    pub fn count_deviation(&self, module_count: u32) -> u32 {
        match self.baseline_module_count {
            None => 0,
            Some(base) => {
                let diff = module_count.abs_diff(base);
                diff.saturating_sub(self.module_count_tolerance)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_ruleset_is_valid_json_roundtrip() {
        let rs = Ruleset::default();
        let json = serde_json::to_string(&rs).unwrap();
        let parsed = Ruleset::from_json(&json).unwrap();
        assert_eq!(rs, parsed);
    }

    #[test]
    fn known_cheat_match_is_case_insensitive_exact() {
        let rs = Ruleset::default();
        assert!(rs.matches_known_cheat("CheatEngine.dll"));
        assert!(rs.matches_known_cheat("CHEATENGINE.DLL"));
        assert!(!rs.matches_known_cheat("cheatengine_x64.dll"));
        assert!(!rs.matches_known_cheat("legit.dll"));
    }

    #[test]
    fn suspicious_pattern_is_substring_case_insensitive() {
        let rs = Ruleset::default();
        assert!(rs.matches_suspicious_pattern("my_aimbot.dll"));
        assert!(rs.matches_suspicious_pattern("SuperHack.exe"));
        assert!(!rs.matches_suspicious_pattern("kernel32.dll"));
    }

    #[test]
    fn expected_location_prefix_is_case_insensitive() {
        let rs = Ruleset::default();
        assert!(rs.is_expected_location("C:\\Windows\\System32\\ntdll.dll"));
        assert!(rs.is_expected_location("c:\\program files\\game\\game.exe"));
        assert!(!rs.is_expected_location("C:\\Users\\me\\AppData\\evil.dll"));
        assert!(!rs.is_expected_location("C:\\Temp\\loader.dll"));
        assert!(!rs.is_expected_location("")); // empty path is unexpected
    }

    #[test]
    fn count_deviation_respects_baseline_and_tolerance() {
        let rs = Ruleset {
            baseline_module_count: Some(100),
            module_count_tolerance: 10,
            ..Default::default()
        };
        assert_eq!(rs.count_deviation(100), 0); // on baseline
        assert_eq!(rs.count_deviation(105), 0); // within tolerance
        assert_eq!(rs.count_deviation(120), 10); // 20 over, tolerance 10
        assert_eq!(rs.count_deviation(80), 10); // 20 under, tolerance 10
    }

    #[test]
    fn count_deviation_is_zero_without_baseline() {
        let rs = Ruleset::default();
        assert_eq!(rs.count_deviation(999), 0);
    }

    #[test]
    fn bundled_sample_ruleset_file_parses() {
        // The shipped sample ruleset must both parse and be internally coherent.
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("rules/default.rules.json");
        let rs = Ruleset::load_path(&path).expect("bundled ruleset must parse");
        assert_eq!(rs.version, 1);
        assert!(rs.matches_known_cheat("aimbot.dll"));
        assert!(rs.matches_suspicious_pattern("superhack.dll"));
        assert!(rs.is_expected_location("C:\\Windows\\System32\\x.dll"));
        assert!(!rs.is_expected_location("C:\\Users\\x\\AppData\\evil.dll"));
    }

    #[test]
    fn from_json_parses_sample_ruleset() {
        let json = r#"{
            "version": 1,
            "name": "demo",
            "weights": { "unsigned_module": 30, "unexpected_path": 15, "known_cheat_name": 60, "suspicious_name": 25, "count_anomaly": 10 },
            "thresholds": { "suspicious": 25, "malicious": 70 },
            "expected_locations": ["C:\\Windows\\"],
            "suspicious_name_patterns": ["cheat", "hack"],
            "known_cheat_names": ["aimbot.dll"],
            "baseline_module_count": 120,
            "module_count_tolerance": 20
        }"#;
        let rs = Ruleset::from_json(json).unwrap();
        assert_eq!(rs.version, 1);
        assert!(rs.matches_known_cheat("aimbot.dll"));
        assert_eq!(rs.count_deviation(150), 10);
    }
}
