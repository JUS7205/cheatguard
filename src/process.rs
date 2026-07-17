//! Process-integrity scanning.
//!
//! **What this is:** a *defensive* scanner. It enumerates a target process's
//! loaded modules (DLLs) and tests each one against the ruleset: known-cheat
//! names, suspicious-naming patterns, unexpected load locations, and (on
//! Windows) an unsigned-module flag.
//!
//! **Honesty guarantee:** on non-Windows targets this module does **not** fake
//! data. [`scan_process`] returns an empty, `supported: false` result so callers
//! and tests can distinguish "no modules found" from "platform unsupported".
//!
//! **Authenticode / signing:** `is_signed` is currently reported as `None`
//! (unknown) on every platform. Real Authenticode verification requires a
//! `WinVerifyTrust` + `WINTRUST_DATA` integration that is intentionally *not*
//! implemented here so we never ship a half-correct verifier. The scorer treats
//! `None` as "unknown" (no penalty). The scanning/analysis pipeline and scoring
//! logic are fully real and unit-tested; only the raw signature bit is left as a
//! documented integration seam.

use crate::report::RuleMatch;
use crate::rules::Ruleset;
use crate::scoring::Signal;
use std::path::PathBuf;

/// A single enumerated module with the facts the analyzer needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleInfo {
    /// Module basename, e.g. `aimbot.dll`.
    pub name: String,
    /// Full load path, e.g. `C:\Temp\aimbot.dll`. Empty if unknown.
    pub path: String,
    /// Authenticode signature status: `Some(true)` signed, `Some(false)` not,
    /// `None` = not determined on this platform/integration.
    pub is_signed: Option<bool>,
}

/// Error returned by [`scan_process`] when the OS-level enumeration fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanError {
    /// Could not open the target process (e.g. access denied / not found).
    OpenProcessFailed(u32),
    /// Module enumeration failed.
    EnumFailed(String),
    /// Win32 API returned an unexpected zero/error.
    ApiError(String),
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanError::OpenProcessFailed(code) => {
                write!(
                    f,
                    "OpenProcess failed (pid may not exist or access denied), code={code}"
                )
            }
            ScanError::EnumFailed(m) => write!(f, "module enumeration failed: {m}"),
            ScanError::ApiError(m) => write!(f, "win32 api error: {m}"),
        }
    }
}

impl std::error::Error for ScanError {}

/// Analyze one module against the ruleset, returning triggered signals + matches.
///
/// Pure function (no I/O) — fully unit-testable. It inspects:
/// * `is_signed == Some(false)` -> [`Signal::UnsignedModule`]
/// * `!ruleset.is_expected_location(path)` -> [`Signal::UnexpectedPath`]
/// * `ruleset.matches_known_cheat(name)` -> [`Signal::KnownCheatName`]
/// * `ruleset.matches_suspicious_pattern(name)` -> [`Signal::SuspiciousName`]
pub fn analyze_module(module: &ModuleInfo, ruleset: &Ruleset) -> (Vec<Signal>, Vec<RuleMatch>) {
    let mut signals = Vec::new();
    let mut matches = Vec::new();

    if module.is_signed == Some(false) {
        signals.push(Signal::UnsignedModule);
        matches.push(RuleMatch {
            module: module.name.clone(),
            module_path: module.path.clone(),
            signal: "unsigned_module".to_string(),
            reason: "module is not Authenticode-signed".to_string(),
        });
    }

    if !ruleset.is_expected_location(&module.path) {
        signals.push(Signal::UnexpectedPath);
        matches.push(RuleMatch {
            module: module.name.clone(),
            module_path: module.path.clone(),
            signal: "unexpected_path".to_string(),
            reason: format!("loaded from unexpected location: {}", module.path),
        });
    }

    if ruleset.matches_known_cheat(&module.name) {
        signals.push(Signal::KnownCheatName);
        matches.push(RuleMatch {
            module: module.name.clone(),
            module_path: module.path.clone(),
            signal: "known_cheat_name".to_string(),
            reason: format!("basename matches known cheat: {}", module.name),
        });
    } else if ruleset.matches_suspicious_pattern(&module.name) {
        signals.push(Signal::SuspiciousName);
        matches.push(RuleMatch {
            module: module.name.clone(),
            module_path: module.path.clone(),
            signal: "suspicious_name".to_string(),
            reason: format!("name matches suspicious pattern: {}", module.name),
        });
    }

    (signals, matches)
}

/// Compute the [`Signal::CountAnomaly`] trigger for a module count vs. baseline.
///
/// Returns `Some(Signal::CountAnomaly)` when the ruleset has a baseline and the
/// count deviates beyond tolerance; otherwise `None`.
pub fn count_anomaly(module_count: usize, ruleset: &Ruleset) -> Option<Signal> {
    if ruleset.count_deviation(module_count as u32) > 0 {
        Some(Signal::CountAnomaly)
    } else {
        None
    }
}

/// Enumerate the loaded modules of `pid`.
///
/// * **Windows**: uses `K32EnumProcessModules` (Psapi) to list `HMODULE`s and
///   `GetModuleFileNameExW` for each path, then derives the basename. Signature
///   status is left as `None` (see module docs).
/// * **non-Windows**: returns `Ok(vec![])` (an *honest empty* result — callers
///   must check [`scan_process`]'s `supported` flag).
pub fn enumerate_modules(pid: u32) -> Result<Vec<ModuleInfo>, ScanError> {
    #[cfg(windows)]
    {
        enumerate_modules_windows(pid)
    }
    #[cfg(not(windows))]
    {
        let _ = pid;
        Ok(Vec::new())
    }
}

#[cfg(windows)]
fn enumerate_modules_windows(pid: u32) -> Result<Vec<ModuleInfo>, ScanError> {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::ProcessStatus::{GetModuleFileNameExW, K32EnumProcessModules};
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    // In windows-sys 0.52, HANDLE/HMODULE are `isize` (a raw handle value), not a pointer.
    let handle: HANDLE =
        unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid) };
    if handle == INVALID_HANDLE_VALUE || handle == 0 {
        return Err(ScanError::OpenProcessFailed(pid));
    }

    // SAFETY: we own `handle` here and close it on every return path.
    let res = (|| {
        // First call: determine required buffer size. K32EnumProcessModules takes
        // `*mut HMODULE` (`*mut isize`); pass a 1-element scratch buffer to satisfy
        // the pointer arg while reading back `needed`.
        let mut needed: u32 = 0;
        let mut scratch_module: isize = 0;
        let ok = unsafe {
            K32EnumProcessModules(handle, &mut scratch_module as *mut isize, 0, &mut needed)
        };
        // When called with cb=0 the return indicates only "handle valid"; a zero
        // `needed` means the process exposes no modules we can snapshot.
        if needed == 0 {
            if ok == 0 {
                return Err(ScanError::EnumFailed("K32EnumProcessModules failed".into()));
            }
            return Ok(Vec::new());
        }
        let count = (needed as usize) / std::mem::size_of::<isize>();
        if count == 0 {
            return Ok(Vec::new());
        }
        let mut handles: Vec<isize> = vec![0; count];
        let mut needed2: u32 = 0;
        let ok = unsafe {
            K32EnumProcessModules(
                handle,
                handles.as_mut_ptr(),
                (handles.len() * std::mem::size_of::<isize>()) as u32,
                &mut needed2,
            )
        };
        if ok == 0 {
            return Err(ScanError::EnumFailed("K32EnumProcessModules failed".into()));
        }

        let mut modules = Vec::with_capacity(count);
        for &hmod in &handles {
            let mut buf = [0u16; 260];
            let len =
                unsafe { GetModuleFileNameExW(handle, hmod, buf.as_mut_ptr(), buf.len() as u32) };
            if len == 0 {
                continue;
            }
            let path = String::from_utf16_lossy(&buf[..len as usize]);
            let name = PathBuf::from(&path)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| path.clone());
            modules.push(ModuleInfo {
                name,
                path,
                is_signed: None,
            });
        }
        Ok(modules)
    })();

    unsafe {
        CloseHandle(handle);
    }
    res
}

/// Scan a process end-to-end and return the report inputs.
///
/// Returns `(matches, signals, module_count, supported, error)` so the caller
/// (CLI) can construct a [`crate::report::ScanReport`]. On a hard enumeration
/// error, `matches`/`signals` are empty, `supported` reflects the platform, and
/// `error` carries the message.
pub fn scan_process(
    pid: u32,
    ruleset: &Ruleset,
) -> (Vec<RuleMatch>, Vec<Signal>, usize, bool, Option<String>) {
    let supported = cfg!(windows);
    let modules = match enumerate_modules(pid) {
        Ok(m) => m,
        Err(e) => {
            return (Vec::new(), Vec::new(), 0, supported, Some(e.to_string()));
        }
    };

    let mut all_signals: Vec<Signal> = Vec::new();
    let mut all_matches: Vec<RuleMatch> = Vec::new();
    for m in &modules {
        let (sig, mut mt) = analyze_module(m, ruleset);
        all_signals.extend(sig);
        all_matches.append(&mut mt);
    }

    if let Some(count_sig) = count_anomaly(modules.len(), ruleset) {
        all_signals.push(count_sig);
        all_matches.push(RuleMatch {
            module: "<process>".to_string(),
            module_path: String::new(),
            signal: "count_anomaly".to_string(),
            reason: format!(
                "loaded module count {} deviates from baseline",
                modules.len()
            ),
        });
    }

    (all_matches, all_signals, modules.len(), supported, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rs() -> Ruleset {
        Ruleset::default()
    }

    #[test]
    fn analyze_known_cheat_from_temp_is_malicious_signals() {
        let m = ModuleInfo {
            name: "aimbot.dll".to_string(),
            path: "C:\\Temp\\aimbot.dll".to_string(),
            is_signed: None,
        };
        let (sig, mt) = analyze_module(&m, &rs());
        assert!(sig.contains(&Signal::KnownCheatName));
        assert!(sig.contains(&Signal::UnexpectedPath));
        assert!(!sig.contains(&Signal::SuspiciousName)); // exact known-cheat wins short-circuit
        assert_eq!(mt.len(), 2);
    }

    #[test]
    fn analyze_suspicious_name_not_known_cheat() {
        let m = ModuleInfo {
            name: "my_hack_tool.dll".to_string(),
            path: "C:\\Windows\\my_hack_tool.dll".to_string(),
            is_signed: None,
        };
        let (sig, mt) = analyze_module(&m, &rs());
        assert!(sig.contains(&Signal::SuspiciousName));
        assert!(!sig.contains(&Signal::KnownCheatName));
        assert!(!sig.contains(&Signal::UnexpectedPath)); // expected location
        assert_eq!(mt.len(), 1);
    }

    #[test]
    fn analyze_unsigned_module_signal() {
        let m = ModuleInfo {
            name: "legit.dll".to_string(),
            path: "C:\\Program Files\\game\\legit.dll".to_string(),
            is_signed: Some(false),
        };
        let (sig, _) = analyze_module(&m, &rs());
        assert!(sig.contains(&Signal::UnsignedModule));
        assert!(!sig.contains(&Signal::UnexpectedPath)); // expected location
    }

    #[test]
    fn analyze_signed_module_no_unsigned_signal() {
        let m = ModuleInfo {
            name: "legit.dll".to_string(),
            path: "C:\\Program Files\\game\\legit.dll".to_string(),
            is_signed: Some(true),
        };
        let (sig, mt) = analyze_module(&m, &rs());
        assert!(sig.is_empty());
        assert!(mt.is_empty());
    }

    #[test]
    fn analyze_clean_module_no_signals() {
        let m = ModuleInfo {
            name: "kernel32.dll".to_string(),
            path: "C:\\Windows\\System32\\kernel32.dll".to_string(),
            is_signed: None,
        };
        let (sig, mt) = analyze_module(&m, &rs());
        assert!(sig.is_empty());
        assert!(mt.is_empty());
    }

    #[test]
    fn count_anomaly_detects_deviation() {
        let mut r = rs();
        r.baseline_module_count = Some(100);
        r.module_count_tolerance = 5;
        assert_eq!(count_anomaly(80, &r), Some(Signal::CountAnomaly));
        assert_eq!(count_anomaly(120, &r), Some(Signal::CountAnomaly));
        assert_eq!(count_anomaly(102, &r), None); // within tolerance
    }

    #[test]
    fn count_anomaly_none_without_baseline() {
        assert_eq!(count_anomaly(9999, &rs()), None);
    }

    #[test]
    fn scan_process_is_honest_on_nonwindows() {
        // This test runs on whatever host cargo uses. On Windows it may succeed;
        // on non-Windows it must return supported=false and an empty scan.
        let (mt, sig, count, supported, err) = scan_process(0, &rs());
        if !supported {
            assert!(mt.is_empty());
            assert!(sig.is_empty());
            assert_eq!(count, 0);
        } else {
            // On Windows, pid 0 is invalid -> OpenProcessFailed reported.
            let _ = err;
        }
    }
}
