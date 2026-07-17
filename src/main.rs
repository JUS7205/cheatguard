//! `cheatguard` CLI — anti-cheat detection primitives.
//!
//! Usage:
//! ```text
//! cheatguard scan <pid> [--rules path/to/rules.json]
//! ```
//!
//! Prints a JSON [`ScanReport`](cheatguard::report::ScanReport) to stdout: the
//! matched rules, the aggregated 0..=100 risk score, and the verdict
//! (CLEAN / SUSPICIOUS / MALICIOUS).
//!
//! The bundled default ruleset is embedded below so the binary works with no
//! external files; `--rules` overrides it with your own JSON ruleset.

use std::process::ExitCode;

/// Bundled default ruleset (mirrors `rules/default.rules.json`).
const DEFAULT_RULESET_JSON: &str = include_str!("../rules/default.rules.json");

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        print_usage();
        return ExitCode::from(2);
    }

    match args[1].as_str() {
        "scan" => run_scan(&args[2..]),
        "--help" | "-h" | "help" => {
            print_usage();
            ExitCode::SUCCESS
        }
        "--version" | "-V" | "version" => {
            println!("cheatguard {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("error: unknown subcommand '{other}'");
            print_usage();
            ExitCode::from(2)
        }
    }
}

fn print_usage() {
    eprintln!(
        "cheatguard {} — engine-agnostic anti-cheat detection primitives (defensive scanner)\n\
         \n\
         USAGE:\n  \
         cheatguard scan <pid> [--rules <path>]\n\
         \n\
         ARGS:\n  \
         <pid>      Target process id to scan.\n  \
         --rules    Optional path to a JSON ruleset (defaults to the bundled ruleset).\n\
         \n\
         OUTPUT:\n  \
         A JSON report is printed to stdout: matches, score (0-100), verdict.\n",
        env!("CARGO_PKG_VERSION")
    );
}

fn run_scan(args: &[String]) -> ExitCode {
    let mut pid: Option<u32> = None;
    let mut rules_path: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--rules" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --rules requires a path");
                    return ExitCode::from(2);
                }
                rules_path = Some(args[i].clone());
            }
            other => {
                if other.starts_with('-') {
                    eprintln!("error: unknown flag '{other}'");
                    return ExitCode::from(2);
                }
                match other.parse::<u32>() {
                    Ok(p) => pid = Some(p),
                    Err(_) => {
                        eprintln!("error: invalid pid '{other}' (expected a positive integer)");
                        return ExitCode::from(2);
                    }
                }
            }
        }
        i += 1;
    }

    let pid = match pid {
        Some(p) => p,
        None => {
            eprintln!("error: missing <pid> argument");
            return ExitCode::from(2);
        }
    };

    let ruleset = match rules_path {
        Some(path) => match cheatguard::rules::Ruleset::load_path(std::path::Path::new(&path)) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("error: failed to load ruleset '{path}': {e}");
                return ExitCode::from(1);
            }
        },
        None => match cheatguard::rules::Ruleset::from_json(DEFAULT_RULESET_JSON) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("error: bundled ruleset failed to parse: {e}");
                return ExitCode::from(1);
            }
        },
    };

    let (matches, signals, module_count, supported, error) = cheatguard::process::scan_process(pid, &ruleset);
    let report = cheatguard::report::build(
        pid,
        matches,
        &signals,
        module_count,
        &ruleset,
        supported,
        error.clone(),
    );

    let json = serde_json::to_string_pretty(&report).unwrap_or_else(|e| {
        eprintln!("error: failed to serialize report: {e}");
        std::process::exit(1);
    });
    println!("{json}");

    // Exit non-zero when the scan reported a hard error, so callers/CI can detect it.
    match error {
        Some(_) => ExitCode::from(1),
        None => ExitCode::SUCCESS,
    }
}
