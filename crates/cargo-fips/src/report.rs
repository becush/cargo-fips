//! Human- and machine-readable reporting of check findings.

/// The standard closing disclaimer. The tool reports drift, never compliance
/// (spec §5, §15).
pub const NOT_A_DETERMINATION: &str = "this result reflects drift from your declared validated \
configuration. It is not a determination of FIPS compliance.";

/// Outcome of a single check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Pass,
    Fail,
    Warn,
    Info,
}

impl Status {
    fn glyph(self) -> &'static str {
        match self {
            Status::Pass => "\u{2713}", // ✓
            Status::Fail => "\u{2717}", // ✗
            Status::Warn => "!",
            Status::Info => "\u{00b7}", // ·
        }
    }

    fn label(self) -> &'static str {
        match self {
            Status::Pass => "PASS",
            Status::Fail => "FAIL",
            Status::Warn => "WARN",
            Status::Info => "INFO",
        }
    }
}

/// A single finding line.
#[derive(Debug, Clone)]
pub struct Finding {
    pub status: Status,
    pub message: String,
}

/// A collection of findings for one subcommand run.
#[derive(Debug, Default)]
pub struct Report {
    findings: Vec<Finding>,
}

impl Report {
    pub fn new() -> Self {
        Self::default()
    }

    fn push(&mut self, status: Status, message: impl Into<String>) {
        self.findings.push(Finding {
            status,
            message: message.into(),
        });
    }

    pub fn pass(&mut self, message: impl Into<String>) {
        self.push(Status::Pass, message);
    }

    pub fn fail(&mut self, message: impl Into<String>) {
        self.push(Status::Fail, message);
    }

    pub fn warn(&mut self, message: impl Into<String>) {
        self.push(Status::Warn, message);
    }

    pub fn info(&mut self, message: impl Into<String>) {
        self.push(Status::Info, message);
    }

    /// All recorded findings (used by tests; for forthcoming `attest`/JSON output).
    #[allow(dead_code)]
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    /// Number of hard failures (policy violations).
    pub fn violations(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.status == Status::Fail)
            .count()
    }

    /// Print findings. `quiet` switches to one tab-separated line per finding.
    pub fn print(&self, quiet: bool) {
        for f in &self.findings {
            if quiet {
                println!("{}\t{}", f.status.label(), f.message);
            } else {
                println!("  {} {}", f.status.glyph(), f.message);
            }
        }
    }
}
