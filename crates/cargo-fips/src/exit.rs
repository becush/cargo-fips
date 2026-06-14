//! Exit-code convention (spec §10.6).
//!
//! | Code | Meaning |
//! |------|---------|
//! | 0 | Pass — no policy violation detected |
//! | 1 | Policy violation — drift from declared state |
//! | 2 | Configuration or usage error (e.g. missing `fips.toml`) |
//! | 3 | Registry data unavailable for the requested certificate |

/// A process exit status with the meaning fixed by the spec.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    Pass = 0,
    PolicyViolation = 1,
    Usage = 2,
    RegistryUnavailable = 3,
}

impl Exit {
    /// The numeric exit code.
    pub fn code(self) -> u8 {
        self as u8
    }
}
