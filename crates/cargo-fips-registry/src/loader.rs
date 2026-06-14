//! Loading registry records: built-in (compiled in), or from a directory.
//!
//! The `url` source from `fips.toml` (`[registry] source = "url"`) is not yet
//! implemented; see the spec, §8.3.

use std::path::{Path, PathBuf};

use crate::model::RegistryEntry;

/// Errors that can occur while loading the registry.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("registry I/O error at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse registry JSON at {path}: {source}")]
    Parse {
        path: String,
        #[source]
        source: serde_json::Error,
    },
}

/// Built-in registry records compiled into the binary (`source = "builtin"`).
///
/// Each entry is the raw JSON of a `registry/modules/*.json` file, embedded at
/// build time. Add new modules here as adapters land.
const BUILTIN_ENTRIES: &[(&str, &str)] = &[(
    "aws-lc-fips.json",
    include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../registry/modules/aws-lc-fips.json"
    )),
)];

/// An in-memory collection of registry records.
#[derive(Debug, Clone, Default)]
pub struct Registry {
    entries: Vec<RegistryEntry>,
}

impl Registry {
    /// Load the built-in registry distributed with the tool.
    pub fn builtin() -> Result<Self, RegistryError> {
        let mut entries = Vec::with_capacity(BUILTIN_ENTRIES.len());
        for (name, raw) in BUILTIN_ENTRIES {
            let entry: RegistryEntry =
                serde_json::from_str(raw).map_err(|source| RegistryError::Parse {
                    path: format!("<builtin>/{name}"),
                    source,
                })?;
            entries.push(entry);
        }
        Ok(Self { entries })
    }

    /// Load every `*.json` under `dir` (or its `modules/` subdirectory if present).
    pub fn from_path(dir: &Path) -> Result<Self, RegistryError> {
        let modules_dir: PathBuf = if dir.join("modules").is_dir() {
            dir.join("modules")
        } else {
            dir.to_path_buf()
        };

        let read_dir = std::fs::read_dir(&modules_dir).map_err(|source| RegistryError::Io {
            path: modules_dir.display().to_string(),
            source,
        })?;

        let mut entries = Vec::new();
        for item in read_dir {
            let item = item.map_err(|source| RegistryError::Io {
                path: modules_dir.display().to_string(),
                source,
            })?;
            let path = item.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let raw = std::fs::read_to_string(&path).map_err(|source| RegistryError::Io {
                path: path.display().to_string(),
                source,
            })?;
            let entry: RegistryEntry =
                serde_json::from_str(&raw).map_err(|source| RegistryError::Parse {
                    path: path.display().to_string(),
                    source,
                })?;
            entries.push(entry);
        }
        Ok(Self { entries })
    }

    /// All loaded records.
    pub fn entries(&self) -> &[RegistryEntry] {
        &self.entries
    }

    /// Look up a record by CMVP certificate number (e.g. `"4816"`).
    pub fn certificate(&self, cmvp_number: &str) -> Option<&RegistryEntry> {
        self.entries
            .iter()
            .find(|e| e.certificate.cmvp_number == cmvp_number)
    }

    /// Look up a record by registry module id (e.g. `"aws-lc-fips"`).
    pub fn module(&self, id: &str) -> Option<&RegistryEntry> {
        self.entries.iter().find(|e| e.module.id == id)
    }
}
