//! Per-application network namespaces — route a specific executable through the tunnel.
//!
//! Phase 3 feature. Stub only for now.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::AppResult;

/// Bind a single executable to a named network namespace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetnsRule {
    pub executable_path: PathBuf,
    pub ns_name: String,
}

/// Sets up / tears down namespaces and the rules within them.
pub struct NetnsManager;

impl NetnsManager {
    /// Create the namespace and wire it to the tunnel.
    pub async fn setup(&self, ns_name: &str) -> AppResult<()> {
        let _ = ns_name;
        todo!()
    }

    /// Remove the namespace and all its plumbing.
    pub async fn teardown(&self, ns_name: &str) -> AppResult<()> {
        let _ = ns_name;
        todo!()
    }

    /// Add a per-app rule into a namespace.
    pub async fn add_rule(&self, rule: &NetnsRule) -> AppResult<()> {
        let _ = rule;
        todo!()
    }

    /// Remove a per-app rule from a namespace.
    pub async fn remove_rule(&self, rule: &NetnsRule) -> AppResult<()> {
        let _ = rule;
        todo!()
    }
}
