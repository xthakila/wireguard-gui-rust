//! Networking helpers: AllowedIPs presets, per-app network namespaces, kill switch, privilege.

pub mod allowed_ips;
pub mod boot;
pub mod killswitch;
pub mod nat;
pub mod netns;
pub mod privilege;
pub mod watchdog;
