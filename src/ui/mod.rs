//! View layer. Each screen is rendered by a `pub fn <name>(state) -> Element<Message>`.
//!
//! Phase 2 CORE: these are placeholder views (`text("todo")`) so the crate compiles and the
//! `State`/`Message`/`Screen` contract is frozen. The real widgets get filled in the next stage.

pub mod editor;
pub mod plan;
pub mod profile_list;
pub mod server;
pub mod settings;
pub mod status;
