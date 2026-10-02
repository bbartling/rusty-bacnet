//! Code shared by the one-shot commands, the shell and the TUI.
//!
//! Anything that more than one front end needs lives here, so the TUI does not
//! grow a third copy of a parser or a lookup that the CLI already has.

pub(crate) mod interfaces;
pub(crate) mod range;
