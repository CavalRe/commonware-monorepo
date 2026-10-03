//! Pure synchronization and ordering mechanisms.

pub(super) mod ancestry;
pub(super) mod floor;
pub(super) use crate::multimmit::ordering::order;
pub(super) mod paths;
