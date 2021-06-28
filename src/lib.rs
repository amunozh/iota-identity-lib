mod identity_manager;
pub use identity_manager::{IdentityManager, Validator};
pub use identity::core::json;
pub use identity::iota::{IotaDID, IotaDocument};
pub use anyhow::{Result, Error};
