use crate::api::{Storage, IdentityManager};
use anyhow::Result;

pub struct IdentityManagerBuilder{
    storage: Storage,
    mainnet: bool,
}

impl IdentityManagerBuilder{
    pub (crate) fn new() -> Self{
        IdentityManagerBuilder{storage: Storage::Memory, mainnet: false}
    }

    pub fn storage(mut self, storage: Storage) -> Self{
        self.storage = storage;
        self
    }

    pub fn main_net(mut self, mainnet: bool) -> Self{
        self.mainnet = mainnet;
        self
    }

    pub async fn build(self) -> Result<IdentityManager>{
        IdentityManager::new(self.storage, self.mainnet).await
    }
}
