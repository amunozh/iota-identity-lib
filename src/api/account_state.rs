use serde::{Serialize, Deserialize};
use anyhow::Result;
use crate::api::utils::{encrypt, decrypt};
use std::fs::OpenOptions;
use std::io::{Write, Read};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AccountState{
    dids: Vec<(String, String)>,
    vcs: Vec<(String, String)>
}

impl AccountState{
    pub fn new(dids: Vec<(String, String)>, vcs: Vec<(String, String)>) -> Self{
        AccountState{ dids, vcs }
    }

    pub fn encrypt(&self, psw: &str) -> Result<Vec<u8>>{
        encrypt(self, psw)
    }

    pub fn decrypt(bytes: &[u8], psw: &str) -> Result<AccountState>{
        decrypt(bytes, psw)
    }

    pub fn write_to_file(&self, file_path: &str, psw: &str) -> Result<()>{
        let mut fr = OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .open(file_path)?;

        fr.write_all(&self.encrypt(psw)?)?;
        Ok(())
    }

    pub fn from_file(file_path: &str, psw: &str) -> Result<AccountState>{
        let mut fr = OpenOptions::new().read(true).open(file_path)?;
        let mut input = vec![];
        fr.read_to_end(&mut input)?;
        Ok(AccountState::decrypt(&input, psw)?)
    }


    pub fn dids(&self) -> &Vec<(String, String)> {
        &self.dids
    }
    pub fn vcs(&self) -> &Vec<(String, String)> {
        &self.vcs
    }
}
