use identity::iota::{IotaDocument, Client, Network, CredentialValidator, CredentialValidation, IotaDID};
use identity::credential::{Credential, Subject, CredentialBuilder};
use identity::core::{Value, FromJson, Url, ToJson, Timestamp};
use anyhow::{Result, Error};
use identity::account::{Account, AccountStorage, AutoSave, IdentityCreate};
use std::collections::HashMap;
use regex::Regex;
use crate::api::account_state::AccountState;
use std::path::Path;
use chrono::Local;
use crate::api::identity_manager_builder::IdentityManagerBuilder;

#[derive(Debug, Clone)]
pub enum Storage{
    Memory,
    Stronghold(String, Option<String>),
}

pub struct IdentityManager{
    account: Account,
    documents: HashMap<String, IotaDocument>,
    credentials: HashMap<String, Credential>,
    dir_psw: Option<(String, Option<String>)>,
    network: String,
}

impl IdentityManager{
     pub async fn new(storage: Storage, mainnet: bool) -> Result<Self>{
        let (storage, dir_pass) = match storage{
            Storage::Stronghold(dir, password) => {
                let regex = Regex::new(".*\\.[a-zA-Z0-9]+").unwrap();
                if regex.is_match(&dir){
                    return Err(Error::msg("The path must refer to a folder and not to a file"));
                }
                let path = format!("{}/stronghold.hodl", dir);
                let stronghold = AccountStorage::Stronghold(path.into(), password.clone());
                (stronghold, Some((format!("{}/idvc.hodl", dir), password)))
            },
            _ => (AccountStorage::Memory, None)
        };

        let account = Account::builder()
            .storage(storage)
            .autosave(AutoSave::Every)
            .build().await?;
        let (documents, credentials) = IdentityManager::try_restore(&account, &dir_pass).await?;
        let network = if mainnet {"main".to_owned()} else {"test".to_owned()};
        Ok(IdentityManager{account, documents, credentials, dir_psw: dir_pass, network})
    }

    pub async fn default() -> Result<Self>{
        IdentityManager::new(Storage::Memory, false).await
    }

    pub fn builder() -> IdentityManagerBuilder{
        IdentityManagerBuilder::new()
    }

    async fn try_restore(account: &Account, dir_pass: &Option<(String, Option<String>)>) -> Result<(HashMap<String, IotaDocument>, HashMap<String, Credential>)>{
        let (dir, psw) = match dir_pass {
            None => return Ok((HashMap::default(), HashMap::default())),
            Some(res) => res
        };

        if !Path::new(dir).exists(){
            return Ok((HashMap::default(), HashMap::default()))
        }

        let psw = match psw {
            None => "psw",
            Some(psw) => psw,
        };

        let state = AccountState::from_file(dir, psw)?;
        let mut documents = HashMap::default();
        for (name, did_str) in state.dids() {
            let did = IotaDID::parse(did_str)?;
            println!("{} -> {}", name, did);
            let doc = account.resolve_identity(&did).await?;
            documents.insert(name.clone(), doc);
        }

        let vcs = state.vcs().iter().map(|x| (x.0.clone(), serde_json::from_str(&x.1).unwrap())).collect();
        Ok((documents, vcs))
    }

    pub async fn create_identity(&mut self, identity_name: &str) -> Result<IotaDocument>{
        let snap = self.account.create_identity(IdentityCreate::new().network(&self.network)).await?;
        let did = snap.identity().try_did()?;
        let document = self.account.resolve_identity(did).await?;
        self.documents.insert(identity_name.to_lowercase(), document.clone());
        Ok(document)
    }

    pub async fn issue_credential_as(&self, identity_name: &str, subject_did: &IotaDID, credential_type: &str, serde_json: Value) -> Result<Credential>{
        let issuer_did= match self.get_identity(identity_name){
            None => return Err(Error::msg("Unknown identity name")),
            Some(doc) => doc.id()
        };
        let mut map = match serde_json.as_object(){
            None => return Err(Error::msg("Invalid json format")),
            Some(map) => map.clone()
        };
        map.insert("id".to_string(), Value::String(subject_did.as_str().to_string()));
        let subject = Subject::from_json_value(Value::Object(map))?;

        let expiration = Timestamp::from_unix(Local::now().timestamp() + (3600*24*7));
        // Build credential using subject above and issuer.
        let mut credential: Credential = CredentialBuilder::default()
            .issuer(Url::parse(issuer_did.as_str())?)
            .type_(credential_type)
            .subject(subject)
            .expiration_date(expiration)
            .build()?;

        self.sign_credential(issuer_did, &mut credential).await?;
        Ok(credential)
    }

    async fn sign_credential(&self, issuer_did: &IotaDID, credential: &mut Credential) -> Result<()>{
        self.account.sign(issuer_did, "_sign-0", credential).await?;
        Ok(())
    }

    pub fn store_credential(&mut self, id: &str, credential: &Credential){
        self.credentials.insert(id.to_string().to_lowercase(), credential.clone());
    }

    pub fn identities(&self) -> Vec<(&String, &IotaDocument)>{
        self.documents.iter().map(|x| (x.0, x.1)).collect()
    }

    pub fn get_identity(&self, identity_name: &str) -> Option<&IotaDocument>{
        self.documents.get(&identity_name.to_lowercase())
    }

    pub fn get_credential(&self, id: &str) -> Option<&Credential>{
        self.credentials.get(&id.to_lowercase())
    }
}

impl Drop for IdentityManager{
    fn drop(&mut self) {
        let (dir, psw) = match &self.dir_psw {
            None => return,
            Some(res) => res
        };

        let psw = match psw {
            None => "psw",
            Some(psw) => psw,
        };

        let dids = self.documents.iter().map(|x| (x.0.clone(), x.1.id().as_str().to_string())).collect();
        let vcs = self.credentials.iter().map(|x| (x.0.clone(), x.1.to_json().unwrap())).collect();
        let state = AccountState::new(dids, vcs);
        match state.write_to_file(dir, psw){
            Ok(_) => {}
            Err(e) => eprintln!("{}",e)
        };
    }
}


pub struct Validator;
impl Validator{

    pub async fn validate_credential(credential: &Credential, expected_did_issuer: &IotaDID) -> Result<bool>{
        let client = Client::builder().network(Network::from_did(expected_did_issuer)).build().await?;
        let validator = CredentialValidator::new(&client);
        let json = credential.to_json()?;
        let validation: CredentialValidation = validator.check(&json).await?;
        let validate = validation.verified;

        Ok(validate && validation.issuer.did.as_str() == expected_did_issuer.as_str())
    }
}
