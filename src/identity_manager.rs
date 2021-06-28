use identity::iota::{IotaDocument, Client, Network, CredentialValidator, CredentialValidation, IotaDID};
use identity::credential::{Credential, Subject, CredentialBuilder};
use identity::core::{Value, FromJson, Url, ToJson};
use anyhow::{Result, Error};
use identity::account::{Account, AccountStorage, AutoSave, IdentityCreate};
use std::collections::HashMap;

pub struct IdentityManager{
    account: Account,
    documents: HashMap<String, IotaDocument>,
    credentials: HashMap<String, Credential>,
}

impl IdentityManager{
    pub async fn new(storage: AccountStorage) -> Result<Self>{
        let account = Account::builder()
            .storage(storage)
            .autosave(AutoSave::Every)
            .build().await?;
        let documents = HashMap::default();
        let credentials = HashMap::default();
        Ok(
            IdentityManager{account, documents, credentials}
        )
    }

    pub async fn default() -> Result<Self>{
        IdentityManager::new(AccountStorage::Memory).await
    }

    pub async fn create_identity(&mut self, identity_name: &str) -> Result<IotaDocument>{
        let snap = self.account.create_identity(IdentityCreate::default()).await?;
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

        // Build credential using subject above and issuer.
        let mut credential: Credential = CredentialBuilder::default()
            .issuer(Url::parse(issuer_did.as_str())?)
            .type_(credential_type)
            .subject(subject)
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
