use identity::iota::{IotaDocument, Client, Network, CredentialValidator, CredentialValidation};
use identity::crypto::KeyPair;
use identity::credential::{Credential, Subject, CredentialBuilder};
use identity::core::{Value, FromJson, Url, ToJson};
use anyhow::{Result, Error};

pub struct IdentityManager{
    did_document: IotaDocument,
    key_pair: KeyPair,
    credentials: Vec<Credential>,
    client: Client
}

impl IdentityManager{
    pub async fn new(mainnet: bool) -> Result<IdentityManager>{
        let network = if mainnet {Network::Mainnet} else {Network::Testnet};
        let client = Client::builder().network(network).build().await?;
        let key_pair = KeyPair::new_ed25519()?;
        let mut did_document = IotaDocument::from_keypair(&key_pair)?;
        did_document.sign(key_pair.secret())?;
        let credentials = vec![];
        Ok(
            IdentityManager{did_document, key_pair, credentials, client}
        )
    }

    pub async fn publish_identity(&mut self) -> Result<()>{
        self.did_document.publish(&self.client).await?;
        Ok(())
    }

    pub fn new_credential(&mut self, issuer_did: &str, credential_type: &str, serde_json: Value) -> Result<Credential>{
        let mut map = match serde_json.as_object(){
            None => return Err(Error::msg("Invalid json format")),
            Some(map) => map.clone()
        };
        map.insert("id".to_string(), Value::String(self.did()));
        let subject = Subject::from_json_value(Value::Object(map))?;

        // Build credential using subject above and issuer.
        let credential: Credential = CredentialBuilder::default()
            .issuer(Url::parse(issuer_did)?)
            .type_(credential_type)
            .subject(subject)
            .build()?;

        self.credentials.push(credential.clone());
        Ok(credential)
    }

    pub fn sign_credential(&self, credential: &mut Credential) -> Result<()>{
        self.did_document.sign_data(credential, self.key_pair.secret())?;
        Ok(())
    }

    pub fn did(&self) -> String{
        self.did_document.id().as_str().to_string()
    }
}

pub struct Validator{
    client: Client,
}

impl Validator{
    pub async fn new(mainnet: bool) -> Result<Validator>{
        let network = if mainnet {Network::Mainnet} else {Network::Testnet};
        let client = Client::builder().network(network).build().await?;
        Ok(Validator{ client })
    }

    pub async fn validate_from_vc(&self, credential: &Credential, expected_did_issuer: &str) -> Result<bool>{
        let validator = CredentialValidator::new(&self.client);
        let json = credential.to_json()?;
        let validation: CredentialValidation = validator.check(&json).await?;
        let validate = validation.verified;

        Ok(validate && validation.issuer.did.as_str() == expected_did_issuer)
    }
}
