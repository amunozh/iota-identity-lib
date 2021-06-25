use identity::iota::{IotaDocument, Client, Network, Result};
use identity::crypto::KeyPair;
use identity::credential::{Credential, Subject, CredentialBuilder};
use identity::core::{Value, FromJson, Url};

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
        let subject = Subject::from_json_value(serde_json)?;

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
