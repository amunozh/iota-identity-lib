use identity::iota::{Result, CredentialValidator, CredentialValidation, Client, Network};
use iota_identity_lib::identity_manager::IdentityManager;
use identity::core::ToJson;
use identity::core::json;

#[tokio::main]
async fn main() -> Result<()> {

    let mut issuer = IdentityManager::new(true).await?;
    issuer.publish_identity().await?;
    let mut subject = IdentityManager::new(true).await?;
    subject.publish_identity().await?;

    let did_issuer = issuer.did();
    let did_subject = subject.did();
    println!("{}\n{}", did_issuer, did_subject);

    let did_issuer = issuer.did();
    let mut credential = subject.new_credential(&did_issuer, "ChannelWriteAuthorization", json!({
        "id": &did_subject,
        "channel_authorization":{
            "actor_id": "m123456",
            "channel_id": "123456789:1234"
        }
    }))?;

    let client = Client::builder().network(Network::Mainnet).build().await?;
    issuer.sign_credential(&mut credential)?;

    // Convert the Verifiable Credential to JSON and "exchange" with a verifier
    let message: String = credential.to_json()?;

    // Create a `CredentialValidator` instance that will fetch
    // and validate all associated documents from the IOTA Tangle.
    let validator: CredentialValidator = CredentialValidator::new(&client);

    // Perform the validation operation.
    let validation: CredentialValidation = validator.check(&message).await?;

    println!("Credential Validation > {:#?}", validation.subjects);

    Ok(())
}
