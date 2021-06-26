use iota_identity_lib::*;


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
        "channel_authorization":{
            "actor_id": "m123456",
            "channel_id": "123456789:1234"
        }
    }))?;

    issuer.sign_credential(&mut credential)?;

    let validator = Validator::new(true).await?;

    println!("Credential Validation > {:#?}", validator.validate_from_vc(&credential, &did_issuer).await?);

    Ok(())
}
