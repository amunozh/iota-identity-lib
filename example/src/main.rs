use iota_identity_lib::Result;
use iota_identity_lib::api::{Storage, IdentityManager, Validator};
use iota_identity_lib::iota::{json, IotaDID};

async fn try_create(storage: Storage) -> Result<()>{
    let mut issuer = IdentityManager::default().await?;
    issuer.create_identity("Santer Reply").await?;
    issuer.create_identity("Santer Reply2").await?;
    let list: Vec<(String, String)> = issuer.identities().iter_mut().map(|x| (x.0.to_string(), x.1.id().as_str().to_string())).collect();
    println!("IDENTITY LIST:\n{:?}", list);
    let issuer_did = issuer.get_identity("santer reply").unwrap().id();
    println!("ISSUER: {}", issuer_did.as_str());

    let mut subject = IdentityManager::new(storage).await?;
    let subject_doc = subject.create_identity("Personale").await?;
    let subject_did = subject_doc.id();
    println!("SUBJECT: {}", subject_did.as_str());

    let credential = issuer.issue_credential_as("Santer Reply", subject_did, "ChannelWriterAuthorization", json!({
        "channel_authorization":{
            "actor_id": "m123456",
            "channel_id": "123456789:1234"
        }
    })).await?;

    subject.store_credential("cred", &credential);
    let credential = subject.get_credential("cred").unwrap();
    let validation = Validator::validate_credential(credential, issuer_did).await?;
    println!("{}", validation);

    Ok(())
}

async fn try_restore(storage: Storage, issuer_did: &str) -> Result<()>{
    let subject = IdentityManager::new(storage).await?;
    let list: Vec<(String, String)> = subject.identities().iter_mut().map(|x| (x.0.to_string(), x.1.id().as_str().to_string())).collect();
    println!("IDENTITY LIST:\n{:?}", list);

    let credential = subject.get_credential("cred").unwrap();
    let validation = Validator::validate_credential(credential, &IotaDID::parse(issuer_did)?).await?;
    println!("{}", validation);

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let dir = "./state";
    // let dir2 = "./states/subject";
    let psw = "psw";
    let storage = Storage::Stronghold(dir.to_string(), Some(psw.to_string()));
    // let storage2 = Storage::Stronghold(dir2.to_string(), Some(psw.to_string()));

    // try_create(storage).await?;
    try_restore(storage, "did:iota:HF7SxWGVFE5Umw3t1p1ErJ2DCgrwBoCe5x446tsbaZJL").await?;

    Ok(())
}
