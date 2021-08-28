use iota_identity_lib::Result;
use iota_identity_lib::api::{Storage, IdentityManager, Validator};
use iota_identity_lib::iota::{json, IotaDID, Credential};

async fn create_and_test_issuer(storage: Storage, mainnet: bool) -> Result<()>{
    let mut issuer = IdentityManager::builder()
        .storage(storage)
        .main_net(mainnet)
        .build()
        .await?;
    issuer.create_identity("Santer Reply").await?;
    issuer.create_identity("Santer Reply2").await?;

    let list: Vec<(String, String)> = issuer.identities().iter_mut().map(|x| (x.0.to_string(), x.1.id().as_str().to_string())).collect();
    println!("IDENTITY LIST:\n{:?}", list);

    let issuer_did = issuer.get_identity("santer reply").unwrap().id();
    println!("ISSUER: {}", issuer_did.as_str());
    Ok(())
}

async fn create_and_test_subject(storage: Storage, mainnet: bool) -> Result<()>{
    let mut subject = IdentityManager::builder()
        .storage(storage)
        .main_net(mainnet)
        .build()
        .await?;
    let subject_doc = subject.create_identity("Personale").await?;
    let subject_did = subject_doc.id();
    println!("SUBJECT: {}", subject_did.as_str());
    Ok(())
}

async fn issue_and_sign_vs(issuer: &IdentityManager, subject_did: &IotaDID) -> Result<Credential>{
    let credential = issuer.issue_credential_as("Santer Reply", subject_did, "ChannelWriterAuthorization", json!({
        "channel_authorization":{
            "actor_id": "m123456",
            "channel_id": "123456789:1234"
        }
    })).await?;
    Ok(credential)
}

async fn validate_vc(credential: &Credential, expected_issuer_did: &IotaDID) -> Result<()>{
    let validation = Validator::validate_credential(credential, expected_issuer_did).await?;
    println!("\nVALIDATION: {}\n", validation);
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let mainnet = false;
    let dir = "./states/issuer";
    let dir2 = "./states/subject";
    let psw = "psw";
    let storage = Storage::Stronghold(dir.to_string(), Some(psw.to_string()));
    let storage2 = Storage::Stronghold(dir2.to_string(), Some(psw.to_string()));

    create_and_test_issuer(storage.clone(), mainnet).await?;
    create_and_test_subject(storage2.clone(), mainnet).await?;

    let issuer = IdentityManager::new(storage, mainnet).await?;
    let issuer_did = issuer.get_identity("santer reply").unwrap().id();
    let mut subject = IdentityManager::new(storage2, mainnet).await?;
    let subject_did = subject.get_identity("personale").unwrap().id();

    let cred = issue_and_sign_vs(&issuer, subject_did).await?;
    subject.store_credential("chauth", &cred);

    let cred = subject.get_credential("chauth").unwrap();
    validate_vc(cred, issuer_did).await?;

    assert_eq!(true, Validator::is_document_valid(&issuer_did.to_string(), mainnet).await?);
    assert_eq!(false, Validator::is_document_valid("did:iota:test:BG6DuW2ESTyvLR2CJA4GJAT53NfMJohZYjmfWRiGySeg", false).await?);

    Ok(())
}
