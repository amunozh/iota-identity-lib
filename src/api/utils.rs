use serde::{Serialize};
use aead::generic_array::GenericArray;
use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::XChaCha20Poly1305;
use anyhow::Result;
use crypto::hashes::{
    Digest,
    blake2b::Blake2b256
};
use serde::de::DeserializeOwned;
use base64::{decode_config, URL_SAFE_NO_PAD, encode_config};
use std::fmt::Debug;

pub fn encrypt<T>(data: &T, psw: &str) -> Result<Vec<u8>>
where T: Debug + Serialize
{
    let bytes = bincode::serialize(data)?;

    let (key, nonce) = get_key_nonce(psw);
    let key = GenericArray::from_slice(&key[..]);
    let nonce = GenericArray::from_slice(&nonce[..]);

    let chacha = XChaCha20Poly1305::new(key);
    let enc = match chacha.encrypt(nonce, bytes.as_ref()){
        Ok(res) => res,
        Err(_) => return Err(anyhow::Error::msg("Error during state encryption")),
    };
    let base64 = encode_config(&enc, URL_SAFE_NO_PAD);
    Ok(base64.as_bytes().to_vec())
}

pub fn decrypt<T>(data: &[u8], psw: &str) -> Result<T>
where T: Debug + DeserializeOwned
{
    let bytes = decode_config(data, URL_SAFE_NO_PAD)?;

    let (key, nonce) = get_key_nonce(psw);
    let key = GenericArray::from_slice(&key[..]);
    let nonce = GenericArray::from_slice(&nonce[..]);

    let chacha = XChaCha20Poly1305::new(key);
    let dec = match chacha.decrypt(nonce, bytes.as_ref()){
        Ok(res) => res,
        Err(_) => return Err(anyhow::Error::msg("Error during state decryption")),
    };

    let dec = bincode::deserialize(&dec)?;
    Ok(dec)
}

fn get_key_nonce(psw: &str) -> (Vec<u8>, Vec<u8>) {
    let key_hash = &hash_string(psw)[..32];
    let nonce_hash = &hash_string(key_hash)[..24];
    let key = key_hash.as_bytes();
    let nonce = nonce_hash.as_bytes();
    (key.to_vec(), nonce.to_vec())
}

fn hash_string(string: &str) -> String{
    let hash = Blake2b256::digest(&string.as_bytes());
    hex::encode(&hash)
}
