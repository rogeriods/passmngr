use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Result};
use argon2::Argon2;
use rand::RngCore;

pub const SALT_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;

pub fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!("Key derivation failed: {}", e))?;
    Ok(key)
}

pub fn encrypt(plaintext: &[u8], key: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>)> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| anyhow!("Invalid key length: {}", e))?;
    let mut nonce = vec![0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let nonce_slice = Nonce::from_slice(&nonce);
    let ciphertext = cipher
        .encrypt(nonce_slice, plaintext)
        .map_err(|e| anyhow!("Encryption failed: {}", e))?;
    Ok((ciphertext, nonce))
}

pub fn decrypt(ciphertext: &[u8], key: &[u8; 32], nonce: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| anyhow!("Invalid key length: {}", e))?;
    let nonce_slice = Nonce::from_slice(nonce);
    let plaintext = cipher
        .decrypt(nonce_slice, ciphertext)
        .map_err(|e| anyhow!("Decryption failed: {}", e))?;
    Ok(plaintext)
}
