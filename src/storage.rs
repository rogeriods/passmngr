use std::io::Write;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Serialize};

use rand::RngCore;

use crate::crypto;
use crate::models::{Entry, Vault};

const VAULT_FILE: &str = "vault.json";

#[derive(Debug, Serialize, Deserialize)]
struct EncryptedVault {
    salt: String,
    nonce: String,
    ciphertext: String,
}

fn vault_path() -> PathBuf {
    PathBuf::from(VAULT_FILE)
}

fn read_master_password() -> Result<String> {
    let password = rpassword::prompt_password("Master password: ")?;
    Ok(password)
}

fn read_master_password_confirm() -> Result<String> {
    let password = rpassword::prompt_password("Master password: ")?;
    let confirm = rpassword::prompt_password("Confirm master password: ")?;
    if password != confirm {
        return Err(anyhow!("Passwords do not match"));
    }
    Ok(password)
}

pub fn init_vault() -> Result<()> {
    let path = vault_path();
    if path.exists() {
        return Err(anyhow!(
            "Vault already exists at {}",
            path.display()
        ));
    }

    let password = read_master_password_confirm()?;

    let mut salt = vec![0u8; crypto::SALT_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);

    let key = crypto::derive_key(&password, &salt)?;

    let vault = Vault::new();
    let plaintext = serde_json::to_vec(&vault)?;

    let (ciphertext, nonce) = crypto::encrypt(&plaintext, &key)?;

    let encrypted = EncryptedVault {
        salt: BASE64.encode(&salt),
        nonce: BASE64.encode(&nonce),
        ciphertext: BASE64.encode(&ciphertext),
    };

    let json = serde_json::to_string_pretty(&encrypted)?;
    std::fs::write(&path, json)?;

    println!("Vault initialized at {}", path.display());
    Ok(())
}

fn unlock_vault(password: &str) -> Result<Vault> {
    let path = vault_path();
    let json = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read vault at {}", path.display()))?;
    let encrypted: EncryptedVault = serde_json::from_str(&json)?;

    let salt = BASE64.decode(&encrypted.salt)?;
    let nonce = BASE64.decode(&encrypted.nonce)?;
    let ciphertext = BASE64.decode(&encrypted.ciphertext)?;

    let key = crypto::derive_key(password, &salt)?;
    let plaintext = crypto::decrypt(&ciphertext, &key, &nonce)?;

    let vault: Vault = serde_json::from_slice(&plaintext)?;
    Ok(vault)
}

fn save_vault(vault: &Vault, password: &str) -> Result<()> {
    let path = vault_path();
    let json = std::fs::read_to_string(&path)?;
    let encrypted: EncryptedVault = serde_json::from_str(&json)?;

    let salt = BASE64.decode(&encrypted.salt)?;
    let key = crypto::derive_key(password, &salt)?;

    let plaintext = serde_json::to_vec(vault)?;
    let (ciphertext, nonce) = crypto::encrypt(&plaintext, &key)?;

    let new_encrypted = EncryptedVault {
        salt: BASE64.encode(&salt),
        nonce: BASE64.encode(&nonce),
        ciphertext: BASE64.encode(&ciphertext),
    };

    let out = serde_json::to_string_pretty(&new_encrypted)?;
    std::fs::write(&path, out)?;
    Ok(())
}

fn prompt_field(prompt: &str, default: Option<&str>) -> Result<String> {
    let default = default.unwrap_or("");
    print!("{}", prompt);
    if !default.is_empty() {
        print!(" [{}]", default);
    }
    print!(": ");
    std::io::stdout().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let trimmed = input.trim().to_string();
    if trimmed.is_empty() && !default.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(trimmed)
    }
}

fn prompt_entry(name: &str, existing: Option<&Entry>) -> Result<Entry> {
    println!("--- Editing entry: {} ---", name);

    let username = prompt_field("Username", existing.and_then(|e| e.username.as_deref()))?;

    let password = if let Some(existing) = existing {
        let pwd = rpassword::prompt_password("Password (leave blank to keep existing): ")?;
        if pwd.is_empty() {
            existing.password.clone()
        } else {
            pwd
        }
    } else {
        let pwd = rpassword::prompt_password("Password: ")?;
        if pwd.is_empty() {
            return Err(anyhow!("Password cannot be empty"));
        }
        pwd
    };

    let url = prompt_field("URL", existing.and_then(|e| e.url.as_deref()))?;
    let notes = prompt_field("Notes", existing.and_then(|e| e.notes.as_deref()))?;

    Ok(Entry {
        name: name.to_string(),
        username: if username.is_empty() {
            None
        } else {
            Some(username)
        },
        password,
        url: if url.is_empty() { None } else { Some(url) },
        notes: if notes.is_empty() {
            None
        } else {
            Some(notes)
        },
    })
}

pub fn add_entry(name: &str) -> Result<()> {
    let password = read_master_password()?;
    let mut vault = unlock_vault(&password)?;

    if vault.entries.iter().any(|e| e.name == name) {
        return Err(anyhow!("Entry '{}' already exists", name));
    }

    let entry = prompt_entry(name, None)?;
    vault.entries.push(entry);
    save_vault(&vault, &password)?;
    println!("Entry '{}' added", name);
    Ok(())
}

pub fn get_entry(name: &str) -> Result<()> {
    let password = read_master_password()?;
    let vault = unlock_vault(&password)?;

    let entry = vault
        .entries
        .iter()
        .find(|e| e.name == name)
        .ok_or_else(|| anyhow!("Entry '{}' not found", name))?;

    println!("Name:     {}", entry.name);
    println!("Username: {}", entry.username.as_deref().unwrap_or("(none)"));
    println!("Password: {}", entry.password);
    println!("URL:      {}", entry.url.as_deref().unwrap_or("(none)"));
    println!("Notes:    {}", entry.notes.as_deref().unwrap_or("(none)"));
    Ok(())
}

pub fn list_entries() -> Result<()> {
    let password = read_master_password()?;
    let vault = unlock_vault(&password)?;

    if vault.entries.is_empty() {
        println!("No entries in vault");
        return Ok(());
    }

    println!("Entries ({} total):", vault.entries.len());
    for entry in &vault.entries {
        let username = entry.username.as_deref().unwrap_or("");
        println!("  {} ({})", entry.name, username);
    }
    Ok(())
}

pub fn delete_entry(name: &str) -> Result<()> {
    let password = read_master_password()?;
    let mut vault = unlock_vault(&password)?;

    let len_before = vault.entries.len();
    vault.entries.retain(|e| e.name != name);

    if vault.entries.len() == len_before {
        return Err(anyhow!("Entry '{}' not found", name));
    }

    save_vault(&vault, &password)?;
    println!("Entry '{}' deleted", name);
    Ok(())
}

pub fn update_entry(name: &str) -> Result<()> {
    let password = read_master_password()?;
    let mut vault = unlock_vault(&password)?;

    let idx = vault
        .entries
        .iter()
        .position(|e| e.name == name)
        .ok_or_else(|| anyhow!("Entry '{}' not found", name))?;

    let entry = prompt_entry(name, Some(&vault.entries[idx]))?;
    vault.entries[idx] = entry;
    save_vault(&vault, &password)?;
    println!("Entry '{}' updated", name);
    Ok(())
}
