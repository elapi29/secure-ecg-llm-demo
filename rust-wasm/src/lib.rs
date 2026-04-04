use wasm_bindgen::prelude::*;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    Key, XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer, Verifier};
use getrandom::getrandom;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Serialize, Deserialize)]
pub struct SecurePackage {
    pub payload_b64: String,
    pub nonce_b64: String,
    pub ciphertext_b64: String,
    pub signature_b64: String,
    pub public_key_b64: String,
}

fn derive_key_from_passphrase(passphrase: &str) -> [u8; 32] {
    let digest = Sha256::digest(passphrase.as_bytes());
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    key
}

fn random_nonce_24() -> Result<[u8; 24], JsValue> {
    let mut nonce = [0u8; 24];
    getrandom(&mut nonce).map_err(|e| JsValue::from_str(&format!("getrandom failed: {e}")))?;
    Ok(nonce)
}

fn random_secret_key() -> Result<[u8; 32], JsValue> {
    let mut secret = [0u8; 32];
    getrandom(&mut secret).map_err(|e| JsValue::from_str(&format!("getrandom failed: {e}")))?;
    Ok(secret)
}

#[wasm_bindgen]
pub fn sign_and_encrypt(payload_json: &str, passphrase: &str) -> Result<String, JsValue> {
    let payload_bytes = payload_json.as_bytes();

    // Keypair Ed25519
    let secret_bytes = random_secret_key()?;
    let secret = SecretKey::from_bytes(&secret_bytes)
        .map_err(|e| JsValue::from_str(&format!("secret key error: {e}")))?;
    let public: PublicKey = (&secret).into();
    let keypair = Keypair { secret, public };

    // Sign payload
    let signature: Signature = keypair.sign(payload_bytes);

    // Encrypt payload with XChaCha20Poly1305
    let key_bytes = derive_key_from_passphrase(passphrase);
    let key = Key::from_slice(&key_bytes);
    let cipher = XChaCha20Poly1305::new(key);

    let nonce_bytes = random_nonce_24()?;
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, payload_bytes)
        .map_err(|e| JsValue::from_str(&format!("encryption failed: {e}")))?;

    let pkg = SecurePackage {
        payload_b64: STANDARD.encode(payload_bytes),
        nonce_b64: STANDARD.encode(nonce_bytes),
        ciphertext_b64: STANDARD.encode(ciphertext),
        signature_b64: STANDARD.encode(signature.to_bytes()),
        public_key_b64: STANDARD.encode(keypair.public.to_bytes()),
    };

    serde_json::to_string_pretty(&pkg)
        .map_err(|e| JsValue::from_str(&format!("serialization failed: {e}")))
}

#[wasm_bindgen]
pub fn verify_signature(payload_json: &str, signature_b64: &str, public_key_b64: &str) -> Result<bool, JsValue> {
    let payload_bytes = payload_json.as_bytes();

    let signature_bytes = STANDARD
        .decode(signature_b64)
        .map_err(|e| JsValue::from_str(&format!("invalid signature b64: {e}")))?;

    let public_key_bytes = STANDARD
        .decode(public_key_b64)
        .map_err(|e| JsValue::from_str(&format!("invalid public key b64: {e}")))?;

    let signature = Signature::from_bytes(&signature_bytes)
        .map_err(|e| JsValue::from_str(&format!("invalid signature: {e}")))?;

    let public_key = PublicKey::from_bytes(&public_key_bytes)
        .map_err(|e| JsValue::from_str(&format!("invalid public key: {e}")))?;

    match public_key.verify(payload_bytes, &signature) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[wasm_bindgen]
pub fn decrypt_payload(ciphertext_b64: &str, nonce_b64: &str, passphrase: &str) -> Result<String, JsValue> {
    let ciphertext = STANDARD
        .decode(ciphertext_b64)
        .map_err(|e| JsValue::from_str(&format!("invalid ciphertext b64: {e}")))?;

    let nonce_bytes = STANDARD
        .decode(nonce_b64)
        .map_err(|e| JsValue::from_str(&format!("invalid nonce b64: {e}")))?;

    if nonce_bytes.len() != 24 {
        return Err(JsValue::from_str("nonce must be 24 bytes for XChaCha20Poly1305"));
    }

    let key_bytes = derive_key_from_passphrase(passphrase);
    let key = Key::from_slice(&key_bytes);
    let cipher = XChaCha20Poly1305::new(key);

    let nonce = XNonce::from_slice(&nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| JsValue::from_str(&format!("decryption failed: {e}")))?;

    String::from_utf8(plaintext)
        .map_err(|e| JsValue::from_str(&format!("utf8 decode failed: {e}")))
}