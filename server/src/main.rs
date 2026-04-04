use axum::{
    extract::Json,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    Key, XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{PublicKey, Signature, Verifier};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use tower_http::services::ServeDir;

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
}

#[derive(Debug, Deserialize)]
struct SecurePackage {
    payload_b64: String,
    nonce_b64: String,
    ciphertext_b64: String,
    signature_b64: String,
    public_key_b64: String,
}

#[derive(Debug, Serialize)]
struct IngestResponse {
    signature_valid: bool,
    decrypted_payload: Value,
    message: String,
}

fn derive_key_from_passphrase(passphrase: &str) -> [u8; 32] {
    let digest = Sha256::digest(passphrase.as_bytes());
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    key
}

async fn health() -> impl IntoResponse {
    Json(HealthResponse { status: "ok" })
}

async fn ingest(Json(pkg): Json<SecurePackage>) -> impl IntoResponse {
    let passphrase = "demo-passphrase-change-me";

    let payload_bytes = match STANDARD.decode(&pkg.payload_b64) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("invalid payload_b64: {e}"),
            )
                .into_response()
        }
    };

    let nonce_bytes = match STANDARD.decode(&pkg.nonce_b64) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("invalid nonce_b64: {e}"),
            )
                .into_response()
        }
    };

    let ciphertext_bytes = match STANDARD.decode(&pkg.ciphertext_b64) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("invalid ciphertext_b64: {e}"),
            )
                .into_response()
        }
    };

    let signature_bytes = match STANDARD.decode(&pkg.signature_b64) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("invalid signature_b64: {e}"),
            )
                .into_response()
        }
    };

    let public_key_bytes = match STANDARD.decode(&pkg.public_key_b64) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("invalid public_key_b64: {e}"),
            )
                .into_response()
        }
    };

    let public_key = match PublicKey::from_bytes(&public_key_bytes) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("invalid public key bytes: {e}"),
            )
                .into_response()
        }
    };

    let signature = match Signature::from_bytes(&signature_bytes) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("invalid signature bytes: {e}"),
            )
                .into_response()
        }
    };

    let signature_valid = public_key.verify(&payload_bytes, &signature).is_ok();

    if nonce_bytes.len() != 24 {
        return (
            StatusCode::BAD_REQUEST,
            "nonce must be 24 bytes for XChaCha20Poly1305".to_string(),
        )
            .into_response();
    }

    let key_bytes = derive_key_from_passphrase(passphrase);
    let key = Key::from_slice(&key_bytes);
    let cipher = XChaCha20Poly1305::new(key);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let decrypted_bytes = match cipher.decrypt(nonce, ciphertext_bytes.as_ref()) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("decryption failed: {e}"),
            )
                .into_response()
        }
    };

    let decrypted_json: Value = match serde_json::from_slice(&decrypted_bytes) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("decrypted payload is not valid JSON: {e}"),
            )
                .into_response()
        }
    };

    let response = IngestResponse {
        signature_valid,
        decrypted_payload: decrypted_json,
        message: "Package received, verified, and decrypted.".to_string(),
    };

    (StatusCode::OK, Json(response)).into_response()
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/health", get(health))
        .route("/ingest", post(ingest))
        .fallback_service(ServeDir::new("../frontend"));

    let addr = SocketAddr::from(([127, 0, 0, 1], 8787));
    println!("secure-ecg-llm-demo running on http://127.0.0.1:8787");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}