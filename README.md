# Secure Clinical Metadata Pipeline (Rust + WASM)

A minimal, production-oriented MVP for **secure ingestion of clinical metadata**  
designed for **AI-ready pipelines (Spark / Databricks / LLM workflows)**.

---

## 🚀 What this demo shows

This project demonstrates a full secure flow:

1. Record metadata (ECG / DICOM / biosignals)
2. Protect it client-side (WASM)
   - Digital signature
   - Encryption (AEAD)
3. Send to backend securely
4. Verify + decrypt server-side
5. Validate schema + policy
6. Store into **Bronze layer**
7. Generate audit trail

---

## 🧠 Why this matters

Clinical AI pipelines require:

- Trust in data integrity  
- Protection of patient metadata  
- Compliance-aware ingestion  
- Safe handoff to downstream AI systems  

This MVP focuses on:

> **Record → Protect → Validate → Store → Safe for AI**

---

## 🏗️ Architecture

![Architecture](docs/architecture-overview.png)

---

## 🔐 Security Model

- Client-side protection via Rust + WASM  
- AEAD encryption (XChaCha20Poly1305)  
- Digital signatures (Ed25519 – placeholder for PQC)  
- Server-side verification before ingestion  
- Policy checks before storage  
- Audit logging  

---

## 📦 Project Structure

frontend/ → browser demo
rust-wasm/ → crypto (sign + encrypt)
server/ → secure ingestion backend
landing/ → public marketing page
samples/ → example metadata
docs/ → diagrams


---

## ⚙️ Run locally

### 1. Start backend

```bash
cd server
cargo run --release

´´´
Backend runs on:

http://127.0.0.1:8787

cd frontend
python3 -m http.server 8080

http://127.0.0.1:8080
