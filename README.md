# secure-ecg-llm-demo

Rust + WebAssembly MVP for signed and encrypted ECG metadata, designed for secure LLM / tool ingestion workflows.

## Screenshot

![secure-ecg-llm-demo](docs/secure-ecg-llm-demo_1.png)
![secure-ecg-llm-demo](docs/secure-ecg-llm-demo_2.png)
![secure-ecg-llm-demo](docs/secure-ecg-llm-demo_3.png)


## Overview

This project demonstrates a secure metadata handling flow for ECG-related workflows.

Current pipeline:

`ECG metadata JSON -> sign in browser -> encrypt in browser -> send to Rust backend -> verify -> decrypt -> recover structured payload`

The goal is not only to structure metadata, but to make it verifiable and secure before it enters an AI, agent, or downstream tool pipeline.

## What this MVP demonstrates

- browser-side signing
- browser-side encryption
- backend-side verification
- backend-side decryption
- structured payload recovery
- Rust + WASM integration for secure metadata handling

## Current demo scope

This MVP works with ECG metadata JSON derived from a DICOM ECG workflow.

Example fields currently handled include:

- modality
- manufacturer
- study date
- patient ID
- SOP class UID
- multiplex count
- channel labels
- sampling frequency
- sample counts

## Why this matters

Clinical and biosignal workflows often begin with files or metadata that are difficult to pass safely into downstream systems.

This demo explores a lightweight secure preprocessing layer where metadata can be signed, encrypted, transmitted, verified, and recovered before entering an LLM or tool workflow.

## Architecture

- `frontend/` — browser UI
- `frontend/pkg/` — generated WASM bindings
- `rust-wasm/` — Rust WebAssembly signing + encryption module
- `server/` — Rust backend for verification + decryption

## Current flow

1. Load ECG metadata JSON in the browser
2. Sign metadata in WebAssembly
3. Encrypt metadata in WebAssembly
4. Send protected package to Rust backend
5. Verify signature in backend
6. Decrypt payload in backend
7. Return structured JSON response

## Run locally

### 1. Build the WASM package

```bash
cd rust-wasm
wasm-pack build --target web --out-dir ../frontend/pkg --release