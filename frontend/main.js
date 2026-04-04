import init, { sign_and_encrypt, verify_signature, decrypt_payload } from "./pkg/secure_ecg_crypto.js";

const sampleMetadata = {
  modality: "ECG",
  manufacturer: "Mortara Instrument, Inc.",
  study_date: "20130125",
  patient_id: "642341",
  sop_class_uid: "1.2.840.10008.5.1.4.1.1.9.1.1",
  multiplex_count: 2,
  multiplexes: [
    {
      index: 0,
      channels: 12,
      samples: 10000,
      sampling_frequency_hz: 1000,
      channel_labels: [
        "Lead I (Einthoven)",
        "Lead II",
        "Lead III",
        "Lead aVR",
        "Lead aVL",
        "Lead aVF",
        "Lead V1",
        "Lead V2",
        "Lead V3",
        "Lead V4",
        "Lead V5",
        "Lead V6"
      ]
    },
    {
      index: 1,
      channels: 12,
      samples: 1200,
      sampling_frequency_hz: 1000,
      channel_labels: [
        "Lead I (Einthoven)",
        "Lead II",
        "Lead III",
        "Lead aVR",
        "Lead aVL",
        "Lead aVF",
        "Lead V1",
        "Lead V2",
        "Lead V3",
        "Lead V4",
        "Lead V5",
        "Lead V6"
      ]
    }
  ]
};

const metadataEl = document.getElementById("metadata");
const passphraseEl = document.getElementById("passphrase");
const protectedOutputEl = document.getElementById("protectedOutput");
const serverOutputEl = document.getElementById("serverOutput");
const loadSampleBtn = document.getElementById("loadSampleBtn");
const protectBtn = document.getElementById("protectBtn");
const sendBtn = document.getElementById("sendBtn");

let currentEnvelope = null;

loadSampleBtn.addEventListener("click", () => {
  metadataEl.value = JSON.stringify(sampleMetadata, null, 2);
});

protectBtn.addEventListener("click", async () => {
  try {
    const payload = metadataEl.value.trim();

    if (!payload) {
      serverOutputEl.textContent = "No metadata JSON provided.";
      return;
    }

    const envelopeJson = sign_and_encrypt(payload, passphraseEl.value);
    currentEnvelope = JSON.parse(envelopeJson);

    protectedOutputEl.textContent = JSON.stringify(currentEnvelope, null, 2);

    const verified = verify_signature(
      payload,
      currentEnvelope.signature_b64,
      currentEnvelope.public_key_b64
    );

    const decrypted = decrypt_payload(
      currentEnvelope.ciphertext_b64,
      currentEnvelope.nonce_b64,
      passphraseEl.value
    );

    serverOutputEl.textContent = JSON.stringify(
      {
        local_check: {
          signature_valid: verified,
          decrypted_preview: JSON.parse(decrypted)
        }
      },
      null,
      2
    );
  } catch (err) {
    console.error(err);
    protectedOutputEl.textContent = "Nothing yet.";
    serverOutputEl.textContent = `Protect error: ${err}`;
  }
});

sendBtn.addEventListener("click", async () => {
  if (!currentEnvelope) {
    serverOutputEl.textContent = "First click: Sign + encrypt";
    return;
  }

  try {
    const resp = await fetch("/ingest", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(currentEnvelope)
    });

    const text = await resp.text();

    if (!resp.ok) {
      serverOutputEl.textContent = `HTTP ${resp.status}\n${text}`;
      return;
    }

    const data = JSON.parse(text);
    serverOutputEl.textContent = JSON.stringify(data, null, 2);
  } catch (err) {
    console.error(err);
    serverOutputEl.textContent = `Send error: ${err}`;
  }
});

(async function boot() {
  try {
    await init();
    metadataEl.value = JSON.stringify(sampleMetadata, null, 2);
    protectedOutputEl.textContent = "WASM ready.";
    serverOutputEl.textContent = "Server not contacted yet.";
  } catch (err) {
    console.error(err);
    protectedOutputEl.textContent = "WASM init failed.";
    serverOutputEl.textContent = `Init error: ${err}`;
  }
})();