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

const summaryModalityEl = document.getElementById("summaryModality");
const summaryManufacturerEl = document.getElementById("summaryManufacturer");
const summaryMultiplexesEl = document.getElementById("summaryMultiplexes");
const summaryChannelsEl = document.getElementById("summaryChannels");

const localSignatureStatusEl = document.getElementById("localSignatureStatus");
const localPreviewStatusEl = document.getElementById("localPreviewStatus");
const backendVerificationStatusEl = document.getElementById("backendVerificationStatus");
const backendPayloadStatusEl = document.getElementById("backendPayloadStatus");

const stepLoadedEl = document.getElementById("stepLoaded");
const stepProtectedEl = document.getElementById("stepProtected");
const stepVerifiedEl = document.getElementById("stepVerified");

let currentEnvelope = null;

function setStepState(stepEl, active, text) {
  stepEl.classList.toggle("active", active);
  const stateEl = stepEl.querySelector(".step-state");
  stateEl.textContent = text;
}

function updateSummaryFromMetadata(obj) {
  summaryModalityEl.textContent = obj?.modality ?? "—";
  summaryManufacturerEl.textContent = obj?.manufacturer ?? "—";
  summaryMultiplexesEl.textContent = obj?.multiplex_count ?? "—";

  const firstMultiplex = Array.isArray(obj?.multiplexes) && obj.multiplexes.length > 0
    ? obj.multiplexes[0]
    : null;

  summaryChannelsEl.textContent = firstMultiplex?.channels ?? "—";
}

function parseCurrentMetadata() {
  const raw = metadataEl.value.trim();
  if (!raw) return null;
  return JSON.parse(raw);
}

function resetProtectionState() {
  currentEnvelope = null;
  protectedOutputEl.textContent = "Nothing yet.";
  serverOutputEl.textContent = "Nothing yet.";

  localSignatureStatusEl.textContent = "Not run";
  localPreviewStatusEl.textContent = "Not available";
  backendVerificationStatusEl.textContent = "Not run";
  backendPayloadStatusEl.textContent = "Not available";

  setStepState(stepProtectedEl, false, "Waiting");
  setStepState(stepVerifiedEl, false, "Waiting");
}

function loadMetadataObject(obj) {
  metadataEl.value = JSON.stringify(obj, null, 2);
  updateSummaryFromMetadata(obj);

  setStepState(stepLoadedEl, true, "Ready");
  resetProtectionState();
}

metadataEl.addEventListener("input", () => {
  try {
    const obj = parseCurrentMetadata();
    if (obj) {
      updateSummaryFromMetadata(obj);
      setStepState(stepLoadedEl, true, "Ready");
    } else {
      updateSummaryFromMetadata({});
      setStepState(stepLoadedEl, false, "Waiting");
    }
    resetProtectionState();
  } catch {
    setStepState(stepLoadedEl, false, "Invalid JSON");
    summaryModalityEl.textContent = "—";
    summaryManufacturerEl.textContent = "—";
    summaryMultiplexesEl.textContent = "—";
    summaryChannelsEl.textContent = "—";
    resetProtectionState();
  }
});

loadSampleBtn.addEventListener("click", () => {
  loadMetadataObject(sampleMetadata);
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

    const decryptedObj = JSON.parse(decrypted);

    localSignatureStatusEl.textContent = verified ? "Valid" : "Invalid";
    localPreviewStatusEl.textContent = decryptedObj?.modality ? "Recovered" : "Unavailable";

    setStepState(stepProtectedEl, true, verified ? "Protected" : "Protection issue");
    serverOutputEl.textContent = JSON.stringify(
      {
        local_check: {
          signature_valid: verified,
          decrypted_preview: decryptedObj
        }
      },
      null,
      2
    );
  } catch (err) {
    console.error(err);
    currentEnvelope = null;
    protectedOutputEl.textContent = "Nothing yet.";
    serverOutputEl.textContent = `Protect error: ${err}`;
    localSignatureStatusEl.textContent = "Error";
    localPreviewStatusEl.textContent = "Unavailable";
    setStepState(stepProtectedEl, false, "Error");
  }
});

sendBtn.addEventListener("click", async () => {
  if (!currentEnvelope) {
    serverOutputEl.textContent = "First click: Protect metadata";
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
      backendVerificationStatusEl.textContent = "Failed";
      backendPayloadStatusEl.textContent = "Unavailable";
      setStepState(stepVerifiedEl, false, "Error");
      return;
    }

    const data = JSON.parse(text);
    serverOutputEl.textContent = JSON.stringify(data, null, 2);

    backendVerificationStatusEl.textContent = data.signature_valid ? "Valid" : "Invalid";
    backendPayloadStatusEl.textContent = data.decrypted_payload ? "Recovered" : "Unavailable";

    setStepState(
      stepVerifiedEl,
      true,
      data.signature_valid ? "Verified" : "Verification issue"
    );
  } catch (err) {
    console.error(err);
    serverOutputEl.textContent = `Send error: ${err}`;
    backendVerificationStatusEl.textContent = "Error";
    backendPayloadStatusEl.textContent = "Unavailable";
    setStepState(stepVerifiedEl, false, "Error");
  }
});

(async function boot() {
  try {
    await init();
    loadMetadataObject(sampleMetadata);
    protectedOutputEl.textContent = "WASM ready.";
    serverOutputEl.textContent = "Server not contacted yet.";
  } catch (err) {
    console.error(err);
    protectedOutputEl.textContent = "WASM init failed.";
    serverOutputEl.textContent = `Init error: ${err}`;
  }
})();