/**
 * PIP Inspector — popup script (Phase 1).
 *
 * Submits the current tab's URL to the PIP backend POST /api/v1/inspect and
 * renders the deterministic Phase 1 result (score, classification, reasons).
 * Phase 2+ intelligence is deliberately not implemented.
 */

const BACKEND_INSPECT_URL = "http://localhost:8000/api/v1/inspect";

const form = document.getElementById("inspect-form");
const urlInput = document.getElementById("url-input");
const inspectButton = document.getElementById("inspect-button");
const resultEl = document.getElementById("result");
const statusEl = document.getElementById("status");

function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = String(text);
  return div.innerHTML;
}

async function currentTabUrl() {
  try {
    const [tab] = await chrome.tabs.query({
      active: true,
      currentWindow: true,
    });

    return (tab && tab.url) || "";
  } catch (error) {
    console.error("Could not read current tab URL:", error);
    return "";
  }
}

async function inspect(url) {
  console.log("[PIP] Sending inspection request:", url);

  const response = await fetch(BACKEND_INSPECT_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
  url,
  collect: true,
  intelligence: true
}),
  });

  if (!response.ok) {
    const body = await response.json().catch(() => ({}));

    throw new Error(
      body.detail ||
        `Backend responded with status ${response.status}`
    );
  }

const result = await response.json();

console.log("[PIP] Backend inspection result:", result);

if (typeof result.score !== "number") {
  console.error("[PIP] Invalid score received:", result);
  throw new Error("Backend returned an invalid risk score.");
}

if (!result.classification) {
  console.error("[PIP] Missing classification:", result);
  throw new Error("Backend returned no classification.");
}

return result;

}

function renderResult(result) {
  console.log("[PIP] COMPLETE BACKEND RESPONSE:", result);

  const score = result.score;
  const classification = result.classification;

  const reasons =
    Array.isArray(result.reasons) && result.reasons.length
      ? result.reasons
          .map((reason) => `<li>${escapeHtml(reason)}</li>`)
          .join("")
      : "<li>No risk indicators found.</li>";

  resultEl.innerHTML = `
    <div class="result-header">
      <span class="badge ${escapeHtml(classification || "unknown")}">
        ${escapeHtml(classification || "unknown")}
      </span>

      <span class="score">
        Risk score:
        <strong>${escapeHtml(score ?? "—")}</strong>/100
      </span>
    </div>

    <p class="result-url">
      ${escapeHtml(result.url || "")}
    </p>

    <ul class="reasons">
      ${reasons}
    </ul>

    <details>
      <summary>Extracted features</summary>
      <pre>${escapeHtml(
        JSON.stringify(result.features || {}, null, 2)
      )}</pre>
    </details>

    <details>
      <summary>Raw backend response</summary>
      <pre>${escapeHtml(
        JSON.stringify(result, null, 2)
      )}</pre>
    </details>
  `;

  resultEl.hidden = false;
}

function setStatus(message, isError = false) {
  statusEl.textContent = message;
  statusEl.classList.toggle("error", Boolean(isError));
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();

  const url = urlInput.value.trim();

  if (!url) {
    setStatus("Please enter a URL.", true);
    return;
  }

  inspectButton.disabled = true;
  setStatus("Inspecting…");
  resultEl.hidden = true;

  try {
    const result = await inspect(url);

    renderResult(result);

    setStatus(`Inspection #${result.id} completed`);
  } catch (error) {
    console.error("[PIP] Inspection failed:", error);

    setStatus(
      error && error.message
        ? error.message
        : "Inspection failed.",
      true
    );
  } finally {
    inspectButton.disabled = false;
  }
});

currentTabUrl().then((url) => {
  if (url) {
    urlInput.value = url;
  }
});