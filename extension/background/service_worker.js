/**
 * PIP Inspector — background service worker (Phase 0 foundation).
 *
 * No inspection logic is implemented in Phase 0. This worker only establishes
 * the message-passing contract that later phases will use to request and
 * receive URL inspections.
 */

chrome.runtime.onInstalled.addListener(() => {
  console.log("PIP Inspector installed (Phase 0 foundation)");
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  // Phase 0 contract: PING -> { ok: true, version }
  if (message && message.type === "PING") {
    sendResponse({ ok: true, version: chrome.runtime.getManifest().version });
    return true; // keep the message channel open for the async response
  }
  return false;
});
