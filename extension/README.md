# PIP Inspector — Chrome Extension (Phase 0)

Manifest V3 foundation for the Phishing Intelligence Platform browser
extension. No inspection logic is implemented in Phase 0.

## Load unpacked

1. Open `chrome://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked** and select this `extension/` directory

## Structure

```
extension/
├── manifest.json                 # MV3 manifest (storage permission only)
├── background/service_worker.js  # Message-passing contract (PING)
├── content/content.js            # Page-context skeleton (no behavior yet)
├── popup/                        # Popup shell (form disabled until later phases)
└── tests/validate_manifest.js    # Manifest validation script
```

## Validate

```bash
npm test
```

## Phase 0 contract

`PING` → `{ ok: true, version: "<manifest version>" }`

Later phases will extend this contract with URL inspection requests.
