# PIP — Phishing Intelligence Platform

A transparent phishing URL inspection platform.

**Phase 0 — Project Foundation** established the project structure and a
working backend / dashboard / extension architecture.

**Phase 1 — Transparent Heuristic URL Scoring** added a deterministic,
explainable URL inspection engine (feature extraction + explicit scoring rules,
no ML/LLM).

**Phase 2A — Safe HTTP/HTML Collection** adds a bounded, SSRF-protected
collection layer that gathers limited HTTP/HTML evidence for eligible URLs
(status, content type, size, redirects, timing, HTML element counts).

**Phase 2B — DNS Intelligence Foundation** adds informational DNS resolution
and classification for the inspected hostname (bounded stdlib resolution,
safe address categorization, structured errors; never bypasses SSRF).

**Phase 2C — Intelligence Foundation** adds SSL certificate intelligence,
domain intelligence hints, rule-based intelligence fusion, and stub
interfaces for WHOIS, screenshot, and OCR capabilities. The intelligence
pipeline is feature-flagged via the `intelligence` request parameter
(default `false`). When enabled, it collects SSL certificate data from
HTTPS targets, generates domain intelligence signals, and fuses all
intelligence sources into a structured summary — without altering the
Phase 1 score or bypassing SSRF protection.

Phases 2D+ are **not** implemented (no LLM, OCR, screenshots, SHAP, graph
analysis, machine learning, JavaScript behavioral execution,
threat-intelligence APIs, crawling, or port scanning).

> [!IMPORTANT]
> Only the PIP project workspace is used. No `.env` files, credentials,
> secrets, personal files, browser profiles, or files outside the workspace are
> ever accessed by this project or its tooling.

## Repository layout

```
edi_project/
├── backend/       FastAPI service (health endpoint, SQLite, inspection model)
├── dashboard/     React + Vite frontend (talks to the backend)
├── extension/     Chrome extension foundation (Manifest V3)
├── README.md
└── ARCHITECTURE.md
```

## Phase 1 — URL inspection

The backend exposes a deterministic, fully transparent scoring engine:

- **Feature extraction** — scheme, IP hostname, `@` symbol, suspicious
  keywords, URL length, subdomain count, query-parameter count, suspicious TLD,
  hostname digit/hyphen counts, plus malformed-input handling.
- **Scoring rules** — explicit and inspectable (see
  `backend/app/engine/rules.py`). Each fired rule adds fixed points.
- **Classification bands** — `0–29 = safe`, `30–69 = suspicious`,
  `70–100 = malicious`. The score is clamped to 0–100.

Endpoints:

| Method | Path                         | Description                        |
|--------|------------------------------|------------------------------------|
| POST   | `/api/v1/inspect`            | Run the engine on a URL, persist it (Phase 1 + optional collection) |
| GET    | `/api/v1/inspections`        | List recent inspections (newest first) |
| GET    | `/api/v1/inspections/{id}`   | Retrieve a persisted inspection    |
| GET    | `/api/v1/health`             | Application health                 |

Example:

```bash
curl -X POST http://localhost:8000/api/v1/inspect \
  -H "Content-Type: application/json" \
  -d '{"url": "http://user@a.b.c.example-verify-account.tk/?x=1"}'
```

## Phase 2B — DNS intelligence (informational)

Every `POST /api/v1/inspect` response includes a `dns` field for the inspected
hostname: IPv4/IPv6 addresses, deduplicated `addresses` and `address_count`,
`resolution_ms`, per-address categories (`private`, `loopback`, `link-local`,
`unspecified`, `multicast`, `reserved`, `public`, incl. IPv4-mapped IPv6),
`has_private`, `all_private`, and structured `error` info. Resolution uses
`socket.getaddrinfo` on a bounded worker thread (~5 s timeout); literal IPs are
classified without a lookup (`status: "literal"`). DNS is informational only
and never weakens Phase 2A SSRF protection.

## Phase 2C — Intelligence foundation

`POST /api/v1/inspect` accepts an optional `"intelligence": true` flag. When set,
the backend executes the Phase 2C intelligence pipeline **after** the standard
Phase 1/2A/2B pipeline completes:

- **SSL Intelligence** — For HTTPS targets, connects to port 443 of the
  inspected hostname with a 5-second timeout, extracts certificate details
  (issuer, subject, validity dates, serial number, age, expiration status,
  self-signed detection, hostname match). HTTP targets return
  `{"status": "not_applicable"}`. No port scanning, no alternate ports,
  no multiple connections.
- **Domain Intelligence Hints** — Pure logic that generates informational
  signals from existing evidence (new/expired/self-signed SSL certs,
  hostname mismatches, private DNS, suspicious HTML indicators). Does not
  alter the Phase 1 score.
- **WHOIS Stub** — Abstract interface returning
  `{"status": "not_configured"}`. No external API calls.
- **Screenshot Stub** — Abstract interface returning
  `{"status": "not_configured"}`. No browser automation.
- **OCR Stub** — Abstract interface returning
  `{"status": "not_configured"}`. No image processing.
- **Fusion Engine** — Rule-based combination of all intelligence sources
  into a structured summary with signals, risk hints, evidence, and
  reasoning. Never overwrites the Phase 1 score/classification.

When `intelligence` is `false` (default), no Phase 2C processing occurs and
the response is fully backward compatible with Phase 1/2A/2B.

No external API keys are required for implemented Phase 2C functionality.
SSL intelligence uses only the Python standard library (`ssl`/`socket`).

## Phase 2A — safe HTTP/HTML collection

`POST /api/v1/inspect` accepts an optional `"collect": true` flag. When set,
the backend collects bounded HTTP/HTML evidence for eligible URLs:

- HTTP status, content type, response size (bytes read), redirect chain,
  response time, and — for HTML content — title, link/form/script/input and
  password-input counts.
- Raw response bodies are **never stored**. No JavaScript execution, no
  browser automation, no crawling, no port scanning.
- Bounded requests: 5 s timeout, 512 KiB response limit, 5 redirects max.
- **SSRF protection runs before any connection**: localhost, loopback, private
  RFC 1918, link-local, unspecified, reserved, multicast, CGNAT, TEST-NET,
  and documentation ranges are rejected, including hostnames that resolve to
  any such address. Blocked targets return
  `{"status": "blocked", "reason": "private_or_local_target"}`.
- Opt-out: with `"collect": false` (the default) Phase 1 scoring still runs
  and the collection result is absent (`null`, stored as SQL NULL).

Collection evidence is available through `GET /api/v1/inspections` and
`GET /api/v1/inspections/{id}`.

## Versioning

- Application version: `1.1.0`
- Backend: `backend/app/core/config.py` (`app_version`)
- Dashboard: `dashboard/package.json`
- Extension: `extension/manifest.json`

Dependency versions are pinned for stability; no unnecessary dependencies are
introduced.

## Quick start

### Backend

Requires Python 3.11+.

```bash
cd backend
python -m venv .venv
# activate:  source .venv/Scripts/activate   (Git Bash / Windows)
#            source .venv/bin/activate        (macOS / Linux)
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Health check: <http://localhost:8000/api/v1/health>

Inspect a URL (Phase 1):

```bash
curl -X POST http://localhost:8000/api/v1/inspect \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com/login"}'
```

Run tests:

```bash
cd backend
python -m pytest
```

### Dashboard

Requires Node.js 18+ and npm.

```bash
cd dashboard
npm install
npm run dev          # http://localhost:5173
```

The Vite dev server proxies `/api` to the backend (`http://localhost:8000`).

Run tests and build:

```bash
cd dashboard
npm test
npm run build
```

### Extension

Load the unpacked `extension/` directory in Chrome:

1. Open `chrome://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked** and select the `extension/` directory

Validate the manifest:

```bash
cd extension
npm test
```

## Testing

- Backend: `pytest` suite in `backend/tests/` (271 tests: health, DB model, schemas, Phase 1 engine, Phase 2A collection/SSRF, Phase 2B DNS, Phase 2C SSL/intelligence/fusion)
- Dashboard: `vitest` suite in `dashboard/src/`
- Extension: manifest validation script in `extension/tests/`

## Security

- No secrets are stored or required by this project.
- Configuration is plain application settings (see `backend/app/core/config.py`);
  no `.env` loading exists in Phase 0.
- The backend only exposes a public health endpoint in Phase 0.

## Scope boundaries

Phases 1, 2A, 2B, and 2C are implemented. Phases 2D+ are deliberately excluded:
LLM/Gemini/OpenAI/DeepSeek, OCR (beyond stub), screenshots (beyond stub),
WHOIS (beyond stub), SHAP, campaign correlation, graph analysis, machine
learning, continual learning, JavaScript behavioral execution,
threat-intelligence APIs, crawling, port scanning, and external security
scanning. None of these are implemented.
