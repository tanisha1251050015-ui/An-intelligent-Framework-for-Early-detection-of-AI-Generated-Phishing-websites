# PIP — Architecture

## Overview

PIP is a transparent phishing URL inspection platform composed of three
components:

| Component   | Tech                         | Role                                            |
|-------------|------------------------------|-------------------------------------------------|
| `backend`   | Python 3.11, FastAPI, SQLite | HTTP API, deterministic scoring engine, storage |
| `dashboard` | React 18, Vite, TypeScript   | Web UI that talks to the backend API            |
| `extension` | Chrome Manifest V3           | Browser extension that inspects the current URL |

## Component boundaries

```
┌───────────────┐   POST /inspect   ┌──────────────────┐   REST   ┌──────────────┐
│   Extension   │──────────────────►│     Backend      │◄────────►│   Dashboard  │
│   (MV3)       │◄──────────────────│  FastAPI :8000   │          │  Vite :5173  │
└───────────────┘      result       └────────┬─────────┘          └──────────────┘
                                             │
                                      ┌──────▼──────┐
                                      │  SQLite DB  │
                                      └─────────────┘
```

- **Backend → Dashboard:** HTTP REST over `/api/v1` (proxied by the Vite dev
  server in development). CORS is enabled for the dashboard origin.
- **Extension → Backend:** the popup reads the active tab's URL (`activeTab`)
  and POSTs it to `/api/v1/inspect` (host permission for `localhost:8000`),
  then renders the returned score/classification/reasons.

## Backend

### Phase 2C intelligence foundation (informational)

```
backend/app/core/
├── ssl_intelligence.py      # SSL certificate extraction (stdlib ssl/socket)
├── domain_intelligence.py   # Domain intelligence hints (pure logic)
├── fusion.py                # Rule-based intelligence fusion engine
├── whois_intelligence.py    # WHOIS stub (not_configured)
└── ocr.py                   # OCR stub (not_configured)
backend/app/collection/
└── screenshot.py            # Screenshot stub (not_configured)
```

**SSL Intelligence** — For HTTPS targets, connects to port 443 of the
inspected hostname with a ~5 s timeout using `ssl`/`socket`. Extracts:
issuer, subject, validity dates (not_before/not_after), serial number,
signature algorithm, certificate age in days, is_expired, is_self_signed,
hostname_match. HTTP targets return `{"status": "not_applicable"}`. No port
scanning, no alternate ports, no crawling. Always runs after SSRF validation.

**Domain Intelligence Hints** — Pure Python logic that generates
informational signals from Phase 1 features, Phase 2A collection, Phase 2B
DNS, and Phase 2C SSL evidence. Produces signals, risk_hints, and reasoning
without altering the Phase 1 score.

**Fusion Engine** — Rule-based combination of all intelligence sources
(Phase 1, 2A, 2B, 2C SSL, domain hints, WHOIS stub, screenshot stub, OCR
stub) into a structured intelligence summary. Never overwrites the Phase 1
score or classification.

**Stubs** — WHOIS, screenshot, and OCR modules return
`{"status": "not_configured"}` placeholders. No external services, APIs, or
API keys required.

**Informational only** — Intelligence pipeline never weakens or bypasses
Phase 2A SSRF protection. DNS remains informational. Phase 1 score remains
authoritative.

### Phase 2B DNS intelligence (informational)

``backend/app/core/dns_intelligence.py`` resolves ONLY the hostname of the URL
currently being inspected using the standard library (`socket.getaddrinfo`) on
a bounded daemon worker thread (~5 s timeout; configurable per call). Results
include IPv4/IPv6 lists, deduplicated addresses, `address_count`,
`resolution_ms`, per-address categories (private/loopback/link-local/
unspecified/multicast/reserved/public, incl. IPv4-mapped IPv6), `has_private`,
`all_private`, and structured errors. Literal IPs are classified WITHOUT a DNS
lookup (`status: "literal"`). DNS failures/timeouts are structured results and
never crash the API.

**Informational only** — DNS intelligence never weakens or bypasses the Phase
2A SSRF protection, which remains authoritative for whether an HTTP request is
allowed. No enumeration, scanning, crawling, or external lookups.

### Phase 2A safe collection layer

```
backend/app/collection/
├── ssrf.py        # Target validation BEFORE any connection (private/local/reserved rejected)
├── collector.py   # Bounded requests: 5s timeout, 512KiB limit, 5 redirects; evidence dict
├── html_parser.py # Minimal HTML stats (title, link/form/script/input/password counts)
└── __init__.py
```

- Collection is **opt-in** per request (`"collect": true`). With
  `"collect": false` (default) Phase 1 scoring still runs and the collection
  result is absent (`null`, stored as SQL NULL).
- Evidence: HTTP status, content type, response size (bytes read), truncation
  flag, redirect count/chain, response time, and HTML element counts for
  `text/html` content. Raw bodies are never stored.
- No JavaScript, no browser automation, no crawling, no port scanning.
- SSRF: literal IPs and every resolved address are checked against
  private/loopback/link-local/reserved/multicast/unspecified/CGNAT/TEST-NET/
  documentation ranges; `localhost` names are rejected; blocked targets are
  reported as `{"status": "blocked", "reason": "private_or_local_target"}`
  **without any outbound request**.

### Phase 1 engine (deterministic and explainable)

```
backend/app/engine/
├── parser.py      # URL parsing + validation (MalformedURLError -> HTTP 422)
├── features.py    # Phase 1 feature extraction + keyword/TLD constants
├── rules.py       # Explicit scoring rules (registry of rule functions)
├── scorer.py      # Sums fired rules, clamps score to 0-100
└── classifier.py  # Classification bands
```

Pipeline: `extract_features(url) -> score_features(features) -> persist`.

#### Feature set

| Feature                  | Definition                                   |
|--------------------------|----------------------------------------------|
| `scheme`                 | `http` / `https`                             |
| `is_ip_hostname`         | Hostname parses as IPv4/IPv6                 |
| `has_at_symbol`          | `@` present in the URL's netloc              |
| `suspicious_keywords`    | Known phishing terms found in the URL        |
| `url_length`             | Character count of the URL                   |
| `subdomain_count`        | Labels beyond the registered domain          |
| `query_parameter_count`  | Number of query parameters                   |
| `tld` / `is_suspicious_tld` | Top-level domain vs. high-risk TLD list   |
| `hostname_digit_count`   | Digits in the hostname                       |
| `hostname_hyphen_count`  | Hyphens in the hostname                      |
| malformed input          | Empty / missing scheme / missing hostname / unsupported scheme → 422 |

#### Scoring rules (fixed for Phase 1)

| Rule                   | Penalty                                    |
|------------------------|--------------------------------------------|
| HTTP instead of HTTPS  | +15                                        |
| Raw IP hostname        | +40                                        |
| `@` symbol             | +30                                        |
| Suspicious keyword     | +10 each (cap +40)                         |
| Long URL               | +10 (>75), +20 (>150), +30 (>300)          |
| Many subdomains        | +15 (≥3), +25 (≥5)                         |
| Many query parameters  | +10 (≥3), +20 (≥8)                         |
| Suspicious TLD         | +25                                        |
| Digit-heavy hostname   | +10 (≥4), +20 (≥8)                         |
| Hyphenated hostname    | +10 (≥2), +15 (≥4)                         |

The total is clamped to the inclusive range **0–100** and mapped to a band:

| Band        | Score   |
|-------------|---------|
| `safe`      | 0–29    |
| `suspicious`| 30–69   |
| `malicious` | 70–100  |

### API contract

#### `POST /api/v1/inspect`

Request: `{ "url": "...", "collect": true, "intelligence": true }` — `collect`
and `intelligence` are optional and default to `false`. The `collect` flag
enables Phase 2A HTTP/HTML collection. The `intelligence` flag enables Phase 2C
SSL intelligence, domain hints, and fusion. The response adds `dns` (Phase 2B),
`ssl`, `whois`, and `intelligence` fields when applicable. Malformed input
(missing scheme, missing hostname, unsupported scheme, empty) returns `422`
with a detail message.

Response (200):

```json
{
  "id": 1,
  "url": "https://example.com/login",
  "status": "completed",
  "score": 10,
  "classification": "safe",
  "features": {
    "scheme": "https",
    "hostname": "example.com",
    "is_ip_hostname": false,
    "has_at_symbol": false,
    "suspicious_keywords": ["login"],
    "url_length": 26,
    "subdomain_count": 0,
    "query_parameter_count": 0,
    "tld": "com",
    "is_suspicious_tld": false,
    "hostname_digit_count": 0,
    "hostname_hyphen_count": 0
  },
  "reasons": ["Hostname contains suspicious keyword(s): login"],
  "created_at": "2026-08-13T00:00:00Z",
  "updated_at": "2026-08-13T00:00:00Z"
}
```

#### `GET /api/v1/inspections` and `GET /api/v1/inspections/{id}`

List recent inspections (newest first, `limit` 1–100, default 20) and retrieve
a persisted inspection (`404` when missing). Both include the `collection`
evidence dict where available (`null` when absent).

#### `GET /api/v1/health`

Unchanged from Phase 0 (includes live database connectivity).

### Application layout

```
backend/
├── app/
│   ├── main.py               # FastAPI app factory, lifespan, CORS, router mount
│   ├── core/config.py        # Plain application settings (no secrets, no .env)
│   ├── db/
│   │   ├── base.py           # SQLAlchemy declarative Base
│   │   └── session.py        # Engine, SessionLocal, get_db dependency
│   ├── engine/               # Phase 1 deterministic engine (see above)
│   ├── collection/           # Phase 2A safe HTTP/HTML collection (see above)
│   ├── models/inspection.py  # Inspection ORM model
│   ├── schemas/              # Pydantic request/response schemas
│   └── api/v1/               # health.py, inspect.py, router.py
└── tests/                    # pytest suite
```

### Data model

`inspections` table (extended in Phase 1):

| Column           | Type      | Notes                                   |
|------------------|-----------|-----------------------------------------|
| `id`             | INTEGER   | Primary key                             |
| `url`            | TEXT(2048)| The inspected URL                       |
| `status`         | TEXT(32)  | `pending` / `processing` / `completed` / `failed` |
| `score`          | INTEGER   | Clamped 0–100 risk score (Phase 1)      |
| `classification` | TEXT(32)  | `safe` / `suspicious` / `malicious`     |
| `features_json`  | TEXT      | Serialized extracted features           |
| `reasons_json`   | TEXT      | Serialized rule reasons                 |
| `collection_json`| TEXT      | Collection evidence (SQL NULL when absent; added by idempotent migration) |
| `dns_data`       | TEXT      | DNS intelligence (SQL NULL for pre-Phase 2B records) |
| `ssl_data`       | TEXT      | SSL intelligence (SQL NULL when absent; Phase 2C)    |
| `whois_data`     | TEXT      | WHOIS stub data (SQL NULL when absent; Phase 2C)    |
| `intelligence_json` | TEXT   | Fused intelligence summary (SQL NULL when absent; Phase 2C) |
| `created_at`     | DATETIME  | Server default `now()`                  |
| `updated_at`     | DATETIME  | Server default `now()`, updated on change|

The database is SQLite at `backend/data/pip.db` (auto-created, gitignored).

## Dashboard

React 18 + TypeScript on Vite. Phase 1 adds:

- `src/api/client.ts` — `inspectUrl()` client for `POST /api/v1/inspect`.
- An inspection panel: submit a URL, see the classification badge, score,
  reasons, and extracted features.

## Extension

Chrome Manifest V3. Phase 1 adds:

- `activeTab` permission + `http://localhost:8000/*` host permission.
- Popup reads the active tab's URL, submits it to `POST /api/v1/inspect`, and
  renders the result (badge, score, reasons, features).

## Phase boundaries

### Implemented (Phases 0–2C)

- Project structure and versioning
- Backend health endpoint + SQLite
- Deterministic, transparent heuristic scoring engine (feature extraction,
  explicit rules, 0–100 clamp, classification bands) — frozen
- `POST /api/v1/inspect` + `GET /api/v1/inspections` + `GET /api/v1/inspections/{id}`
  with persistence
- Safe HTTP/HTML collection layer with SSRF protection, bounded requests, and
  opt-out (`collect` flag)
- DNS intelligence foundation (bounded stdlib resolution, safe classification,
  informational only — never bypasses SSRF)
- Phase 2C intelligence foundation: SSL intelligence, domain intelligence
  hints, rule-based fusion, WHOIS/screenshot/OCR stubs
- Feature-flagged intelligence pipeline (`intelligence` request flag)
- Idempotent additive database migration
- Dashboard inspection panel wired to the API
- Extension popup inspection of the current tab
- Test suites (271 tests): engine, collection, SSRF, migration, API,
  dashboard, manifest, SSL intelligence, domain intelligence, fusion,
  intelligence API, intelligence migration

### Explicitly NOT implemented (Phase 2D+)

LLM/Gemini/OpenAI/DeepSeek integration, full OCR (beyond stub), full
screenshots (beyond stub), full WHOIS (beyond stub), SHAP, campaign
correlation, graph analysis, machine learning, continual learning, JavaScript
behavioral execution, threat-intelligence APIs, crawling, port scanning,
external security scanning, and any intelligence beyond the Phase 2C
foundation.

## Security model

- No secrets, API keys, or credentials exist anywhere in the project.
- No `.env` files are read by any component or tooling.
- The engine performs no network requests; it is pure string parsing.
- SSL intelligence uses only the Python standard library (no external services).
- The extension only talks to the local PIP backend origin.
