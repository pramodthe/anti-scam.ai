# AI Email Risk Agent Spec

## 1. Objective
Build a LangGraph/LangChain based email risk agent that:
1. Reviews each incoming email.
2. Quarantines suspicious emails first.
3. Sends low-risk emails to user inbox flow.
4. Supports HITL (human-in-the-loop) labeling to improve future scam detection.

## 2. Scope
This spec extends the current app (FastAPI + Streamlit + Gmail integration) with an AI risk workflow.

In scope:
1. Risk scoring and quarantine routing.
2. Quarantine storage in JSON format.
3. In-memory tracking for active review state.
4. HITL labels (`scam=1`, `not_scam=0`) persisted for training data.
5. Feedback loop dataset generation.
6. Link and website trust verification for URLs found in incoming emails.

Out of scope (phase 1):
1. Full model fine-tuning pipeline.
2. Multi-tenant auth/roles.
3. Production-grade distributed queueing.

## 3. Core Functional Requirements

### FR-1: Ingest Incoming Email
Each incoming email must be converted to structured data:
1. `id`
2. `thread_id`
3. `from_email`
4. `from_name`
5. `to_email`
6. `subject`
7. `body`
8. `received_at`
9. `headers` (optional raw map)

### FR-2: Node 1 Quarantine Decision
Node 1 is the first security gate and must decide `quarantine` or `deliver`.

Node 1 should evaluate:
1. Sender name anomalies.
2. Company/domain mismatch (display name vs sender domain).
3. Email type/risk pattern (invoice urgency, password reset bait, gift card, wire transfer, credential request, impersonation).
4. Link/attachment indicators (if available).

Node 1 output:
1. `risk_score` in `[0.0, 1.0]`
2. `risk_reasons` list
3. `decision`: `quarantine` or `deliver`

### FR-3: Routing
1. If `decision=quarantine`, store record in quarantine JSON + in-memory state.
2. If `decision=deliver`, make email visible in normal inbox flow.

### FR-4: Quarantine Storage
Quarantined emails must be saved as JSON records.

Required fields:
1. `id`
2. `description`
3. `risk_score`
4. `risk_reasons`
5. `model_version`
6. `status` (`pending_human_review`, `confirmed_scam`, `confirmed_legit`, `released`)
7. `label` (`null`, `1`, `0`)
8. `created_at`
9. `updated_at`

Storage strategy:
1. In-memory store for active runtime (fast HITL UI updates).
2. Persistent JSON file (`data/quarantine.jsonl`) for audit/history and training.

### FR-5: HITL Labeling
In quarantine UI, user must be able to click:
1. `Scam` -> set `label=1`, `status=confirmed_scam`
2. `Not Scam` -> set `label=0`, `status=confirmed_legit` (and optionally release)

For every label event, persist:
1. `id`
2. `description`
3. `risk_score`
4. `label`
5. `reviewed_at`

### FR-6: Training Feedback Data
Label events are appended to `data/training_feedback.jsonl`.

This dataset is used to:
1. Improve prompt/rules immediately.
2. Later train/evaluate a stronger classifier.

### FR-7: URL Extraction
For each email, extract and normalize website URLs from subject/body (including HTML content when present).

Requirements:
1. Scan only `http`/`https` links.
2. Remove obvious tracking query params (e.g. `utm_*`, `fbclid`, `gclid`) during normalization.
3. Deduplicate by normalized URL.
4. Scan only the first `N` unique links (`N` default: `3`, configurable).

### FR-8: Website Verification
Each extracted URL must be verified using two checks:
1. Deterministic SSL/TLS certificate checks:
   - cert present,
   - cert time validity,
   - hostname match,
   - issuer/subject/expiry capture.
2. Yutori browser-agent inspection:
   - open URL and follow redirects,
   - summarize page intent,
   - flag phishing/credential/payment traps,
   - flag brand-domain mismatch signals.

Output per URL:
1. `yutori_verdict`: `safe` | `suspicious` | `malicious` | `unknown`
2. `scan_status`: `ok` | `timeout` | `error`
3. structured evidence fields (see `LinkScanResult`)

### FR-9: Strict Link Routing Policy
Routing must be fail-closed for link risk by default.

Rules:
1. If any URL is `malicious` => force `quarantine`.
2. If scan status is `timeout`/`error` and fail-closed enabled => force `quarantine`.
3. If URL is unreachable and fail-closed enabled => force `quarantine`.
4. Final risk score is `max(base_email_score, link_risk_score)`.

### FR-10: Link Explainability & Persistence
Quarantine records must include per-link evidence so users can review why an email was flagged.

Persist:
1. URL-level checks (`ssl_*`, `yutori_*`, status, flags)
2. aggregate `link_risk_score`
3. boolean `link_scan_failed_closed`

## 4. Proposed Architecture

### 4.1 LangGraph State
```python
class EmailRiskState(TypedDict):
    email: dict
    features: dict
    risk_score: float
    risk_reasons: list[str]
    decision: str  # "quarantine" | "deliver"
    human_label: int | None  # 1 scam, 0 legit
```

### 4.2 Graph Nodes
1. `ingest_email_node`
2. `extract_features_node`
3. `extract_links_node`
4. `scan_links_node` (SSL + Yutori browser checks)
5. `node1_risk_score_node` (LLM + deterministic heuristics + link aggregation)
6. `route_node`
7. `quarantine_store_node` (if high risk)
8. `deliver_node` (if low risk)
9. `hitl_label_node` (async UI action updates label)
10. `feedback_persist_node`

### 4.3 Decision Thresholds (initial)
1. `risk_score >= 0.65` -> quarantine
2. `risk_score < 0.65` -> deliver

Threshold must be configurable in `.env`.

### 4.4 Link Scan Configuration
1. `RISK_LINK_SCAN_ENABLED=true`
2. `RISK_LINK_SCAN_MAX_URLS=3`
3. `RISK_LINK_SCAN_TIMEOUT_SECONDS=20`
4. `RISK_LINK_SCAN_FAIL_CLOSED=true`
5. `RISK_LINK_SCAN_ALLOW_HTTP=false`
6. `YUTORI_API_KEY=...`
7. `YUTORI_BASE_URL=...`
8. `YUTORI_BROWSE_MAX_STEPS=20`

## 5. API/Backend Additions

Add endpoints in FastAPI:
1. `POST /risk/emails/evaluate` -> run graph for one email.
2. `POST /risk/links/evaluate` -> run URL/website checks for diagnostics.
3. `GET /risk/quarantine` -> list quarantined emails.
4. `GET /risk/quarantine/{id}` -> quarantine detail.
5. `POST /risk/quarantine/{id}/label` with `{ "label": 1|0 }`.
6. `POST /risk/quarantine/{id}/release` (optional phase 1).

## 6. UI Requirements (Streamlit)
1. Add `Quarantine` tab.
2. Show each quarantined email with:
   - sender
   - subject
   - description
   - risk score
   - reasons
3. Add `Scam` and `Not Scam` buttons.
4. Show label history count and basic precision metrics.
5. During inbox refresh, show per-email scan progress (`Scanning email X/Y`).
6. In quarantine details, show link-level verdict + SSL summary.
7. Show fail-closed reason when link scan timeout/error forced quarantine.

## 7. Model Strategy
Phase 1:
1. Hybrid scoring = LLM classification + hard rules.
2. No fine-tune yet.
3. Store explanations for transparency.

Phase 2:
1. Add link-centric website trust layer (SSL + Yutori browser checks).
2. Keep deterministic + LLM base scoring, but enforce strict link gating.
3. Persist link evidence for explainable human review.

## 7.1 Phase 2: Link & Website Trust Verification
Every inbound email URL is inspected with a synchronous fail-closed flow:
1. URL extraction and normalization.
2. SSL/TLS certificate verification.
3. Yutori browser-agent website inspection.
4. Strict routing where malicious or unknown-under-fail-closed link outcomes quarantine the email.

## 8. Data Contracts

### 8.1 Quarantine Record Example
```json
{
  "id": "msg_123",
  "description": "Display name says PayPal support but sender domain is unrelated and requests urgent login verification.",
  "risk_score": 0.91,
  "risk_reasons": [
    "display_name_domain_mismatch",
    "credential_phishing_pattern",
    "urgency_language"
  ],
  "model_version": "risk-agent-v1",
  "status": "pending_human_review",
  "label": null,
  "created_at": "2026-02-27T21:00:00Z",
  "updated_at": "2026-02-27T21:00:00Z"
}
```

### 8.2 HITL Feedback Record Example
```json
{
  "id": "msg_123",
  "description": "Possible impersonation and credential theft pattern.",
  "risk_score": 0.91,
  "label": 1,
  "reviewed_at": "2026-02-27T21:15:00Z"
}
```

### 8.3 LinkScanResult Example
```json
{
  "original_url": "https://example.com/login?utm_source=mail",
  "normalized_url": "https://example.com/login",
  "final_url": "https://example.com/signin",
  "reachable": true,
  "http_status": 200,
  "ssl_valid": true,
  "ssl_issuer": "CN=Example CA",
  "ssl_subject": "CN=example.com",
  "ssl_expires_at": "2027-10-11T00:00:00Z",
  "ssl_hostname_match": true,
  "yutori_verdict": "suspicious",
  "yutori_summary": "Login prompt and redirect behavior are suspicious for this sender context.",
  "risk_flags": [
    "suspicious_link_detected",
    "brand_domain_mismatch"
  ],
  "scan_status": "ok"
}
```

## 9. Acceptance Criteria
1. Every incoming email is evaluated by Node 1.
2. Suspicious emails are quarantined before user inbox delivery.
3. Quarantined records are visible in UI and saved in JSON.
4. User can label each quarantined email as scam (`1`) or not scam (`0`).
5. Labels are persisted for training feedback.
6. System can reload prior quarantine history from JSON on restart.
7. For emails with URLs, up to configured max links are scanned synchronously.
8. SSL and Yutori checks both contribute to link evidence.
9. Any malicious/timeout/error/unreachable link under fail-closed policy triggers quarantine.
10. Quarantine records persist `link_results`, `link_risk_score`, and `link_scan_failed_closed`.

## 10. Implementation Plan
1. Create new `backend/app/risk_agent/` module (graph, nodes, rules, store).
2. Add JSONL persistence utilities and in-memory cache layer.
3. Add FastAPI risk endpoints and schemas.
4. Add Streamlit Quarantine tab + HITL actions.
5. Add tests for routing, labeling, and persistence.
6. Add metrics logging for false positives/false negatives.
7. Add `links.py`, `ssl_check.py`, `yutori_client.py`, and `link_scoring.py`.
8. Add `/risk/links/evaluate` diagnostic endpoint.
9. Add tests for URL extraction, SSL parsing, Yutori mapping, and link fail-closed routing.

## 11. Open Decisions
1. Use `langgraph` directly first, with optional LangChain wrappers where needed.
2. Keep first version single-user and local-file based.
3. Move to Redis/Postgres when multi-user support is needed.
4. Keep synchronous link scans in phase 2; revisit async worker queue in phase 3 if latency grows.
