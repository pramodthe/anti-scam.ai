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
3. `node1_risk_score_node` (LLM + deterministic heuristics)
4. `route_node`
5. `quarantine_store_node` (if high risk)
6. `deliver_node` (if low risk)
7. `hitl_label_node` (async UI action updates label)
8. `feedback_persist_node`

### 4.3 Decision Thresholds (initial)
1. `risk_score >= 0.65` -> quarantine
2. `risk_score < 0.65` -> deliver

Threshold must be configurable in `.env`.

## 5. API/Backend Additions

Add endpoints in FastAPI:
1. `POST /risk/emails/evaluate` -> run graph for one email.
2. `GET /risk/quarantine` -> list quarantined emails.
3. `GET /risk/quarantine/{id}` -> quarantine detail.
4. `POST /risk/quarantine/{id}/label` with `{ "label": 1|0 }`.
5. `POST /risk/quarantine/{id}/release` (optional phase 1).

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

## 7. Model Strategy
Phase 1:
1. Hybrid scoring = LLM classification + hard rules.
2. No fine-tune yet.
3. Store explanations for transparency.

Phase 2:
1. Train a lightweight classifier on labeled data.
2. Compare against baseline on held-out labeled set.

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

## 9. Acceptance Criteria
1. Every incoming email is evaluated by Node 1.
2. Suspicious emails are quarantined before user inbox delivery.
3. Quarantined records are visible in UI and saved in JSON.
4. User can label each quarantined email as scam (`1`) or not scam (`0`).
5. Labels are persisted for training feedback.
6. System can reload prior quarantine history from JSON on restart.

## 10. Implementation Plan
1. Create new `backend/app/risk_agent/` module (graph, nodes, rules, store).
2. Add JSONL persistence utilities and in-memory cache layer.
3. Add FastAPI risk endpoints and schemas.
4. Add Streamlit Quarantine tab + HITL actions.
5. Add tests for routing, labeling, and persistence.
6. Add metrics logging for false positives/false negatives.

## 11. Open Decisions
1. Use `langgraph` directly first, with optional LangChain wrappers where needed.
2. Keep first version single-user and local-file based.
3. Move to Redis/Postgres when multi-user support is needed.

