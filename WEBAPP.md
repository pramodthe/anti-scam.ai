# Basic Gmail App

This app is intentionally minimal:
1. Send email
2. View inbox emails
3. AI risk evaluation and quarantine
4. HITL labeling (`Scam` / `Not Scam`)
5. Delete email (move to trash) with manual HITL confirmation

## Setup

```bash
cd /Users/pramodthebe/Desktop/websecurity
cp .env.example .env
```

Required:
1. Gmail OAuth token in `.secrets/token.json`
2. `.venv-webapp313` activated
3. `OPENAI_API_KEY` (optional but recommended; if missing, risk scoring falls back to rules only)

Optional risk routing controls in `.env`:
1. `RISK_DECISION_MODE=hybrid` (or `rules_only`, `llm_only`)
2. `RISK_FAIL_CLOSED=true` to quarantine when LLM is unavailable in `llm_only` mode
3. `RISK_LINK_SCAN_ENABLED=true` to enable URL website checks
4. `RISK_LINK_SCAN_MAX_URLS=3` to cap per-email link scans
5. `RISK_LINK_SCAN_TIMEOUT_SECONDS=20`
6. `RISK_LINK_SCAN_FAIL_CLOSED=true` to quarantine on link scan timeout/error
7. `YUTORI_API_KEY` and optional `YUTORI_BASE_URL` for browser-agent scans
8. Optional Yutori overrides: `YUTORI_BROWSE_PATH`, `YUTORI_BROWSE_RESULT_PATH`, `YUTORI_POLL_TIMEOUT_SECONDS`

## Run

```bash
cd /Users/pramodthebe/Desktop/websecurity
source .venv-webapp313/bin/activate
uvicorn backend.api:app --reload --port 8000
```

```bash
cd /Users/pramodthebe/Desktop/websecurity
source .venv-webapp313/bin/activate
streamlit run frontend/streamlit_app.py --server.port 8501 --server.address 127.0.0.1
```

## API

1. `GET /health`
2. `GET /gmail/emails?email_address=...&minutes_since=...&include_read=...&max_results=...`
3. `POST /gmail/send`
4. `DELETE /gmail/emails/{message_id}`
5. `POST /risk/emails/evaluate`
6. `POST /risk/links/evaluate`
7. `GET /risk/quarantine`
8. `GET /risk/quarantine/{message_id}`
9. `POST /risk/quarantine/{message_id}/label`
10. `POST /risk/quarantine/{message_id}/release`

## LangSmith Studio (Local Dev)

Preview the LangGraph workflow in Studio without changing API routes:

```bash
cd /Users/pramodthebe/Desktop/websecurity
source .venv-webapp313/bin/activate
langgraph dev --config langgraph.json --no-browser
```

Then open Studio with the local server base URL (printed by `langgraph dev`, default is `http://127.0.0.1:2024`).
