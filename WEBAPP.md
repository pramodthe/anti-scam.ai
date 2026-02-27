# Basic Gmail App

This app is intentionally minimal:
1. Send email
2. View inbox emails
3. Delete email (move to trash) with manual HITL confirmation

## Setup

```bash
cd /Users/pramodthebe/Desktop/websecurity
cp .env.example .env
```

Required:
1. Gmail OAuth token in `.secrets/token.json`
2. `.venv-webapp313` activated

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
