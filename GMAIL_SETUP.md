# Gmail OAuth Setup Guide

This app uses only Gmail operations (list/send/delete).
Store OAuth files in root `.secrets/`.

## 1. Prerequisites

1. Google Cloud project
2. Gmail API enabled
3. OAuth Client ID for **Desktop app**

Recommended flow in Google Cloud:
1. Configure OAuth consent screen
2. Choose `External` if using personal Gmail
3. Add yourself as a test user
4. Create OAuth client (`Desktop app`)
5. Download the client JSON

## 2. Place OAuth Client Secret File

From repo root:

```bash
cd /Users/pramodthebe/Desktop/websecurity
mkdir -p .secrets
cp /path/to/downloaded-client.json .secrets/secrets.json
```

Required filename:
- `.secrets/secrets.json`

## 3. Run OAuth Login Flow

Activate your venv first, then run:

```bash
cd /Users/pramodthebe/Desktop/websecurity
source .venv-webapp313/bin/activate
python scripts/setup_gmail.py
```

What this does:
1. Opens browser for Google login and consent
2. Requests scopes:
   - `https://www.googleapis.com/auth/gmail.modify`
   - `https://www.googleapis.com/auth/gmail.send`
3. Writes token file:
   - `.secrets/token.json`

## 4. Verify Credentials Are Available

You should now have both files:
1. `.../.secrets/secrets.json`
2. `.../.secrets/token.json`

`gmail_tools.py` loads credentials in this order:
1. `GMAIL_TOKEN` / `GMAIL_SECRET` env vars (JSON string)
2. local `.secrets/token.json`

If none found, tools fall back to mock behavior.

## 5. Optional: Put Token/Secret in Environment

For hosted usage (or if you do not want local files), set:
- `GMAIL_TOKEN` (full JSON from `token.json`)
- `GMAIL_SECRET` (full JSON from `secrets.json`)

Example:

```bash
export GMAIL_TOKEN='{"token":"...","refresh_token":"..."}'
export GMAIL_SECRET='{"installed":{"client_id":"...","client_secret":"..."}}'
```

## 6. Start App

Backend:
```bash
cd /Users/pramodthebe/Desktop/websecurity
source .venv-webapp313/bin/activate
uvicorn backend.api:app --reload --port 8000
```

Frontend:
```bash
cd /Users/pramodthebe/Desktop/websecurity
source .venv-webapp313/bin/activate
streamlit run frontend/streamlit_app.py --server.port 8501 --server.address 127.0.0.1
```

## 7. Root Web App Usage

The root app is a basic Gmail app now:
1. Send email
2. Refresh and view inbox emails
3. Delete (trash) with manual HITL confirmation in UI

## 8. Troubleshooting

### `Client secrets file not found`
Put the file at exactly:
- `.secrets/secrets.json`

### `access blocked` / app not verified
Add your account as a **test user** in OAuth consent screen.

### `invalid_grant` / expired refresh
Delete old token and re-auth:

```bash
rm .secrets/token.json
python scripts/setup_gmail.py
```

### Token not found
Ensure `.secrets/token.json` exists or set `GMAIL_TOKEN`.
