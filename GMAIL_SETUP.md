# Gmail OAuth Setup Guide

This app uses only Gmail operations (list/send/delete).
Tokens and optional OAuth client backup live under root `.secrets/` (gitignored).

## Quick path: Setup page (Next.js)

1. In Google Cloud, create an OAuth client with type **Web application** (not Desktop).
2. Under **Authorized redirect URIs**, add exactly:
   - `http://127.0.0.1:8000/auth/google/callback`  
   (or match `GMAIL_OAUTH_REDIRECT_URI` in `.env` if you changed host/port.)
3. Start the API (`:8000`) and Next.js (`:3000`), then open **`http://127.0.0.1:3000/setup`** (or **Gmail setup** in the sidebar).
4. Paste **Client ID** and **Client secret**, click **Save**, then **Sign in with Google**.

The API writes `.secrets/oauth_app.json` and `.secrets/token.json` locally. Set `FRONTEND_URL` in `.env` if the UI is not at `http://127.0.0.1:3000`.

---

## 1. Prerequisites

1. Google Cloud project
2. Gmail API enabled
3. OAuth client — either **Web application** (Setup page / browser redirect above) or **Desktop app** (`scripts/setup_gmail.py`)

Recommended flow in Google Cloud:
1. Configure OAuth consent screen
2. Choose `External` if using personal Gmail
3. Add yourself as a test user
4. Create OAuth client (**Web application** for `/setup`, or **Desktop app** for the Python script)
5. For Desktop: download the client JSON; for Web: copy Client ID and secret and set the redirect URI as above

## 2. Configure the OAuth client (pick one)

### Option A — `.env` (recommended for teams)

In repo root `.env`, set the OAuth client from Google Cloud (same values work for Web or Desktop flows):

```bash
GMAIL_OAUTH_CLIENT_ID=....apps.googleusercontent.com
GMAIL_OAUTH_CLIENT_SECRET=...
```

Do not commit `.env`. Each developer can use their own Google Cloud project or share a test client ID (with test users on the consent screen).

### Option B — JSON file

```bash
cd /path/to/websecurity
mkdir -p .secrets
cp /path/to/downloaded-client.json .secrets/secrets.json
```

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
3. Writes the token (default `GMAIL_TOKEN_PATH` or `.secrets/token.json`) and stores the signed-in Gmail address inside the token JSON

You can leave `GMAIL_ACCOUNT` empty in `.env`: the app uses the address from the token (or you can set `GMAIL_ACCOUNT` to match for clarity).

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

Frontend (Next.js):
```bash
cd /Users/pramodthebe/Desktop/websecurity/frontend-next
NEXT_PUBLIC_EMAIL_API_BASE=http://127.0.0.1:8000 npm run dev
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
