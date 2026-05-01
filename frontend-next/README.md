# Next.js Frontend

This folder contains the replacement UI for the email security app.

## Run

```bash
cd /Users/pramodthebe/Desktop/websecurity/frontend-next
npm install
npm run dev
```

By default the app talks to the FastAPI email backend at `http://127.0.0.1:8000`.

If you need a different API URL, set:

```bash
NEXT_PUBLIC_EMAIL_API_BASE=http://127.0.0.1:8000
```
