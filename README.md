# AUNIX — Audit for Unix

SSH key inventory dashboard. Register machines, run an agent on each, view
discovered keys, permissions, and pairing status in one place.

## Project layout

```
aunix/
├── backend/             FastAPI app
│   ├── main.py
│   ├── database.py
│   ├── models.py
│   ├── schemas.py
│   ├── security.py
│   ├── deps.py
│   ├── agent_builder.py
│   ├── routers/         auth, targets, keys, scan_results, installers
│   └── requirements.txt
├── frontend/            Static site (HTML/CSS/JS)
│   ├── index.html
│   ├── script.js
│   └── styles.css
├── agent_template/      Files packaged into each agent tarball
│   ├── aunix_scan.py
│   ├── run.sh
│   └── README.txt
├── render.yaml          One-click Render deploy
└── .env.example
```

## How it fits together

1. User registers and logs in (email + password + TOTP).
2. User registers a machine through the dashboard. The API generates a per-target
   agent token and includes it in a downloadable `.tar.gz` package.
3. User extracts the tarball on the target machine and runs `sudo ./run.sh`.
4. The agent fingerprints SSH keys with `ssh-keygen` and POSTs to
   `/api/scan-results` using its agent token as a Bearer credential.
5. The dashboard polls `/api/keys?target_id=...` and renders the inventory.

Two distinct credentials:
- **JWT** for the dashboard user (browser → API).
- **Agent token** per target machine (scanner → API). Stored hashed in the DB.
  Re-issued whenever the user re-downloads the agent.

## Local development

### 1. Backend

```
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp ../.env.example .env  # then edit values
export $(cat .env | xargs)
uvicorn main:app --reload --port 8000
```

Postgres needs to exist; create the database first:
```
createdb aunix
```

### 2. Frontend

The frontend is plain static files. Easiest is the VS Code Live Server
extension (port 5500) or:

```
cd frontend
python -m http.server 5500
```

Open http://localhost:5500. The default `API_BASE` in `script.js` points at
`http://127.0.0.1:8000/api`.

### 3. Run the scanner against your local API

For testing the agent without going through the dashboard:

```
cd agent_template
echo '{"target_id":1,"agent_token":"<paste_from_register_response>","api_url":"http://127.0.0.1:8000/api"}' > config.json
sudo ./run.sh
```

Or use `--no-upload` to preview a scan without sending it anywhere.

## Deploying to Render (free tier)

Render hosts the API, the static frontend, and Postgres on a single platform.
The free tiers cover all three (Postgres is free for 90 days, then $7/mo).

### Steps

1. Push this repo to GitHub.
2. Go to https://dashboard.render.com → **New** → **Blueprint**.
3. Connect your GitHub repo. Render reads `render.yaml` and offers to create
   the API service, the static site, and the Postgres database.
4. After the first deploy, fill in the two env vars Render couldn't infer:
   - On `aunix-api`, set `PUBLIC_API_URL` to
     `https://aunix-api-XXXX.onrender.com/api` (replace with your actual URL).
   - On `aunix-api`, set `CORS_ORIGINS` to your static site URL,
     e.g. `https://aunix-web-XXXX.onrender.com`.
5. On the static site (`aunix-web`), edit `frontend/index.html` to add
   the API base before the script tag:
   ```html
   <script>
     window.AUNIX_CONFIG = { apiBase: "https://aunix-api-XXXX.onrender.com/api" };
   </script>
   <script src="script.js"></script>
   ```
   Commit and push — Render auto-redeploys.
6. Visit your static site URL and register the first user.

### Notes on the free tier

- The web service spins down after 15 minutes of inactivity. The first
  request after that takes ~30 seconds to wake up. Subsequent requests are fast.
- The free Postgres is good for 90 days. Two options after that:
  - Upgrade to the $7/mo plan, or
  - Switch the `DATABASE_URL` env var to a free Supabase Postgres connection
    string and redeploy. No code changes needed.

## Forever-free alternative: Render + Supabase

If you want to avoid the 90-day Postgres limit:

1. Create a free Supabase project at https://supabase.com.
2. Settings → Database → copy the connection string (use the "Session pooler"
   URI for compatibility).
3. In Render, remove the `databases:` block from `render.yaml` and instead
   set `DATABASE_URL` manually to the Supabase string.
4. Redeploy.

## Security notes

- JWTs use HS256 with a server-side secret. Rotate `JWT_SECRET` to invalidate
  all sessions.
- Agent tokens are stored as SHA-256 hashes in the DB. The plaintext token
  only exists in the downloaded tarball.
- Re-downloading an agent rotates the token; the previous one stops working.
- The dashboard never displays agent tokens after the first creation response.
- This project does not yet implement email verification or rate limiting.
  For a public deployment beyond a capstone demo, add both before going live.
