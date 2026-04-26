# AUNIX — Step-by-Step Deploy Guide

This walks you through running AUNIX locally end-to-end first, then deploying it
publicly on Render's free tier. Total time: ~30–45 minutes for local, +20 minutes
for cloud.

You'll need a Mac or Linux machine for development. The scanner agent itself
runs on any Linux/macOS target you want to audit.

---

## Part 1 — Local development (run everything on your laptop)

### 1.1 Install prerequisites

You need:

- **Python 3.10+** — `python3 --version`
- **PostgreSQL 13+** — `psql --version`
- **Node.js** is *not* required (the frontend is plain static files)
- **OpenSSH client tools** — `ssh-keygen --version` (already installed on Mac
  and most Linux distros)

If you're missing Postgres on macOS:
```
brew install postgresql@16
brew services start postgresql@16
```

On Ubuntu/Debian:
```
sudo apt install postgresql postgresql-contrib
sudo systemctl start postgresql
```

### 1.2 Get the code

Extract the tarball you were given, or clone from your repo:
```
tar -xzf aunix_project.tar.gz
cd aunix
```

Project layout:
```
aunix/
├── backend/             FastAPI server
├── frontend/            Static site (HTML/CSS/JS)
├── agent_template/      Files baked into each agent download
├── render.yaml
├── .env.example
└── README.md
```

### 1.3 Create the database

```
createdb aunix
```

If you get a permissions error, run it as the `postgres` user:
```
sudo -u postgres createdb aunix
sudo -u postgres createuser --superuser $(whoami)   # one-time setup
```

Verify:
```
psql aunix -c "SELECT version();"
```

### 1.4 Set up the backend

```
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Create a `.env` file in the **project root** (not in `backend/`):
```
cd ..   # back to aunix/
cp .env.example .env
```

Edit `.env`. For local dev, set:

```
DATABASE_URL=postgresql+psycopg2://localhost:5432/aunix
JWT_SECRET=<generate one — see below>
JWT_EXPIRY_HOURS=24
PUBLIC_API_URL=http://127.0.0.1:8000/api
CORS_ORIGINS=http://127.0.0.1:5500,http://localhost:5500
```

Generate a JWT secret:
```
python3 -c "import secrets; print(secrets.token_urlsafe(64))"
```
Paste the output as the value of `JWT_SECRET`.

### 1.5 Start the backend

From the `aunix/` root:
```
cd backend
source .venv/bin/activate
set -a && source ../.env && set +a   # exports the env vars
uvicorn main:app --reload --port 8000
```

You should see something like:
```
INFO:     Uvicorn running on http://127.0.0.1:8000
INFO:     Application startup complete.
```

Sanity-check it works:
```
curl http://127.0.0.1:8000/healthz
# {"ok":true}
```

Tables get created automatically on first startup.

### 1.6 Start the frontend

In a **second terminal**, from `aunix/`:
```
cd frontend
python3 -m http.server 5500
```

Open <http://localhost:5500> in your browser.

If you use VS Code, the **Live Server** extension is nicer (right-click
`index.html` → "Open with Live Server"). Same default port 5500.

### 1.7 Register your first user

1. Click **Register here** on the login screen.
2. Enter name, email, and a password (8+ chars).
3. A QR code appears. Open Google Authenticator / 1Password / Authy on your
   phone and scan it.
4. Enter the 6-digit code shown in the app.
5. You're logged in.

If something goes wrong, check the backend terminal for the error.

### 1.8 Register and scan your first machine

1. Sidebar → **Register a New Machine**.
2. Hostname: anything. IP and OS are optional. Click Register.
3. The browser auto-downloads `aunix-agent-1.tar.gz` and shows the run
   command in a modal. Copy the command.
4. Open a terminal **on the machine you want to audit** (your laptop is fine
   for testing).
5. Move the tarball there if needed (`scp` or just keep it on your laptop).
6. Run:
   ```
   tar -xzf aunix-agent-1.tar.gz
   cd aunix-agent-1
   sudo ./run.sh
   ```
7. The scanner finds keys, fingerprints them with `ssh-keygen`, and posts to
   the backend. You'll see something like:
   ```
   Scanning for SSH keys...
     candidate files: 47
     fingerprinted keys: 12
   Uploading to http://127.0.0.1:8000/api (target_id=1)...
   Upload OK:
   {"message":"Scan results uploaded successfully", ...}
   ```
8. Refresh the dashboard. The Fleet Overview shows real numbers and the
   Per-Machine Detail view has your machine's keys.

> **Note:** If the agent is on a different machine than the backend, you'll
> need to either expose port 8000 to that machine or use the deployed
> version. The agent in this case has `api_url=http://127.0.0.1:8000/api`
> baked in — that only works if the agent runs on the same host as the
> backend.

### 1.9 Common local issues

**"Address already in use" on port 8000 or 5500.** Kill the previous process:
```
lsof -i :8000          # find PID
kill -9 <PID>
```

**"could not connect to server: Connection refused" from psycopg2.**
Postgres isn't running. `brew services start postgresql@16` (Mac) or
`sudo systemctl start postgresql` (Linux).

**Backend starts but the frontend gets CORS errors in the browser console.**
Confirm your frontend URL (what's in the address bar) is in `CORS_ORIGINS`
in `.env`, then restart the backend.

**MFA QR code doesn't appear.** Look at the backend terminal. If you see a
`qrcode` or `PIL` import error, run `pip install qrcode[pil]` inside the venv.

---

## Part 2 — Deploy to Render (free tier)

Render hosts the API, the frontend, and Postgres on one platform. Free tier
covers everything (Postgres is free for 90 days, then $7/mo).

### 2.1 Push the code to GitHub

Create a new GitHub repo (private is fine), then:
```
cd aunix
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin git@github.com:<you>/aunix.git
git push -u origin main
```

Make sure `.env` is **not** committed — there's already a sensible
`.gitignore` if you generated one with the framework, but double-check:
```
git ls-files | grep -F .env
# should be empty
```

If `.env` is tracked, untrack it:
```
git rm --cached .env
echo ".env" >> .gitignore
git commit -am "Ignore .env"
git push
```

### 2.2 Create a Render account

1. Go to <https://dashboard.render.com>.
2. Sign up with GitHub. Authorize Render to read your repos.

### 2.3 Deploy via Blueprint

1. Dashboard → **New** → **Blueprint**.
2. Pick the `aunix` repo. Render reads `render.yaml`.
3. It proposes three services:
   - `aunix-api` (web service, FastAPI)
   - `aunix-web` (static site, frontend)
   - `aunix-db` (Postgres)
4. Click **Apply**. Wait 3–5 minutes for the first deploy. Postgres comes
   up first; the API service waits for it.

When it finishes, you'll have three URLs. Note them — you'll need two:
- API URL, e.g. `https://aunix-api-abcd.onrender.com`
- Static site URL, e.g. `https://aunix-web-wxyz.onrender.com`

### 2.4 Fill in the env vars Render couldn't infer

Render set `DATABASE_URL` and `JWT_SECRET` automatically. Two are still
blank because Render can't know your URLs in advance.

Go to **aunix-api** → **Environment**, and set:

| Key | Value |
|---|---|
| `PUBLIC_API_URL` | `https://aunix-api-abcd.onrender.com/api` |
| `CORS_ORIGINS`   | `https://aunix-web-wxyz.onrender.com` |

Click **Save Changes**. Render redeploys the API automatically (~1 minute).

### 2.5 Point the frontend at the deployed API

Edit `frontend/index.html`. **Right before** `<script src="script.js"></script>`,
add:

```html
<script>
  window.AUNIX_CONFIG = {
    apiBase: "https://aunix-api-abcd.onrender.com/api"
  };
</script>
<script src="script.js"></script>
```

Replace the URL with **your** API URL. Commit and push:
```
git commit -am "Point frontend at deployed API"
git push
```

The static site auto-redeploys (~30 seconds).

### 2.6 Verify the deployed app

1. Open your static site URL.
2. Register a new user (the QR code is generated server-side).
3. Register a machine. The downloaded tarball will phone home to the
   deployed API.
4. On any Linux/macOS machine you want to audit:
   ```
   tar -xzf aunix-agent-1.tar.gz
   cd aunix-agent-1
   sudo ./run.sh
   ```
   This time `config.json` has the public API URL, so the agent uploads
   correctly even from another network.
5. Refresh the dashboard. Data shows up.

### 2.7 The free-tier sleep behavior

The free Render web service spins down after 15 minutes of inactivity. The
first request after sleep takes ~30 seconds to wake up (you'll see a spinner
in the browser; the API will eventually respond).

If that's annoying for a demo, two options:
- Upgrade `aunix-api` to the $7/mo Starter plan — no sleep.
- Use UptimeRobot (free) to ping `/healthz` every 5 minutes. This keeps the
  service warm. Some consider this against Render's terms but it's a common
  practice.

### 2.8 The 90-day Postgres limit

Render's free Postgres expires after 90 days. Two paths:
- **Pay $7/mo** to keep the same database.
- **Move to Supabase free Postgres** (forever-free up to 500MB). Steps:
  1. Sign up at <https://supabase.com>, create a new project.
  2. Settings → Database → "Connection string" → pick the **Session pooler**
     URI. Copy it.
  3. In Render, on `aunix-api` → Environment, replace `DATABASE_URL` with
     the Supabase string.
  4. Save. Render redeploys. Tables auto-create on startup.
  5. In Render, you can now delete the `aunix-db` service.

---

## Part 3 — How to use it day-to-day

Once deployed, the workflow is:

1. Log in.
2. Register every machine you want to audit.
3. Distribute the agent package to each (scp, email, etc.).
4. Run `sudo ./run.sh` on each machine. Schedule it as a cron job for
   recurring scans:
   ```
   # Re-scan nightly at 2am
   0 2 * * * /opt/aunix-agent/run.sh >> /var/log/aunix.log 2>&1
   ```
5. Watch the **Fleet Overview** for headline numbers and risk trends.
6. Use the **Top Risk Machines** list to prioritize remediation.
7. For each high-priority machine, switch to **Per-Machine Detail** to see
   exactly which keys to fix.
8. Export a CSV report any time from the sidebar.

---

## Troubleshooting

**Agent says "ssh-keygen not found in PATH" and finds 0 keys.**
Install OpenSSH client tools on the target:
- Debian/Ubuntu: `sudo apt install openssh-client`
- RHEL/CentOS: `sudo dnf install openssh-clients`
- macOS: already installed.

**Agent uploads but dashboard still shows 0 keys.**
Check the dashboard's **My Machines** section. The `last_scan_at` column
should show a recent timestamp. If it does but Fleet Overview shows nothing,
make sure you're looking at the right user account (each user only sees
their own machines).

**"Invalid agent token" errors from the agent.**
The token was rotated. Re-download the agent (sidebar → My Machines →
Re-download agent) and use the fresh tarball.

**Logged out unexpectedly.**
JWTs expire after 24 hours by default. Just log in again. To extend,
increase `JWT_EXPIRY_HOURS` in the API env vars.

**Free tier API is slow on first request after a break.**
That's the 15-minute sleep waking up. Subsequent requests within the next
15 minutes are fast. Either upgrade to Starter, or use UptimeRobot to keep
it warm.
