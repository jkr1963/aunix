# AUNIX — Local Setup Guide (MacBook Air M1)

This walks you through running AUNIX entirely on your MacBook from scratch.
By the end you'll have:

- A FastAPI backend running on `http://localhost:8000`
- A static frontend running on `http://localhost:5500`
- A Postgres database on your laptop
- The scanner agent running against your own machine and reporting back to
  the dashboard

Total time: ~45 minutes if everything goes smoothly.

---

## Step 0 — What you should have already

- macOS on an Apple Silicon Mac (M1 / M2 / M3 — same instructions)
- Admin access to your laptop (you'll need `sudo` for the scanner)
- The `aunix_project.tar.gz` file I gave you, OR the `aunix/` folder

If you only have the tarball, extract it first:
```
cd ~/Desktop
tar -xzf aunix_project.tar.gz -C ~/Desktop/aunix-project
```
And from now on `~/Desktop/aunix-project` is your project root. Wherever
this guide says "the project root", that's what it means.

> **About the terminal:** Open Terminal.app (or iTerm2) for everything below.
> Each step says exactly which directory to be in. If you get lost, run `pwd`
> to see where you are.

---

## Step 1 — Install Homebrew (if you don't have it)

Homebrew is the package manager for macOS. Check if it's installed:

```
brew --version
```

If you see a version number, skip to Step 2.

If you see "command not found", install it:

```
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

When it finishes, it'll print **"Next steps"** with two commands to add Brew
to your shell PATH. They'll look like this (the exact path is `/opt/homebrew`
on M1, not `/usr/local`):

```
echo >> ~/.zprofile
echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zprofile
eval "$(/opt/homebrew/bin/brew shellenv)"
```

Run those, then verify:
```
brew --version
which brew
# /opt/homebrew/bin/brew
```

---

## Step 2 — Install the things AUNIX needs

```
brew install python@3.12 postgresql@16
```

This pulls in Python 3.12 and Postgres 16. OpenSSH client tools (`ssh-keygen`)
are already on macOS — you don't need to install those.

Verify versions:

```
python3 --version          # Python 3.12.x
psql --version             # psql (PostgreSQL) 16.x
ssh-keygen --version 2>&1 | head -1   # OpenSSH_X.X
```

> **If `python3 --version` shows something older than 3.10**, that's macOS's
> built-in Python being preferred. Fix the PATH:
> ```
> echo 'export PATH="/opt/homebrew/opt/python@3.12/bin:$PATH"' >> ~/.zprofile
> source ~/.zprofile
> python3 --version  # should now be 3.12
> ```

---

## Step 3 — Start Postgres and create the database

Start the Postgres service so it runs in the background:

```
brew services start postgresql@16
```

Wait 5 seconds for it to come up. Then verify:

```
brew services list
# postgresql@16  started  ...
```

Now create the database and the user. On a fresh Brew install of Postgres,
your Mac username automatically becomes a superuser, so this works:

```
createdb aunix
```

Verify it exists:

```
psql aunix -c "SELECT current_database(), current_user;"
```

You should see one row with `aunix` and your username.

> **If `createdb` says "command not found"**, Postgres binaries aren't on
> your PATH. Fix it:
> ```
> echo 'export PATH="/opt/homebrew/opt/postgresql@16/bin:$PATH"' >> ~/.zprofile
> source ~/.zprofile
> ```
>
> **If you see "FATAL: role does not exist"**, create the role:
> ```
> /opt/homebrew/opt/postgresql@16/bin/createuser -s $(whoami)
> ```

---

## Step 4 — Get the AUNIX code in place

If you extracted the tarball already, skip this. Otherwise:

```
cd ~/Desktop
mkdir aunix-project
cd aunix-project
tar -xzf ~/Downloads/aunix_project.tar.gz
ls
```

You should see:
```
DEPLOY_GUIDE.md   agent_template   frontend         render.yaml
LOCAL_SETUP_MAC.md  backend        README.md
.env.example
```

From here on, **the project root is `~/Desktop/aunix-project`** (or wherever
you extracted to). Every step below either uses this root or a subfolder of it.

---

## Step 5 — Set up the Python virtual environment

A venv keeps AUNIX's Python packages isolated from your system Python. From
the project root:

```
cd backend
python3 -m venv .venv
source .venv/bin/activate
```

Your prompt should now show `(.venv)` at the front. That means you're inside
the venv. Install the dependencies:

```
pip install --upgrade pip
pip install -r requirements.txt
```

This takes ~1 minute. Watch for any red error lines. If everything succeeds,
you'll see something like:
```
Successfully installed bcrypt-4.0.1 fastapi-0.115.0 PyJWT-2.9.0 ... uvicorn-0.30.6
```

> **If `pip install` fails on `psycopg2-binary`** with a compiler error:
> that package usually has prebuilt wheels for M1, but if it doesn't, run:
> ```
> brew install libpq
> export LDFLAGS="-L/opt/homebrew/opt/libpq/lib"
> export CPPFLAGS="-I/opt/homebrew/opt/libpq/include"
> pip install psycopg2-binary
> ```

Stay in the `(.venv)` for the next steps. If you close the terminal and come
back later, you'll need to re-activate it:
```
cd ~/Desktop/aunix-project/backend
source .venv/bin/activate
```

---

## Step 6 — Configure environment variables

The backend reads its config from environment variables. For local dev, the
easiest way is a `.env` file in the **project root** (NOT in `backend/`).

From the project root:

```
cd ~/Desktop/aunix-project
cp .env.example .env
```

Open `.env` in any editor:
```
open -e .env
```
(That opens TextEdit. Or use `code .env` if you have VS Code, or
`nano .env` for terminal editing.)

Generate a JWT secret:
```
python3 -c "import secrets; print(secrets.token_urlsafe(64))"
```
Copy that long random string. Then edit `.env` to look like this:

```
DATABASE_URL=postgresql+psycopg2://localhost:5432/aunix
JWT_SECRET=<paste the long string you just generated>
JWT_EXPIRY_HOURS=24
PUBLIC_API_URL=http://127.0.0.1:8000/api
CORS_ORIGINS=http://127.0.0.1:5500,http://localhost:5500
```

Save and close.

> **Important:** the line for `DATABASE_URL` has no username or password.
> That's correct on macOS Homebrew Postgres — it uses your OS username and
> trusts local connections without a password.

---

## Step 7 — Start the backend

You need to make sure the venv is active AND the env vars are loaded.

From the project root:

```
cd ~/Desktop/aunix-project/backend
source .venv/bin/activate
set -a && source ../.env && set +a
uvicorn main:app --reload --port 8000
```

What's happening on those lines:
- `source .venv/bin/activate` — turn on the Python venv
- `set -a` — tell bash to auto-export every variable assignment
- `source ../.env` — read the `.env` file (which assigns variables)
- `set +a` — turn auto-export back off
- `uvicorn ...` — start the FastAPI server

You should see:

```
INFO:     Will watch for changes in these directories: [...]
INFO:     Uvicorn running on http://0.0.0.0:8000
INFO:     Started reloader process
INFO:     Started server process
INFO:     Waiting for application startup.
INFO:     Application startup complete.
```

In a **second terminal window**, verify the API is up:

```
curl http://127.0.0.1:8000/healthz
# {"ok":true}
```

And check the auto-generated API docs in your browser:
http://127.0.0.1:8000/docs

You'll see all the endpoints (auth, targets, keys, scan-results, installers,
dashboard). On first startup the backend creates all the database tables
automatically — you can confirm:

```
psql aunix -c "\dt"
# user_accounts | target_machines | ssh_key_inventory
```

> **Leave this terminal running.** The backend keeps logging requests as you
> use the app. Don't close it. To stop the backend later: `Ctrl-C`.

---

## Step 8 — Start the frontend

In a **second terminal window** (the first is busy running the backend),
go to the project root:

```
cd ~/Desktop/aunix-project/frontend
python3 -m http.server 5500
```

You'll see:
```
Serving HTTP on :: port 5500 (http://[::]:5500/) ...
```

Open in your browser: http://localhost:5500

You should see the AUNIX login screen.

> **If the page is blank**, open Chrome DevTools (Cmd-Option-I) → Console.
> Look for red errors. If they say "Failed to load script.js" or similar,
> make sure you started the http.server from inside `frontend/` and not
> from the project root. Use `pwd` to verify.

---

## Step 9 — Register your first user

In the browser:

1. Click **Register here** at the bottom of the login card.
2. Fill in:
   - Name: anything
   - Email: anything (doesn't have to be real for local dev)
   - Password: at least 8 characters
   - Confirm password: same
3. Click Submit.
4. A QR code appears.
5. On your phone, open Google Authenticator (or 1Password, Authy, Microsoft
   Authenticator — any TOTP app works). Tap "+" → "Scan a QR code" → point
   at your laptop screen.
6. Your phone now shows a 6-digit code that refreshes every 30 seconds.
7. Type that code into the field below the QR.
8. Click **Activate MFA**.

You'll be auto-logged-in. The dashboard says "Welcome, <your name>".

The Fleet Overview is empty — that's expected; you haven't registered any
machines yet.

> **If the QR code never appears**, check the backend terminal. You may see
> a `qrcode` import error. Reinstall it inside the venv:
> ```
> # In the backend terminal: Ctrl-C to stop, then:
> pip install --force-reinstall 'qrcode[pil]'
> # Then restart uvicorn (Step 7's command).
> ```

---

## Step 10 — Register a machine and download the agent

We're going to register your own MacBook as a target and scan it.

1. In the sidebar (click the ☰ icon top-left), click **Register a New Machine**.
2. Fill in:
   - Hostname: `my-mac` (or whatever)
   - IP Address: leave blank (optional)
   - Operating System: `macOS 14` (or whatever you have)
3. Click Register.

Two things happen automatically:

- A file called `aunix-agent-1.tar.gz` (or `aunix-agent-2.tar.gz`, etc.,
  depending on how many machines you've registered) downloads to your
  `~/Downloads` folder.
- A modal appears showing the install command, with a **Copy command** button.

Don't close the modal yet. The command shown is:
```
tar -xzf aunix-agent-1.tar.gz && cd aunix-agent-1 && sudo ./run.sh
```

---

## Step 11 — Run the scanner

Open a **third terminal window** (or use the second one if your backend is
in the first). The frontend's http.server can stay running on port 5500;
that's fine.

```
cd ~/Downloads
tar -xzf aunix-agent-1.tar.gz
cd aunix-agent-1
ls
```

You should see:
```
README.txt    aunix_scan.py    config.json    run.sh
```

Look at `config.json` — it has the target ID, agent token, and API URL the
backend baked in:
```
cat config.json
```

Now run the scanner:

```
sudo ./run.sh
```

It'll ask for your Mac password (because of `sudo`). Enter it.

You'll see output like:

```
===========================================
AUNIX SSH key scanner
Working directory: /Users/you/Downloads/aunix-agent-1
Using Python: /opt/homebrew/bin/python3
===========================================
Scanning for SSH keys...
  candidate files: 8
  fingerprinted keys: 4
Uploading to http://127.0.0.1:8000/api (target_id=1)...
Upload OK:
{"message":"Scan results uploaded successfully","target_id":1,"scan_type":"agent","records_inserted":4}
```

Numbers will vary depending on how many SSH keys you have on your Mac.

If you've never used SSH, you might have 0–2 keys. That's fine — you'll still
see the scan in the dashboard, just with fewer rows.

> **If you see "ssh-keygen not found in PATH"**, the agent ran with a stripped
> `sudo` PATH. Try:
> ```
> sudo env "PATH=$PATH" ./run.sh
> ```
>
> **If you see "Network error: Cannot connect to 127.0.0.1:8000"**, your
> backend isn't running. Go back to Step 7. The backend terminal should still
> have uvicorn running. If it crashed, scroll up in that terminal to see why.

---

## Step 12 — See your results in the dashboard

Go back to your browser at http://localhost:5500.

Click **Refresh** in the sidebar (or just wait — the page polls every 30
seconds). You should now see:

- **Fleet Overview**: real numbers in the KPI strip. Total machines: 1.
  SSH keys: whatever was found.
- **Top Risk Machines**: your Mac, with its severity counts.
- **Algorithm Distribution**: a chart showing which SSH key algorithms you have.
- **Key Staleness / Key Age**: histograms.
- **Per-Machine Detail** (click in the sidebar): the full keys table with
  severity badges and findings.

If your Mac has standard `~/.ssh/id_ed25519` keys with proper permissions,
you'll see mostly "info"-level entries and a clean dashboard.

If you have weak permissions on private keys, RSA-1024 keys, or keys outside
standard SSH directories, you'll see findings light up in red and orange.
That's the whole point — it's auditing **your** machine.

---

## Step 13 — Try a re-scan

Once everything works once, you can re-run the scanner any time:

```
cd ~/Downloads/aunix-agent-1
sudo ./run.sh
```

It overwrites the previous scan results for that machine. Useful for
testing — make a change (e.g., `chmod 644 ~/.ssh/id_ed25519` to deliberately
weaken a permission), re-scan, and watch a new Critical finding appear in
the dashboard. Don't forget to set it back: `chmod 600 ~/.ssh/id_ed25519`.

---

## Daily startup cheat sheet

Once everything is set up, here's what you do each time you want to develop:

**Terminal 1 — backend:**
```
cd ~/Desktop/aunix-project/backend
source .venv/bin/activate
set -a && source ../.env && set +a
uvicorn main:app --reload --port 8000
```

**Terminal 2 — frontend:**
```
cd ~/Desktop/aunix-project/frontend
python3 -m http.server 5500
```

Then open http://localhost:5500.

To stop everything: `Ctrl-C` in each terminal. Postgres keeps running in the
background — that's fine, leave it. If you ever want to stop it:
```
brew services stop postgresql@16
```

---

## What to do when something breaks

### "Address already in use" on port 8000 or 5500

Something else is using the port. Find and kill it:
```
lsof -i :8000
# Note the PID, then:
kill -9 <PID>
```

### "Connection refused" trying to reach the backend

The backend isn't running. Check Terminal 1. If uvicorn crashed, look at
the last few lines for the error.

### Backend logs show "could not connect to server" from psycopg2

Postgres isn't running. Start it:
```
brew services start postgresql@16
```

### CORS errors in the browser DevTools console

The frontend URL isn't in `CORS_ORIGINS`. Check what the address bar shows
(probably `http://localhost:5500` or `http://127.0.0.1:5500`) and confirm
it's in your `.env`. Then restart the backend (Step 7) — env vars are read
once at startup.

### "Invalid agent token" when running `run.sh`

You re-downloaded the agent (which rotates the token) but kept using the
old tarball. Delete the old folder and start fresh:
```
rm -rf ~/Downloads/aunix-agent-1*
```
Re-download from the dashboard (sidebar → My Machines → Re-download agent).

### MFA code says "Invalid OTP"

Two possibilities:
1. Your Mac's clock is more than 30 seconds out of sync. Fix:
   System Settings → General → Date & Time → "Set time and date
   automatically" ON.
2. You used the code right at the 30-second flip. The current code on your
   phone is the one to use.

### "fingerprinted keys: 0" but you definitely have keys

Run the scanner with verbose output:
```
sudo ./aunix_scan.py --no-upload
```
This prints the JSON it would upload. If it says zero keys but you have
`~/.ssh/id_ed25519`, the scanner may not be looking in your home directory
because of how `sudo` resets `$HOME`. Try:
```
sudo HOME="$HOME" ./run.sh
```

### Need to wipe and start over

```
# Stop the backend (Ctrl-C)
dropdb aunix
createdb aunix
# Restart the backend - tables auto-create on startup
```

This deletes ALL users, machines, and scan data. New `.env` not needed —
just restart uvicorn.

---

When this is all working, go back to the `DEPLOY_GUIDE.md` for the cloud
deployment steps.
