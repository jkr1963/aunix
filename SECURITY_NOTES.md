# AUNIX Security Notes — Agent Protection

## Why "encrypting" the scanner agent is impossible in the strict sense

The AUNIX scanner agent is Python code that must run on the target machine.
For the code to execute, the CPU must see plaintext instructions. This means
**any technique that obscures the code is removable by anyone with sufficient
patience**, because the executable form has to exist *somewhere* on the target.

This applies equally to:

- **Bytecode compilation** (`.pyc`) — Python bytecode is well-documented and
  trivially decompiled with tools like `decompyle3` or `uncompyle6`.
- **PyArmor / Sourcedefender / similar** — these are stronger but still
  reversible. They wrap the code in a runtime that decrypts it in-memory at
  startup. An attacker can dump that in-memory representation.
- **Cython compilation to C extensions** — produces native code, but the
  scanner's network requests, file paths, and bearer tokens are all still
  visible via static analysis or runtime instrumentation (e.g., `strace`).
- **Binary packaging via PyInstaller or Nuitka** — bundles the interpreter
  and bytecode into one executable. Same decompilation routes apply.

For a script designed to inspect filesystem state, no protection technique is
both practical to deploy and unbreakable. The threat is the same one faced by
every closed-source application: if it runs on hardware you control, you can
reverse-engineer it.

## What AUNIX actually defends against

Rather than pretending the agent is encrypted, we defend against the
realistic threats:

### Threat 1 — A stolen tarball uploads spoofed scan results

**Defense:** Per-scan agent token rotation.

Each agent download issues a fresh agent token (a 32-byte URL-safe random
string), stored as SHA-256 in the backend database. On every successful scan
upload, the backend issues a new token in the response, and the agent
overwrites its `config.json`. The old token is no longer valid.

Implications:

- An attacker who steals a tarball BEFORE the legitimate user has run
  it gets one upload. The legitimate user's first scan attempt then fails
  with 401 — surfacing the tampering.
- An attacker who steals a tarball AFTER any successful scan gets a token
  that is already invalid.
- A man-in-the-middle who reads a single scan upload sees a token that
  is invalidated the moment the request lands. They cannot replay it.

### Threat 2 — A user shares their tarball with someone else

**Defense:** Per-target tokens scoped to a single target_id, plus
per-scan rotation.

A shared tarball can scan the original target machine but cannot register
new targets, cannot view other users' targets, and cannot do anything in
the dashboard. The shared tarball also rotates after one use.

The dashboard enforces all data scoping by `user_id`; the agent token gives
write-only access to scan results for one specific target row.

### Threat 3 — A persistent attacker with root on the target

**Honest answer:** Not defendable. If an attacker has persistent root on
the target, they can read `config.json`, see the rotated token after each
scan, and exfiltrate data alongside the legitimate flow. This is true of
any agent-based monitoring tool (CrowdStrike, Datadog, Splunk Forwarder).

The expected response in this scenario is: AUNIX itself reports the
findings that explain the compromise (loose key permissions, suspicious
authorized_keys entries, unrotated keys with broad access), giving the
operator the signal needed to investigate.

## What the obfuscation step actually does

The agent that ships in the tarball has been:

1. **Stripped of docstrings** — function and class documentation removed.
2. **Stripped of comments** — `#` lines collapsed.
3. **Blank lines collapsed** to single blanks.

Result: roughly a 25–30% file-size reduction and visibly less readable code.
**This is a speed bump, not a wall.** A motivated attacker spends 30 minutes
re-formatting the source and adding their own comments. We ship it because:

- It demonstrates that we don't expect the agent to be casually browsed.
- It removes inline documentation that might unnecessarily explain the
  detection rules to someone trying to evade them.

We do NOT claim it provides cryptographic protection. The **token rotation**
is what does the security work.

## Token mechanics in detail

### Storage on the server

The plaintext agent token is **never** stored. We compute SHA-256 of it and
store the digest in `target_machines.agent_token_hash`. A database leak of
this column does not leak any agent credentials.

### Storage on the client

The plaintext token lives in `aunix-agent-N/config.json` with file
permissions `0600`. On a multi-user system this prevents non-root users
from reading the token. It does not, of course, protect against root
attackers (see Threat 3).

### Rotation cadence

- **On download:** a new token is issued every time the user clicks
  "Download agent" from the dashboard. The previous token (if any) is
  invalidated.
- **On scan:** every successful upload to `/api/scan-results` returns a
  new token in `rotated_agent_token`, which the agent persists.

This means a typical agent's token has a useful lifetime of one scan run,
typically minutes.

### Failure modes

- **Network fails mid-rotation:** The backend has already committed the
  new token; the agent didn't see the response. Next scan attempt fails
  with 401. Recovery: re-download the agent from the dashboard.
- **Two scans interleave:** Last writer wins. Only one of the two scans
  has its data persisted; the other gets 401. In practice the agent is
  invoked manually via `sudo ./run.sh`, so concurrent runs are rare.
