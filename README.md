# Particle Masterserver

A minimal, standalone discovery/signaling server for the Particle Global OS
Network Layer (see the Particle Network Layer design plan for the full
specification). It is a **doorway, not an authority**:

- Introduces peers (session proof, dynamic route attach, signal relay)
- Never sees group membership, real identity, or payload content
- Keeps **no persistent logs** — sessions/routes/dedupe cache are in-memory only and reset on restart

This is the same server the default `discovery.particlerealms.online` deployment
runs. Anyone can self-host their own instance and add it to a client's master
server list (`engine/network/routes/MasterServerList.js`).

## What this server can / cannot do

**Can:**
- Assign temporary session ids and verify a client controls its claimed key (`HELLO`/`PROVE`)
- Create/track dynamic, opaque routes (`ATTACH_ROUTE`/`DETACH_ROUTE`)
- List other live subscribers of a route (`DISCOVER` → `PEERS`)
- Relay small signaling payloads between route subscribers (`SIGNAL`/`FORWARD`/`PUBLISH`), with TTL, dedupe, and rate limits

**Cannot:**
- Create group members, override votes, or read group data
- Decrypt or meaningfully inspect relayed payloads (opaque to this server)
- Ban anyone from a private group, or persist any history after restart

## Quick start (any machine with Python 3.11+)

No virtual environment — dependencies install directly against your system
Python. If you'd rather isolate them yourself, create/activate a venv before
running these scripts; they just call `python`/`python3` as found on PATH.

**Easiest — installer + launcher scripts** (separate steps, so re-running the
installer never interrupts a running server):

```bat
:: Windows
install.bat
start.bat
```

```bash
# Linux / macOS
chmod +x install.sh start.sh   # first time only — git doesn't preserve the +x bit from a Windows checkout
./install.sh
./start.sh
```

Override the bind address/port with `PARTICLE_HOST` / `PARTICLE_PORT` env vars before running `start.bat`/`start.sh`.

**Manual equivalent:**

```bash
python -m pip install -r requirements.txt      # or requirements-dev.txt to also run tests
python -m uvicorn app.main:app --host 127.0.0.1 --port 8080 \
    --workers 1 --ws-max-size 65536 --ws-ping-interval 25 --ws-ping-timeout 20 \
    --limit-concurrency 128 --no-access-log
```

Verify:

```bash
curl -i http://127.0.0.1:8080/healthz   # expect 204
curl -i http://127.0.0.1:8080/readyz    # expect 204 (503 if over max-concurrency)
```

## Running the test suite

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

## Configuration

Everything is overridable via environment variables (see `app/config.py`) —
no config file to edit:

| Variable | Default | Meaning |
|---|---|---|
| `PARTICLE_MAX_FRAME_BYTES` | 65536 | max inbound WS message size |
| `PARTICLE_MAX_ROUTES_PER_SESSION` | 8 | routes one session may attach to |
| `PARTICLE_MAX_FANOUT` | 16 | max recipients per relayed signal |
| `PARTICLE_MAX_HOPS` | 3 | default TTL for relayed signals |
| `PARTICLE_MAX_CONCURRENCY` | 128 | connections before `/readyz` returns 503 |
| `PARTICLE_ROUTE_LEASE_SECONDS` | 90 | route subscription lease duration |
| `PARTICLE_SESSION_STALE_SECONDS` | 90 | disconnect idle sessions after this long |
| `PARTICLE_DEDUPE_WINDOW_SECONDS` | 120 | how long a relayed message's dedupe key is remembered |
| `PARTICLE_PROOF_DEADLINE_SECONDS` | 5 | must complete HELLO/PROVE within this long |
| `PARTICLE_CLEANUP_INTERVAL_SECONDS` | 15 | background prune tick interval |

## Deploying

- **Raspberry Pi 5 (reference deployment):** see `PI5_SETUP.md` — this is a
  manual, hands-on-hardware process; run it yourself on the physical device.
- **systemd unit:** `systemd/particle-masterserver.service` (adjust paths/user)
- **Cloudflare Tunnel:** `cloudflared/config.yml.example`
- Any other host works the same way — this is a plain ASGI app; anything that
  can run `uvicorn` (or another ASGI server) behind a TLS-terminating proxy/tunnel works.

## Self-hosting for a client's master server list

A client's shipped master server list (`master_servers` in
`normalizeMasterServerList()`, `engine/network/routes/MasterServerList.js`)
is just:

```json
{
  "url": "wss://your-domain/v1/ws",
  "priority": 2,
  "role": "bootstrap",
  "trust": "introducer_only",
  "enabled": true
}
```

Point it at your own `wss://` endpoint once your instance is reachable over
TLS (Cloudflare Tunnel, or any reverse proxy that terminates TLS and forwards
`Upgrade: websocket`). Lower `priority` numbers are tried first.
