# Raspberry Pi 5 (1 GB) Setup Manual

Reference deployment for the default Particle Masterserver instance. This is
a **manual, hands-on-hardware process** — run these steps yourself on the
physical Pi (Cascade cannot execute commands on hardware it has no access to).

Assumes: 64-bit Raspberry Pi OS, `cloudflared` already installed and logged in
(`cloudflared tunnel login` already run), and CPython 3.12. The reference Pi
lock is ABI-specific and the installer refuses source distributions.

## 1. System prep

```bash
sudo apt update && sudo apt full-upgrade -y
```

1 GB RAM is tight once WebSocket fan-out grows — add swap headroom:

```bash
sudo dphys-swapfile swapoff
sudo sed -i 's/^CONF_SWAPSIZE=.*/CONF_SWAPSIZE=1024/' /etc/dphys-swapfile
sudo dphys-swapfile setup
sudo dphys-swapfile swapon
```

## 2. Create a dedicated user + directory

```bash
sudo useradd -r -s /usr/sbin/nologin particle
sudo mkdir -p /opt/particle-masterserver
sudo chown particle:particle /opt/particle-masterserver
```

## 3. Deploy the code

From your dev machine (or `git clone` directly on the Pi if this repo is
reachable from it):

```bash
# from a machine with this repo, e.g. via scp/rsync:
rsync -av --exclude '.git' Masterserver/ pi@<pi-host>:/tmp/particle-masterserver/
ssh pi@<pi-host> "sudo rsync -av --delete /tmp/particle-masterserver/ /opt/particle-masterserver/ && sudo chown -R particle:particle /opt/particle-masterserver"
```

## 4. Python environment

The installer creates `/opt/particle-masterserver/.venv` and selects the
hash-verified Linux aarch64/CPython 3.12 lock without modifying system Python.
Set `PYTHON_BIN` explicitly if `python3` is not version 3.12:

```bash
cd /opt/particle-masterserver
sudo -u particle chmod +x install.sh start.sh
sudo -u particle env PYTHON_BIN=/usr/bin/python3.12 ./install.sh
```

## 5. Run it manually first (sanity check before installing the service)

```bash
sudo -u particle env PARTICLE_HOST=127.0.0.1 PARTICLE_PORT=8080 ./start.sh
```

In another shell, verify `/healthz`, `/status`, and `/v2/manifest`. This manual
sanity run uses a process-ephemeral development key; the systemd production
configuration below requires the external persistent key. Ctrl+C to stop.

## 6. Install as a systemd service

```bash
sudo cp systemd/particle-masterserver.service /etc/systemd/system/
sudo cp particle-masterserver.env.example /etc/particle-masterserver.env
sudo install -d -o particle -g particle -m 0750 /etc/particle-masterserver
sudo -u particle .venv/bin/python generate_signing_key.py --output /etc/particle-masterserver/node-signing-key.pem
sudo chmod 0600 /etc/particle-masterserver/node-signing-key.pem
sudo nano /etc/particle-masterserver.env
sudo systemctl daemon-reload
sudo systemctl enable --now particle-masterserver
sudo systemctl status particle-masterserver
```

The service unit also caps the socket accept backlog, open file descriptors,
tasks, and memory. Keep these finite; raise them only alongside a measured gate.

## 7. Cloudflare Tunnel

```bash
cloudflared tunnel create particle-masterserver
cloudflared tunnel route dns particle-masterserver discovery.<your-domain>
sudo mkdir -p /etc/cloudflared
sudo cp cloudflared/config.yml.example /etc/cloudflared/config.yml
sudo nano /etc/cloudflared/config.yml   # fill in <TUNNEL_ID>, credentials path, hostname
sudo cloudflared service install
sudo systemctl enable --now cloudflared
```

The tunnel rule deliberately returns 404 for `/v2/node`; it is a public browser
edge, not a trusted-node edge. If node mesh is enabled, deploy the separate
`node-discovery.example.com` nginx virtual host, issue each node a client
certificate, generate `PARTICLE_NODE_MESH_PROXY_TOKEN` with
`openssl rand -hex 32`, and put the same token in the installed nginx config.
Never expose Uvicorn directly or route the node hostname through the public
tunnel rule.

Create Cloudflare WAF/rate-limit rules for `/v1/ws` and `/v2/ws` upgrade
requests plus `/v2/admission` and `/v2/turn`. Cloudflare does not inspect
WebSocket frames after the 101 upgrade, so the server's frame, operation,
queue, and proof limits remain mandatory.

## 8. Verify end-to-end

```bash
curl -i https://discovery.<your-domain>/healthz   # expect 204
```

Run both a two-client V1 compatibility test and a pinned V2 test with
`tests/network/mesh_test.py`, then validate the V2 evidence offline.

If this Pi also runs coturn, start from `coturn/turnserver.conf.example`, replace
the secret/certificate/address values, set the resulting file to mode `0600`,
and open only ports 3478, 5349, and UDP 49152-49407. Confirm allocation,
bandwidth, and private-peer denials before running the forced-relay gate.

## 9. 1 GB RAM guardrails

> The service never uses `--break-system-packages`; all dependencies live in
> its dedicated virtual environment.

- `--workers 1` only — never scale to multiple workers on this hardware.
- The transport admits up to 192 concurrent HTTP/WebSocket operations so 128
  proven sessions still have headroom for admissions and metrics; the
  application independently caps active sessions at 128.
- WebSocket compression is disabled to avoid per-connection compression state
  and compression-amplification surprises on a 1 GB host.
- The origin edge stays on HTTP/1.1; Cloudflare may negotiate H2/H3 at its own
  protected edge. Do not re-enable origin HTTP/2 without a current nginx build
  and finite concurrent-stream/request limits.
- Admission, TURN, signed-signal verification, pre-parse messages, proof
  attempts, dedupe entries, socket writes, open files, RAM, and swap all have
  independent finite budgets.
- Node queries/acks, route registries, discovery results, descriptor caches, and
  lease lifetimes have independent finite budgets; node shutdown clears them.
- No database or access log; rendezvous state is ephemeral and queues are bounded.
- Structured operational logs go to rate-limited journald:
  `sudo journalctl -u particle-masterserver -f`.
- Scrape loopback `/metrics` and record RSS, CPU, event-loop lag, relay p95/p99,
  admission/proof success, queue/rate rejection, TURN issuance, and node health
  during the 60-minute 128-client hard gate.

## 10. Updating

```bash
# redeploy code (step 3), then:
sudo systemctl restart particle-masterserver
```

Keep the previous `/opt/particle-masterserver` as a `.bak` copy. Protocol
rollback disables V2 advertisement in the signed manifest while `/v1/ws`
remains operational; no database migration is needed.
