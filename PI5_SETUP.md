# Raspberry Pi 5 (1 GB) Setup Manual

Reference deployment for the default Particle Masterserver instance. This is
a **manual, hands-on-hardware process** — run these steps yourself on the
physical Pi (Cascade cannot execute commands on hardware it has no access to).

Assumes: Raspberry Pi OS, `cloudflared` already installed and logged in
(`cloudflared tunnel login` already run), Python 3.13 available by default.

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

No virtual environment — dependencies install directly against the system
Python 3.13:

```bash
cd /opt/particle-masterserver
sudo -u particle chmod +x install.sh start.sh
sudo -u particle ./install.sh
```

## 5. Run it manually first (sanity check before installing the service)

```bash
sudo -u particle env PARTICLE_HOST=127.0.0.1 PARTICLE_PORT=8080 ./start.sh
```

In another shell: `curl -i http://127.0.0.1:8080/healthz` should return `204`.
Ctrl+C to stop once confirmed.

## 6. Install as a systemd service

```bash
sudo cp systemd/particle-masterserver.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now particle-masterserver
sudo systemctl status particle-masterserver
```

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

## 8. Verify end-to-end

```bash
curl -i https://discovery.<your-domain>/healthz   # expect 204
```

Open a WebSocket test client against `wss://discovery.<your-domain>/v1/ws`
and send a `HELLO` — you should get a `HELLO` challenge back.

## 9. 1 GB RAM guardrails

> Note: `install.sh`/`start.sh` install and run against the system Python
> directly (no venv), matching the Windows scripts. If your Pi's system
> Python is externally-managed (PEP 668), `install.sh` automatically detects
> pip's `externally-managed-environment` error and retries with
> `--break-system-packages` — acceptable here since `particle` is a dedicated,
> single-purpose service account. Don't reuse this pattern on a shared/dev
> machine.

- `--workers 1` only — never scale to multiple workers on this hardware.
- `--limit-concurrency 128` — lower it (e.g. 64) if you observe memory pressure: `free -h`.
- No database, no access log — memory stays bounded by live sessions/routes/dedupe-cache only, and fully resets on restart.
- Watch logs (systemd journal, not app logs — the app itself logs nothing): `sudo journalctl -u particle-masterserver -f`

## 10. Updating

```bash
# redeploy code (step 3), then:
sudo systemctl restart particle-masterserver
```

Keep the previous `/opt/particle-masterserver` as a `.bak` copy before
overwriting if you want an easy rollback path.
