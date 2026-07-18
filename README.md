# Particle Masterserver v2

A standalone Particle-native discovery, admission, encrypted-signaling, TURN
credential, and trusted-node mesh service. It is a doorway, not gameplay
authority: rendezvous state is ephemeral, V2 routes are opaque, and signaling
payloads are HPKE ciphertext the service cannot inspect.

`/v1/ws` and `particle-discovery/1` remain available for explicit legacy
compatibility. V2 pin, manifest, or integrity failure never triggers an
automatic downgrade.

## Interfaces

| Interface | Exposure | Purpose |
|---|---|---|
| `GET /healthz`, `GET /readyz` | public | process and capacity probes |
| `GET /status` | public | version, uptime, readiness, protocol support; no sensitive counts |
| `GET /v2/manifest` | public | signed canonical node identity and endpoints |
| `POST /v2/admission` | public, rate limited | short-lived grant bound to a P-256 identity key |
| `POST /v2/turn` | admitted clients | expiring TURN-only ICE server configuration |
| `/v1/ws` | compatibility | preserved `particle-discovery/1` protocol |
| `/v2/ws` | public | secure session, opaque route, directed encrypted signaling |
| `/v2/node` | trusted nodes | `particle-node/1`; deploy behind inbound mTLS enforcement |
| `GET /metrics` | loopback/admin token | Prometheus metrics without route/client identifiers |

V2 uses `HELLO(grant, identityKey, encryptionKey) -> CHALLENGE -> PROVE ->
SESSION_READY`. Peers receive only session ID, HPKE public key, and key ID for
members of the same opaque route. Directed offers, answers, and ICE candidates
use RFC 9180 P-256/HKDF-SHA-256/AES-128-GCM.

## Quick start (Python 3.11+)

The installers create a dedicated `.venv` and install fully pinned,
hash-verified dependencies. CPython 3.12 on Linux aarch64 uses
`requirements-pi.lock`; other supported hosts use `requirements.lock`.

```bat
install.bat
start.bat
```

```bash
chmod +x install.sh start.sh
./install.sh
./start.sh
```

Manual equivalent on Linux/macOS:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes --only-binary=:all: -r requirements-pi.lock
.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8080 \
  --workers 1 --ws websockets --ws-max-size 65536 --ws-max-queue 16 --ws-ping-interval 25 \
  --ws-ping-timeout 20 --ws-per-message-deflate false --limit-concurrency 192 \
  --backlog 256 \
  --proxy-headers --forwarded-allow-ips 127.0.0.1 \
  --timeout-graceful-shutdown 20 --no-server-header --no-access-log
```

`--ws websockets` is intentional for this pinned release: it is the Uvicorn
engine that enforces `--ws-max-queue 16`. The current Sans-I/O engine enforces
message size but maintains an unbounded ASGI receive queue, so switching it is
blocked until that queue can be bounded and the slow-reader gate is rerun.

Verify:

```bash
curl -i http://127.0.0.1:8080/healthz
curl -i http://127.0.0.1:8080/readyz
curl -s http://127.0.0.1:8080/status
curl -s http://127.0.0.1:8080/v2/manifest
```

## Tests

```bash
python -m venv .venv-dev
.venv-dev/bin/python -m pip install -r requirements-dev.txt
.venv-dev/bin/python -m pytest -q
```

## Configuration

Start from `particle-masterserver.env.example`; keep the populated file and
keys outside the repository.

| Variable | Default | Meaning |
|---|---:|---|
| `PARTICLE_MAX_FRAME_BYTES` | 65536 | maximum WS message bytes |
| `PARTICLE_MAX_ROUTES_PER_SESSION` | 32 | opaque V2 routes per session |
| `PARTICLE_MAX_V1_ROUTES_PER_SESSION` | 8 | legacy V1 route limit |
| `PARTICLE_MAX_FANOUT` | 16 | maximum relay fanout |
| `PARTICLE_MAX_CONCURRENCY` | 128 | readiness/capacity limit |
| server `--limit-concurrency` | 192 | transport headroom above the 128-session application gate |
| `PARTICLE_MAX_JSON_DEPTH` | 16 | pre-decode JSON nesting limit |
| `PARTICLE_MAX_JSON_NODES` | 512 | decoded JSON structural-node limit |
| `PARTICLE_MAX_DEDUPE_ENTRIES` | 65536 | process-wide replay/dedupe entry ceiling |
| `PARTICLE_ADMISSION_CRYPTO_CONCURRENCY` | 8 | global P-256 admission work slots |
| `PARTICLE_ADMISSION_RATE_BURST` | 128 | per-address admission burst; accommodates the Pi gate behind one NAT |
| `PARTICLE_ADMISSION_RATE_PER_SECOND` | 2 | sustained per-address admission rate |
| `PARTICLE_ADMISSION_GLOBAL_BURST` | 256 | process-wide admission burst |
| `PARTICLE_ADMISSION_GLOBAL_PER_SECOND` | 32 | sustained process-wide admission rate |
| `PARTICLE_TURN_RATE_BURST` | 20 | per-address TURN credential request burst |
| `PARTICLE_TURN_RATE_PER_SECOND` | 1 | sustained per-address TURN request rate |
| `PARTICLE_TURN_GLOBAL_BURST` | 128 | process-wide TURN request burst |
| `PARTICLE_TURN_GLOBAL_PER_SECOND` | 16 | sustained process-wide TURN request rate |
| `PARTICLE_SIGNAL_GLOBAL_BURST` | 512 | process-wide signed-signal verification burst |
| `PARTICLE_SIGNAL_GLOBAL_PER_SECOND` | 256 | sustained process-wide ECDSA signal verification rate |
| `PARTICLE_MESSAGE_GLOBAL_BURST` | 2048 | process-wide pre-parse WebSocket message burst |
| `PARTICLE_MESSAGE_GLOBAL_PER_SECOND` | 1024 | sustained process-wide WebSocket message rate |
| `PARTICLE_OUTBOUND_SEND_TIMEOUT_SECONDS` | 5 | control/relay write deadline before slow-client closure |
| `PARTICLE_ROUTE_LEASE_SECONDS` | 90 | route descriptor lease |
| `PARTICLE_PROOF_DEADLINE_SECONDS` | 10 | traffic-independent proof deadline |
| server `--ws-max-queue` | 16 | WebSocket inbound queue target |
| `PARTICLE_OUTBOUND_QUEUE_FRAMES` | 64 | per-session writer frame budget |
| `PARTICLE_OUTBOUND_QUEUE_BYTES` | 262144 | per-session writer byte budget |
| `PARTICLE_NODE_ID` | `particle-node-dev` | stable signed node identity |
| `PARTICLE_ADVERTISE_V2` | true | signed V2 advertisement; set false for rollback while V1 remains live |
| `PARTICLE_SIGNING_KEY_FILE` | empty | P-256 signing key; required in production |
| `PARTICLE_NETWORK_ROOT_ID` | development root | pinned root reference |
| `PARTICLE_NETWORK_ROOT_VERSION` | 1 | monotonic trust-root revision |
| `PARTICLE_NETWORK_ROOT_ROLLBACK_VERSION` | 0 | explicitly authorized rollback revision |
| `PARTICLE_SIGNING_KEY_ACTIVATES_AT` | 0 | node-key activation epoch seconds |
| `PARTICLE_SIGNING_KEY_EXPIRES_AT` | 2147483647 | node-key expiry epoch seconds |
| `PARTICLE_TURN_URLS_JSON` | `[]` | TURN/TURNS URLs for expiring coturn REST credentials |
| `PARTICLE_TURN_SHARED_SECRET` | empty | coturn `static-auth-secret`, kept outside the repository |
| `PARTICLE_TURN_SHARED_SECRETS_JSON` | `[]` | overlapping `{id,secret,activatesAt,expiresAt}` TURN secrets for rotation |
| `PARTICLE_TURN_SERVERS_JSON` | `[]` | static-provider compatibility when REST secret is unset |
| `PARTICLE_METRICS_TOKEN` | empty | bearer token for non-loopback metrics |
| `PARTICLE_NODE_MESH_ENABLED` | false | enable trusted maximum-eight-node mesh |
| `PARTICLE_TRUSTED_NODES_JSON` | `[]` | trusted endpoints, manifests, and pins |
| `PARTICLE_NODE_MESH_REQUIRE_MTLS` | true | fail closed unless the reverse proxy verified a client certificate |
| `PARTICLE_NODE_MESH_MEMBERSHIP_EPOCH` | 1 | operator-controlled topology generation shared by every trusted node |
| `PARTICLE_NODE_MESH_SUSPICION_SECONDS` | 10 | quorum observation delay before removing a node from rendezvous ownership |
| `PARTICLE_NODE_MESH_MAX_CLOCK_SKEW_SECONDS` | 30 | reject stale node state and fail readiness on excessive skew |
| `PARTICLE_NODE_MESH_MAX_PENDING_OPERATIONS` | 1024 | process-wide outstanding node query/ack ceiling |
| `PARTICLE_NODE_MESH_MAX_ROUTE_DESCRIPTORS` | 16384 | hard cap for replicated descriptors and discovery cache |
| `PARTICLE_NODE_MESH_PROXY_TOKEN` | empty | secret attestation shared only by the mTLS proxy and application |
| `PARTICLE_READINESS_REQUIRE_TURN` | false | require configured TURN before reporting ready; production example enables it |
| `PARTICLE_ALLOWED_ORIGINS_JSON` | production origins | allowed browser WS origins |

Generate a node key with:

```bash
python generate_signing_key.py --output /etc/particle-masterserver/node-signing-key.pem
```

See `TRUST_AND_ROTATION.md` for overlapping key activation, rollback metadata,
and offline recovery. The initial node mesh is fully connected, limited to
eight trusted nodes, uses rendezvous hashing for primary/replica route owners,
and replicates only expiring descriptors and encrypted signal envelopes.

## Client endpoint entry

```json
{
  "url": "wss://your-domain/v2/ws",
  "serverKeyPin": "<sha256-of-node-signing-public-key>",
  "networkRootId": "particle-network-root-v1",
  "networkRootVersion": 1,
  "networkRootRollbackVersion": 0,
  "allowLegacyV1": false,
  "priority": 1,
  "enabled": true
}
```

During a signing-key rotation, use `serverKeyPins` instead of `serverKeyPin`.
Each entry is `{ "pin", "activatesAt", "expiresAt", "revoked" }`; the daemon
accepts only a currently active, non-revoked pin and also enforces the key's
signed activation window from the manifest. Ship both old and new entries for
the overlap, then revoke/remove the old entry in the next monotonic root release.

An endpoint may use V1 only when `allowLegacyV1` is explicitly true. BitTorrent
fallback configuration is separate and unchanged.

## Deployment

- Raspberry Pi reference: `PI5_SETUP.md`
- systemd: `systemd/particle-masterserver.service`
- Cloudflare Tunnel example: `cloudflared/config.yml.example`
- coturn allocation/bandwidth/peer-network hardening:
  `coturn/turnserver.conf.example`
- TLS/mTLS termination: use the dedicated `node-discovery` hostname from the
  nginx example. It requires a trusted client certificate and overwrites both
  `X-SSL-Client-Verify` and `X-Particle-Node-Proxy-Token`; the application
  constant-time verifies both signals before parsing a node hello, then verifies
  the pinned signed manifest. Generate the proxy token with `openssl rand -hex 32`
  and set the same value in the installed nginx config and service environment.
  The public hostname and Cloudflare Tunnel example return 404 for `/v2/node`.
- `nginx/particle-masterserver.conf.example` is the reference TLS/mTLS edge and
  deliberately does not expose `/metrics`. It bounds connections, request rate,
  headers, bodies, slow clients, upstream connection time, and TLS session work.
  Edge access logs are disabled so request floods cannot become disk-exhaustion
  attacks; operational counters remain available through protected `/metrics`.
  Its per-IP ceiling of 160 preserves a 128-client run behind one NAT; lower it
  for deployments that do not require that topology.

DoS protection is layered. Nginx or the provider edge limits initial HTTP and
WebSocket upgrade pressure; Uvicorn bounds its accept backlog, concurrent work,
WebSocket message size and receive queue; the application independently limits
sessions, proof time, JSON complexity, operations, routes, fanout, admission
cryptography and outbound queues. The browser daemon also bounds streamed HTTP
responses, inbound crypto work, routes, pending directed messages, local signal
rate and `WebSocket.bufferedAmount`. A pinned server that sends binary,
oversized, malformed, or queue-flooding input fails closed.

The second audit also caps proof verification at three attempts per socket,
places aggregate message admission before JSON decoding, places per-session and
global signal budgets before ECDSA verification, caps replay/dedupe cardinality,
actively closes stale receives, and gives every application send a deadline.
The client coalesces concurrent TURN/admission refreshes and requires 30 stable
seconds before reconnect backoff resets, preventing accept-then-close loops.
Authenticated node links also use a single-claim guard so a duplicate mTLS and
manifest-authenticated connection cannot orphan an older receive loop.

The third audit separates public TLS from node mTLS, adds proxy-to-application
attestation, blocks the node endpoint at the public tunnel, and caps outstanding
node operations, replicated descriptors, discovery responses, and descriptor
caches. Remote leases must fit the configured lease/skew window and cannot
reuse a local or differently owned session ID. Mesh shutdown cancels pending
futures and clears every ephemeral registry. The service sandbox drops all
Linux capabilities and restricts process visibility, IPC, realtime scheduling,
kernel logs, and reboot controls. The TURN reference also denies IPv6 loopback,
ULA, link-local, and multicast peers.

The locked Uvicorn release intentionally uses `--ws websockets`: current
Uvicorn documents `--ws-max-size`, `--ws-max-queue`, and compression control
for that implementation, while its newer SansIO path does not yet expose the
same complete set of resource controls. Re-test those controls before changing
the protocol implementation or upgrading past the lock file.

Provider WAF rules do not replace application WebSocket limits. Cloudflare
documents that security controls apply to the initial upgrade request but do
not inspect frames after HTTP 101. The implemented limits follow the resource
guidance in [RFC 6455 section 10.4](https://datatracker.ietf.org/doc/html/rfc6455#section-10.4),
[nginx connection limiting](https://nginx.org/en/docs/http/ngx_http_limit_conn_module.html),
[nginx request limiting](https://nginx.org/en/docs/http/ngx_http_limit_req_module.html),
and [websockets memory guidance](https://websockets.readthedocs.io/en/stable/topics/memory.html).
HTTP 429 responses include `Retry-After` as described by
[RFC 6585](https://www.rfc-editor.org/rfc/rfc6585.html#section-4). Proxy-derived
client addresses are accepted only from loopback, following
[Uvicorn's trusted-proxy guidance](https://www.uvicorn.org/deployment/#proxies-and-forwarded-headers).
The origin disables unnecessary HTTP/2 multiplexing; if an operator re-enables
it, keep nginx patched and configure finite streams/requests per the
[nginx HTTP/2 module](https://nginx.org/en/docs/http/ngx_http_v2_module.html).

For coturn, configure every active secret from `PARTICLE_TURN_SHARED_SECRETS_JSON`
as a coturn REST shared secret during the overlap. `/v2/turn` uses the newest
active secret and a random per-grant pseudonym, avoiding stable identity material
in TURN logs. The browser daemon renews admission before refreshing credentials.
The reference coturn configuration independently caps four allocations per
credential, 128 allocations globally, per-session and aggregate bandwidth,
allocation setup time, and relay ports. It disables unused TCP-relay, DTLS,
RFC 5780, multicast, CLI, and verbose logging surfaces and denies private peer
networks reachable from the relay host. Coturn documents these controls in its
[current turnserver reference](https://github.com/coturn/coturn/blob/master/README.turnserver).

## Existing mesh tester release gate

```bash
python ../tests/network/mesh_test.py --protocol v2 \
  --url wss://discovery.example.com/v2/ws \
  --server-key-pin <pin> --route-secret <shared-invite> \
  --clients 128 --duration 3600 --signal-rate 2 \
  --slow-clients 4 --disconnect-every 300 \
  --gate pi-128 --metrics-token <admin-token> \
  --evidence-signing-key /secure/evidence-witness.pem \
  --json-out particle-mesh-evidence.json
python ../tests/network/validate_mesh_evidence.py particle-mesh-evidence.json \
  --witness-key /secure/evidence-witness-public.pem
```

Tester exit codes are `0` pass, `1` failed assertion/runtime, and `2` invalid
invocation or missing dependency. The browser gate at
`tests/network/mesh-test.html` covers direct/forced-relay DataChannels, RTT,
TURN refresh, ICE restart, reconnect, and evidence export. Generate the
deployable copy from the same source with:

```bash
python tests/network/build_mesh_test_deploy.py
```

The Pi hard gate is 128 clients for 60 minutes. The 500-client, 15-minute run
remains report-only until it meets the same thresholds.
