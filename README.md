# Afterglow WireGuard Agent

A headless WireGuard controller for Project Afterglow. The service keeps SQLite metadata, the managed WireGuard configuration, the live interface, and fail-closed Linux firewall policy synchronized without service restarts.

## Features

- Authenticated FastAPI API with bearer-token protection.
- Durable SQLite authority with WAL, process lease, operation locking, migrations, and UUIDv4 installation identity.
- Server and client key management with atomic, permission-restricted writes.
- WireGuard configuration rendering, `wg syncconf`, interface/L3 readback, and peer reconciliation.
- Staged peer authorization guards for create/enable transitions.
- Alternating owned INPUT/FORWARD firewall generations with fail-closed cutover.
- Permanent stage chains, blocked private/reserved route policy, scoped MASQUERADE, and forwarding readback.
- Client profiles with routes, DNS, MTU, and persistent keepalive controls.
- PNG/SVG/base64 QR codes and digest-only single-use or reusable share tokens.
- Per-peer cumulative transfer counters and RX/TX rate monitoring.
- Temporary same-origin web console for client management and traffic monitoring.
- Native systemd and Docker deployment artifacts.

## Requirements

- Python 3.12+
- Linux with WireGuard kernel support and `wireguard-tools`
- `iptables`, `iproute2`, and permission to manage WireGuard/network policy

The pinned dependencies are in `requirements.lock`, `requirements-test.lock`, and `requirements-build.lock`.

## Configuration authority

The native VM is the default runtime. Docker is an optional packaging mode for the same application and state layout; never run both modes against the same state mount at the same time.

Cloud-init or the VM environment file supplies infrastructure-owned settings. The required endpoint value is `WG_SERVER_HOST`: it must be the public IP address or a public DNS name that peers use to reach the WireGuard server. It is separate from each client's tunnel address. A client's public network endpoint is learned by WireGuard during handshake; the API owns the client's private tunnel address and profile settings.

Required infrastructure settings:

- `WG_SERVER_HOST`
- `API_AUTH_TOKEN` (at least 32 random characters)
- `API_ALLOWED_CIDRS` when `API_HOST` is non-loopback
- `WG_OUTBOUND_INTERFACE` when the default route cannot be selected automatically

Optional infrastructure settings with safe defaults include the WireGuard interface and port, VPN subnet, default DNS, API bind/port, persistent keepalive, HTTPS public origin, documentation switch, and insecure-HTTP opt-in.

Copy `.env.example` to an environment file and replace the deployment-specific values:

```dotenv
WG_INTERFACE=wg0
WG_PORT=51820
WG_SERVER_HOST=203.0.113.10
WG_SERVER_NET=10.8.0.0/24
WG_DEFAULT_DNS=1.1.1.1
API_AUTH_TOKEN=replace-with-a-long-random-token
API_HOST=0.0.0.0
API_PORT=8080
WG_PERSISTENT_KEEPALIVE=25
WG_OUTBOUND_INTERFACE=eth0
ALLOW_INSECURE_HTTP=false
API_ALLOWED_CIDRS=192.0.2.0/24
API_DOCS_ENABLED=false
```

`deploy/install.sh` is the supported one-step native installer. It builds the pinned wheel, installs the runtime virtual environment, writes the root-only environment file, installs the systemd/tmpfiles artifacts, and starts the service. It can install from exported variables, an environment file, or the interactive wizard below.

## Automated native installation

Environment-driven installation:

```bash
export WG_SERVER_HOST=203.0.113.10
export API_AUTH_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
export API_ALLOWED_CIDRS=198.51.100.10/32
export WG_OUTBOUND_INTERFACE=eth0
./deploy/install.sh
```

The installer self-elevates with `sudo`, preserves only the supported configuration variables, and never prints `API_AUTH_TOKEN`.

The standard-library terminal wizard asks for the same values, masks the token, generates one when left blank, and invokes the installer:

```bash
python3 deploy/install-tui.py
```

For unattended VM provisioning, edit the four required placeholders in `deploy/cloud-init.yaml` and provide it as OpenStack user-data. Cloud-init downloads the configured repository branch, runs the same installer, and starts the native service. Replace the `main.tar.gz` URL with a reviewed commit or release URL for production.

The API owns non-infrastructure client settings:

- client name and optional tunnel address
- profile routes and DNS
- MTU and persistent keepalive
- enabled/disabled state
- share-token lifetime and single-use policy

Non-loopback HTTP requires an explicit `ALLOW_INSECURE_HTTP=true` decision and source CIDR restriction. HTTPS or a secure reverse proxy is recommended for public exposure. Runtime state and secrets are stored outside the repository at fixed paths:

- `/var/lib/afterglow-wg-agent/agent.db`
- `/var/lib/afterglow-wg-agent/keys/`
- `/etc/wireguard/wg0.conf`
- `/run/afterglow-wg-agent/`

## Development

Create a virtual environment and install the pinned runtime and test dependencies:

```bash
python3 -m venv .venv
.venv/bin/pip install --require-hashes -r requirements.lock
.venv/bin/pip install --require-hashes -r requirements-test.lock
PYTHONPATH=src .venv/bin/python -m pytest -q
PYTHONPATH=src .venv/bin/python -m compileall -q src tests
```

The console entry point is:

```bash
afterglow-wg-agent serve
```

The application performs lease acquisition, authority validation, restrictive network policy reconciliation, WireGuard convergence, and readback before serving requests.

## API overview

All `/api/v1/**` endpoints require `Authorization: Bearer <API_AUTH_TOKEN>` unless noted.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/healthz` | Unauthenticated health check |
| `GET` | `/api/v1/status` | Interface, peer, handshake, and transfer status |
| `GET` | `/api/v1/traffic` | Per-peer cumulative transfer and rate metrics |
| `GET` | `/api/v1/clients` | List clients |
| `POST` | `/api/v1/clients` | Create a client |
| `PUT` / `PATCH` | `/api/v1/clients/{id}` | Replace or update client controls |
| `DELETE` | `/api/v1/clients/{id}` | Delete a client and release its address |
| `GET` | `/api/v1/clients/{id}/config` | Download the current client profile |
| `GET` | `/api/v1/clients/{id}/qrcode?format=png\|svg\|base64` | Generate a QR code |
| `POST` | `/api/v1/clients/{id}/share` | Create a time-limited share URL |
| `GET` | `/download/{token}` | Download a shared profile without bearer auth |

Profile-bearing responses use `Cache-Control: no-store`. Share tokens are never stored in plaintext.

## Native deployment (default)

The VM-first path builds and installs the wheel under `/opt/afterglow-wg-agent`, writes `/etc/afterglow-wg-agent.env`, and runs the systemd unit directly on the host. Use `deploy/install.sh` for normal installations; the manual commands below are only for an already-built artifact.

For a preinstalled native artifact:

```bash
sudo install -m 0644 deploy/afterglow-wg-agent.service /etc/systemd/system/
sudo install -m 0644 deploy/afterglow-wg-agent.tmpfiles.conf /etc/tmpfiles.d/afterglow-wg-agent.conf
sudo systemd-tmpfiles --create /etc/tmpfiles.d/afterglow-wg-agent.conf
sudo systemctl daemon-reload
sudo systemctl enable --now afterglow-wg-agent.service
```

The unit runs as root with `CAP_NET_ADMIN`, a private runtime directory, a fixed state directory, restricted filesystem access, and no access logging. Do not run native and Docker instances concurrently against the same state mount.

## Docker deployment (optional)


Build the image:

```bash
sudo docker build --pull -t afterglow-wg-agent:dev .
```

Run with the exact state/config/runtime mounts and only the required network capability:

```bash
sudo docker run -d \
  --name afterglow-wg-agent \
  --restart=on-failure:5 \
  -p 8080:8080/tcp \
  -p 51820:51820/udp \
  --cap-drop=ALL \
  --cap-add=NET_ADMIN \
  --sysctl net.ipv4.ip_forward=1 \
  --env-file /etc/afterglow-wg-agent.env \
  -e WG_OUTBOUND_INTERFACE=eth0 \
  --mount type=bind,src=/etc/wireguard,dst=/etc/wireguard \
  --mount type=bind,src=/var/lib/afterglow-wg-agent,dst=/var/lib/afterglow-wg-agent \
  --tmpfs /run/afterglow-wg-agent:rw,noexec,nosuid,size=1m,mode=0700 \
  afterglow-wg-agent:dev
```

When using Docker bridge networking, include the Docker bridge CIDR in `API_ALLOWED_CIDRS` if published API requests arrive from that bridge source range. The `serve --require-runtime-mounts` mode exits before state or network side effects when required mounts are absent.

## Security model

The forwarding policy intentionally allows VPN clients to reach the Internet through the configured outbound interface while rejecting private, reserved, metadata, and peer-to-peer destinations by default. Broad `-i wg0 -o wg0` forwarding is not installed. Changes that widen peer access remain quarantined until configuration, runtime state, response construction, and durable commit succeed.

Cloud security-group ingress is deployment-specific and must separately allow UDP `51820` and the restricted API TCP port. The supplied VM deployment does not infer or mutate cloud firewall rules.

## Verification

The implementation has been exercised with the full Python test suite, bytecode compilation, systemd unit verification, native API CRUD/profile/QR/share smoke tests, namespace firewall generation tests, WireGuard gateway handshake tests, browser console QA, Docker image/mount/lease/API/restart tests, and clean-state checks.
