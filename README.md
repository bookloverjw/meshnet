# meshnet

Secure remote access between your devices using WireGuard tunnels. A self-hosted alternative to NordVPN's Meshnet — connect to your office PC from home without opening router ports.

## How It Works

```
[Home Mac] <--WireGuard tunnel--> [Relay Server] <--WireGuard tunnel--> [Office PC]
                                       |
                              NAT traversal + peer
                              discovery coordinator
```

1. A lightweight **relay server** (`meshd`) runs on a cheap VPS and coordinates peer discovery
2. **Clients** (`mesh`) run on your devices, connect to the relay, and establish encrypted WireGuard tunnels
3. NAT hole-punching is attempted first for direct P2P; the relay forwards traffic if direct connection fails
4. All traffic between devices is encrypted end-to-end using Curve25519 + ChaCha20-Poly1305 (WireGuard)

## Prerequisites

- [Go 1.21+](https://go.dev/dl/) (to build from source)
- [WireGuard](https://www.wireguard.com/install/) installed on each device:
  - **macOS**: `brew install wireguard-go wireguard-tools`
  - **Windows**: Download from [wireguard.com](https://www.wireguard.com/install/)
- A small VPS for the relay server ($5/mo DigitalOcean, Linode, etc.)

## Quick Start

### 1. Build

```bash
# Build for your current platform
make build

# Or cross-compile for all platforms
make build-all
```

### 2. Deploy the Relay Server

Copy `bin/meshd-linux-amd64` to your VPS and run:

```bash
# Generate a shared secret
export MESHNET_AUTH_TOKEN=$(openssl rand -hex 32)
echo "Save this token: $MESHNET_AUTH_TOKEN"

# Run the relay (with TLS via Let's Encrypt cert)
./meshd --addr :443 --cert /etc/letsencrypt/live/yourdomain/fullchain.pem \
        --key /etc/letsencrypt/live/yourdomain/privkey.pem \
        --token "$MESHNET_AUTH_TOKEN"

# Or without TLS (for testing only)
./meshd --addr :8080
```

### 3. Set Up Your Home Mac

```bash
# Initialize (generates keys, creates config)
./mesh init

# Edit config to add your relay server
# Config location: ~/Library/Application Support/meshnet/config.json
```

Edit the config:
```json
{
  "device_name": "home-mac",
  "relay_addr": "your-vps-ip-or-domain",
  "relay_port": 443,
  "tunnel_ipv4": "10.100.0.1",
  "listen_port": 51820
}
```

### 4. Set Up Your Office PC

```bash
# Initialize
mesh.exe init

# Edit config: %APPDATA%\meshnet\config.json
```

Edit the config:
```json
{
  "device_name": "office-pc",
  "relay_addr": "your-vps-ip-or-domain",
  "relay_port": 443,
  "tunnel_ipv4": "10.100.0.2",
  "listen_port": 51820
}
```

### 5. Exchange Trust

On your Mac, note the public key from `mesh status`, then on each device:

```bash
# On the Mac:
mesh trust <office-pc-public-key> office-pc

# On the PC:
mesh trust <home-mac-public-key> home-mac
```

### 6. Connect

```bash
# On both devices, go online:
mesh up

# From your Mac, tunnel to the office:
mesh connect office-pc

# You'll see:
# [meshnet] tunnel UP to office-pc
# [meshnet] remote machine available at: 10.100.0.2
```

Now use **Microsoft Remote Desktop** (RDP), **VNC**, or **SSH** to connect to `10.100.0.2`.

## CLI Reference

| Command | Description |
|---------|-------------|
| `mesh init` | Initialize device, generate keys, create config |
| `mesh up` | Connect to relay and go online |
| `mesh peers` | List all peers on the network |
| `mesh connect <name>` | Establish WireGuard tunnel to a peer |
| `mesh trust <key> [name]` | Trust a peer's public key |
| `mesh status` | Show current config and tunnel status |
| `mesh down` | Tear down tunnel and disconnect |
| `mesh keygen` | Generate a new keypair |

## Works With Your VPN

This runs alongside NordVPN, ExpressVPN, or any commercial VPN without conflicts. Your VPN handles general internet privacy on its own network interface; meshnet creates a separate encrypted tunnel between your specific devices.

## Architecture

```
meshnet/
  cmd/
    mesh/       # Client CLI (runs on your Mac + PC)
    meshd/      # Relay server (runs on your VPS)
  internal/
    client/     # Mesh client: relay connection, tunnel management
    relay/      # Relay server: peer registry, message forwarding
    crypto/     # Curve25519 key generation (WireGuard-compatible)
    protocol/   # Wire protocol (JSON over WebSocket)
    nat/        # STUN endpoint discovery, UDP hole-punching
    tunnel/     # WireGuard interface setup (macOS, Windows, Linux)
    config/     # Cross-platform config management
```

## Security

- All tunnel traffic encrypted with WireGuard (Curve25519 + ChaCha20-Poly1305)
- Peer authentication via public key exchange (trust-on-first-use model)
- Relay server only sees encrypted WireGuard packets when relaying
- Config files stored with 0600 permissions
- Auth token protects relay from unauthorized access
