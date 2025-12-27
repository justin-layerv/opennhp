# NHP (Network Hiding Protocol) Architecture

## Overview

NHP implements a "zero trust" network access model where protected resources are hidden until
a valid cryptographic knock is received. This document describes the communication patterns
between NHP components.

## Components

### NHP Server (`nhp-serverd`)
- **Listens on**: UDP 62206 (exposed via NLB to internet)
- **Function**: Receives knock packets from agents, validates them, and instructs ACs to open access
- **Config files**: `config.toml`, `ac.toml` (AC peers)

### NHP Access Controller (`nhp-acd`)
- **Does NOT listen** for incoming UDP connections
- **Dials OUT** to servers to establish connection
- **Listens on**: HTTP 8888 (localhost only, proxied by Traefik on 443)
- **Function**: Manages firewall (iptables/ipset) to allow/deny access
- **Config files**: `config.toml`, `http.toml`, `server.toml` (server peers), `remote.toml` (etcd)

### Traefik (on AC instances)
- **Listens on**: HTTPS 443, HTTP 80
- **Function**: TLS termination, reverse proxy to nhp-acd HTTP

## Communication Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           KNOCK FLOW                                    │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   ┌─────────┐     UDP 62206      ┌─────────────┐                        │
│   │  Agent  │ ─────────────────► │ NHP Server  │                        │
│   │ (User)  │     (via NLB)      │             │                        │
│   └─────────┘                    └──────┬──────┘                        │
│                                         │                               │
│                                         │ NHP_AOP (UDP)                 │
│                                         │ (through established conn)    │
│                                         ▼                               │
│                                  ┌─────────────┐                        │
│                                  │   NHP AC    │                        │
│                                  │  (dials to  │                        │
│                                  │   server)   │                        │
│                                  └──────┬──────┘                        │
│                                         │                               │
│                                         │ ipset/iptables update         │
│                                         ▼                               │
│                                  ┌─────────────┐                        │
│                                  │  Firewall   │                        │
│                                  │  (ACCEPT    │                        │
│                                  │  agent IP)  │                        │
│                                  └─────────────┘                        │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                    AC-SERVER CONNECTION (IMPORTANT!)                    │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   The AC INITIATES the connection to the server, NOT the other way.     │
│                                                                         │
│   1. AC starts up, reads server peers from server.toml (or etcd)        │
│   2. AC dials UDP connection to each server (OUTBOUND)                  │
│   3. AC sends NHP_AOL (AC Online) message to announce itself            │
│   4. Server responds with NHP_AAK (AC Acknowledge)                      │
│   5. Connection is now established for bidirectional communication      │
│   6. Server can send NHP_AOP (AC Operation) messages to AC              │
│                                                                         │
│   ┌─────────────┐                    ┌─────────────┐                    │
│   │   NHP AC    │ ──── NHP_AOL ────► │ NHP Server  │                    │
│   │             │ ◄─── NHP_AAK ───── │             │                    │
│   │             │                    │             │                    │
│   │             │ ◄─── NHP_AOP ───── │ (on knock)  │                    │
│   └─────────────┘                    └─────────────┘                    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## HTTP Refresh Flow (Alternative to UDP knock)

For web-based demos, the `/refresh` endpoint provides HTTP-based access:

```
┌─────────┐     HTTPS 443       ┌──────────┐     HTTP 8888      ┌─────────┐
│  User   │ ──────────────────► │ Traefik  │ ─────────────────► │ NHP AC  │
│ Browser │ /refresh/{token}    │          │    (localhost)     │ (httpac)│
└─────────┘                     └──────────┘                    └────┬────┘
                                                                     │
                                                                     │ Validate token
                                                                     │ Add to ipset
                                                                     ▼
                                                              ┌─────────────┐
                                                              │  Firewall   │
                                                              └─────────────┘
```

## Key Configuration

### Server ac.toml
```toml
[[ACs]]
ACId = "sandbox-ac"
Hostname = ""
Ip = "10.100.0.43"        # AC's internal IP (for receiving NHP_AOP)
Port = 62206              # AC's NHP port
PubKeyBase64 = "..."      # AC's public key
```

### AC server.toml
```toml
[[Servers]]
Hostname = "nlb.example.com"  # Server NLB DNS
Ip = ""
Port = 62206                  # Server's NHP port
PubKeyBase64 = "..."          # Server's public key
```

## Failure Modes

### AC Cannot Reach Server
When the AC cannot establish connection to ANY server:
1. `maintainServerConnectionRoutine` detects all servers failed
2. Calls `a.iptables.AcceptAllInput()` to allow all traffic
3. Logs: "accept iptables input v2"

This is a **failopen** behavior to prevent total lockout.

### Server Cannot Reach AC
If server has wrong AC IP/port or keys don't match:
1. Server sends NHP_AOP but AC never receives it
2. User's knock succeeds at server but firewall never opens
3. User cannot access protected resource

## etcd Configuration (Multi-tenant Mode)

When `remote.toml` exists with etcd endpoints, AC loads config from etcd instead of local files.

### Per-AC Key Architecture (SECURITY)

**IMPORTANT**: Private keys are NEVER stored in etcd. Each AC instance generates its own
Curve25519 keypair on first boot and stores it in AWS Secrets Manager.

**etcd keys**:
- `/nhp/config` - Shared config (HTTP settings, server peers). Seeded by Terraform Lambda.
- `/nhp/ac-registry/{instance-id}` - Per-AC registration with public key and AWS identity.

**etcd config structure** (TOML format, NO private keys):
```toml
[HttpConfig]
EnableHttp = true
HttpListenPort = 8888

[[Servers]]
Hostname = "nlb.example.com"
Port = 62206
PubKeyBase64 = "..."
ExpireTime = 1924991999
```

**AC Registry Entry** (`/nhp/ac-registry/{instance-id}`):
```toml
PublicKey = "base64-encoded-public-key"
InstanceId = "i-1234567890abcdef0"
Ip = "10.0.0.100"
Port = 62206
RegisteredAt = 1703980800
IdentityDocument = "base64-encoded-aws-identity-document"
IdentitySignature = "base64-encoded-rsa2048-signature"
```

### AC Startup Flow

1. AC instance starts
2. Generates Curve25519 keypair (or retrieves from Secrets Manager if reboot)
3. Stores private key in Secrets Manager (`{prefix}-ac-{instance-id}`)
4. Fetches AWS Instance Identity Document with RSA-2048 signature
5. Registers public key + identity in etcd at `/nhp/ac-registry/{instance-id}`
6. Loads local config.toml (with private key)
7. Connects to etcd, loads server peers from `/nhp/config`
8. Dials out to NHP servers

### Server-Side AC Trust

The NHP server dynamically discovers ACs by watching `/nhp/ac-registry/` prefix:

1. On startup, loads all existing registry entries
2. If running in AWS, verifies each AC's AWS Instance Identity Document
3. Adds verified ACs as trusted peers
4. Watches for new registrations/deletions and reconciles

**AWS Identity Verification** (conditional - only when server runs in AWS):
- Verifies RSA-2048 signature using AWS region-specific certificates
- Validates instance ID and private IP match the registration
- Validates AWS account ID matches expected value

### Cleanup

- **On termination**: ASG lifecycle hook triggers Lambda to delete etcd entry + secret
- **Weekly audit**: Lambda compares registry to running instances, cleans orphans

**IMPORTANT**: If etcd has no `[[Servers]]` section, AC has no servers to connect to
and will fall back to "accept all" mode (failopen).

## Debugging Tips

1. **Check AC logs**: `/opt/layerv/nhp-ac/logs/ac*.log`
2. **Look for "server discovery sub-routine"**: Shows AC attempting to connect to server
3. **Look for "accept iptables input"**: Indicates server connection failed
4. **Check server logs**: `docker logs nhp-server`
5. **Verify keys match**: AC's public key in server's ac.toml must match AC's private key
6. **Check etcd config**:
   ```bash
   ETCDCTL_API=3 etcdctl get /nhp/config --print-value-only
   ```

## Security Groups

- **Server SG**: Allow UDP 62206 from 0.0.0.0/0 (for agent knocks via NLB)
- **AC SG**: Allow UDP 62206 from VPC CIDR (for server-to-AC communication, though AC dials out)
- **AC SG**: Allow TCP 443, 80 from 0.0.0.0/0 (for HTTPS via NLB)
