# Technical Design Document

# Per-Instance Server Keypairs

## Eliminating Shared-Key Peer Pool Collisions

---

| **Document Info** | |
|-------------------|------------------------|
| **Version**       | 1.0                    |
| **Date**          | March 11, 2026         |
| **Author**        | Architecture Team      |
| **Status**        | Draft                  |
| **Repository**    | layervai/nhp           |

---

## Table of Contents

1. [Background](#1-background)
2. [Problem Statement](#2-problem-statement)
3. [Goals and Non-Goals](#3-goals-and-non-goals)
4. [Proposed Architecture](#4-proposed-architecture)
5. [Detailed Design](#5-detailed-design)
6. [Security Considerations](#6-security-considerations)
7. [Migration Plan](#7-migration-plan)
8. [Open Questions](#8-open-questions)

---

## 1. Background

### Current State

All NHP servers in an ASG share a single keypair loaded from AWS Secrets Manager (`/nhp/{env}/server/private-key`). This shared key is fundamental to the NLB design: ACs encrypt NHP_AOL (registration) messages to the shared public key, and any server behind the NLB can decrypt them.

### Interim Fix: Peer Group Mode

An interim fix (Peer Group Mode) allows the AC's `Device.peerMap` to hold multiple peers under a single public key by promoting colliding entries to a `PeerGroup` that dispatches by address. This is a workaround — the root cause remains.

**Why an interim fix isn't sufficient long-term:**

- Peer Group Mode adds complexity to the core NHP peer management layer
- `CheckRecvAddress` must iterate all group members on every packet — O(n) per packet instead of O(1)
- Shared keys mean a single key compromise exposes all servers simultaneously
- The `PeerGroup` abstraction leaks: callers using `SendAddr()` get one member's address, not all. AC connection management must remain aware of the multi-server topology independently
- Key rotation requires coordinated rollout across all servers simultaneously

---

## 2. Problem Statement

`Device.peerMap` (`nhp/core/device.go:64`) is `map[string]Peer` keyed by base64-encoded public key. When an AC connects to 3 assigned servers that share the same key, `AddPeer` overwrites — only 1 of 3 survives. NHP_AOP from the other 2 is rejected by `validatePeer` ("peer does not match its previous address"). Result: ~66% of knock requests fail after server instance refresh.

The root cause is that server identity is conflated with a shared cryptographic key. The correct fix is to give each server its own identity (keypair).

---

## 3. Goals and Non-Goals

### Goals

- Each server instance has a unique keypair, generated at launch
- AC receives per-server public keys in NHP_ARD targets and NHP_AAK peers
- Peer pool collisions are eliminated — each server maps to a distinct key
- NLB initial registration continues to work (AC must be able to connect without knowing which server will answer)
- Key compromise of one server does not expose others
- Key rotation can be performed per-server without coordinated rollout

### Non-Goals

- Changing the NHP packet format or cryptographic algorithms
- Removing the shared key entirely in Phase 1 (it's still needed for NLB initial connection)
- Per-instance keys for ACs (ACs already have unique keys)

---

## 4. Proposed Architecture

### Dual-Key Model

Each server has **two keys**:

| Key | Purpose | Scope | Storage |
|-----|---------|-------|---------|
| **Registration key** (shared) | NLB initial NHP_AOL decryption | All servers in ASG | Secrets Manager (existing) |
| **Operational key** (per-instance) | NHP_AOP encryption, direct AC communication | Single server instance | Generated at launch, public key stored in DynamoDB |

**Flow:**

```
1. AC → NLB (NHP_AOL encrypted with shared registration key)
      Any server decrypts, processes registration

2. Server → AC (NHP_AAK or NHP_ARD with per-server operational public keys)
      AC now knows each assigned server's unique key

3. AC → Server (direct, encrypted with per-server operational key)
      Bypasses NLB, uses direct IP from NHP_ARD target

4. Server → AC (NHP_AOP encrypted with AC's key, from server's operational key)
      AC validates peer by unique key — no collision
```

### Key Lifecycle

```
Server Launch:
  1. Generate Ed25519/X25519 keypair in memory
  2. Store public key in DynamoDB: /nhp/servers/{instance-id}/pubkey
  3. Also load shared registration key from Secrets Manager (for NHP_AOL)

Server Shutdown (H4 drain):
  1. Send NHP_ARD to ACs (redirecting to NLB)
  2. Remove DynamoDB entry: /nhp/servers/{instance-id}/pubkey

AC Registration:
  1. AC sends NHP_AOL to NLB (encrypted with shared registration key)
  2. Server responds with NHP_AAK including assigned servers' operational public keys
  3. AC connects directly to each assigned server using their operational keys
```

---

## 5. Detailed Design

### 5.1 Server Startup: Key Generation

In `UdpServer.Start()`, after loading the shared key:

```go
// Generate per-instance operational keypair
operationalPrivKey, operationalPubKey := GenerateKeypair()
s.operationalDevice = NewDevice(NHP_SERVER, operationalPrivKey, opts)

// Register operational public key in DynamoDB
s.storage.PutServerKey(s.instanceId, base64Encode(operationalPubKey))
```

The server now has two `Device` instances:
- `s.device` — shared registration key (handles NHP_AOL from NLB)
- `s.operationalDevice` — per-instance key (handles NHP_AOP, direct AC communication)

### 5.2 DynamoDB Schema Addition

New item in the existing `nhp-{env}-ac-assignments` table (or a new `nhp-{env}-server-keys` table):

```
PK: SERVER#{instance-id}
SK: KEY
Attributes:
  pubKeyBase64: string    // operational public key
  ip: string              // server's private IP
  port: int               // NHP UDP port
  az: string              // availability zone
  registeredAt: int64     // unix timestamp
  ttl: int64              // auto-cleanup if server dies without draining
```

TTL ensures stale entries are cleaned up if a server is killed without graceful shutdown.

### 5.3 NHP_AAK / NHP_ARD: Include Operational Keys

When server responds to NHP_AOL with NHP_AAK, include the assigned servers' operational public keys in the `Peers` field:

```go
// Current (shared key):
Peers: []RedirectTarget{
    {IP: "10.0.1.5", Port: 62206, PubKeyBase64: SHARED_KEY},
    {IP: "10.0.2.8", Port: 62206, PubKeyBase64: SHARED_KEY},
    {IP: "10.0.3.12", Port: 62206, PubKeyBase64: SHARED_KEY},
}

// Per-instance keys:
Peers: []RedirectTarget{
    {IP: "10.0.1.5", Port: 62206, PubKeyBase64: SERVER_1_OP_KEY},
    {IP: "10.0.2.8", Port: 62206, PubKeyBase64: SERVER_2_OP_KEY},
    {IP: "10.0.3.12", Port: 62206, PubKeyBase64: SERVER_3_OP_KEY},
}
```

The assignment lookup (`GetACAssignment`) already returns server IPs and AZs. It needs to also return each server's operational public key from DynamoDB.

### 5.4 AC-Side: Standard Peer Map

With unique keys per server, the AC's `Device.peerMap` works as designed:

```
peerMap["SERVER_1_OP_KEY"] = UdpPeer{ip: "10.0.1.5"}
peerMap["SERVER_2_OP_KEY"] = UdpPeer{ip: "10.0.2.8"}
peerMap["SERVER_3_OP_KEY"] = UdpPeer{ip: "10.0.3.12"}
```

No collision. No `PeerGroup` needed. `validatePeer` works with O(1) lookup.

### 5.5 Server-Side: Dual Device Routing

The server needs to route incoming packets to the correct `Device`:

- Packets arriving on the NLB listener → `s.device` (shared registration key)
- Packets arriving on the direct connection → `s.operationalDevice` (per-instance key)

Since NHP decryption tries the packet against the device's keypair, and the header contains the recipient's public key, the server can inspect the header to route:

```go
func (s *UdpServer) routePacket(pkt []byte) *Device {
    recipientPubKey := extractRecipientKey(pkt)  // from NHP header
    if recipientPubKey == s.device.PublicKeyBase64() {
        return s.device  // shared registration key
    }
    return s.operationalDevice  // per-instance operational key
}
```

Alternatively, both devices can share the same receive queue and try decryption — only the correct key succeeds. This is simpler but wastes one failed decryption attempt per packet.

### 5.6 NHP_AOP: Use Operational Key

When server sends NHP_AOP to an AC (knock result), it encrypts with the AC's public key and signs with its **operational** private key:

```go
// Current: uses shared device
md := &core.MsgData{
    ConnData: conn.ConnData,
    PeerPk:   conn.ACPeer.PublicKey(),
    // implicitly uses s.device's private key
}

// Per-instance: uses operational device
md := &core.MsgData{
    ConnData: conn.ConnData,
    PeerPk:   conn.ACPeer.PublicKey(),
    Device:   s.operationalDevice,  // new field or separate send path
}
```

The AC already has the operational public key in its peer map, so it can validate the sender.

### 5.7 Files Changed

| File | Change |
|------|--------|
| `nhp/core/device.go` | Add key generation helper. No structural changes to peerMap. |
| `endpoints/server/udpserver.go` | Add `operationalDevice` field, dual-device routing, key registration in DynamoDB on start, cleanup on stop |
| `endpoints/server/config.go` | No changes — shared key config stays for registration |
| `endpoints/server/msghandler.go` | `processACOnline` and `sendARD` include operational pub keys from DynamoDB |
| `endpoints/server/storage/` | `GetServerKey`, `PutServerKey`, `DeleteServerKey` operations |
| `endpoints/ac/registration.go` | No changes needed — already uses `PubKeyBase64` from `RedirectTarget` |
| `terraform/modules/compute/` | DynamoDB table/GSI for server keys (or additional attributes on existing table) |
| `terraform/modules/compute/iam.go` | Server IAM policy: DynamoDB read/write for server key items |

---

## 6. Security Considerations

| Concern | Mitigation |
|---------|------------|
| Operational key in memory only | Key never persists to disk. Generated fresh each launch. Server termination destroys the key. |
| DynamoDB stores public key only | Private key never leaves the server's memory. Public key exposure has no security impact. |
| Shared registration key remains | Still needed for NLB. But it's only used for initial NHP_AOL — all subsequent communication uses operational keys. Compromise of the shared key only allows impersonating the NLB endpoint, not individual servers. |
| Key rotation | Per-instance keys rotate on every instance refresh. No coordination needed. |
| Replay attacks | NHP protocol already has transaction IDs and timestamps. Per-instance keys don't change this. |
| DynamoDB TTL stale entries | TTL auto-deletes server keys if a server dies without cleanup. ACs that still reference the old key will fail `LookupPeer` and re-register via NLB. |

---

## 7. Migration Plan

### Phase 1: Peer Group Mode (current, interim)

Implement `PeerGroup` in `nhp/core/` to handle shared-key collisions at the peer map level. Ships immediately to unblock sandbox.

### Phase 2: Per-Instance Operational Keys

1. **Server-side key generation + DynamoDB storage** — server generates keypair on launch, stores public key in DynamoDB, cleans up on shutdown
2. **Assignment lookup includes operational keys** — `GetACAssignment` returns per-server public keys alongside IPs
3. **NHP_AAK/NHP_ARD carry operational keys** — AC receives unique keys for each assigned server
4. **Dual-device routing on server** — NLB traffic uses shared device, direct traffic uses operational device
5. **NHP_AOP uses operational device** — server signs knock results with per-instance key

### Phase 3: Deprecate Peer Group Mode

Once per-instance keys are deployed and verified:

1. Remove `PeerGroup` from `nhp/core/` (or keep as safety net)
2. Monitor for any remaining shared-key collisions (should be zero)
3. Consider removing the shared registration key entirely if NLB initial connection can be redesigned (e.g., unauthenticated NHP_AOL with server-side challenge)

---

## 8. Open Questions

| # | Question | Notes |
|---|----------|-------|
| 1 | Should the operational key be Ed25519 or X25519? | Current NHP uses Curve25519 for ECDH. Operational key should match. |
| 2 | DynamoDB table: new table or GSI on existing `ac-assignments`? | New table is cleaner. Existing table PK is `AC#{acId}` which doesn't fit server keys. |
| 3 | How does `MsgData` specify which device to use for encryption? | Options: (a) new `Device` field on `MsgData`, (b) separate `sendMsgCh` per device, (c) device selection in `sendMessageRoutine` based on message type. Option (a) is simplest. |
| 4 | What happens during rolling deployment when some servers have operational keys and some don't? | AC falls back to shared key for servers that don't advertise an operational key. `PeerGroup` handles the transition. Feature flag: server only advertises operational key if `UseOperationalKeys` config is true. |
| 5 | Can we skip the dual-device model and just use the operational key for everything? | No — NLB initial connection requires a known key. AC can't encrypt NHP_AOL to an unknown per-instance key. The shared registration key is needed for bootstrapping. |
| 6 | TTL value for DynamoDB server key entries? | Match ASG lifecycle hook timeout (3600s) plus buffer. 7200s (2 hours) should cover any graceful shutdown scenario. |
