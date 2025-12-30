# Full NHP E2E Test Design Document

## Executive Summary

This document evaluates and designs end-to-end tests for the complete NHP (Network Hiding Protocol) flow, covering AC-Server connections (Phase 1) and Agent authentication with access control (Phase 2).

## Current State Analysis

### Existing Infrastructure

The `docker/docker-compose.yaml` provides a complete local NHP stack:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Docker Network: 177.7.0.0/16                 │
│                                                                 │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐ │
│  │  nhp-agent  │    │ nhp-server  │    │      nhp-ac         │ │
│  │  177.7.0.8  │    │  177.7.0.9  │    │    177.7.0.10       │ │
│  │             │    │  :62206/udp │    │  iptables/ipset     │ │
│  └─────────────┘    └─────────────┘    │  Traefik proxy      │ │
│         │                  │           └─────────────────────┘ │
│         │                  │                    │              │
│         │                  │           ┌─────────────────────┐ │
│         │                  │           │     web-app         │ │
│         │                  │           │    177.7.0.11       │ │
│         │                  │           │  (protected)        │ │
│         └──────────────────┴───────────┴─────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### Pre-configured Keys

All components have pre-shared static keys in `docker/nhp-*/etc/`:
- Server knows AC and Agent public keys
- AC knows Server public key
- Agent knows Server public key

### Protocol Flow

```
Phase 1: AC-Server Connection
─────────────────────────────
AC                              Server
 │                                 │
 │──── NHP_AOL (AC Online) ───────►│  AC announces itself
 │                                 │
 │◄─── NHP_AAK (AC Ack) ──────────│  Server acknowledges
 │                                 │
 │  [Connection established]       │
 │  [Periodic keepalive]           │


Phase 2: Agent Access Request
─────────────────────────────
Agent              Server                AC
  │                   │                   │
  │── NHP_KNK ───────►│                   │  Agent knocks
  │  (knock)          │                   │
  │                   │── NHP_AOP ───────►│  Server instructs AC
  │                   │   (open access)   │
  │                   │                   │  AC opens iptables
  │                   │◄── NHP_ART ──────│  AC confirms
  │                   │   (result)        │
  │◄── NHP_ACK ──────│                   │  Agent gets ack
  │                   │                   │
  │════════════════ Access to web-app ═══│  Agent can now access
```

---

## Phase 1: AC-Server Connection Tests

### Objective

Verify that AC successfully connects to Server and the connection survives configuration updates (validates our fix for the AC peer wipe bug).

### Test Scenarios

#### 1.1 Basic AC-Server Handshake

**What we test:**
- AC starts and connects to Server
- NHP_AOL/NHP_AAK handshake completes
- Server's peer pool contains AC's public key

**Observable indicators:**
- Server logs: "Receive [NHP_AOL] message"
- AC logs: "Receive [NHP_AAK] message"
- Both show successful peer validation

**Implementation approach:**
```go
func TestACServerHandshake(t *testing.T) {
    // 1. Start docker-compose (server + ac)
    // 2. Wait for services to be healthy
    // 3. Parse AC logs for "NHP_AAK"
    // 4. Parse Server logs for "NHP_AOL"
    // 5. Verify no "peer not found" errors
}
```

**Complexity:** Low
**Dependencies:** Docker, log parsing
**CI-friendly:** Yes

#### 1.2 Connection Survives Config Update

**What we test:**
- AC connects to Server (baseline)
- etcd config is updated (no `[[ACs]]` section)
- AC connection remains valid (our fix!)

**Observable indicators:**
- No "peer not found in peer pool" errors after config update
- AC continues sending periodic keepalives
- No connection drops in logs

**Implementation approach:**
```go
func TestACConnectionSurvivesConfigUpdate(t *testing.T) {
    // 1. Start full stack with etcd
    // 2. Wait for AC-Server handshake
    // 3. Update /nhp/config in etcd (no [[ACs]])
    // 4. Wait 5 seconds
    // 5. Verify AC connection still works (check logs)
    // 6. Verify no "peer not found" errors
}
```

**Complexity:** Medium
**Dependencies:** Docker, etcd, log parsing
**CI-friendly:** Yes

#### 1.3 AC Reconnection After Server Restart

**What we test:**
- AC connects to Server
- Server restarts
- AC automatically reconnects

**Observable indicators:**
- New NHP_AOL/NHP_AAK handshake in logs
- No prolonged connection failures

**Complexity:** Medium
**Dependencies:** Docker orchestration
**CI-friendly:** Yes (with proper wait times)

### Phase 1 Infrastructure Requirements

```yaml
# tests/local/docker-compose.phase1.yaml
services:
  etcd:
    image: quay.io/coreos/etcd:v3.5.11
    # ... (same as existing)

  nhp-server:
    build:
      context: ../..
      dockerfile: docker/Dockerfile.server
    environment:
      - ETCD_ENDPOINTS=http://etcd:2379
    depends_on:
      etcd: { condition: service_healthy }
    volumes:
      - ./config/server:/nhp-server/etc

  nhp-ac:
    build:
      context: ../..
      dockerfile: docker/Dockerfile.ac
    environment:
      - ETCD_ENDPOINTS=http://etcd:2379
    depends_on:
      - nhp-server
    cap_add:
      - NET_ADMIN
```

### Phase 1 Test Code Structure

```
tests/
└── e2e-local/
    ├── docker-compose.phase1.yaml
    ├── config/
    │   ├── server/
    │   │   ├── config.toml
    │   │   ├── ac.toml        # AC public key
    │   │   └── remote.toml    # etcd connection
    │   └── ac/
    │       ├── config.toml
    │       ├── server.toml    # Server public key
    │       └── remote.toml    # etcd connection
    ├── phase1_test.go
    └── helpers.go
```

### Phase 1 Estimated Effort

| Task | Hours |
|------|-------|
| Create docker-compose.phase1.yaml | 1 |
| Generate test key pairs | 0.5 |
| Create config templates | 1 |
| Write test helpers (log parsing, wait) | 2 |
| Implement 3 test scenarios | 2 |
| CI integration | 1 |
| **Total** | **7.5 hours** |

---

## Phase 2: Agent Authentication Tests

### Objective

Verify the complete agent authentication flow and access control mechanism.

### Critical Insight: Test Complexity

Phase 2 is significantly more complex because:

1. **NHP Protocol Implementation Required**
   - Agent must send valid NHP_KNK (knock) packets
   - Packets require curve25519 encryption
   - Transaction IDs, counters, timestamps must be correct

2. **Plugin Authentication**
   - Server uses plugins (passcode, oidc, example) for auth
   - Tests need valid credentials for the plugin

3. **iptables Verification**
   - Need to verify rules are actually created
   - Requires access to AC container's iptables/ipset

### Test Scenarios

#### 2.1 Successful Agent Authentication

**What we test:**
- Agent sends NHP_KNK with valid credentials
- Server authenticates via plugin
- Server sends NHP_AOP to AC
- AC opens iptables for agent IP
- Agent can access protected web-app

**Observable indicators:**
- Server logs: "Receive [NHP_KNK]", auth success
- AC logs: "Receive [NHP_AOP]", "[HandleAccessControl] succeed"
- Agent can HTTP GET web-app

**Implementation approaches:**

**Option A: Use existing nhp-agent binary**
```go
func TestAgentAuthentication_ViaContainer(t *testing.T) {
    // 1. Start full stack (server + ac + web-app)
    // 2. Start nhp-agent container with test config
    // 3. Agent automatically sends knock on startup
    // 4. Verify via logs + HTTP access to web-app
}
```
- Pro: Uses real agent, tests full stack
- Con: Need to configure agent, less control

**Option B: Programmatic agent simulation**
```go
func TestAgentAuthentication_Programmatic(t *testing.T) {
    // 1. Start server + ac + web-app
    // 2. Use nhp/core package to craft NHP_KNK packet
    // 3. Send UDP packet to server
    // 4. Verify via logs + HTTP access
}
```
- Pro: Fine-grained control, can test edge cases
- Con: Need to implement packet construction, crypto

**Option C: HTTP-based testing (if server HTTP enabled)**
```go
func TestAgentAuthentication_ViaHTTP(t *testing.T) {
    // 1. Start server with HTTP enabled
    // 2. Use Server's HTTP API to trigger knock
    // 3. Verify access
}
```
- Pro: Simple HTTP calls
- Con: Server may not expose this API

**Recommendation: Option A for Phase 2.1**

#### 2.2 Invalid Credentials Rejected

**What we test:**
- Agent sends NHP_KNK with wrong passcode
- Server rejects authentication
- AC does NOT open iptables
- Agent cannot access web-app

**Complexity:** Medium (need to configure agent with bad creds)

#### 2.3 Access Timeout/Revocation

**What we test:**
- Agent authenticates successfully
- Wait for access timeout (e.g., 30 seconds)
- Verify iptables rules are removed
- Agent can no longer access web-app

**Complexity:** High (requires waiting, timing sensitive)

#### 2.4 Multiple Agents Concurrent Access

**What we test:**
- Multiple agents authenticate simultaneously
- Each gets their own iptables rules
- All can access web-app independently

**Complexity:** High (multiple agent instances)

### Phase 2 Infrastructure Requirements

```yaml
# tests/local/docker-compose.phase2.yaml
services:
  etcd:
    # ... same as phase1

  nhp-server:
    # ... same as phase1
    volumes:
      - ./config/server:/nhp-server/etc
      - ./config/plugins:/nhp-server/plugins  # plugin config

  nhp-ac:
    # ... same as phase1

  web-app:
    image: nginx:alpine
    networks:
      nhp-test:
        ipv4_address: 177.7.0.11

  # Test agent - configured for testing
  nhp-agent:
    build:
      context: ../..
      dockerfile: docker/Dockerfile.agent
    volumes:
      - ./config/agent:/nhp-agent/etc
    depends_on:
      - nhp-server
      - nhp-ac
```

### Phase 2 Test Code Structure

```
tests/
└── e2e-local/
    ├── docker-compose.phase2.yaml
    ├── config/
    │   ├── server/
    │   │   ├── ... (from phase1)
    │   │   ├── agent.toml     # Agent public key
    │   │   └── resource.toml  # Plugin config
    │   ├── ac/
    │   │   └── ... (from phase1)
    │   └── agent/
    │       ├── config.toml
    │       ├── server.toml    # Server public key
    │       └── resource.toml  # Target resource
    ├── phase1_test.go
    ├── phase2_test.go
    └── helpers.go
```

### Phase 2 Estimated Effort

| Task | Hours |
|------|-------|
| Extend docker-compose for agent | 1 |
| Configure agent with test credentials | 1 |
| Write iptables verification helper | 2 |
| Implement successful auth test | 2 |
| Implement invalid creds test | 1 |
| Implement timeout test | 2 |
| CI integration | 1 |
| **Total** | **10 hours** |

---

## Technical Challenges & Mitigations

### Challenge 1: Log Parsing Reliability

**Problem:** Relying on log parsing is fragile; log formats may change.

**Mitigation:**
- Use structured log patterns with regex
- Add health check endpoints to Server/AC that expose connection state
- Consider adding test-mode flags that expose metrics

### Challenge 2: Timing Sensitivity

**Problem:** Network/container startup times vary; tests may be flaky.

**Mitigation:**
- Use exponential backoff with retries
- Wait for specific log messages indicating readiness
- Add health checks to docker-compose services
- Use generous timeouts in CI

### Challenge 3: iptables Verification

**Problem:** Need to verify iptables rules inside AC container.

**Mitigation:**
```go
func verifyIptablesRule(t *testing.T, srcIP string) bool {
    // docker exec nhp-ac ipset list nhp_default_v4 | grep srcIP
    cmd := exec.Command("docker", "exec", "nhp-ac",
        "ipset", "list", "nhp_default_v4")
    output, _ := cmd.Output()
    return strings.Contains(string(output), srcIP)
}
```

### Challenge 4: Key Management

**Problem:** Need consistent, known keys across all components.

**Mitigation:**
- Use fixed test keys (already exist in docker/nhp-*/etc/)
- Generate fresh keys during test setup if needed
- Document key relationships clearly

### Challenge 5: CI Resource Usage

**Problem:** Building 4 Docker images is slow.

**Mitigation:**
- Cache Docker layers in CI
- Use pre-built images for CI (push test images)
- Run Phase 1 and Phase 2 in parallel (different workflows)

---

## Recommendation

### Phased Implementation

**Phase 1 (Recommended to start):**
- High value, lower complexity
- Validates the fix we just made
- Can run in CI within reasonable time
- **Start here**

**Phase 2 (After Phase 1 is stable):**
- Higher complexity, but high value
- Requires more infrastructure setup
- Consider starting with Option A (container-based agent)

### CI Strategy

```yaml
# .github/workflows/e2e-tests.yml
jobs:
  e2e-phase1:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build images
        run: docker compose -f tests/e2e-local/docker-compose.phase1.yaml build
      - name: Run Phase 1 tests
        run: go test -v -tags=e2e ./tests/e2e-local/... -run Phase1

  e2e-phase2:
    runs-on: ubuntu-latest
    needs: e2e-phase1  # Only run if Phase 1 passes
    steps:
      - uses: actions/checkout@v4
      - name: Build images
        run: docker compose -f tests/e2e-local/docker-compose.phase2.yaml build
      - name: Run Phase 2 tests
        run: go test -v -tags=e2e ./tests/e2e-local/... -run Phase2
```

### Success Metrics

| Metric | Phase 1 | Phase 2 |
|--------|---------|---------|
| Test coverage | AC-Server connection | Full auth flow |
| CI time | ~3 min | ~5 min |
| Flakiness target | <5% | <10% |
| Maintenance burden | Low | Medium |

---

## Next Steps

1. **Approve this design** - Review and provide feedback
2. **Implement Phase 1** - Create docker-compose, write tests
3. **Stabilize Phase 1** - Run in CI for 1-2 weeks
4. **Implement Phase 2** - Build on Phase 1 infrastructure
5. **Document** - Update TESTING.md with e2e test instructions

---

## Appendix: Key Files Reference

| Component | Config Location | Key Files |
|-----------|-----------------|-----------|
| Server | `docker/nhp-server/etc/` | config.toml, ac.toml, agent.toml, http.toml |
| AC | `docker/nhp-ac/etc/` | config.toml, server.toml |
| Agent | `docker/nhp-agent/etc/` | config.toml, server.toml, resource.toml |

## Appendix: Message Types

| Type | Value | Direction | Purpose |
|------|-------|-----------|---------|
| NHP_KNK | 1 | Agent→Server | Knock request |
| NHP_AOL | 10 | AC→Server | AC online announcement |
| NHP_AAK | 11 | Server→AC | AC acknowledgement |
| NHP_AOP | 3 | Server→AC | Open access instruction |
| NHP_ART | 12 | AC→Server | Access result |
| NHP_ACK | 5 | Server→Agent | Knock acknowledgement |
