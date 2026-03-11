# AC ↔ NHP Server Connection Hardening Plan

## Problem Statement

On 2026-03-10, a production outage revealed fragile AC ↔ NHP server connection semantics. After NHP server instances were replaced (ASG instance refresh), new servers had zero AC connections. NLB routed knock requests to servers without ACs, causing immediate 500 errors. The system took 10+ minutes to self-heal because:

1. ACs only re-register via NLB every 60 seconds (`RegistrationRefreshInterval`)
2. NLB round-robin doesn't guarantee all servers get AC registrations
3. New servers can't forward knocks because they have no peers in DynamoDB yet
4. `/health/ready` reports healthy even with zero AC connections, so NLB keeps routing traffic to them

The result: **every server restart creates a window where knock requests fail**, and the window length is non-deterministic.

---

## Current Architecture

```
AC Startup:
  AC → NLB (UDP 62206) → random Server
  Server → NHP_ARD (redirect to 3 assigned servers)
  AC → connects directly to 3 assigned server IPs
  AC → sends NHP_KPL every 10s, NHP_AOL every 60s

Knock Flow:
  Client → NLB (TLS 443) → random Server
  Server → looks up AC in acConnectionMap
  If found: Server → NHP_AOP → AC → ipset add → NHP_ART → Server → 302
  If not found + forwarder: Server → HTTP POST /nhp/internal/knock → peer Server
  If not found + no forwarder: 500 "no ac connection is available"
```

**Key data structures:**
- `acConnectionMap map[string][]*ACConn` — in-memory, per-server, indexed by AC ID
- DynamoDB `ac-assignments` table — AC→server assignments with 30min TTL
- Cloud Map — server health/discovery for forwarding

**Key intervals:**
- AC keepalive: 10s (NHP_KPL, fire-and-forget)
- AC re-registration: 60s (NHP_AOL, expects NHP_AAK)
- AC health timeout: 30s (3 missed keepalives)
- Assignment TTL: 1800s (30 minutes)
- AC reconnect backoff: exponential up to 5 minutes

---

## Hardening Measures

### H1: AC-Aware Health Checks (Quick Win)

**Problem:** `/health/ready` reports healthy even when a server has zero AC connections. NLB routes knock traffic to it, which always fails.

**Fix:** Add an AC connection check to the readiness probe.

```go
// healthmanager.go
func (hm *HealthManager) registerACChecker(us *UdpServer) {
    hm.RegisterChecker("ac_peers", &ACPeerChecker{server: us})
}

type ACPeerChecker struct {
    server *UdpServer
}

func (c *ACPeerChecker) Check(ctx context.Context) HealthCheckResult {
    // Count unique AC IDs, not total connections per AC.
    // An AC may have multiple connections (blue/green), but for health
    // checking we only care whether at least one AC peer exists.
    c.server.acConnectionMapMutex.RLock()
    peerCount := len(c.server.acConnectionMap)
    c.server.acConnectionMapMutex.RUnlock()

    if peerCount == 0 {
        return HealthCheckResult{
            Status:  "fail",
            Message: "no AC peers connected",
        }
    }
    return HealthCheckResult{
        Status:  "pass",
        Message: fmt.Sprintf("%d AC peer(s) connected", peerCount),
    }
}
```

**Behavior:**
- Server boots → `/health/ready` returns 503 → NLB marks unhealthy → no traffic
- AC connects → `/health/ready` returns 200 → NLB marks healthy → traffic flows
- All ACs disconnect → NLB drains traffic → no more knock failures

**Edge case:** On cold start with no ACs in the cluster, ALL servers would be unhealthy. The NLB would return 503 to all clients. This is correct behavior — knocks genuinely can't succeed without ACs.

**Consideration:** Make this a soft check (warning) on `/health/ready` but hard check on a new `/health/knock-ready` endpoint. The NLB HTTPS listener health check can point to `/health/knock-ready` while Docker/ECS health checks use `/health/live`. This avoids ASG terminating servers that are otherwise healthy but just waiting for ACs.

**Files:** `endpoints/server/healthmanager.go`, `endpoints/server/httpserver.go` (router)

**Effort:** Small (1 PR). **Impact:** Eliminates knock failures during topology changes entirely.

---

### H2: Server Startup AC Solicitation

**Problem:** After server restart, it passively waits for ACs to re-register (up to 60s per AC). During this window, it has zero AC connections and can't forward knocks.

**Fix:** On startup, the server actively solicits AC connections.

**Option A — Query DynamoDB assignments:**
On boot, query `ac-assignments` table for ACs assigned to this server (by server IP or instance ID). For each assigned AC, the server already knows the AC's last-known IP:port. Send a solicitation message (new NHP_ASR — AC Solicitation Request) to trigger immediate NHP_AOL from the AC.

```
Server boots → queries DynamoDB → finds ACs assigned to old IP
  → Can't solicit (old IPs are gone)
  → But CAN register itself in Cloud Map immediately
  → ACs' next health check (10s) detects new server entry
  → ACs send NHP_AOL to new server
```

**Option B — Cloud Map broadcast:**
On boot, server registers in Cloud Map immediately (already happens). Add logic to broadcast a "server ready" signal that ACs listen for. ACs check Cloud Map on each keepalive cycle and connect to any new servers they see.

**Option C — Stateless NLB re-registration:**
On boot, server sends a control message to the NLB IP that tells any AC currently connected via NLB to re-register. This is simpler but less targeted.

**Recommended: Option A + fallback to natural re-registration.**

**Files:** `endpoints/server/udpserver.go` (startup), `endpoints/server/msghandler.go` (AC discovery), `endpoints/ac/registration.go` (solicitation handler)

**Effort:** Medium (1-2 PRs). **Impact:** Reduces AC connection window from 60s to <10s.

---

### H3: Faster AC Re-Registration Interval

**Problem:** ACs re-send NHP_AOL every 60 seconds. If NLB routes this to an already-connected server, the new server waits another 60s.

**Fix:** Reduce `RegistrationRefreshInterval` from 60s to 15s, and ensure the AC sends NHP_AOL to ALL known server endpoints (not just the NLB).

```go
// registration.go
const RegistrationRefreshInterval = 15 // seconds (was 60)
```

**Current behavior:** AC sends NHP_AOL only to its assigned servers (direct IPs). If assigned servers are gone (terminated), it falls back to NLB. The NLB routes to a random server, which may or may not be one that needs the registration.

**Proposed behavior:**
1. AC sends NHP_AOL to all assigned server IPs (direct)
2. If any assigned server is unreachable (3 missed keepalives), AC ALSO sends NHP_AOL to NLB
3. NLB registration triggers re-assignment, which may redirect AC to new servers
4. AC connects to new servers within 1 keepalive cycle

**Files:** `endpoints/ac/registration.go` (constants, keepalive loop)

**Effort:** Small (1 PR). **Impact:** Reduces worst-case connection window from 60s to 15s.

---

### H4: Graceful Server Shutdown Drain

**Problem:** When a server shuts down (ASG termination), it drops all AC connections without warning. ACs discover the loss after 30s (health timeout), then re-register via NLB.

**Fix:** On SIGTERM, the server sends NHP_ARD (redirect) to all connected ACs, telling them to reconnect via NLB immediately.

```go
// udpserver.go — in shutdown handler
func (us *UdpServer) drainACConnections() {
    us.acConnectionMapMutex.RLock()
    defer us.acConnectionMapMutex.RUnlock()

    for acId, conns := range us.acConnectionMap {
        for _, conn := range conns {
            // Send redirect to NLB address
            us.sendACRedirect(conn, us.nlbAddress)
            log.Info("Drained AC %s to NLB during shutdown", acId)
        }
    }
}
```

**AC side:** On receiving NHP_ARD, the AC already disconnects from the old server and connects to the new targets. No AC-side changes needed.

**Interaction with ASG:** The ASG sends SIGTERM, waits for the lifecycle hook timeout (default 3600s), then force-terminates. The drain should complete in <1s.

**Files:** `endpoints/server/udpserver.go` (shutdown), `endpoints/server/main/main.go` (signal handler)

**Effort:** Small (1 PR). **Impact:** Eliminates the 30s AC health timeout window during planned shutdowns.

---

### H5: HTTP Knock Forwarding Without Prior Assignment

**Problem:** HTTP knock forwarding requires the forwarding server to look up which server the AC is assigned to in DynamoDB. New servers that just booted have no assignment data and can't forward.

**Fix:** Fall back to broadcasting the knock to ALL healthy servers in Cloud Map when no assignment data exists.

```go
// http_forward.go — in ForwardHttpKnock()
func (f *HttpForwarder) ForwardHttpKnock(ctx context.Context, ...) (*ServerKnockAckMsg, error) {
    // Try assignment-based forwarding first
    servers, err := f.getAssignedServers(acId)
    if err != nil || len(servers) == 0 {
        // Fallback: try all healthy servers from Cloud Map
        servers, err = f.getAllHealthyServers()
        if err != nil || len(servers) == 0 {
            return nil, fmt.Errorf("no servers available for forwarding")
        }
        log.Info("No assignment data for AC %s, trying all %d healthy servers", acId, len(servers))
    }

    // Existing: shuffle and try in order
    ...
}
```

**Files:** `endpoints/server/http_forward.go`

**Effort:** Small (1 PR). **Impact:** Enables forwarding even when DynamoDB has no assignment for the AC.

---

### H6: AC Connection Metrics & Alerting

**Problem:** No visibility into AC connection state. The outage was discovered by users, not monitoring.

**Fix:** Publish AC connection metrics to CloudWatch.

```go
// metrics.go — new gauge
func (mp *MetricsPublisher) SetACPeerCount(count int) {
    mp.mu.Lock()
    mp.gauges["ac_peer_count"] = float64(count)
    mp.mu.Unlock()
}
```

**Metrics to add:**
| Metric | Type | Description |
|--------|------|-------------|
| `ac_peer_count` | Gauge | Number of connected AC peers |
| `knock_no_ac` | Counter | Knock requests that failed due to no AC |
| `knock_forwarded` | Counter | Knock requests forwarded to peer server |
| `knock_forward_failed` | Counter | Forwarded knocks that failed on all peers |
| `ac_registration_latency_ms` | Histogram | Time from server boot to first AC connection |

**CloudWatch Alarms:**
- `ac_peer_count == 0` for >60s on any server → P1 alert
- `knock_no_ac > 0` sustained for >30s → P2 alert

**Files:** `endpoints/server/metrics.go`, `endpoints/server/httpserver.go`, `endpoints/server/udpserver.go`

**Effort:** Small (1 PR). **Impact:** Early warning before user-facing failures.

---

### H7: Assignment Table Seeding on Server Boot

**Problem:** New server instances don't exist in the AC assignment table. ACs that query their assignment get stale server IPs.

**Fix:** On boot, each server registers itself in the assignment table with its current IP. ACs that re-register see the updated server list.

```go
// udpserver.go — after Start()
func (us *UdpServer) registerSelfInAssignmentTable() {
    // Upsert this server's IP in the assignment table
    // so ACs querying assignments find us
    err := us.storage.RegisterServer(ctx, ServerRecord{
        ServerIP:   us.localIP,
        InstanceID: us.instanceID,
        AZ:         us.az,
        StartedAt:  time.Now(),
    })
}
```

**Files:** `endpoints/server/udpserver.go`, `endpoints/server/storage.go` (or equivalent)

**Effort:** Medium (1 PR). **Impact:** Makes AC assignments aware of new servers immediately.

---

## Implementation Order

```
Week 1 (immediate, blocks nothing):
├── H1: AC-aware health checks (eliminates knock failures) ✅ DONE
├── H3: Faster re-registration interval (15s → reduces window) — partial (60s→30s)
└── H6: AC connection metrics (visibility)

Week 2 (reduces recovery time):
├── H4: Graceful shutdown drain (eliminates planned-shutdown window)
└── H5: Forwarding without assignment (enables cold-start forwarding)

Week 3 (full hardening):
├── H2: Server startup AC solicitation (proactive recovery)
└── H7: Assignment table seeding (awareness of new servers)
```

**Combined effect:** With all measures, the knock failure window during server replacement goes from **60+ seconds (non-deterministic)** to **0 seconds** (NLB stops routing before AC connects, then starts routing only after AC connects).

---

## Verification

### Test: Server Rolling Restart
1. Baseline: create QURL, verify knock succeeds
2. Trigger instance refresh on server ASG
3. Monitor `knock_no_ac` metric — should stay at 0
4. Continuously resolve QURLs during refresh — should never get 500
5. After refresh completes, verify all servers have AC connections

### Test: AC Fleet Restart
1. Restart all AC instances simultaneously
2. Monitor `ac_peer_count` on all servers
3. Verify recovery to full connectivity within 15s
4. Verify no knock failures during recovery (NLB routes away from AC-less servers)

### Test: Mixed Failure
1. Terminate 1 server + 1 AC simultaneously
2. Verify remaining servers handle all knocks
3. Verify new server gets AC connections within 15s
4. Verify new AC connects to all servers within 15s

---

## Risk Assessment

| Measure | Risk | Mitigation |
|---------|------|------------|
| H1 (health check) | All servers unhealthy on cold start | Use separate `/health/knock-ready` endpoint; ASG uses `/health/live` |
| H2 (solicitation) | New NHP message type | Version negotiation; ACs ignore unknown messages |
| H3 (faster interval) | More DynamoDB writes | 15s is still light; assignment writes are conditional |
| H4 (shutdown drain) | Drain races with SIGKILL | 1s drain; ASG lifecycle hook gives 3600s |
| H5 (broadcast forward) | Fan-out amplification | Limit to 3 servers; shuffle for load distribution |
| H6 (metrics) | CloudWatch costs | Batch publishing (already implemented); ~$2/month |
| H7 (table seeding) | Stale entries | TTL on server records; Cloud Map as source of truth |
