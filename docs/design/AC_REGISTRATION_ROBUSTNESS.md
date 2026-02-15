# AC Registration Robustness Improvements

## Problem Statement

AC registration can become stale when:
1. AC's UDP socket is recreated (timeout, system pressure, network change)
2. AC sends from new source port but server has stale connection entry
3. Server tries to send knock operations to old (dead) connection

This causes "knock_failed" errors even when AC is running and registered.

## Root Causes

### 1. Server: No Cleanup of Old Connections on Re-registration

**File:** `endpoints/server/msghandler.go` in `HandleACOnline()`

When an AC re-registers, the server simply overwrites the `acConnectionMap` entry:
```go
s.acConnectionMap[acId] = acConn
```

But the **old connection object** remains in `remoteConnectionMap` and may still be
referenced. The server needs to:
1. Find and close the old connection for this AC ID
2. Remove it from `remoteConnectionMap`
3. Then store the new connection

**Fix:** Add connection cleanup before storing new AC connection.

### 2. AC: Connection Timeout Doesn't Trigger Re-registration

**File:** `endpoints/ac/udpac.go` in `connectionRoutine()`

The connection can timeout and be deleted without triggering re-registration:
```go
case <-time.After(time.Duration(conn.ConnData.TimeoutMs) * time.Millisecond):
    log.Debug("Connection routine idle timeout")
    return  // Connection deleted silently
```

When the next message is sent, a new connection is created with a new source port,
but the server's registration isn't updated.

**Fix:** Notify the registration manager when a server connection times out.

### 3. Unidirectional Keepalives Don't Detect Socket Issues

**File:** `endpoints/ac/registration.go`

KPL packets are sent but no response is expected:
```go
// NHP_KPL is unidirectional - the server receives but doesn't respond.
server.UpdateLastSeen()  // Updated on SEND, not on confirmed delivery
```

This means the AC considers the connection healthy as long as sends succeed locally,
even if packets never reach the server (e.g., NAT mapping expired, socket recreated).

**Fix:** Add periodic bidirectional health checks or track actual packet delivery.

## Proposed Solutions

### Solution 1: Server-Side Stale Connection Cleanup (High Priority)

In `HandleACOnline()`, before storing new connection:

```go
// Clean up any existing connection for this AC ID
s.acConnectionMapMutex.Lock()
if oldConn, exists := s.acConnectionMap[acId]; exists {
    // Close old connection and remove from remoteConnectionMap
    oldConnData := oldConn.ConnData
    s.acConnectionMapMutex.Unlock()

    // Remove from remoteConnectionMap
    s.remoteConnectionMapMutex.Lock()
    for addr, conn := range s.remoteConnectionMap {
        if conn.ConnData.Equal(oldConnData) {
            delete(s.remoteConnectionMap, addr)
            log.Info("server-ac(%s)[HandleACOnline] Removed stale connection from %s", acId, addr)
            break
        }
    }
    s.remoteConnectionMapMutex.Unlock()

    s.acConnectionMapMutex.Lock()
}
s.acConnectionMap[acId] = acConn
s.acConnectionMapMutex.Unlock()
```

### Solution 2: AC Connection Timeout Triggers Re-registration (High Priority)

In `connectionRoutine()`, notify registration when server connection times out:

```go
case <-time.After(time.Duration(conn.ConnData.TimeoutMs) * time.Millisecond):
    log.Debug("Connection routine idle timeout")
    // If this is a server connection, trigger re-registration
    if a.registration != nil && a.isServerConnection(conn) {
        log.Warning("Server connection timed out, triggering re-registration")
        go a.registration.TriggerReregistration("connection_timeout")
    }
    return
```

### Solution 3: Bidirectional Health Check (Medium Priority)

Add optional bidirectional health verification:

```go
// Every N keepalive intervals, send a KPL that expects a response
if r.healthCheckCounter % BidirectionalCheckInterval == 0 {
    md := &core.MsgData{
        HeaderType:    core.NHP_KPL,
        Flags:         KPL_FLAG_EXPECT_RESPONSE,  // New flag
        ResponseMsgCh: make(chan *core.PacketParserData, 1),
    }
    // Wait for response with short timeout
    select {
    case ppd := <-md.ResponseMsgCh:
        server.UpdateLastSeen()
    case <-time.After(KeepaliveTimeout):
        log.Warning("Bidirectional health check failed")
        // Trigger re-registration
    }
}
```

### Solution 4: Connection Identity Tracking (Medium Priority)

Track connection identity (local port) and detect changes:

```go
type ACConn struct {
    // ... existing fields
    LocalPort int  // Track the local port at registration time
}

// In processACOperation, verify connection identity
if acConn.LocalPort != 0 && acConn.ConnData.LocalAddr.Port != acConn.LocalPort {
    log.Warning("AC connection port changed (%d -> %d), may be stale",
        acConn.LocalPort, acConn.ConnData.LocalAddr.Port)
    // Optionally reject and wait for re-registration
}
```

## Implementation Priority

1. **Solution 1** (Server cleanup) - ✅ IMPLEMENTED in this PR
2. **Solution 2** (AC timeout handling) - Prevents silent connection loss
3. **Solution 4** (Identity tracking) - Defense in depth
4. **Solution 3** (Bidirectional check) - Future enhancement

## Implementation Notes (Solution 1)

The fix was implemented in `endpoints/server/msghandler.go` in `HandleACOnline()`.

Key changes:
- Before storing a new AC connection, check if one already exists for that AC ID
- If the old connection has a different remote address (IP:port), it's stale
- Remove the stale connection from `remoteConnectionMap` and close it
- Then store the new connection

The comparison uses remote address string (`IP:port`) rather than `ConnData.Equal()`
because `Equal()` compares by `InitTime` which doesn't detect port changes.

## Testing Recommendations

1. **Unit test:** Simulate AC re-registration, verify old connection is cleaned up
2. **Integration test:** Kill AC socket (iptables drop), verify recovery
3. **E2E test:** Force NAT timeout, verify knock still works after re-registration
4. **Chaos test:** Random connection drops during knock operations
