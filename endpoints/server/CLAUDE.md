# endpoints/server — Local Guidance

## Lock Order

When acquiring multiple mutexes in `endpoints/server/`, follow this order
to prevent deadlocks. New code that takes locks in a different order
must update this list and audit all existing call sites.

- **Peer maps before peers**: `acPeerMapMutex` / `dbPeerMapMutex` /
  `agentPeerMapMutex` are acquired before any `peer.Lock()` (which
  `MatchesIP`, `RecvAddr`, `UpdateRecv`, `LastSendTime`, etc. take
  internally). Do not invert: `isKnownPeerIP` (`udpserver.go`) holds
  the map mutex while iterating peers, and a reverse-order site would
  deadlock against it.
- **`remoteConnectionMapMutex` is leaf-most for the conn lifecycle**:
  no other mutex is acquired while holding it. The connection
  routine's defer takes it briefly to remove the global-map entry.
- **`acConnectionMapMutex` then `remoteConnectionMapMutex`, never
  reversed AND never nested.** `HandleACOnline`'s stale-conn cleanup
  acquires `acConnectionMapMutex` first to find the stale entry,
  releases it, then acquires `remoteConnectionMapMutex` to remove
  the global-map entry. The two are never held simultaneously — even
  nested-in-order acquisition is forbidden because the connection
  routine's defer would invert against it (it removes from
  `acConnectionMap` first, then from `remoteConnectionMap` via
  `removeConnection`).
- **`agentPeerMapMutex` then `device.peerMapMutex`, never reversed.**
  `AddAgentPeer` (`udpserver.go`) holds `agentPeerMapMutex` across
  the `device.AddPeer` call so both maps reflect the new agent in a
  single critical section — closes a TOCTOU window where
  `agentPeerMap` had the pubkey but `device.peerMap` didn't yet, a
  blind spot for any future receive-path consumer that gates
  synchronously on `device.peerMap` (e.g. NHP_LST register/list).
  Safe because `core.Device` methods never call back into
  `UdpServer` and so cannot reach `agentPeerMapMutex` from inside
  `device.peerMapMutex`. A future change that takes
  `device.peerMapMutex` and then `agentPeerMapMutex` would deadlock
  against `AddAgentPeer`.
