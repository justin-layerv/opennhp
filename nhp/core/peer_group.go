package core

import (
	"net"
	"sync"
)

// MaxPeerGroupSize is the maximum number of members in a PeerGroup.
// In practice, ACs are assigned to 3 servers. This cap prevents unbounded
// growth from bugs while allowing headroom for transient states.
const MaxPeerGroupSize = 5

// PeerGroup wraps multiple UdpPeer instances that share the same public key
// but have different network addresses. This occurs when NHP servers in an
// ASG share a keypair loaded from Secrets Manager.
//
// PeerGroup implements the Peer interface so it is transparent to callers.
// Address-sensitive operations (CheckRecvAddress, UpdateRecv) dispatch to
// the correct member by matching the remote address.
//
// Lock ordering: Device.peerMapMutex > PeerGroup.mu > UdpPeer.Mutex.
// PeerGroup methods hold mu while calling UdpPeer methods (which acquire
// UdpPeer.Mutex). No UdpPeer method calls back into PeerGroup or Device.
type PeerGroup struct {
	mu      sync.Mutex
	members []*UdpPeer // invariant: len >= 2, all share same PubKeyBase64
}

// NewPeerGroup creates a PeerGroup from two or more initial members.
func NewPeerGroup(first, second *UdpPeer) *PeerGroup {
	return &PeerGroup{
		members: []*UdpPeer{first, second},
	}
}

// AddMember adds a peer to the group. If a member with the same IP and port
// already exists, it is replaced (re-registration) and the call returns true.
// Returns false if the group is already at MaxPeerGroupSize and the new peer
// has a unique address — the peer is NOT added. Callers MUST check the return
// value if they will subsequently attempt to communicate with the peer; a
// refused peer is absent from the device peer pool and any response from it
// will fail PeerGroup.CheckRecvAddress, producing a confusing
// ErrPeerAddressMismatch instead of a clear "peer pool full" signal.
func (pg *PeerGroup) AddMember(peer *UdpPeer) bool {
	pg.mu.Lock()
	defer pg.mu.Unlock()

	for i, m := range pg.members {
		if udpPeersShareAddress(m, peer) {
			pg.members[i] = peer
			return true
		}
	}
	if len(pg.members) >= MaxPeerGroupSize {
		return false
	}
	pg.members = append(pg.members, peer)
	return true
}

// RemoveMember removes a member matching the given address (IP or Host()).
// Returns the removed member, or nil if not found.
func (pg *PeerGroup) RemoveMember(addr string) *UdpPeer {
	pg.mu.Lock()
	defer pg.mu.Unlock()

	for i, m := range pg.members {
		if m.Ip == addr || m.Host() == addr {
			removed := pg.members[i]
			pg.members = append(pg.members[:i], pg.members[i+1:]...)
			return removed
		}
	}
	return nil
}

// Len returns the number of members in the group.
func (pg *PeerGroup) Len() int {
	pg.mu.Lock()
	defer pg.mu.Unlock()
	return len(pg.members)
}

// Members returns a copy of the member slice. The returned slice is safe to
// iterate without holding the lock; individual UdpPeer methods are still
// internally synchronized.
func (pg *PeerGroup) Members() []*UdpPeer {
	pg.mu.Lock()
	defer pg.mu.Unlock()
	out := make([]*UdpPeer, len(pg.members))
	copy(out, pg.members)
	return out
}

// --- Peer interface implementation ---

func (pg *PeerGroup) DeviceType() DeviceTypeEnum {
	pg.mu.Lock()
	defer pg.mu.Unlock()
	return pg.members[0].DeviceType()
}

func (pg *PeerGroup) Name() string {
	pg.mu.Lock()
	defer pg.mu.Unlock()
	return pg.members[0].Name() + "(group)"
}

func (pg *PeerGroup) PublicKey() []byte {
	pg.mu.Lock()
	defer pg.mu.Unlock()
	return pg.members[0].PublicKey()
}

func (pg *PeerGroup) PublicKeyBase64() string {
	pg.mu.Lock()
	defer pg.mu.Unlock()
	return pg.members[0].PublicKeyBase64()
}

func (pg *PeerGroup) IsExpired() bool {
	pg.mu.Lock()
	defer pg.mu.Unlock()
	for _, m := range pg.members {
		if !m.IsExpired() {
			return false
		}
	}
	return true
}

func (pg *PeerGroup) ResolveHost() string {
	pg.mu.Lock()
	defer pg.mu.Unlock()
	return pg.members[0].ResolveHost()
}

func (pg *PeerGroup) ResolvedIps() []string {
	pg.mu.Lock()
	defer pg.mu.Unlock()
	return pg.members[0].ResolvedIps()
}

func (pg *PeerGroup) Host() string {
	pg.mu.Lock()
	defer pg.mu.Unlock()
	return pg.members[0].Host()
}

func (pg *PeerGroup) SendAddr() net.Addr {
	pg.mu.Lock()
	defer pg.mu.Unlock()
	for _, m := range pg.members {
		if addr := m.SendAddr(); addr != nil {
			return addr
		}
	}
	return nil
}

func (pg *PeerGroup) InvalidateDNSCache() {
	pg.mu.Lock()
	defer pg.mu.Unlock()
	for _, m := range pg.members {
		m.InvalidateDNSCache()
	}
}

func (pg *PeerGroup) LastSendTime() int64 {
	pg.mu.Lock()
	defer pg.mu.Unlock()
	var latest int64
	for _, m := range pg.members {
		if t := m.LastSendTime(); t > latest {
			latest = t
		}
	}
	return latest
}

func (pg *PeerGroup) UpdateSend(currTime int64) {
	pg.mu.Lock()
	defer pg.mu.Unlock()
	pg.members[0].UpdateSend(currTime)
}

func (pg *PeerGroup) RecvAddr() net.Addr {
	pg.mu.Lock()
	defer pg.mu.Unlock()
	// Return the most recently updated member's recv addr
	var latest int64
	var latestAddr net.Addr
	for _, m := range pg.members {
		if t := m.LastRecvTime(); t > latest {
			latest = t
			latestAddr = m.RecvAddr()
		}
	}
	return latestAddr
}

func (pg *PeerGroup) LastRecvTime() int64 {
	pg.mu.Lock()
	defer pg.mu.Unlock()
	var latest int64
	for _, m := range pg.members {
		if t := m.LastRecvTime(); t > latest {
			latest = t
		}
	}
	return latest
}

// CheckRecvAddress checks whether currAddr matches ANY member of the group.
// This is the critical fix: with shared keys, packets from different servers
// (different IPs) are all valid peers within the group.
func (pg *PeerGroup) CheckRecvAddress(currTime int64, currAddr net.Addr) bool {
	pg.mu.Lock()
	defer pg.mu.Unlock()
	for _, m := range pg.members {
		if m.CheckRecvAddress(currTime, currAddr) {
			return true
		}
	}
	return false
}

// UpdateRecv routes the update to the member whose recv address or
// static/cached send address matches currAddr. Falls back to the first
// member if no match. Uses matchesKnownAddr which never triggers DNS
// resolution, keeping the per-packet hot path fast.
func (pg *PeerGroup) UpdateRecv(currTime int64, currAddr net.Addr) {
	pg.mu.Lock()
	defer pg.mu.Unlock()

	addrStr := currAddr.String()
	for _, m := range pg.members {
		if m.matchesKnownAddr(addrStr) {
			m.UpdateRecv(currTime, currAddr)
			return
		}
	}
	// Fallback: new address for the group, update first member
	if len(pg.members) > 0 {
		pg.members[0].UpdateRecv(currTime, currAddr)
	}
}
