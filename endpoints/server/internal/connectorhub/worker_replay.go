package connectorhub

import (
	"container/list"
	"crypto/sha256"
	"sync"
	"time"

	"github.com/OpenNHP/opennhp/nhp/core"
)

const hubWorkerReplayTTL = time.Duration(core.HubLSTReplayWindowSeconds) * time.Second

type replayEntry struct {
	digest    [sha256.Size]byte
	expiresAt time.Time
}

type packetReplayDecision uint8

const (
	packetReplayAccepted packetReplayDecision = iota + 1
	packetReplayExact
	packetReplayCapacityFull
)

// packetReplayCache records packets immediately after NHP authentication,
// before peer admission and response success. That prevents unauthenticated
// traffic from consuming the bounded cache while ensuring every authenticated
// datagram burns its exact-replay slot even when later processing drops it. A
// legitimate retry after such a drop must mint a fresh LST ciphertext.
type packetReplayCache struct {
	mu       sync.Mutex
	capacity int
	entries  map[[sha256.Size]byte]*list.Element
	order    *list.List
	lastNow  time.Time
}

func newPacketReplayCache(capacity int) *packetReplayCache {
	return &packetReplayCache{
		capacity: capacity,
		entries:  make(map[[sha256.Size]byte]*list.Element, capacity),
		order:    list.New(),
	}
}

// accept classifies an exact replay separately from capacity exhaustion.
// Capacity exhaustion is fail closed: no live digest is ever evicted to admit
// a new packet, even if an admission-bound invariant regresses later.
func (c *packetReplayCache) accept(digest [sha256.Size]byte, now time.Time) packetReplayDecision {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Callers may capture now before waiting for this mutex. Clamp it to the
	// latest accepted clock value so concurrent lock acquisition cannot append
	// an earlier expiry behind a later one and strand expired state.
	if now.Before(c.lastNow) {
		now = c.lastNow
	} else {
		c.lastNow = now
	}
	c.removeExpired(now)
	if element, ok := c.entries[digest]; ok {
		entry := element.Value.(replayEntry)
		// The protocol accepts the original packet at the exact replay-window
		// boundary, so the digest remains live at equality too.
		if !entry.expiresAt.Before(now) {
			return packetReplayExact
		}
		// removeExpired normally makes this unreachable. Keep the fail-closed
		// cleanup defensive if the FIFO-expiry invariant ever regresses.
		c.remove(element, entry.digest)
	}
	if c.order.Len() >= c.capacity {
		return packetReplayCapacityFull
	}

	element := c.order.PushBack(replayEntry{digest: digest, expiresAt: now.Add(hubWorkerReplayTTL)})
	c.entries[digest] = element
	return packetReplayAccepted
}

func (c *packetReplayCache) removeExpired(now time.Time) {
	for element := c.order.Front(); element != nil; element = c.order.Front() {
		entry := element.Value.(replayEntry)
		if !entry.expiresAt.Before(now) {
			return
		}
		c.remove(element, entry.digest)
	}
}

func (c *packetReplayCache) remove(element *list.Element, digest [sha256.Size]byte) {
	delete(c.entries, digest)
	c.order.Remove(element)
}
