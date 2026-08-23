package server

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

const (
	maxLiveNHPSessions           = 100_000
	maxSessionIDGenerationTries  = 32
	pendingSessionReservationTTL = 30 * time.Second
	sessionRegistrySweepInterval = time.Second
	maxSessionCloseReplayEvents  = 10_000
	maxAgentSessionCloseCutoffs  = 100_000
	maxExactSessionCloseCutoffs  = 100_000
	// Keep server-side close cutoffs through the AC's complete authenticated AOP
	// replay window, not merely the shorter forwarded-control replay window.
	agentSessionCloseCutoffTTL = time.Duration(core.AOPRecvStalenessFloorSeconds)*time.Second + 5*time.Second
)

var (
	errNHPSessionRegistryFull = errors.New("NHP live-session registry is full")
	errNHPSessionIDCollision  = errors.New("NHP session ID is already reserved")
	errNHPSessionNotReserved  = errors.New("NHP session ID is not reserved by this agent")
)

type liveNHPSession struct {
	agentPubKey      []byte
	issuedAt         time.Time
	sessionExpiresAt time.Time
	retainUntil      time.Time
	acIDs            map[string]struct{}
	inFlight         int
	closing          bool
}

type nhpSessionCloseSnapshot struct {
	SessionID uint64
	IssuedAt  time.Time
	ACIDs     []string
	InFlight  int
}

type agentSessionCloseCutoff struct {
	issuedThrough time.Time
	expiresAt     time.Time
}

type closeEventAdmission uint8

const (
	closeEventRejected closeEventAdmission = iota
	closeEventNew
	closeEventReplay
	closeEventSaturated
)

// liveNHPSessionRegistry is the authoritative process-local allocator and
// close registry for base numeric NHP sessions. Every generated ID is inserted
// under mu before any AOP, ACK, or token publication can observe it. Forwarded
// owners reserve the origin's exact ID before opening their local ACs.
//
// The registry contains no AC token. It retains only the authenticated agent
// Noise key, issuance/deadline, and AC IDs needed to emit opnTime=0 AOPs.
type liveNHPSessionRegistry struct {
	mu sync.Mutex

	sessions                   map[uint64]*liveNHPSession
	closeSeen                  map[string]time.Time
	closeCutoffs               map[string]agentSessionCloseCutoff
	closeCutoffsSaturatedUntil time.Time
	exactCloseCutoffs          map[string]time.Time
	exactCloseSaturatedUntil   time.Time
	nextSweep                  time.Time
	now                        func() time.Time
	newID                      func() uint64
	max                        int
	maxCloseSeen               int
	maxCloseCutoffs            int
	maxExactCloseCutoffs       int
}

func newLiveNHPSessionRegistry() *liveNHPSessionRegistry {
	return &liveNHPSessionRegistry{
		sessions:             make(map[uint64]*liveNHPSession),
		closeSeen:            make(map[string]time.Time),
		closeCutoffs:         make(map[string]agentSessionCloseCutoff),
		exactCloseCutoffs:    make(map[string]time.Time),
		now:                  time.Now,
		newID:                common.NewNHPSessionID,
		max:                  maxLiveNHPSessions,
		maxCloseSeen:         maxSessionCloseReplayEvents,
		maxCloseCutoffs:      maxAgentSessionCloseCutoffs,
		maxExactCloseCutoffs: maxExactSessionCloseCutoffs,
	}
}

func cloneAgentPublicKey(agentPubKey []byte) ([]byte, error) {
	if len(agentPubKey) != 32 {
		return nil, errors.New("authenticated agent public key must be 32 bytes")
	}
	return bytes.Clone(agentPubKey), nil
}

func decodeAgentPublicKey(agentPubKeyB64 string) ([]byte, error) {
	if agentPubKeyB64 == "" {
		return nil, errors.New("authenticated agent public key must not be empty")
	}
	pubKey, err := base64.StdEncoding.DecodeString(agentPubKeyB64)
	if err != nil || len(pubKey) != 32 {
		return nil, errors.New("authenticated agent public key must be canonical base64 for 32 bytes")
	}
	if base64.StdEncoding.EncodeToString(pubKey) != agentPubKeyB64 {
		return nil, errors.New("authenticated agent public key must use canonical base64")
	}
	return pubKey, nil
}

func (r *liveNHPSessionRegistry) reserveNew(agentPubKey []byte, issuedAt time.Time) (uint64, error) {
	if r == nil || issuedAt.IsZero() {
		return 0, errNHPSessionNotReserved
	}
	agentKey, err := cloneAgentPublicKey(agentPubKey)
	if err != nil {
		return 0, err
	}
	return r.reserveNewWithAgent(agentKey, issuedAt)
}

func (r *liveNHPSessionRegistry) reserveNewWithAgent(agentKey []byte, issuedAt time.Time) (uint64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	r.sweepLocked(now, len(r.sessions) >= r.max)
	if len(agentKey) != 0 && r.rejectedByCloseCutoffLocked(agentKey, issuedAt, now) {
		return 0, errNHPSessionNotReserved
	}
	if len(r.sessions) >= r.max {
		return 0, errNHPSessionRegistryFull
	}
	for attempts := 0; attempts < maxSessionIDGenerationTries; attempts++ {
		sessionID := r.newID()
		if sessionID == 0 {
			continue
		}
		if existing := r.sessions[sessionID]; existing != nil {
			if !now.Before(existing.retainUntil) && existing.inFlight == 0 {
				delete(r.sessions, sessionID)
			} else {
				continue
			}
		}
		r.sessions[sessionID] = &liveNHPSession{
			agentPubKey:      agentKey,
			issuedAt:         issuedAt,
			sessionExpiresAt: issuedAt.Add(pendingSessionReservationTTL),
			retainUntil:      issuedAt.Add(pendingSessionReservationTTL),
			acIDs:            make(map[string]struct{}),
		}
		return sessionID, nil
	}
	return 0, errNHPSessionIDCollision
}

// reserveExact installs a forwarded session before the receiver emits AOP.
// A byte-identical duplicate forward is idempotent; a different issuance or
// authenticated agent using the same numeric ID is a collision and fails
// closed.
func (r *liveNHPSessionRegistry) reserveExact(agentPubKey []byte, sessionID uint64, issuedAt, expiresAt time.Time) error {
	if r == nil || sessionID == 0 || issuedAt.IsZero() || !expiresAt.After(issuedAt) {
		return errNHPSessionNotReserved
	}
	agentKey, err := cloneAgentPublicKey(agentPubKey)
	if err != nil || len(agentKey) == 0 {
		return errNHPSessionNotReserved
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	if issuedAt.After(now.Add(agentSessionCloseFutureSkew)) || !expiresAt.After(now) {
		return errNHPSessionNotReserved
	}
	r.sweepLocked(now, len(r.sessions) >= r.max)
	if now.Before(r.exactCloseSaturatedUntil) || r.exactCloseTombstonedLocked(agentKey, sessionID, issuedAt, now) {
		return errNHPSessionNotReserved
	}
	if r.rejectedByCloseCutoffLocked(agentKey, issuedAt, now) {
		return errNHPSessionNotReserved
	}
	if existing := r.sessions[sessionID]; existing != nil {
		if bytes.Equal(existing.agentPubKey, agentKey) && existing.issuedAt.Equal(issuedAt) && !existing.closing {
			if expiresAt.Before(existing.sessionExpiresAt) {
				existing.sessionExpiresAt = expiresAt
			}
			if expiresAt.After(existing.retainUntil) {
				existing.retainUntil = expiresAt
			}
			return nil
		}
		return errNHPSessionIDCollision
	}
	if len(r.sessions) >= r.max {
		return errNHPSessionRegistryFull
	}
	r.sessions[sessionID] = &liveNHPSession{
		agentPubKey:      agentKey,
		issuedAt:         issuedAt,
		sessionExpiresAt: expiresAt,
		retainUntil:      expiresAt,
		acIDs:            make(map[string]struct{}),
	}
	return nil
}

// beginOpen pins an in-flight AOP to an exact reservation. Once an EXT marks a
// session closing, no later AOP may begin for it.
func (r *liveNHPSessionRegistry) beginOpen(sessionID uint64, issuedAt time.Time) error {
	if r == nil || sessionID == 0 || issuedAt.IsZero() {
		return errNHPSessionNotReserved
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	entry := r.sessions[sessionID]
	if entry == nil || !entry.issuedAt.Equal(issuedAt) || entry.closing || !r.now().Before(entry.sessionExpiresAt) {
		return errNHPSessionNotReserved
	}
	entry.inFlight++
	return nil
}

// finishOpen releases one in-flight AOP. A successful ART records the AC even
// when an EXT raced the AOP; the caller then treats the closing-state error as
// an admission failure while the close worker retries and tears down the exact
// pinhole that just opened.
func (r *liveNHPSessionRegistry) finishOpen(sessionID uint64, issuedAt, sessionExpiresAt, acRetainUntil time.Time, acID string, succeeded bool) error {
	if r == nil || sessionID == 0 || issuedAt.IsZero() {
		return errNHPSessionNotReserved
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	entry := r.sessions[sessionID]
	if entry == nil || !entry.issuedAt.Equal(issuedAt) || entry.inFlight <= 0 {
		return errNHPSessionNotReserved
	}
	entry.inFlight--
	if !succeeded {
		return nil
	}
	if acID == "" || !sessionExpiresAt.After(issuedAt) || acRetainUntil.Before(sessionExpiresAt) {
		return errNHPSessionNotReserved
	}
	entry.sessionExpiresAt = sessionExpiresAt
	if acRetainUntil.After(entry.retainUntil) {
		entry.retainUntil = acRetainUntil
	}
	entry.acIDs[acID] = struct{}{}
	if entry.closing {
		return errNHPSessionNotReserved
	}
	return nil
}

func (r *liveNHPSessionRegistry) release(agentPubKey []byte, sessionID uint64, issuedAt time.Time) {
	if r == nil || sessionID == 0 {
		return
	}
	agentKey, err := cloneAgentPublicKey(agentPubKey)
	if err != nil {
		return
	}
	r.releaseExact(agentKey, sessionID, issuedAt)
}

func (r *liveNHPSessionRegistry) releaseUnowned(sessionID uint64, issuedAt time.Time) {
	if r == nil || sessionID == 0 {
		return
	}
	r.releaseExact(nil, sessionID, issuedAt)
}

func (r *liveNHPSessionRegistry) releaseExact(agentKey []byte, sessionID uint64, issuedAt time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry := r.sessions[sessionID]
	if entry != nil && bytes.Equal(entry.agentPubKey, agentKey) && entry.issuedAt.Equal(issuedAt) && entry.inFlight == 0 && len(entry.acIDs) == 0 {
		delete(r.sessions, sessionID)
	}
}

// snapshotExactSessionForCompensation marks one exact current session closing
// after the AC admitted it but the ACK/token pipeline failed. A zero issuedAt
// selects the current exact numeric ID for the authenticated agent and is used
// only by an immediately observable ACK transport failure; callers that still
// have the issuance timestamp must supply it.
func (r *liveNHPSessionRegistry) snapshotExactSessionForCompensation(agentKey []byte, sessionID uint64, issuedAt time.Time) (nhpSessionCloseSnapshot, bool) {
	if r == nil || sessionID == 0 || (agentKey != nil && len(agentKey) != 32) {
		return nhpSessionCloseSnapshot{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	entry := r.sessions[sessionID]
	if entry == nil || !bytes.Equal(entry.agentPubKey, agentKey) || (!issuedAt.IsZero() && !entry.issuedAt.Equal(issuedAt)) {
		return nhpSessionCloseSnapshot{}, false
	}
	entry.closing = true
	acIDs := make([]string, 0, len(entry.acIDs))
	for acID := range entry.acIDs {
		acIDs = append(acIDs, acID)
	}
	sort.Strings(acIDs)
	return nhpSessionCloseSnapshot{SessionID: sessionID, IssuedAt: entry.issuedAt, ACIDs: acIDs, InFlight: entry.inFlight}, true
}

func (r *liveNHPSessionRegistry) exactSessionIssuedAt(agentKey []byte, sessionID uint64) (time.Time, bool) {
	if r == nil || sessionID == 0 || (agentKey != nil && len(agentKey) != 32) {
		return time.Time{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	entry := r.sessions[sessionID]
	if entry == nil || !bytes.Equal(entry.agentPubKey, agentKey) {
		return time.Time{}, false
	}
	return entry.issuedAt, true
}

func (r *liveNHPSessionRegistry) exactSessionRetainUntil(agentKey []byte, sessionID uint64, issuedAt time.Time) (time.Time, bool) {
	if r == nil || sessionID == 0 || (agentKey != nil && len(agentKey) != 32) {
		return time.Time{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	entry := r.sessions[sessionID]
	if entry == nil || !bytes.Equal(entry.agentPubKey, agentKey) || (!issuedAt.IsZero() && !entry.issuedAt.Equal(issuedAt)) {
		return time.Time{}, false
	}
	return entry.retainUntil, true
}

func exactSessionCloseKey(agentKey []byte, sessionID uint64, issuedAt time.Time) string {
	var suffix [16]byte
	binary.BigEndian.PutUint64(suffix[:8], sessionID)
	binary.BigEndian.PutUint64(suffix[8:], uint64(issuedAt.UnixNano()))
	return string(agentKey) + string(suffix[:])
}

// recordExactSessionCloseCutoff prevents an authenticated exact-close event
// from racing a delayed NHP_FWD reservation for the same logical session. The
// tuple is agent key + numeric session + issuance, so sibling sessions and a
// later reuse of the numeric ID remain admissible. Capacity exhaustion rejects
// every forwarded reservation until the event window expires rather than
// dropping a close tombstone and reopening access.
func (r *liveNHPSessionRegistry) recordExactSessionCloseCutoff(agentKey []byte, sessionID uint64, issuedAt, expiresAt time.Time) (bool, error) {
	if r == nil || len(agentKey) != 32 || sessionID == 0 || issuedAt.IsZero() || !expiresAt.After(r.now()) {
		return false, errNHPSessionNotReserved
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	r.sweepLocked(now, false)
	key := exactSessionCloseKey(agentKey, sessionID, issuedAt)
	if current := r.exactCloseCutoffs[key]; current.After(expiresAt) {
		expiresAt = current
	}
	if _, exists := r.exactCloseCutoffs[key]; exists {
		r.exactCloseCutoffs[key] = expiresAt
		return false, nil
	}
	if len(r.exactCloseCutoffs) >= r.maxExactCloseCutoffs {
		first := !now.Before(r.exactCloseSaturatedUntil)
		if expiresAt.After(r.exactCloseSaturatedUntil) {
			r.exactCloseSaturatedUntil = expiresAt
		}
		return first, nil
	}
	r.exactCloseCutoffs[key] = expiresAt
	return false, nil
}

func (r *liveNHPSessionRegistry) exactCloseTombstonedLocked(agentKey []byte, sessionID uint64, issuedAt, now time.Time) bool {
	expiresAt, ok := r.exactCloseCutoffs[exactSessionCloseKey(agentKey, sessionID, issuedAt)]
	return ok && now.Before(expiresAt)
}

func (r *liveNHPSessionRegistry) hasExactSession(agentKey []byte, sessionID uint64, issuedAt time.Time) bool {
	if r == nil || len(agentKey) != 32 || sessionID == 0 || issuedAt.IsZero() {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	entry := r.sessions[sessionID]
	return entry != nil && bytes.Equal(entry.agentPubKey, agentKey) && entry.issuedAt.Equal(issuedAt)
}

func (s *UdpServer) ReserveForwardedNHPSession(agentPubKeyB64 string, sessionID uint64, issuedAt, expiresAt time.Time) error {
	agentPubKey, err := decodeAgentPublicKey(agentPubKeyB64)
	if err != nil {
		return errNHPSessionNotReserved
	}
	return s.sessionRegistry().reserveExact(agentPubKey, sessionID, issuedAt, expiresAt)
}

func (s *UdpServer) ReleaseForwardedNHPSession(agentPubKeyB64 string, sessionID uint64, issuedAt time.Time) {
	agentPubKey, err := decodeAgentPublicKey(agentPubKeyB64)
	if err != nil {
		return
	}
	s.sessionRegistry().release(agentPubKey, sessionID, issuedAt)
}

func (s *UdpServer) CompensateForwardedNHPSession(agentPubKeyB64 string, sessionID uint64, issuedAt time.Time) bool {
	agentPubKey, err := decodeAgentPublicKey(agentPubKeyB64)
	if err != nil {
		return false
	}
	return s.compensateFailedNHPSession(agentPubKey, sessionID, issuedAt)
}

// snapshotAgentSessions returns token-free close work without removing it from
// the registry. The caller must complete each exact snapshot only after every
// AC close succeeds. A failed close therefore remains available for a bounded
// retry until the last admitted AC's compensated lifetime has elapsed.
func (r *liveNHPSessionRegistry) snapshotAgentSessions(agentPubKey []byte, issuedThrough time.Time) []nhpSessionCloseSnapshot {
	snapshots, _ := r.snapshotAgentSessionsWithStatus(agentPubKey, issuedThrough)
	return snapshots
}

// snapshotAgentSessionsWithStatus additionally reports the first transition
// into fleet-global cutoff saturation so the server can emit one bounded
// operational signal without placing metrics inside the registry lock.
func (r *liveNHPSessionRegistry) snapshotAgentSessionsWithStatus(agentPubKey []byte, issuedThrough time.Time) ([]nhpSessionCloseSnapshot, bool) {
	if r == nil {
		return nil, false
	}
	if issuedThrough.IsZero() {
		return nil, false
	}
	agentKey, err := cloneAgentPublicKey(agentPubKey)
	if err != nil {
		return nil, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	r.sweepLocked(now, false)
	// Fleet clocks may differ by the bounded future-skew allowance accepted for
	// forwarded close events. Extend the cutoff by that same allowance so an
	// older session stamped by a clock-ahead owner cannot arrive after EXT and
	// reopen. A genuinely new session inside this short window must retry.
	issuedThrough = issuedThrough.Add(agentSessionCloseFutureSkew)
	cutoffSaturated := r.recordCloseCutoffLocked(agentKey, issuedThrough, now)
	closed := make([]nhpSessionCloseSnapshot, 0)
	for sessionID, entry := range r.sessions {
		if !bytes.Equal(entry.agentPubKey, agentKey) || entry.issuedAt.After(issuedThrough) || !now.Before(entry.retainUntil) {
			continue
		}
		entry.closing = true
		acIDs := make([]string, 0, len(entry.acIDs))
		for acID := range entry.acIDs {
			acIDs = append(acIDs, acID)
		}
		sort.Strings(acIDs)
		closed = append(closed, nhpSessionCloseSnapshot{SessionID: sessionID, IssuedAt: entry.issuedAt, ACIDs: acIDs, InFlight: entry.inFlight})
	}
	sort.Slice(closed, func(i, j int) bool { return closed[i].SessionID < closed[j].SessionID })
	return closed, cutoffSaturated
}

// recordAgentSessionCloseCutoff records the fail-closed admission cutoff before
// close work is coalesced. A follower may return immediately, but a delayed
// pre-EXT forwarded open must still be rejected even while the existing leader
// is closing an older snapshot.
func (r *liveNHPSessionRegistry) recordAgentSessionCloseCutoff(agentPubKey []byte, issuedThrough time.Time) bool {
	if r == nil || issuedThrough.IsZero() {
		return false
	}
	agentKey, err := cloneAgentPublicKey(agentPubKey)
	if err != nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	r.sweepLocked(now, false)
	return r.recordCloseCutoffLocked(agentKey, issuedThrough.Add(agentSessionCloseFutureSkew), now)
}

// completeAgentSessionClose removes only the exact session issuance captured
// by snapshotAgentSessions. A delayed completion cannot delete a later session
// even if a numeric ID is reused after expiry.
func (r *liveNHPSessionRegistry) completeAgentSessionClose(agentPubKey []byte, snapshot nhpSessionCloseSnapshot) bool {
	if r == nil || snapshot.SessionID == 0 || snapshot.IssuedAt.IsZero() {
		return false
	}
	agentKey, err := cloneAgentPublicKey(agentPubKey)
	if err != nil {
		return false
	}
	return r.completeExactSessionClose(agentKey, snapshot)
}

func (r *liveNHPSessionRegistry) completeExactSessionClose(agentKey []byte, snapshot nhpSessionCloseSnapshot) bool {
	if r == nil || snapshot.SessionID == 0 || snapshot.IssuedAt.IsZero() || (agentKey != nil && len(agentKey) != 32) {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	entry := r.sessions[snapshot.SessionID]
	if entry == nil || !entry.closing || entry.inFlight != 0 || !bytes.Equal(entry.agentPubKey, agentKey) || !entry.issuedAt.Equal(snapshot.IssuedAt) {
		return false
	}
	delete(r.sessions, snapshot.SessionID)
	return true
}

func (r *liveNHPSessionRegistry) admitCloseEvent(eventID string, expiresAt time.Time) closeEventAdmission {
	if r == nil || eventID == "" {
		return closeEventRejected
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	for id, expiry := range r.closeSeen {
		if !now.Before(expiry) {
			delete(r.closeSeen, id)
		}
	}
	if !expiresAt.After(now) {
		return closeEventRejected
	}
	if _, exists := r.closeSeen[eventID]; exists {
		return closeEventReplay
	}
	if len(r.closeSeen) >= r.maxCloseSeen {
		// Do not suppress the authenticated teardown when replay tracking is
		// saturated. The caller proceeds idempotently and emits a distinct
		// bounded signal; this event is deliberately not inserted.
		return closeEventSaturated
	}
	r.closeSeen[eventID] = expiresAt
	return closeEventNew
}

// rollbackCloseEventAdmission removes only the exact replay-cache admission
// inserted for an event whose close worker could not be scheduled. This keeps
// an HTTP 503 retryable during shutdown races; saturated events are never
// inserted and therefore do not call this method.
func (r *liveNHPSessionRegistry) rollbackCloseEventAdmission(eventID string, expiresAt time.Time) {
	if r == nil || eventID == "" || expiresAt.IsZero() {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if current, ok := r.closeSeen[eventID]; ok && current.Equal(expiresAt) {
		delete(r.closeSeen, eventID)
	}
}

func (r *liveNHPSessionRegistry) sweepLocked(now time.Time, force bool) {
	if !force && now.Before(r.nextSweep) {
		return
	}
	for sessionID, entry := range r.sessions {
		if !now.Before(entry.retainUntil) && entry.inFlight == 0 {
			delete(r.sessions, sessionID)
		}
	}
	for agentKey, cutoff := range r.closeCutoffs {
		if !now.Before(cutoff.expiresAt) {
			delete(r.closeCutoffs, agentKey)
		}
	}
	for key, expiresAt := range r.exactCloseCutoffs {
		if !now.Before(expiresAt) {
			delete(r.exactCloseCutoffs, key)
		}
	}
	if !now.Before(r.closeCutoffsSaturatedUntil) {
		r.closeCutoffsSaturatedUntil = time.Time{}
	}
	if !now.Before(r.exactCloseSaturatedUntil) {
		r.exactCloseSaturatedUntil = time.Time{}
	}
	r.nextSweep = now.Add(sessionRegistrySweepInterval)
}

func (r *liveNHPSessionRegistry) rejectedByCloseCutoffLocked(agentKey []byte, issuedAt, now time.Time) bool {
	if now.Before(r.closeCutoffsSaturatedUntil) {
		return true
	}
	cutoff, ok := r.closeCutoffs[string(agentKey)]
	return ok && now.Before(cutoff.expiresAt) && !issuedAt.After(cutoff.issuedThrough)
}

func (r *liveNHPSessionRegistry) recordCloseCutoffLocked(agentKey []byte, issuedThrough, now time.Time) bool {
	key := string(agentKey)
	expiresAt := now.Add(agentSessionCloseCutoffTTL)
	if existing, ok := r.closeCutoffs[key]; ok {
		if issuedThrough.After(existing.issuedThrough) {
			existing.issuedThrough = issuedThrough
		}
		if expiresAt.After(existing.expiresAt) {
			existing.expiresAt = expiresAt
		}
		r.closeCutoffs[key] = existing
		return false
	}
	if len(r.closeCutoffs) >= r.maxCloseCutoffs {
		// Capacity exhaustion fails closed for every forwarded/local owned
		// reservation during the replay window. Dropping an older live cutoff
		// would permit a delayed pre-EXT forward to reopen an AC pinhole.
		firstTransition := !now.Before(r.closeCutoffsSaturatedUntil)
		if expiresAt.After(r.closeCutoffsSaturatedUntil) {
			r.closeCutoffsSaturatedUntil = expiresAt
		}
		return firstTransition
	}
	r.closeCutoffs[key] = agentSessionCloseCutoff{issuedThrough: issuedThrough, expiresAt: expiresAt}
	return false
}

func (s *UdpServer) sessionRegistry() *liveNHPSessionRegistry {
	s.agentSessionsOnce.Do(func() {
		if s.agentSessions == nil {
			s.agentSessions = newLiveNHPSessionRegistry()
		}
	})
	return s.agentSessions
}
