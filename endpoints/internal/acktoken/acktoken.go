// Package acktoken holds the AC-issued ACK-token entry type and its
// DynamoDB wire/marshaling helpers. nhp-server uses it to WRITE entries to
// the shared store on ACK issuance and to read them back in its own
// /nhp/internal/token/validate handler. The type lives here (rather than in
// package server) so the wire schema has a single definition that a future
// fleet-visible reader could share without importing package server.
//
// nhp-server stamps server-resolved fields (KnockSrcIP, owner_id, RunID) that
// downstream consumers of /nhp/internal/token/validate cross-check against the
// presented token.
package acktoken

import (
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/utils"
)

// ttlGraceSeconds keeps DynamoDB's eventual TTL reaper behind the
// app-enforced ExpireTime by one minute. Validators still reject expired
// entries synchronously; the grace only prevents near-expiry rows from
// disappearing before a delayed cross-instance validation can observe and
// classify them.
const ttlGraceSeconds int64 = 60

// ACTokenEntry represents an AC-issued ACK token entry with user and AC
// token information. It is the value nhp-server stores in
// common.TokenStore[*ACTokenEntry] and persists to the shared store, then
// reads back in its /nhp/internal/token/validate handler.
//
// KnockSrcIP is the IP the agent knocked from — a server-stamped field the
// AC cannot derive from NHP-AOP (the AOP source IP can differ from the
// server-observed knock source under NAT). /nhp/internal/token/validate
// exposes it so a downstream FRP login can be cross-checked against the IP
// that earned the pinhole.
//
// RunID is the agent's authenticated knock/Login-cycle identifier. Registered-
// agent native UDP knocks populate it from the KNK application body. Generic
// and HTTP bookkeeping entries may store an empty string, but those entries do
// not satisfy the signed positive token-validation contract.
//
// User is *common.AgentUser and is legitimately nil during the ACK-path
// window before the agent identity is captured. Readers (the validate
// handlers) defensively nil-check; construction paths MUST treat nil User
// as a valid transitional state, not a bug.
//
// Post-store mutation is forbidden. TokenStore.Load returns the same pointer
// that was stored, and readers access fields lock-free under that invariant.
// A future caller that writes to a stored entry must either swap a fresh
// entry in via Store or guard the entry with a mutex.
type ACTokenEntry struct {
	User *common.AgentUser
	// ResourceId is the ACK token map/catalog key used by the AC path.
	ResourceId string
	// ProtectedResourceId is the authenticated public resource subject the
	// session may serve. It is distinct from the catalog key above.
	ProtectedResourceId string
	ACTokens            map[string]string
	KnockSrcIP          string
	RunID               string
	SessionId           uint64
	OpenTime            int
	// SessionExpireTime is the AC authorization deadline (issuance +
	// OpenTime). ExpireTime is deliberately later because it includes the
	// late-packet token-resolution buffer; consumers must fence serving with
	// SessionExpireTime instead.
	SessionExpireTime time.Time
	ExpireTime        time.Time
}

// GetExpireTime implements common.TokenEntry. It lives in this package
// (not as a method on a server-side alias) because Go forbids declaring a
// method on a type alias whose named type is defined in another package —
// server.ACTokenEntry is a true alias of this type.
func (e *ACTokenEntry) GetExpireTime() time.Time {
	return e.ExpireTime
}

// Compile-time assertion: *ACTokenEntry satisfies common.TokenEntry. This is
// load-bearing — nhp-server stores it in common.TokenStore[*ACTokenEntry]
// and relies on GetExpireTime for CleanExpired dispatch.
var _ common.TokenEntry = (*ACTokenEntry)(nil)

// PersistedItem is the DynamoDB persistence shape for an ACTokenEntry,
// keyed by HashToken(token) so the raw token never lands in the table.
type PersistedItem struct {
	TokenHash             string `dynamodbav:"token_hash"`
	ResourceID            string `dynamodbav:"resource_id,omitempty"`
	ProtectedResourceID   string `dynamodbav:"protected_resource_id,omitempty"`
	UserPresent           bool   `dynamodbav:"user_present,omitempty"`
	UserID                string `dynamodbav:"user_id,omitempty"`
	DeviceID              string `dynamodbav:"device_id,omitempty"`
	OrganizationID        string `dynamodbav:"organization_id,omitempty"`
	AuthServiceID         string `dynamodbav:"auth_service_id,omitempty"`
	OwnerID               string `dynamodbav:"owner_id,omitempty"`
	KnockSrcIP            string `dynamodbav:"knock_src_ip,omitempty"`
	RunID                 string `dynamodbav:"run_id,omitempty"`
	SessionID             uint64 `dynamodbav:"session_id,omitempty"`
	OpenTime              int64  `dynamodbav:"open_time,omitempty"`
	SessionExpiresAtNanos int64  `dynamodbav:"session_expires_at_nanos,omitempty"`
	ExpiresAtNanos        int64  `dynamodbav:"expires_at_nanos"`
	TTL                   int64  `dynamodbav:"ttl"`
}

// ItemFromEntry marshals an entry into its persisted shape under token.
func ItemFromEntry(token string, entry *ACTokenEntry) PersistedItem {
	item := PersistedItem{
		TokenHash:           HashToken(token),
		ResourceID:          entry.ResourceId,
		ProtectedResourceID: entry.ProtectedResourceId,
		KnockSrcIP:          entry.KnockSrcIP,
		RunID:               entry.RunID,
		SessionID:           entry.SessionId,
		OpenTime:            int64(entry.OpenTime),
		ExpiresAtNanos:      entry.ExpireTime.UTC().UnixNano(),
		TTL:                 entry.ExpireTime.UTC().Unix() + ttlGraceSeconds,
	}
	if !entry.SessionExpireTime.IsZero() {
		item.SessionExpiresAtNanos = entry.SessionExpireTime.UTC().UnixNano()
	}
	if entry.User != nil {
		item.UserPresent = true
		item.UserID = entry.User.UserId
		item.DeviceID = entry.User.DeviceId
		item.OrganizationID = entry.User.OrganizationId
		item.AuthServiceID = entry.User.AuthServiceId
		item.OwnerID = entry.User.OwnerId
	}
	return item
}

// EntryFromItem reconstructs an entry from its persisted shape.
func EntryFromItem(item PersistedItem) *ACTokenEntry {
	var user *common.AgentUser
	// UserPresent preserves a non-nil empty user across round-trip.
	if item.UserPresent {
		user = &common.AgentUser{
			UserId:         item.UserID,
			DeviceId:       item.DeviceID,
			OrganizationId: item.OrganizationID,
			AuthServiceId:  item.AuthServiceID,
			OwnerId:        item.OwnerID,
		}
	}
	entry := &ACTokenEntry{
		User:                user,
		ResourceId:          item.ResourceID,
		ProtectedResourceId: item.ProtectedResourceID,
		// ACTokens is intentionally not persisted in the shared store.
		// /nhp/internal/token/validate does not read it, and validate-path
		// readers must not depend on local-vs-shared entries carrying
		// identical token snapshots.
		ACTokens:   map[string]string{},
		KnockSrcIP: item.KnockSrcIP,
		RunID:      item.RunID,
		SessionId:  item.SessionID,
		OpenTime:   int(item.OpenTime),
		ExpireTime: time.Unix(0, item.ExpiresAtNanos).UTC(),
	}
	if item.SessionExpiresAtNanos != 0 {
		entry.SessionExpireTime = time.Unix(0, item.SessionExpiresAtNanos).UTC()
	}
	return entry
}

// HashToken returns the hex SHA-256 of token — the DynamoDB partition key,
// so the raw bearer-equivalent token never lands in the table. Delegates to
// the shared utils.SHA256 so the sha256→hex idiom is defined once.
func HashToken(token string) string {
	return utils.SHA256(token)
}
