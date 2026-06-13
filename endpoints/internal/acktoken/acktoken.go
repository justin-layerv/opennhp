// Package acktoken holds the shared AC-issued ACK-token entry type and its
// fleet-visible DynamoDB read path, so both nhp-server (which WRITES the
// entries) and the AC daemon (which validates against them) share one
// definition of the wire schema without the AC importing package server.
//
// nhp-server remains the sole WRITER of these entries — it stamps
// server-resolved fields (KnockSrcIP, owner_id, RunID) the AC cannot derive
// from the NHP-AOP message. The AC is read-only against this store. See
// docs/design/KNOCK_TOKEN_VALIDATOR_PLACEMENT.md.
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
// common.TokenStore[*ACTokenEntry] and persists to the shared store; the
// AC validator reads it back via a Reader.
//
// KnockSrcIP is the IP the agent knocked from — a server-stamped field the
// AC cannot derive from NHP-AOP (the AOP source IP can differ from the
// server-observed knock source under NAT). /nhp/internal/token/validate
// exposes it so a downstream FRP login can be cross-checked against the IP
// that earned the pinhole.
//
// RunID is the agent's run-scope identifier (nullable; populated via the
// agent registration path). Legacy ACK paths that carry no RunID write the
// empty string.
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
	User       *common.AgentUser
	ResourceId string
	ACTokens   map[string]string
	KnockSrcIP string
	RunID      string
	OpenTime   int
	ExpireTime time.Time
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
	TokenHash      string `dynamodbav:"token_hash"`
	ResourceID     string `dynamodbav:"resource_id,omitempty"`
	UserPresent    bool   `dynamodbav:"user_present,omitempty"`
	UserID         string `dynamodbav:"user_id,omitempty"`
	DeviceID       string `dynamodbav:"device_id,omitempty"`
	OrganizationID string `dynamodbav:"organization_id,omitempty"`
	AuthServiceID  string `dynamodbav:"auth_service_id,omitempty"`
	OwnerID        string `dynamodbav:"owner_id,omitempty"`
	KnockSrcIP     string `dynamodbav:"knock_src_ip,omitempty"`
	RunID          string `dynamodbav:"run_id,omitempty"`
	OpenTime       int64  `dynamodbav:"open_time,omitempty"`
	ExpiresAtNanos int64  `dynamodbav:"expires_at_nanos"`
	TTL            int64  `dynamodbav:"ttl"`
}

// ItemFromEntry marshals an entry into its persisted shape under token.
func ItemFromEntry(token string, entry *ACTokenEntry) PersistedItem {
	item := PersistedItem{
		TokenHash:      HashToken(token),
		ResourceID:     entry.ResourceId,
		KnockSrcIP:     entry.KnockSrcIP,
		RunID:          entry.RunID,
		OpenTime:       int64(entry.OpenTime),
		ExpiresAtNanos: entry.ExpireTime.UTC().UnixNano(),
		TTL:            entry.ExpireTime.UTC().Unix() + ttlGraceSeconds,
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
	return &ACTokenEntry{
		User:       user,
		ResourceId: item.ResourceID,
		// ACTokens is intentionally not persisted in the shared store.
		// /nhp/internal/token/validate does not read it, and validate-path
		// readers must not depend on local-vs-shared entries carrying
		// identical token snapshots.
		ACTokens:   map[string]string{},
		KnockSrcIP: item.KnockSrcIP,
		RunID:      item.RunID,
		OpenTime:   int(item.OpenTime),
		ExpireTime: time.Unix(0, item.ExpiresAtNanos).UTC(),
	}
}

// HashToken returns the hex SHA-256 of token — the DynamoDB partition key,
// so the raw bearer-equivalent token never lands in the table. Delegates to
// the shared utils.SHA256 so the sha256→hex idiom is defined once.
func HashToken(token string) string {
	return utils.SHA256(token)
}
