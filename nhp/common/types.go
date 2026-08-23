package common

import (
	"context"
	"net/url"
	"time"
)

// an object contains represent knocking user information
type AgentUser struct {
	UserId         string
	DeviceId       string
	OrganizationId string
	AuthServiceId  string
	// OwnerId is the server-resolved tenant identity, populated from
	// the NHP-Server's pubkey-bound agent registry (e.g., the
	// `qurl-agent-keys` DDB row) at knock-validation time. Distinct
	// from OrganizationId, which is the client-supplied label per
	// the NHP spec's NHP-KNK Message Fields table.
	//
	// Per CSA Stealth Mode SDP §"NHP Workflow", the
	// NHP-Server authenticates the agent's identity using its
	// public key against the ASP/IAM record. OwnerId carries that
	// authoritatively-resolved identity downstream so protected-
	// service consumers (e.g. tunnel-server's tunnel-auth plugin)
	// can perform application-layer authorization without re-
	// resolving identity from a potentially-spoofable client
	// claim. The pubkey-bound resolution happens once at knock
	// time and is propagated via the ACK-path token entry; see
	// `endpoints/server/tokenstore.go::NewACKTokenEntry`.
	//
	// Empty when the knock arrived via a path that has no pubkey-
	// bound identity (HTTP knock today). Consumers MUST treat
	// OwnerId=="" as "identity not resolved at this hop" and either
	// fall back or reject per their own policy.
	//
	// `json:",omitempty"` matches the `omitempty` shape used by the
	// only fields on this struct that go on the wire today (the
	// validator response in `internal_token_validate.go` wraps this
	// in its own struct with `owner_id,omitempty`). Without the tag,
	// `AccessEntry` JSON-serialized at `endpoints/ac/httpac.go`'s
	// `/refresh` endpoint would emit `"OwnerId": ""` on every
	// successful AC response — present-but-empty, which a strict
	// consumer could read as "AC asserts identity unknown" rather
	// than "AC doesn't carry this field." The leading comma keeps
	// the capitalized field name; only the empty-state shape changes.
	OwnerId string `json:",omitempty"`
}

type ResourceData struct {
	ResourceGroup `mapstructure:",squash"`

	// NHPSessionId is transient server state used to carry the origin
	// server-assigned access-session identifier through authenticated NHP_FWD
	// fanout. It is never loaded from catalog data or serialized as resource
	// metadata; ServerForwardMsg has the explicit wire field.
	NHPSessionId       uint64    `json:"-" mapstructure:"-"`
	NHPSessionIssuedAt time.Time `json:"-" mapstructure:"-"`
	// optional extension data
	AppKey             string         `json:"appKey,omitempty"`
	AppSecret          string         `json:"appSecret,omitempty"`
	AccessKey          string         `json:"accessKey,omitempty"` //nolint:gosec // G117: JSON tag required — resource config loaded from TOML, not user input
	SecretKey          string         `json:"secretKey,omitempty"`
	ExInfo             map[string]any `json:"exinfo,omitempty"`
	RedirectUrl        string         `json:"redirectUrl,omitempty"`
	RedirectWithParams bool           `json:"redirectWithParams,omitempty"`
	SkipAuth           bool           `json:"skipAuth,omitempty"`
	CookieDomain       string         `json:"cookieDomain,omitempty"`

	// qURL v2 protected-resource public key (P1b), surfaced from the NHP
	// catalog row (endpoints/server.Resource) so later admission phases
	// (P3/P4) can key routing/admission on the resource public key. Carried
	// here — alongside the other layerv-local catalog extensions above —
	// rather than on the upstream-synced ResourceGroup/ResourceInfo in
	// nhpmsg.go. Empty for v1 / feature-off resources.
	//
	// UNVALIDATED — consumers MUST verify before trusting. P1b is a dumb
	// carrier: it passes these through without decoding or hashing, so the
	// value can be empty, malformed, or (once it gates admission) attacker-
	// influenced. The admission-gate phase MUST base64url-decode
	// ResourcePublicKeyB64, length-check the DER, and recompute the hash from
	// the decoded bytes — i.e. verify ResourcePublicKeyHash ==
	// SHA-256(decode(ResourcePublicKeyB64)) — rather than trusting the stored
	// hash. Do not use either field as an identity/routing key without that
	// verification.
	//
	//   ResourcePublicKeyB64:  unpadded base64url DER SPKI of the resource pubkey
	//   ResourcePublicKeyHash: lowercase hex SHA-256 of the DECODED DER bytes
	ResourcePublicKeyB64  string `json:"resourcePublicKeyB64,omitempty"`
	ResourcePublicKeyHash string `json:"resourcePublicKeyHash,omitempty"`

	// qURL v2 keyed-identity revocation metadata (P4a). Populated only by the v2
	// signed-claims admission path (qurl plugin authWithNHPClaims), carried here
	// from the admission decision down to the AOP builder, which stamps the
	// matching ServerACOpsMsg fields so the AC can store them on the access/flow
	// entry for immediate, targeted revocation. These are empty for v1 /
	// feature-off admissions (they are not on the catalog row), so the AOP omits
	// them (omitempty) and stays additive/wire-compatible for pre-v2 ACs.
	// (ResourcePublicKeyHash above doubles as the resource revocation key and,
	// unlike the per-admission fields, can ride a catalog ResourceData for a
	// v2-provisioned resource even on a non-v2 knock — see processACOperation.)
	//
	// QurlSessionId is carried ONLY by the steady-state re-knock (authorize) path:
	// the authorize response returns the matched live session, so the refresh
	// stamps it here for the AC's session_id secondary index. The first-knock
	// (prepare) path leaves it empty — prepare does not return a session id — so a
	// freshly-admitted flow is indexed by qurl-user / resource hash only until its
	// first re-knock refreshes it under the session key. revocation_epoch is still
	// NOT carried: neither prepare nor authorize returns it, so it awaits a
	// contract field and a later slice. See
	// docs/design/QURL_V2_KEYED_IDENTITY.md → "AC Admission and Immediate Revocation".
	//
	//   QurlUserPublicKeyHash: lowercase hex SHA-256 of the DECODED qURL-user pubkey
	//   QurlSessionId:         qURL v2 application session id (authorize/re-knock path only)
	//   AdmissionId:           id of the admission decision that opened this access
	//   Deadline:              unix seconds; admission validity deadline (claim exp)
	QurlUserPublicKeyHash string `json:"qurlUserPublicKeyHash,omitempty"`
	QurlSessionId         string `json:"qurlSessionId,omitempty"`
	AdmissionId           string `json:"admissionId,omitempty"`
	Deadline              int64  `json:"deadline,omitempty"`
}

type ResourceGroupMap map[string]*ResourceData
type AuthServiceProviderData struct {
	ResourceGroups ResourceGroupMap `json:"ress"`
	AuthSvcId      string           `json:"aspId"`
	PluginPath     string           `json:"pluginPath,omitempty"`
	PluginHash     string           `json:"pluginHash,omitempty"`
}
type AuthSvcProviderMap map[string]*AuthServiceProviderData

// FindResource returns the first ResourceInfo for a given resource ID.
// This is used by server-to-server forwarding to find the AC connection.
// Returns nil if the resource ID is not found or has no resource entries.
func (asp *AuthServiceProviderData) FindResource(resourceId string) *ResourceInfo {
	if asp == nil {
		return nil
	}
	resData := asp.ResourceGroups[resourceId]
	if resData == nil {
		return nil
	}
	// Return first resource info (all entries in a resource group typically use the same AC)
	for _, info := range resData.Resources {
		return info
	}
	return nil
}

// GetResourceData returns the ResourceData for a given resource ID.
// Returns nil if the resource ID is not found.
func (asp *AuthServiceProviderData) GetResourceData(resourceId string) *ResourceData {
	if asp == nil {
		return nil
	}
	return asp.ResourceGroups[resourceId]
}

// requests
type NhpOTPRequest struct {
	Msg *AgentOTPMsg `json:"msg"`
	// PublicKey is the base64 (std encoding) of the Noise-authenticated
	// initiator static key — the same value NhpRegisterRequest.PublicKey
	// carries on the register path. HandleOTPRequest populates it from
	// ppd.RemotePubKey so OTP-consuming plugins can bind a one-time
	// credential to the requesting agent key rather than to spoofable
	// message fields.
	PublicKey string      `json:"pubKey"`
	SrcAddr   *NetAddress `json:"srcAddr"`
	// RawBody is an exact defensive copy of the decrypted NHP_OTP body. It
	// lets a role-specific plugin perform strict duplicate/unknown/alias-field
	// checks without trusting the permissive typed decode above. Both RawBody
	// and Msg may contain credentials; do not log or persist the enclosing
	// request verbatim.
	RawBody []byte `json:"-"`
}

type NhpRegisterRequest struct {
	Msg       *AgentRegisterMsg     `json:"msg"`
	Ack       *ServerRegisterAckMsg `json:"ack"`
	PublicKey string                `json:"pubKey"`
	SrcAddr   *NetAddress           `json:"srcAddr"`
	// RawBody is an exact defensive copy of the decrypted NHP_REG body. It
	// lets a role-specific plugin perform strict duplicate/unknown/alias-field
	// checks without trusting the permissive typed decode above.
	RawBody []byte `json:"-"`
}

type NhpAuthRequest struct {
	Msg             *AgentKnockMsg     `json:"msg"`
	Ack             *ServerKnockAckMsg `json:"ack"`
	PublicKey       string             `json:"pubKey"`
	SrcAddr         *NetAddress        `json:"srcAddr"`
	WireHeaderType  int                `json:"-"` // Outer packet HeaderType; Msg.HeaderType is the authenticated body type.
	OriginalPacket  []byte             `json:"-"` // Original encrypted knock packet for server-to-server forwarding
	SessionId       uint64             `json:"-"` // Server-assigned NHP access-session identifier; never client supplied.
	SessionIssuedAt time.Time          `json:"-"` // Server issuance time for the access-session lifetime.
}

type NhpListRequest struct {
	Msg       *AgentListMsg        `json:"msg"`
	Ack       *ServerListResultMsg `json:"ack"`
	PublicKey string               `json:"pubKey"`
	SrcAddr   *NetAddress          `json:"srcAddr"`
	// RawBody is an exact defensive copy of the decrypted NHP_LST body. The
	// authenticated initiator identity remains PublicKey, populated separately
	// from PacketParserData.RemotePubKey rather than from these JSON bytes.
	RawBody []byte `json:"-"`
}

type HttpKnockRequest struct {
	UserId         string   `json:"usrId"`
	DeviceId       string   `json:"devId"`
	OrganizationId string   `json:"orgId,omitempty"`
	AuthServiceId  string   `json:"aspId"`
	ResourceId     string   `json:"resId"`
	Token          string   `json:"token"`
	Code           string   `json:"code"`
	DstUrl         string   `json:"dstUrl"`
	Command        string   `json:"command"`
	Url            *url.URL `json:"-"`
	UserAgent      string   `json:"-"`
	SrcIp          string   `json:"srcIp,omitempty"`
	SrcPort        int      `json:"srcPort,omitempty"`
	Forwarded      bool     `json:"forwarded,omitempty"` // Set by internal forwarding to prevent loops

	// Ctx carries the request context for downstream cancellation and value
	// propagation (e.g., correlation IDs).
	//
	// DEPRECATED: storing context in a struct is a Go anti-pattern. The field
	// is retained because the github.com/fengyily/nhp-plugins-sdk callback
	// signature `HttpPluginPostAuthFunc` does not accept an explicit context
	// parameter, so plugins built against that SDK have no other way to
	// thread context through to handleHttpOpenResource. Internal nhp code
	// should NOT add new readers of this field; once the SDK callback gains
	// a context parameter (or is vendored/forked) this field can be removed.
	Ctx context.Context `json:"-"`
}

type HttpRefreshRequest struct {
	Token string `json:"token"`
	SrcIp string `json:"srcIp"`
}
