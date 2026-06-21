package common

import (
	"context"
	"net/url"
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
	Msg     *AgentOTPMsg `json:"msg"`
	SrcAddr *NetAddress  `json:"srcAddr"`
}

type NhpRegisterRequest struct {
	Msg       *AgentRegisterMsg     `json:"msg"`
	Ack       *ServerRegisterAckMsg `json:"ack"`
	PublicKey string                `json:"pubKey"`
	SrcAddr   *NetAddress           `json:"srcAddr"`
}

type NhpAuthRequest struct {
	Msg            *AgentKnockMsg     `json:"msg"`
	Ack            *ServerKnockAckMsg `json:"ack"`
	PublicKey      string             `json:"pubKey"`
	SrcAddr        *NetAddress        `json:"srcAddr"`
	OriginalPacket []byte             `json:"-"` // Original encrypted knock packet for server-to-server forwarding
}

type NhpListRequest struct {
	Msg       *AgentListMsg        `json:"msg"`
	Ack       *ServerListResultMsg `json:"ack"`
	PublicKey string               `json:"pubKey"`
	SrcAddr   *NetAddress          `json:"srcAddr"`
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
