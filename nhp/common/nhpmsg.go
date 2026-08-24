package common

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	utils "github.com/OpenNHP/opennhp/nhp/utils"
)

type NetAddress struct {
	Ip       string `json:"ip"`              // IP address, mandatory
	Port     int    `json:"port,omitempty"`  // optional
	Protocol string `json:"proto,omitempty"` // tcp/udp/empty for any optional
}

func (na *NetAddress) String() string {
	if na.Port == 0 {
		return na.Ip
	}
	return fmt.Sprintf("%s:%d", na.Ip, na.Port)
}

// agent <-> server
type ServerCookieMsg struct {
	TransactionId uint64 `json:"trxId"`
	Cookie        string `json:"cookie"`
}

type AgentOTPMsg struct {
	UserId         string         `json:"usrId"`
	DeviceId       string         `json:"devId"`
	OrganizationId string         `json:"orgId,omitempty"`
	AuthServiceId  string         `json:"aspId"`
	Passcode       string         `json:"pass,omitempty"` //nolint:gosec // G117: JSON tag required — NHP protocol wire format
	UserData       map[string]any `json:"usrData,omitempty"`
}

type AgentRegisterMsg struct {
	UserId         string         `json:"usrId"`
	DeviceId       string         `json:"devId"`
	OrganizationId string         `json:"orgId,omitempty"`
	AuthServiceId  string         `json:"aspId"`
	OTP            string         `json:"otp,omitempty"`
	UserData       map[string]any `json:"usrData,omitempty"`
}

type ServerRegisterAckMsg struct {
	ErrCode       string `json:"errCode"`
	ErrMsg        string `json:"errMsg,omitempty"`
	AuthServiceId string `json:"aspId"`
}

// AgentKnockMsg is the JSON-encoded body the agent places inside the
// AEAD-encrypted NHP knock payload. The body (but NOT the wire
// HeaderCommon preamble) is authenticated against the initiator
// chain-hash state, so every field here is integrity-protected end
// to end between the agent and server.
//
// HeaderType mirrors the wire-level header type (core.NHP_KNK /
// core.NHP_RKN / core.NHP_EXT) inside the AEAD body. Pre-#1154 the
// server trusted only the unauthenticated wire header type byte, so
// a MitM could flip NHP_KNK → NHP_EXT on the wire and (after a
// trivial unkeyed-BLAKE2s recomputation) cause the server to close
// the victim's access. Carrying HeaderType in the body lets the
// server compare and reject any packet where the two disagree. A
// zero value here indicates a legacy agent that predates the fix —
// see endpoints/server/knock_headertype_gate.go for the server-side
// verification policy.
//
// RunID is the caller-owned knock/Login cycle identifier: exactly 16 lowercase
// hexadecimal characters. Generic legacy messages may omit it, but native UDP
// knocks dispatched to the registered-agent auth service require it together
// with a positive RunAttempt before any registry, resource, or AC work.
type AgentKnockMsg struct {
	HeaderType     int    `json:"headerType"`
	UserId         string `json:"usrId"`
	DeviceId       string `json:"devId"`
	OrganizationId string `json:"orgId,omitempty"`
	AuthServiceId  string `json:"aspId"`
	ResourceId     string `json:"resId"`
	RunID          string `json:"runId,omitempty"`
	RunAttempt     uint64 `json:"runAttempt,omitempty"`
	// NativeSessionOperationID and its binding fields are an additive,
	// authenticated registered-agent admission authority. They are either all
	// absent (legacy knock) or all present in their exact canonical form. The
	// compact projection deliberately excludes deployment routes and table
	// names: those are server configuration and encrypted orchestration
	// authority, not caller-selected wire inputs.
	NativeSessionOperationID        string         `json:"operation_id,omitempty"`
	NativeSessionOperationBinding   string         `json:"binding_sha256,omitempty"`
	NativeSessionOperationOwnerID   string         `json:"owner_id,omitempty"`
	NativeSessionOperationPrepared  int64          `json:"prepared_at_ms,omitempty"`
	NativeSessionOperationExpiresAt int64          `json:"expires_at_ms,omitempty"`
	CheckResults                    map[string]any `json:"results,omitempty"`
	UserData                        map[string]any `json:"usrData,omitempty"`

	// NHPSessionId is assigned by the NHP-Server after the authenticated KNK
	// body is decoded. It is server-internal state, never accepted from or
	// serialized back into the agent's KNK body. The server carries this exact
	// value through AOP, ART, ACK, and ACK-token validation.
	NHPSessionId       uint64    `json:"-"`
	NHPSessionIssuedAt time.Time `json:"-"`
	// NHPAgentPublicKey is server-owned authenticated packet metadata. It is
	// copied from PacketParserData.RemotePubKey and carried to the AOP Public Key
	// field; a KNK body can never supply or override it.
	NHPAgentPublicKey string `json:"-"`
	// NHPAgentOwnerID is populated only after the durable operation admission
	// transaction has condition-checked the exact owner/agent registration and
	// public-key claim. Downstream token writers use this server-owned value and
	// never repeat an eventual GSI lookup.
	NHPAgentOwnerID string `json:"-"`
	// ProtectedResourceId is the server-resolved canonical public resource
	// identity bound to a registered-agent ACK token. It is distinct from the
	// wire ResourceId, which is only the knock/catalog routing key, and is never
	// accepted from the application JSON body.
	ProtectedResourceId string `json:"-"`
	// InternalHTTPExit preserves the legacy internal HTTP operation's one-second
	// resource close without reusing the bodyless, agent-global NHP_EXT wire
	// type. It is server-owned application state and is never serialized.
	InternalHTTPExit bool `json:"-"`
	// InternalHTTP identifies the explicitly non-NHP HTTP application path. It
	// permits that application operation to open an AC rule without pretending
	// it has an authenticated NHP-Agent public key.
	InternalHTTP bool `json:"-"`
}

func (knkMsg *AgentKnockMsg) Id() string {
	return knkMsg.AuthServiceId + "/" + knkMsg.ResourceId
}

type PreAccessInfo struct {
	AccessIp       string `json:"acIp"`
	AccessPort     string `json:"acPort"`
	ACPubKey       string `json:"acPubKey"`
	ACToken        string `json:"acToken"`
	ACCipherScheme int    `json:"acCipherScheme"`
}

type ServerKnockAckMsg struct {
	SessionId             uint64                    `json:"sessId,omitempty"`
	CellId                string                    `json:"cellId,omitempty"`
	SessionIssuedAtMillis int64                     `json:"sessIssuedAtMillis,omitempty"`
	RunID                 string                    `json:"runId,omitempty"`
	RunAttempt            uint64                    `json:"runAttempt,omitempty"`
	ErrCode               string                    `json:"errCode"`
	ErrMsg                string                    `json:"errMsg,omitempty"`
	ResourceHost          map[string]string         `json:"resHost"`
	OpenTime              uint32                    `json:"opnTime"`
	AuthProviderToken     string                    `json:"aspToken,omitempty"` // optional for ac backend validation
	AgentAddr             string                    `json:"agentAddr"`
	ACTokens              map[string]string         `json:"acTokens"`
	PreAccessActions      map[string]*PreAccessInfo `json:"preActions,omitempty"` // optional for pre-access
	RedirectUrl           string                    `json:"redirectUrl,omitempty"`
}

type AgentListMsg struct {
	UserId         string         `json:"usrId"`
	DeviceId       string         `json:"devId"`
	OrganizationId string         `json:"orgId,omitempty"`
	AuthServiceId  string         `json:"aspId"`
	UserData       map[string]any `json:"usrData,omitempty"`
}

type ServerListResultMsg struct {
	ErrCode           string         `json:"errCode"`
	ErrMsg            string         `json:"errMsg,omitempty"`
	ListResults       map[string]any `json:"list,omitempty"`
	RetryAfterSeconds *uint32        `json:"retryAfterSeconds,omitempty"`
}

// agent <-> ac
type AgentAccessMsg struct {
	UserId         string         `json:"usrId"`
	DeviceId       string         `json:"devId"`
	OrganizationId string         `json:"orgId,omitempty"`
	ACToken        string         `json:"acToken"`
	UserData       map[string]any `json:"usrData,omitempty"`
}

// ac <-> server
type ServerACOpsMsg struct {
	SessionId             uint64        `json:"sessId,omitempty"`
	SessionOwnerId        string        `json:"sessOwnerId"`
	AgentPublicKey        string        `json:"agentPubKey,omitempty"`
	SessionIssuedAtMillis int64         `json:"sessIssuedAtMillis,omitempty"`
	RunID                 string        `json:"runId,omitempty"`
	RunAttempt            uint64        `json:"runAttempt,omitempty"`
	UserId                string        `json:"usrId"`
	DeviceId              string        `json:"devId"`
	OrganizationId        string        `json:"orgId,omitempty"`
	AuthServiceId         string        `json:"aspId"`
	ResourceId            string        `json:"resId"`
	SourceAddrs           []*NetAddress `json:"srcAddrs"`
	DestinationAddrs      []*NetAddress `json:"dstAddrs"`
	OpenTime              uint32        `json:"opnTime"`

	// qURL v2 keyed-identity revocation metadata (additive; populated only by
	// the v2 signed-claims admission path, omitted for every legacy admission).
	// Carried from the server's admission decision down to the AC so the AC can
	// store it on the access/flow entry for immediate, targeted revocation.
	// Indexing these for O(1) revoke lookup is P4b; P4a only carries + stores.
	// See docs/design/QURL_V2_KEYED_IDENTITY.md → "AC Admission and Immediate Revocation".
	QurlUserPublicKeyHash string `json:"qurlUsrPubKeyHash,omitempty"` // hash of the qURL user's keyed-identity public key
	ResourcePublicKeyHash string `json:"resPubKeyHash,omitempty"`     // hash of the protected resource's public key
	QurlSessionId         string `json:"qurlSessId,omitempty"`        // qURL v2 application session identifier
	AdmissionId           string `json:"admId,omitempty"`             // unique id of the admission decision that opened this access
	RevocationEpoch       uint64 `json:"revEpoch,omitempty"`          // monotonic epoch used to invalidate access on revoke
	Deadline              int64  `json:"deadline,omitempty"`          // unix seconds; admission validity deadline
}

type ACOpsResultMsg struct {
	SessionId       uint64         `json:"sessId,omitempty"`
	SessionOwnerId  string         `json:"sessOwnerId"`
	ErrCode         string         `json:"errCode"`
	ErrMsg          string         `json:"errMsg,omitempty"`
	OpenTime        uint32         `json:"opnTime"`
	ACToken         string         `json:"token"`
	PreAccessAction *PreAccessInfo `json:"preAct"`
}

type ACOnlineMsg struct {
	AuthServiceId string   `json:"aspId"`
	ResourceIds   []string `json:"resIds"`
	ACId          string   `json:"acId,omitempty"`
	// Phase 2 - Per-AC Server Assignment fields
	// License key is globally unique and sufficient for lookup and validation
	LicenseKey string `json:"licKey,omitempty"`  // License key for validation (globally unique)
	ACVersion  string `json:"version,omitempty"` // AC software version

	// Session-control readiness is process-scoped, not static-key-scoped. The
	// AC changes BootID on every process start and advances FlushGeneration only
	// after inherited/live NHP session rules have been synchronously flushed.
	BootID                 string `json:"bootId,omitempty"`
	SessionFlushGeneration uint64 `json:"sessFlushGen,omitempty"`
	SessionFlushComplete   bool   `json:"sessFlushComplete,omitempty"`
}

type ServerACAckMsg struct {
	ErrCode    string `json:"errCode"`
	ErrMsg     string `json:"errMsg,omitempty"`
	ACAddr     string `json:"acAddr"`
	Registered bool   `json:"registered"` // True if AC is registered with this server (Phase 2)

	// The successful AAK echoes the exact process boot, completed flush
	// generation, and AOL transaction it authorizes. The AC must not reopen its
	// admission lease from an ACK for an older pre-flush AOL.
	BootID                 string `json:"bootId,omitempty"`
	SessionFlushGeneration uint64 `json:"sessFlushGen,omitempty"`
	AOLTransactionID       uint64 `json:"aolTrxId,omitempty"`

	// ServerAddr is the server's direct IP:Port for AC to establish direct connection.
	// When AC connects through NLB, responses from the server's direct IP would be
	// dropped by the AC's connected UDP socket. This field allows AC to create a
	// new connection directly to the server, bypassing NLB for subsequent traffic.
	ServerAddr string `json:"serverAddr,omitempty"`

	// ServerPubKey is the server's public key (base64) for the direct connection.
	// This may differ from the shared NLB endpoint key used for initial registration.
	ServerPubKey string `json:"serverPubKey,omitempty"`

	// Peers lists the AC's assigned servers (typically 3, one per AZ).
	// When present, the AC should establish direct connections to each peer.
	// This lets origin servers route knock fan-out through one assigned peer per
	// AZ, so each AZ's AC path can open its local ipset/eBPF pinhole.
	// Omitted when the server doesn't have assignment information.
	Peers []RedirectTarget `json:"peers,omitempty"`
}

type ResourceInfo struct {
	ACId       string      `json:"acId"`
	Hostname   string      `json:"host,omitempty"` // hostname, optional
	Addr       *NetAddress `json:"addr"`           // dst ip + port + protocol
	PortSuffix bool        `json:"portSuffix,omitempty"`
	MaskHost   bool        `json:"maskHost,omitempty"` // do not reveal resource host in ack info
}

// DestHost returns the ResourceHost value sent in knock acks.
//
// Contract:
//   - MaskHost, nil Addr, or empty host returns "".
//   - PortSuffix=false returns the bare host.
//   - PortSuffix=true with Addr.Port > 0 returns "host:port".
//   - PortSuffix=true with Addr.Port <= 0 returns "".
//
// BEHAVIOR CHANGE: PortSuffix=true with a missing/non-positive port used
// to fall through to the bare host. The final case is now intentional
// fail-closed behavior for partially populated per-AZ qurl tunnel rows:
// callers should fix or reject the malformed row at the loader boundary
// instead of silently dropping the required public listener port.
func (r *ResourceInfo) DestHost() string {
	if r.MaskHost || r.Addr == nil {
		return ""
	}

	host := r.Addr.Ip
	if len(r.Hostname) > 0 {
		host = r.Hostname
	}
	if host == "" {
		return ""
	}
	if !r.PortSuffix {
		return host
	}
	if r.Addr.Port <= 0 {
		return ""
	}
	return fmt.Sprintf("%s:%d", host, r.Addr.Port)
}

func (r *ResourceInfo) DstIp() string {
	if r.Addr == nil {
		return ""
	}
	return r.Addr.Ip
}

type ResourceGroup struct {
	AuthServiceId     string                   `json:"aspId"`
	ResourceId        string                   `json:"resId"`
	OpenTime          uint32                   `json:"opnTime,omitempty"`
	AuthProviderToken string                   `json:"aspToken,omitempty"`
	Resources         map[string]*ResourceInfo `json:"resInfo"`
}

func (r *ResourceGroup) Id() string {
	return r.AuthServiceId + "/" + r.ResourceId
}

func (r *ResourceGroup) Hosts() map[string]string {
	hostMap := make(map[string]string)
	for name, info := range r.Resources {
		hostMap[name] = info.DestHost()
	}

	return hostMap
}

type DRGMsg struct {
	DoType         string      `json:"doType"`         // Data object format type, default "ZTDO" (ZTDO format details in Chapter 8). Custom formats allowed.
	DoId           string      `json:"doId"`           // Globally unique data object identifier (typically UUID)
	DbId           string      `json:"dbId"`           // Data broker identifier
	DataSourceType string      `json:"dataSourceType"` // Data source type, default "file", Supported Values: file, stream
	AccessUrl      string      `json:"accessUrl"`      // Data access URL (empty indicates offline transfer)
	AccessByNHP    bool        `json:"accessByNHP"`    // Require NHP handshake before accessing URL (optional if accessUrl empty)
	Spo            SmartPolicy `json:"spo"`
}

type DAKMsg struct {
	DoId    string `json:"doId"`    // Echoes registration request's DoId
	ErrCode int    `json:"errCode"` // Registration error code (0=success)
	ErrMsg  string `json:"errMsg"`  // Error message (empty if success)
}

type DARMsg struct {
	DoId                       string `json:"doId"`                       // Requested data object identifier
	UserId                     string `json:"userId"`                     // User identifier
	TeePublicKey               string `json:"teePublicKey"`               // Base64-encoded TEE (Trusted Execution Environment) public key
	ConsumerEphemeralPublicKey string `json:"consumerEphemeralPublicKey"` // Base64-encoded consumer ephemeral public key
}

type DAGMsg struct {
	DoId           string           `json:"doId"`                     // Echoes request's DoId
	DoType         string           `json:"doType,omitempty"`         // Echoes request's DoType
	DataSourceType string           `json:"dataSourceType,omitempty"` // Data source type, the default value is online, and supported values are online, offline and stream.
	AccessUrl      string           `json:"accessUrl,omitempty"`      // Data access URL
	AccessByNHP    bool             `json:"accessByNHP,omitempty"`    // Indicates whether to grant access to the data through NHP
	Kao            *KeyAccessObject `json:"kao,omitempty"`            // Key access object
	Spo            *SmartPolicy     `json:"spo,omitempty"`            // Smart policy Object
	ErrCode        int              `json:"errCode"`                  // Registration error code (0=success)
	ErrMsg         string           `json:"errMsg"`                   // Error message (empty if success)
}

type DWRMsg struct {
	DoId                       string `json:"doId"`                       // Data object identifier
	TeePublicKey               string `json:"teePublicKey"`               // Based64 encoded TEE public key
	ConsumerEphemeralPublicKey string `json:"consumerEphemeralPublicKey"` // Based64 encoded consumer ephemeral public key
}

type DWAMsg struct {
	DoId    string           `json:"doId"`          // Data object identifier
	Kao     *KeyAccessObject `json:"kao,omitempty"` // Key access object
	ErrCode int              `json:"errCode"`       // Registration error code (0=success)
	ErrMsg  string           `json:"errMsg"`        // Error message (empty if success)
}

type DSAMsg struct {
	DoId    string       `json:"doId"`          // Data object identifier
	SpoId   string       `json:"spoId"`         // Smart Policy Object identifier
	Spo     *SmartPolicy `json:"spo,omitempty"` // Smart policy Object
	TTL     int          `json:"TTL"`           // Evidence validity period in milliseconds
	ErrCode int          `json:"errCode"`       // Registration error code (0=success)
	ErrMsg  string       `json:"errMsg"`        // Error message (empty if success)
}

type DAVMsg struct {
	DoId     string `json:"doId"`     // Data object identifier
	SpoId    string `json:"spoId"`    // Smart Policy Object identifier
	Evidence string `json:"evidence"` // Policy verification evidence
}

type KeyAccessObject struct {
	WrappedDataKey string `json:"wrappedDataKey"`          // Wrapped data private key
	SpoId          string `json:"spoId,omitempty"`         // SPO identifier
	PolicyBinding  string `json:"policyBinding,omitempty"` // Base64-encoded HMAC(HMAC(pao), key) using payload key
}

type SmartPolicy struct {
	PolicyId string `json:"policyId"` // Policy identifier
	Policy   string `json:"policy"`   // Base64-encoded wasm policy
	Embedded bool   `json:"embedded"`
}

func (spo *SmartPolicy) GetPolicy() ([]byte, error) {
	wasmBytes, err := base64.StdEncoding.DecodeString(spo.Policy)
	if err != nil {
		wasmPath, err := utils.DownloadFileToTemp(spo.Policy, "wasm-")
		if err != nil {
			return nil, err
		}
		defer func() { _ = os.Remove(filepath.Dir(wasmPath)) }()
		defer func() { _ = os.Remove(wasmPath) }()
		wasmBytes, err = os.ReadFile(wasmPath)
		if err != nil {
			return nil, err
		}
	}

	return wasmBytes, nil
}

type DBOnlineMsg struct {
	DBId string `json:"dbId,omitempty"`
}

type ServerDBAckMsg struct {
	ErrCode string `json:"errCode"`
	ErrMsg  string `json:"errMsg,omitempty"`
	DBAddr  string `json:"dbAddr"`
}

// DHPKnockMsg — DHP variant of the knock payload carrying
// attestation evidence. If you add a field here with a JSON
// tag that overlaps AgentKnockMsg (specifically `headerType`
// or `aspId`), the #1154 DHP→NHP wire-flip self-limiting
// property may no longer hold — the gate relies on
// FindAuthSvcProvider("") rejecting the malformed
// cross-decoded packet before broadcast. See
// TestDHPKnockMsg_UnmarshalAsAgentKnockMsg_SelfLimits for the
// mechanical fence.
type DHPKnockMsg struct {
	UserId         string         `json:"usrId"`
	DeviceId       string         `json:"devId"`
	OrganizationId string         `json:"orgId,omitempty"`
	UserData       map[string]any `json:"usrData,omitempty"`
	Evidence       string         `json:"evidence"`
}

type ServerDHPKnockAckMsg struct {
	ErrCode  string `json:"errCode"`
	ErrMsg   string `json:"errMsg,omitempty"`
	OpenTime uint32 `json:"opnTime"`
}

// ============================================================================
// Per-AC Server Assignment Messages (Phase 2 - Pluggable Storage Backend)
// See docs/design/PLUGGABLE_STORAGE_BACKEND.md for architecture details.
// ============================================================================

// ForwardAdmissionRevocationData is the qURL v2 revocation subset an origin
// server may carry on NHP_FWD after accepting a per-admission signed-claims
// knock. It intentionally excludes catalog routing and credential fields; the
// receiving server resolves those locally before overlaying this metadata. The
// nested tags match the compact qURL v2 fields on ServerACOpsMsg.
// RevocationEpoch is intentionally absent: epochs ride revoke events, not
// knock-time admission metadata.
type ForwardAdmissionRevocationData struct {
	QurlUserPublicKeyHash string `json:"qurlUsrPubKeyHash,omitempty"`
	ResourcePublicKeyHash string `json:"resPubKeyHash,omitempty"`
	QurlSessionId         string `json:"qurlSessId,omitempty"`
	AdmissionId           string `json:"admId,omitempty"`
	Deadline              int64  `json:"deadline,omitempty"`
}

// ForwardResolvedResourceData is the origin server's already-authorized,
// already-resolved AC routing snapshot for NHP_FWD receivers. It intentionally
// carries only pinhole routing fields plus the qURL v2 resource hash used to
// bind the snapshot back to the knock identity. It must not grow ResourceData's
// credential or extension fields (app secrets, access keys, exinfo, redirects).
type ForwardResolvedResourceData struct {
	AuthServiceId         string                   `json:"aspId,omitempty"`
	ResourceId            string                   `json:"resId,omitempty"`
	OpenTime              uint32                   `json:"opnTime,omitempty"`
	Resources             map[string]*ResourceInfo `json:"resInfo,omitempty"`
	ResourcePublicKeyB64  string                   `json:"resPubKeyB64,omitempty"`
	ResourcePublicKeyHash string                   `json:"resPubKeyHash,omitempty"`
}

// ServerForwardMsg is sent from one server to another to forward a knock (NHP_FWD).
// Used when a knock arrives at a non-assigned server and needs to be forwarded
// to one of the AC's assigned servers.
type ServerForwardMsg struct {
	KnockData            []byte `json:"knockData"`                      // Original encrypted knock packet
	SourceServer         string `json:"sourceServer"`                   // Server ID that received the knock
	UserAddr             string `json:"userAddr"`                       // User's address for response routing
	TransactionId        uint64 `json:"txId"`                           // For response correlation
	Timestamp            int64  `json:"ts"`                             // Unix timestamp - reject if >30s old (replay protection)
	SessionId            uint64 `json:"sessId,omitempty"`               // Origin server-assigned NHP access-session identifier
	SessionIssuedAtNanos int64  `json:"sessionIssuedAtNanos,omitempty"` // Origin server issuance time; used only to derive the serving deadline.

	// AdmissionRevocationData optionally carries qURL v2 revocation metadata
	// produced by the origin server's admission decision. Local catalog
	// resolution remains authoritative for AC routing and ACK construction.
	AdmissionRevocationData *ForwardAdmissionRevocationData `json:"admissionRevocationData,omitempty"`

	// ResolvedResourceData optionally carries the origin's resolved routing row
	// so a peer can still open its local AC pinhole when the inner knock
	// ResourceId is not a catalog key on that peer (for example qURL v2's
	// protected-resource public key). Receivers validate it before use and only
	// fall back to it when local catalog placement cannot resolve the resource.
	ResolvedResourceData *ForwardResolvedResourceData `json:"resolvedResourceData,omitempty"`
}

// ServerForwardResultMsg is the response to ServerForwardMsg (NHP_FRT).
// Contains the result of knock handling from the assigned server.
type ServerForwardResultMsg struct {
	TransactionId uint64 `json:"txId"`              // Echoes request txId
	Success       bool   `json:"success"`           // True if AOP was sent to AC
	ACKData       []byte `json:"ackData,omitempty"` // Response to send to user
	ErrCode       string `json:"errCode,omitempty"` // Error code if failed
	ErrMsg        string `json:"errMsg,omitempty"`  // Error message if failed
}

// RelayForwardMsg is the AEAD body of an NHP_RLY packet (relay -> private
// server), derived from OpenNHP upstream (#2208). The relay wraps a
// browser-originated, end-to-end-encrypted NHP packet (opaque to the relay) in
// InnerPacket and stamps SourceAddr -- the client address the relay observed at
// its TLS/TCP edge. SourceAddr is the sole trusted source of the AC pinhole IP
// (AgentKnockMsg carries no source-IP field). RequestID is a relay-generated,
// cryptographically random correlation ID. The server returns the opaque inner
// reply inside RelayReturnMsg; counters are not a safe correlation key because
// independent agents routinely reuse them.
//
// InnerPacket is a base64 string (not []byte) for parity with upstream and the
// TypeScript js-agent, which exchange a pre-encoded base64 string. encoding/json
// would base64 a []byte to a wire-identical value, but we keep the encoding
// explicit -- do not "simplify" it to []byte.
type RelayForwardMsg struct {
	SourceAddr  *NetAddress `json:"srcAddr"`   // real client address (relay-observed)
	InnerPacket string      `json:"innerPkt"`  // base64-encoded inner NHP packet
	RequestID   string      `json:"requestId"` // random relay correlation ID
}

// RelayReturnMsg is the authenticated server-to-relay envelope. InnerPacket is
// still encrypted end-to-end for the originating agent; the relay validates and
// consumes RequestID, then returns the opaque bytes to exactly one waiter.
type RelayReturnMsg struct {
	RequestID   string `json:"requestId"`
	InnerPacket string `json:"innerPkt"`
}

// RedirectTarget represents an assigned server that the AC should connect to.
// Used in ACRedispatchMsg to redirect AC to its assigned servers.
type RedirectTarget struct {
	IP           string `json:"ip"`                 // Server's public IP
	Hostname     string `json:"hostname,omitempty"` // DNS hostname (for NLB drain redirects)
	Port         int    `json:"port"`               // Server's NHP UDP port
	PubKeyBase64 string `json:"pubKey"`             // Server's public key for NHP_AOL encryption
	AZ           string `json:"az,omitempty"`       // Availability Zone (for debugging/logging)
	ServerID     string `json:"srvId,omitempty"`    // Server ID (for debugging/logging)
}

// Address returns the best available address for display/logging:
// IP if set, else Hostname, else ServerID.
func (rt *RedirectTarget) Address() string {
	if rt.IP != "" {
		return rt.IP
	}
	if rt.Hostname != "" {
		return rt.Hostname
	}
	return rt.ServerID
}

// Validate enforces the RedirectTarget contract: IP is REQUIRED, Port must
// be in the valid range, and PubKeyBase64 must be present. Hostname is
// optional metadata.
//
// Historically the AC accepted hostname-only targets because the server's
// graceful-drain code emitted NHP_ARD messages with Hostname set but IP
// empty. Downstream consumer code (refreshAssignedServerRegistrations,
// IsServerAddress, log lines) used Target.IP as a stable identifier, so a
// hostname-only entry silently broke keepalives and health checks without
// tripping any recovery path. See issue #832 for the full trace.
//
// Callers that need to emit a hostname-based target (e.g. NLB drain) MUST
// resolve the hostname to an IP at construction time and populate IP.
func (rt *RedirectTarget) Validate() error {
	if rt.IP == "" {
		return fmt.Errorf("RedirectTarget.IP is required (Hostname=%q is not a substitute — see #832)", rt.Hostname)
	}
	if net.ParseIP(rt.IP) == nil {
		return fmt.Errorf("RedirectTarget.IP=%q is not a valid IP address", rt.IP)
	}
	if rt.Port <= 0 || rt.Port > 65535 {
		return fmt.Errorf("RedirectTarget.Port=%d out of range (must be 1-65535)", rt.Port)
	}
	if rt.PubKeyBase64 == "" {
		return errors.New("RedirectTarget.PubKeyBase64 is required")
	}
	return nil
}

// ACRedispatchMsg redirects an AC to its assigned servers (NHP_ARD).
// This is an NHP spec message (Type 30) sent in two contexts:
//   - In response to NHP_AOL when the AC connects to a non-assigned server via NLB
//   - Unsolicited during graceful server shutdown (drain), redirecting ACs to the NLB
//
// Protocol rules:
// 1. No redirect chaining - assigned servers MUST respond with NHP_AAK, not NHP_ARD
// 2. AC should terminate current connection and connect to targets in order
type ACRedispatchMsg struct {
	Targets []RedirectTarget `json:"targets"`           // Ordered list of assigned servers (typically 3)
	ErrCode string           `json:"errCode,omitempty"` // Error code if assignment lookup failed
	ErrMsg  string           `json:"errMsg,omitempty"`  // Error message if failed
}

// ACRevocationMsg carries a qURL v2 immediate-revocation event from the NHP
// Server to an AC over NHP_REV (server-to-AC, LayerV extension). The server
// relays it fire-and-forget after receiving the event from qurl-service; the AC
// resolves Scope+ScopeKey to its secondary revocation index and tears down the
// matching live access entries immediately (see (*UdpAC).HandleUdpACRevocation
// → ApplyRevocation, P4b).
//
// Wire contract (CROSS-REPO). The json tags and field semantics mirror
// qurl-service's revocation event (`internal/revocation/event.go`, P4d) so the
// server send side (P4e Slice 2) can field-copy from the qurl-service Event into
// this struct without a semantic transform — that is why the tags are snake_case
// (matching qurl-service) rather than the camelCase used elsewhere in this file.
// Keep the tags stable; they cannot change after Slice 2 ships.
//
//   - Scope is the revocation dimension. qurl-service emits one of "qurl",
//     "resource", "session", or "cell"; this struct's string values mirror those
//     byte-for-byte so the two ends agree without a translation table. The AC
//     handler applies only "qurl"/"resource"/"session" — "cell" is a
//     server-side fanout selector with no AC-local index (the AC drops it), and
//     "admission" is an AC-internal index dimension that is never a wire scope
//     (the handler rejects both as unsupported).
//   - ScopeKey is the scope-PREFIXED key exactly as qurl-service emits it:
//     "<scope>:<identity-hash-or-id>", e.g. "resource:<resource_public_key_hash>"
//     or "qurl:<qurl_user_public_key_hash>" (qurl-service
//     `internal/revocation/scopekey.go` `ScopeKey`). The AC handler strips the
//     "<scope>:" transport prefix before calling ApplyRevocation, which requires
//     the BARE identity (its index is keyed on the bare hash carried onto each
//     AccessEntry at admission). The scope and the prefix MUST agree (qurl-service
//     builds the prefix from the same scope); a mismatch is treated as malformed.
//   - RevocationEpoch is the per-(scope, scope_key) monotonic counter used for
//     idempotency/ordering; the AC applies an event only when its epoch is
//     strictly greater than the last applied for that (Scope, ScopeKey). MUST be
//     non-negative; a negative value is rejected (it would convert to a near-max
//     uint64 and poison the epoch watermark). int64 (not uint64) to match
//     qurl-service's wire type; the handler's negative guard covers the only
//     unsafe input before the uint64 conversion.
//   - EventId is an opaque producer-assigned id (qurl-service "evt_..."), carried
//     for log correlation / tracing across the qurl-service→server→AC hops; it
//     does not affect apply.
type ACRevocationMsg struct {
	Scope           string `json:"scope"`            // "qurl" | "resource" | "session" | "cell" (AC applies the first three)
	ScopeKey        string `json:"scope_key"`        // scope-prefixed "<scope>:<hash>"; handler strips the prefix
	RevocationEpoch int64  `json:"revocation_epoch"` // monotonic epoch (must be >= 0)
	EventId         string `json:"event_id,omitempty"`
}

// ACRevocationAckMsg is the AC→server acknowledgement of an NHP_REV, carried on
// NHP_RVA (AC-to-server, LayerV extension). It is the proof-of-delivery signal
// for DE-Risk #5: the AC sends one after it has PROCESSED a validated NHP_REV,
// and the server uses it to clear that AC's pending-revoke tracker so the
// retry-until-ack-or-age-out loop stops retransmitting (see
// docs/design/QURL_V2_KEYED_IDENTITY.md revocation section, P4e Slice 3, #2793).
//
// Acknowledgement semantics — CONVERGENCE, not work-done (load-bearing): the AC
// acks EVERY validated NHP_REV regardless of how many live entries it flushed.
// ApplyRevocation returns 0 in two legitimate cases that MUST still ack, or the
// server would retry to age-out and falsely mark the revoke degraded:
//   - the retry after a lost ack (the entry was already torn down + deleted by
//     the first apply, so the re-delivered event flushes nothing); and
//   - cell-wide fanout reaching an AC that never admitted the key (the common
//     case — every AC receives every cell-wide revoke).
//
// So the ack means "this AC has reached the post-revocation state for
// (scope, scope_key, epoch)", i.e. there is no live flow for that identity at or
// below this epoch on this AC. It is NOT a claim about how many flows were torn
// down. A reject path (malformed/forged event, unsupported scope, etc.) does NOT
// ack — those age out to the degraded metric, which correctly surfaces
// server↔AC validation drift rather than masking it.
//
// Wire contract (CROSS-REPO-shaped but server↔AC only — qurl-service is not a
// party). The fields echo the NHP_REV the AC received so the server can
// correlate the ack to its pending tracker:
//   - Scope / ScopeKey are echoed VERBATIM as received on the NHP_REV
//     (ScopeKey is still the scope-PREFIXED "<scope>:<id>" form — the AC does
//     NOT strip the prefix on the ack path). The server forwarded scope_key
//     verbatim into the NHP_REV and tracks pending revokes under that exact
//     byte string, so echoing it unmodified lets the server match by string
//     equality. Normalizing/stripping here would reintroduce the
//     fail-open-on-key-mismatch trap the gospel warns about repeatedly.
//   - RevocationEpoch echoes the acked epoch; the server clears a pending
//     tracker only when the ack's epoch matches (or supersedes) the epoch it
//     last sent for that authenticated AC slot (acId + pubkey, resolved from
//     the connection) and (scope, scope_key).
//   - EventId echoes the NHP_REV's event id for cross-hop log correlation; it
//     does not affect ack matching (the (scope, scope_key, epoch) tuple does).
//
// The acking AC's identity is NOT carried in this message: the server resolves
// both acId and the live slot pubkey from the cryptographically-authenticated
// connection pubkey (ppd.RemotePubKey → acConnectionMap), never from a spoofable
// body field. Multiple blue/green AC slots can share one acId, so the pubkey is
// part of the server-side pending key.
type ACRevocationAckMsg struct {
	Scope           string `json:"scope"`
	ScopeKey        string `json:"scope_key"`        // echoed VERBATIM (still scope-prefixed)
	RevocationEpoch int64  `json:"revocation_epoch"` // echoed acked epoch
	EventId         string `json:"event_id,omitempty"`
}
