package server

import (
	"net"

	"github.com/OpenNHP/opennhp/nhp/common"
)

// maxInternalKnockRequestSize caps the POST body /nhp/internal/knock accepts,
// used by handleInternalKnock to trip a 413 before the HMAC compute.
const maxInternalKnockRequestSize int64 = 64 << 10 // 64 KiB

// maxPluginRequestSize caps the request body for /plugins/:aspid. The qurl
// plugin's POST body is small; 16 KiB leaves ample headroom while bounding a
// parser-heavy downstream path. Edge WAF limits may be lower, so this remains
// the server-side backstop for direct or non-WAF ingress.
const maxPluginRequestSize int64 = 16 << 10 // 16 KiB

// SourceAPI identifies a service-to-service API origin. It is authenticated and
// validated by handleInternalKnock before the retired direct-admission terminal.
const SourceAPI = "api"

// HttpKnockForwardRequest is the legacy internal HTTP admission envelope. The
// receiver still parses, authenticates, and validates it so callers get the
// explicit ErrHTTPAccessOperationUnsupported terminal instead of bypassing the
// pre-handler security gates.
type HttpKnockForwardRequest struct {
	Request  *common.HttpKnockRequest `json:"request"`
	Resource *common.ResourceData     `json:"resource"`
	Source   string                   `json:"source,omitempty"`

	// Attestation binds a historical server-to-server hop to the sender's NHP
	// identity. It remains verified on receipt during retirement/rollout overlap.
	Attestation *ForwardHopAttestation `json:"hop_attestation,omitempty"`
}

// ForwardHopAttestation is the per-hop identity binding accepted by the legacy
// internal HTTP envelope during retirement/rollout overlap.
type ForwardHopAttestation struct {
	SenderPubKey string `json:"sender_pubkey"`
	Hop          int    `json:"hop"`
	Timestamp    int64  `json:"ts"`
	MAC          string `json:"mac"`
}

// HttpKnockForwardResponse is the legacy internal HTTP response envelope. The
// retired terminal returns an unsupported ACK and matching Error string.
type HttpKnockForwardResponse struct {
	AckMsg *common.ServerKnockAckMsg `json:"ack_msg"`
	Error  string                    `json:"error,omitempty"`
}

// isPrivateIP checks if an IP address is in RFC 1918 private or loopback space.
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback()
}
