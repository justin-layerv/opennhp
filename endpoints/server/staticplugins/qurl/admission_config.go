package qurl

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/OpenNHP/opennhp/endpoints/server/internal/qurlv2"
)

// qURL v2 admission runtime configuration, parsed once at Init.
//
// These package-level values are the admission path's view of the gated feature:
// whether it is on, and (when on) the issuer trust store it verifies against.
// They are written exactly once inside Init's sync.Once (single writer, before
// any knock can be served) and only read afterward, so no additional
// synchronization is needed — same lifecycle as the package-level resolver.
var (
	// v2AdmissionEnabled mirrors Config.V2AdmissionEnabled. When false, the qv2
	// claims knock path is a total no-op (no verify, no qurl-service call, no AC).
	v2AdmissionEnabled bool

	// v2TrustStore is the issuer trust store used to verify qv2 claim signatures.
	// nil when the feature is off; non-nil and validated when it is on (Init
	// fails closed if the configured store is empty or unparseable).
	v2TrustStore *qurlv2.TrustStore
)

// v2ClockSkewAllowance is the clock-skew tolerance applied to qv2 claim
// liveness (exp/nbf vs now) on the admission path. The signed window is minted
// by qurl-service and verified here and in qurl-service prepare; a small
// symmetric allowance absorbs ordinary NHP-server/qurl-service clock drift
// without materially widening a stale link's usable window. qurl-service's DDB
// state remains the authoritative liveness/revocation gate regardless.
const v2ClockSkewAllowance = 60 * time.Second

// LoadV2TrustStore parses the QURL_V2_ISSUER_TRUST_STORE JSON (a map of issuer
// kid -> base64(DER SPKI P-256 public key)) into a qurlv2.TrustStore. It is
// called from Init only when the v2 admission feature is enabled; an empty or
// structurally invalid store is a hard error so a misconfigured deployment fails
// closed at startup rather than failing every qv2 knock at runtime.
//
// The base64 layer accepts standard base64 (the form `aws kms get-public-key`
// and most tooling emit); the inner bytes must be a parseable P-256 SPKI public
// key (qurlv2.NewTrustStoreFromDER enforces the curve).
func LoadV2TrustStore(storeJSON string) (*qurlv2.TrustStore, error) {
	var b64ByKID map[string]string
	dec := json.NewDecoder(strings.NewReader(storeJSON))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b64ByKID); err != nil {
		return nil, fmt.Errorf("parse QURL_V2_ISSUER_TRUST_STORE JSON: %w", err)
	}
	if len(b64ByKID) == 0 {
		return nil, fmt.Errorf("QURL_V2_ISSUER_TRUST_STORE contains no issuer keys")
	}

	derByKID := make(map[string][]byte, len(b64ByKID))
	for kid, b64 := range b64ByKID {
		if kid == "" {
			return nil, fmt.Errorf("QURL_V2_ISSUER_TRUST_STORE has an empty kid")
		}
		der, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("QURL_V2_ISSUER_TRUST_STORE kid %q: not valid base64: %w", kid, err)
		}
		derByKID[kid] = der
	}

	ts, err := qurlv2.NewTrustStoreFromDER(derByKID)
	if err != nil {
		return nil, fmt.Errorf("build qURL v2 issuer trust store: %w", err)
	}
	return ts, nil
}
