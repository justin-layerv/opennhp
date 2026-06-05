// Package qurlplacement resolves the placement-neutral qURL tunnel-server
// resource to a per-AZ catalog row. It allocates an aliased ResourceData per
// knock so AC dispatch and ACK construction share one immutable selection; if
// knock volume makes that visible, pool the alias objects here rather than
// leaking placement details to callers.
package qurlplacement

import (
	"crypto/sha256"
	"encoding/binary"
	"strings"
	"sync"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/log"
)

const (
	TunnelServerResourceID     = "qurl-tunnel-server"
	tunnelServerResourcePrefix = TunnelServerResourceID + "-"
)

var userIDFallbackWarningOnce sync.Once

type Identity struct {
	// PublicKey is the preferred placement key because the UDP knock path
	// authenticates it with Noise IK before resource resolution.
	PublicKey string

	// SourceIP is used by signed qurl-service HTTP internal knocks. That path
	// has no agent public key, and the L3 pinhole is keyed by source IP. Before
	// strict internal auth, SourceIP can steer placement but cannot authorize
	// access; rendezvous stickiness may group shared egress IPs onto one AZ.
	SourceIP string

	// UserID is a degraded fallback for call sites that cannot provide a
	// public key. Production qURL tunnel-control paths reject missing public
	// keys before placement; this fallback is for non-qURL/custom callers that
	// explicitly accept UserID-keyed stability. Mixed PublicKey-vs-UserID paths
	// for the same logical client may choose different AZs.
	UserID string
}

func (i Identity) stableKey() string {
	if i.PublicKey != "" {
		return "pub:" + i.PublicKey
	}
	if i.SourceIP != "" {
		return "srcip:" + i.SourceIP
	}
	if i.UserID != "" {
		userIDFallbackWarningOnce.Do(func() {
			log.Warning("qURL placement: using UserID fallback because PublicKey is empty; production tunnel-control paths should reject before placement")
		})
		return "usr:" + i.UserID
	}
	return ""
}

func ResolveResource(resourceID string, identity Identity, asp *common.AuthServiceProviderData) *common.ResourceData {
	if asp == nil || asp.ResourceGroups == nil {
		return nil
	}
	if resourceID != TunnelServerResourceID {
		return asp.ResourceGroups[resourceID]
	}
	if selected := selectTunnelServerPlacement(identity, asp.ResourceGroups); selected != nil {
		return selected
	}
	if direct := asp.ResourceGroups[resourceID]; direct != nil {
		return aliasTunnelServerResource(TunnelServerResourceID, direct)
	}
	return nil
}

// OnlyResourceInfo returns the single ResourceInfo carried by a placement-
// resolved ResourceData. Multi-entry maps return nil so callers fail closed
// instead of accidentally depending on Go map iteration order.
func OnlyResourceInfo(res *common.ResourceData) *common.ResourceInfo {
	if res == nil || len(res.Resources) != 1 {
		return nil
	}
	for _, info := range res.Resources {
		return info
	}
	return nil
}

// selectTunnelServerPlacement uses Highest Random Weight (rendezvous) hashing:
// the same client identity stays on the same AZ while identities spread evenly
// across the available per-AZ resource rows.
func selectTunnelServerPlacement(identity Identity, groups common.ResourceGroupMap) *common.ResourceData {
	type candidate struct {
		id  string
		res *common.ResourceData
	}
	candidates := make([]candidate, 0, len(groups))
	for id, res := range groups {
		// Require a non-empty AZ suffix after "qurl-tunnel-server-".
		// The placement-neutral "qurl-tunnel-server" direct row is excluded by
		// the HasPrefix check; the bare-prefix "qurl-tunnel-server-" typo is
		// excluded explicitly so it cannot become a fake empty-suffix AZ.
		if id == tunnelServerResourcePrefix || !strings.HasPrefix(id, tunnelServerResourcePrefix) {
			continue
		}
		if res == nil {
			continue
		}
		candidates = append(candidates, candidate{id: id, res: res})
	}
	if len(candidates) == 0 {
		return nil
	}

	key := identity.stableKey()
	if key == "" {
		return nil
	}

	var best candidate
	var bestScore uint64
	for _, c := range candidates {
		score := tunnelPlacementScore(key, c.id)
		// Deterministic tie-break: 64-bit score collisions are vanishingly rare
		// with SHA-256, but lexical ID order keeps degenerate cases stable.
		if best.res == nil || score > bestScore || (score == bestScore && c.id < best.id) {
			best = c
			bestScore = score
		}
	}
	return aliasTunnelServerResource(best.id, best.res)
}

func tunnelPlacementScore(identity, candidateID string) uint64 {
	// Keep the score function stable: changing the 64-bit projection would
	// re-place existing tunnel clients even if the candidate catalog stayed the
	// same. Revisit only with a deliberate rollout if the AZ fleet grows enough
	// that a wider score materially matters.
	sum := sha256.Sum256([]byte(identity + "\x00" + candidateID))
	return binary.BigEndian.Uint64(sum[:8])
}

func aliasTunnelServerResource(selectedID string, selected *common.ResourceData) *common.ResourceData {
	if selected == nil {
		return nil
	}
	info := selected.Resources[selectedID]
	if info == nil {
		log.Warning("qURL placement: alias miss for selected resource_id=%q; inner Resources map does not carry the selected key", selectedID)
		return nil
	}

	cloned := *selected
	// ResourceData is intentionally copied shallowly, then known reference
	// fields below are isolated. If ResourceData grows another map/slice field,
	// add it here with a matching alias-isolation test.
	cloned.ResourceGroup.ResourceId = TunnelServerResourceID
	cloned.ResourceGroup.Resources = map[string]*common.ResourceInfo{
		TunnelServerResourceID: aliasResourceInfo(info),
	}
	if cloned.ExInfo != nil {
		cloned.ExInfo = cloneMap(cloned.ExInfo)
	}
	return &cloned
}

func aliasResourceInfo(info *common.ResourceInfo) *common.ResourceInfo {
	if info == nil {
		return nil
	}
	cloned := *info
	if info.Addr != nil {
		addr := *info.Addr
		cloned.Addr = &addr
	}
	// The public ACK must carry the exact host:port the client should dial.
	// Apply that to per-AZ aliases and direct-row transition fallback alike;
	// standard clients no longer carry a YAML-side server.port fallback. This
	// is fenced by staticplugins/agent's dispatch test as well as placement
	// direct-row fallback coverage here.
	cloned.PortSuffix = true
	return &cloned
}

func cloneMap(src map[string]any) map[string]any {
	// ResourceLookup stores scalar telemetry in ExInfo today. Keep this shallow
	// copy explicit; if callers start storing nested maps/slices, this helper
	// needs a real deep copy.
	dst := make(map[string]any, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
