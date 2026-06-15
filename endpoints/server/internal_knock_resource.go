package server

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/OpenNHP/opennhp/endpoints/server/internal/qurlplacement"
	"github.com/OpenNHP/opennhp/nhp/common"
)

var (
	errInvalidInternalKnockRequest = errors.New("invalid internal knock request")
	errInternalKnockServerNotReady = errors.New("internal knock server not ready")
)

const (
	qurlInternalKnockAuthServiceID = "qurl"
	qurlDynamicResourcePrefix      = "q_"
	qurlDynamicResourceHexLength   = 11
)

// resolveInternalKnockResource canonicalizes req.AuthServiceId and
// req.ResourceId in place only after a successful catalog lookup so downstream
// AC operations use the same trimmed IDs that were used for catalog lookup.
func (hs *HttpServer) resolveInternalKnockResource(ctx context.Context, req *common.HttpKnockRequest, callerResource *common.ResourceData) (*common.ResourceData, error) {
	aspID := strings.TrimSpace(req.AuthServiceId)
	resourceID := strings.TrimSpace(req.ResourceId)
	// qurl-service already sends request.resId on the pre-cutover producer.
	// Keep lookup identity request-scoped; callerResource is only validated
	// for consistency and used for the bounded opnTime override.
	if aspID == "" || resourceID == "" {
		return nil, fmt.Errorf("%w: missing aspId or resId", errInvalidInternalKnockRequest)
	}

	if callerResource != nil {
		callerAspID := strings.TrimSpace(callerResource.AuthServiceId)
		callerResourceID := strings.TrimSpace(callerResource.ResourceId)
		if callerAspID != "" && callerAspID != aspID {
			return nil, fmt.Errorf("%w: resource aspId %q does not match request aspId %q", errInvalidInternalKnockRequest, callerResource.AuthServiceId, aspID)
		}
		if callerResourceID != "" && callerResourceID != resourceID {
			return nil, fmt.Errorf("%w: resource resId %q does not match request resId %q", errInvalidInternalKnockRequest, callerResource.ResourceId, resourceID)
		}
	}

	if hs == nil || hs.udpServer == nil {
		return nil, errInternalKnockServerNotReady
	}
	srcIP := strings.TrimSpace(req.SrcIp)
	dynamicQURLResource := aspID == qurlInternalKnockAuthServiceID && IsQURLDynamicResourceID(resourceID)
	if dynamicQURLResource && srcIP == "" {
		// Dynamic rows choose the AC directly from storage, but the downstream
		// L3 pinhole still needs qurl-service's caller IP as its source key.
		// Match the static placement path's fail-closed posture on empty SrcIp.
		hs.udpServer.incrCounterIfMetrics(MetricInternalKnockResourceNotFound)
		return nil, common.ErrResourceNotFound
	}
	var resolved *common.ResourceData

	if dynamicQURLResource {
		// Dynamic qURL resources are minted after the ASP-level catalog may
		// already be cached. Keep those q_ rows on an exact row lookup; static
		// qURL resources, including qurl-tunnel-server placement, stay on the
		// ASP catalog.
		dynamicResource, err := hs.udpServer.ResolveInternalKnockResource(ctx, aspID, resourceID, "handleInternalKnock-resource")
		if err != nil {
			return nil, err
		}
		resolved = dynamicResource
	} else {
		aspData, err := hs.udpServer.ResolveInternalKnockAuthSvcProvider(ctx, aspID, "handleInternalKnock-resource")
		if err != nil {
			return nil, err
		}
		// qurl-service's /v1/resolve path has no agent public key; the
		// qurl-service-supplied SrcIp is the stable identity that matches the L3
		// pinhole. In strict mode it is covered by the internal-auth body HMAC;
		// before strict mode, it is still placement-only and not an authz boundary.
		// Empty SrcIp intentionally remains an empty identity so a per-AZ-only
		// catalog fails closed instead of placing by a different key. Rendezvous
		// hashing is sticky, so a small qurl-service egress-IP set can concentrate
		// placement on fewer AZs; that is a load-distribution tradeoff only.
		placementIdentity := qurlplacement.Identity{SourceIP: srcIP}
		resolved = qurlplacement.ResolveResource(resourceID, placementIdentity, aspData)
	}
	if resolved == nil {
		// ASP misses are counted inside ResolveInternalKnockAuthSvcProvider;
		// resourceId misses are only knowable here after ASP resolution.
		hs.udpServer.incrCounterIfMetrics(MetricInternalKnockResourceNotFound)
		return nil, common.ErrResourceNotFound
	}

	// Production handleInternalKnock verifies the body HMAC before reaching this
	// resolver. qurl-service supplies SrcIp from c.ClientIP(), and downstream
	// ACTokenEntry.KnockSrcIP validation consumes this canonical trimmed value.
	req.AuthServiceId = aspID
	req.ResourceId = resourceID
	req.SrcIp = srcIP
	resolved = cloneResourceData(resolved)
	if resolved.OpenTime == 0 {
		resolved.OpenTime = DefaultIpOpenTime
	}
	// The caller value may only LOWER the stored cap (a stricter pinhole window);
	// no lower floor, so allowing 1s is intentionally safe. ClampOpenTimeDownward
	// is the single source of truth for this rule — the qURL plugin applies it to
	// the same effect (it passes callerResource=nil here and clamps locally,
	// since ResolveResourceFunc carries no override).
	if callerResource != nil {
		resolved.OpenTime = ClampOpenTimeDownward(resolved.OpenTime, callerResource.OpenTime)
	}
	return resolved, nil
}

// ClampOpenTimeDownward applies the "an override may only LOWER the ceiling"
// rule that governs AC pinhole windows (#2540): it returns override when it is a
// positive value strictly below ceiling (a stricter window), otherwise ceiling.
// Shared by the headless resolver (callerResource override) and the qURL plugin
// (qurl-service response OpenTime vs. catalog cap) so the two cannot drift; a
// caller minting an NHP-token open-time claim from the result keeps it coupled
// to the pinhole window.
func ClampOpenTimeDownward(ceiling, override uint32) uint32 {
	if override > 0 && override < ceiling {
		return override
	}
	return ceiling
}

func (hs *HttpServer) internalKnockResourceLookupContext() context.Context {
	if hs == nil || hs.udpServer == nil {
		return context.Background()
	}
	return hs.udpServer.LifecycleCtx()
}

// IsQURLDynamicResourceID reports whether resourceID is a dynamic qURL catalog
// key — the "q_" + 11-hex-char display id qurl-service mints (QurlDisplayID).
// Exported so the qURL plugin can fail fast on a malformed NHPResourceID at
// response-validation time using the same predicate the resolver uses to select
// the dynamic-row lookup, so the two cannot drift (#2540).
func IsQURLDynamicResourceID(resourceID string) bool {
	if len(resourceID) != len(qurlDynamicResourcePrefix)+qurlDynamicResourceHexLength ||
		!strings.HasPrefix(resourceID, qurlDynamicResourcePrefix) {
		return false
	}
	for _, ch := range resourceID[len(qurlDynamicResourcePrefix):] {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return false
		}
	}
	return true
}

func cloneResourceData(src *common.ResourceData) *common.ResourceData {
	if src == nil {
		return nil
	}
	// Update this clone when ResourceData/ResourceGroup gain new reference-typed fields.
	dst := *src
	dst.Resources = cloneResourceInfoMap(src.Resources)
	dst.ExInfo = cloneAnyMap(src.ExInfo)
	return &dst
}

func cloneResourceInfoMap(src map[string]*common.ResourceInfo) map[string]*common.ResourceInfo {
	if src == nil {
		return nil
	}
	dst := make(map[string]*common.ResourceInfo, len(src))
	for name, info := range src {
		dst[name] = cloneResourceInfo(info)
	}
	return dst
}

func cloneResourceInfo(src *common.ResourceInfo) *common.ResourceInfo {
	if src == nil {
		return nil
	}
	dst := *src
	if src.Addr != nil {
		addr := *src.Addr
		dst.Addr = &addr
	}
	return &dst
}

func cloneAnyMap(src map[string]any) map[string]any {
	if src == nil {
		return nil
	}
	dst := make(map[string]any, len(src))
	for key, value := range src {
		dst[key] = cloneAnyValue(value)
	}
	return dst
}

func cloneAnySlice(src []any) []any {
	if src == nil {
		return nil
	}
	dst := make([]any, len(src))
	for i, value := range src {
		dst[i] = cloneAnyValue(value)
	}
	return dst
}

func cloneAnyValue(value any) any {
	switch v := value.(type) {
	case map[string]any:
		return cloneAnyMap(v)
	case []any:
		return cloneAnySlice(v)
	default:
		return value
	}
}
