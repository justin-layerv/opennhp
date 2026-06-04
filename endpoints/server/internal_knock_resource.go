package server

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/OpenNHP/opennhp/nhp/common"
)

var (
	errInvalidInternalKnockRequest = errors.New("invalid internal knock request")
	errInternalKnockServerNotReady = errors.New("internal knock server not ready")
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
	aspData, err := hs.udpServer.ResolveInternalKnockAuthSvcProvider(ctx, aspID, "handleInternalKnock-resource")
	if err != nil {
		return nil, err
	}
	resolved := aspData.GetResourceData(resourceID)
	if resolved == nil {
		// ASP misses are counted inside ResolveInternalKnockAuthSvcProvider;
		// resourceId misses are only knowable here after ASP resolution.
		hs.udpServer.metrics.IncrCounter(MetricInternalKnockResourceNotFound)
		return nil, common.ErrResourceNotFound
	}

	req.AuthServiceId = aspID
	req.ResourceId = resourceID
	resolved = cloneResourceData(resolved)
	if resolved.OpenTime == 0 {
		resolved.OpenTime = DefaultIpOpenTime
	}
	// No lower floor: any positive caller value below the stored cap is a
	// stricter pinhole window, so allowing 1s is intentionally safe.
	if callerResource != nil && callerResource.OpenTime > 0 && callerResource.OpenTime < resolved.OpenTime {
		resolved.OpenTime = callerResource.OpenTime
	}
	return resolved, nil
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
