package server

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/OpenNHP/opennhp/nhp/log"
	"github.com/layervai/nhp/internalauth"
)

// handleInternalACRevocationSweep triggers the #1157 F5 mid-session
// revocation path on demand. It intentionally accepts no request
// body: the optional acId selector lives in the signed URL path
// (/nhp/internal/ac-revocations/sweep/:ac_id), and query strings are
// rejected like the other /nhp/internal endpoints because they are
// not part of the signing string.
func (hs *HttpServer) handleInternalACRevocationSweep(ctx *gin.Context) {
	if !hs.authorizeInternalNoBodyRequest(ctx, "internal ac-revocation sweep") {
		return
	}
	if hs.udpServer == nil {
		ctx.JSON(http.StatusServiceUnavailable, gin.H{"error": "udp server unavailable"})
		return
	}
	if !hs.udpServer.acPubkeyRevokeDropEnabled() {
		// This private/internal endpoint intentionally reports the
		// config-disabled state so rollout smoke tests and operators can
		// distinguish "strict drop path unavailable" from "swept, no drops."
		ctx.JSON(http.StatusConflict, gin.H{
			"error": "ac pubkey revoke strict mode or DynamoDB storage is not enabled",
		})
		return
	}

	var acIDs []string
	if acID := strings.TrimSpace(ctx.Param("ac_id")); acID != "" {
		acIDs = []string{acID}
	}
	stats := hs.udpServer.sweepRevokedACPubkeyConnections(
		ctx.Request.Context(),
		acIDs,
		acPubkeyRevokedConnDropSourceOnDemand,
	)
	ctx.JSON(http.StatusOK, stats)
}

func (hs *HttpServer) authorizeInternalNoBodyRequest(ctx *gin.Context, operation string) bool {
	srcIP := extractIP(ctx.Request.RemoteAddr)
	if !isPrivateIP(srcIP) {
		log.Warning("%s rejected: non-private source IP %s", operation, srcIP)
		ctx.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return false
	}
	if ctx.Request.URL.RawQuery != "" || ctx.Request.URL.Fragment != "" {
		log.Warning("%s rejected: URL must have no query or fragment (got query=%q fragment=%q)",
			operation, ctx.Request.URL.RawQuery, ctx.Request.URL.Fragment)
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return false
	}
	if ctx.Request.ContentLength != 0 {
		log.Warning("%s rejected: request body is not allowed src=%s reqID=%s content_length=%d",
			operation, srcIP, GetRequestID(ctx), ctx.Request.ContentLength)
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "body not allowed"})
		return false
	}
	if hs.internalAuthSigner == nil {
		return true
	}

	authErr := hs.internalAuthSigner.Verify(
		ctx.GetHeader(internalauth.Header),
		ctx.Request.Method,
		ctx.Request.URL.Path,
		nil,
		0,
	)
	if authErr == nil {
		if hs.internalAuthEmit != nil {
			hs.internalAuthEmit(MetricInternalAuthSuccess)
		}
		return true
	}

	stage := internalauth.ClassifyAuthFailure(authErr)
	reqID := GetRequestID(ctx)
	if hs.internalAuthRequire {
		log.Warning("%s rejected (strict): src=%s stage=%s reqID=%s", operation, srcIP, stage, reqID)
		if hs.internalAuthEmit != nil {
			hs.internalAuthEmit(MetricInternalAuthFailStrict)
		}
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": internalauth.ErrInternalAuth.Error()})
		return false
	}

	log.Info("%s permit-mode unverified (allowing through): src=%s stage=%s reqID=%s", operation, srcIP, stage, reqID)
	if hs.internalAuthEmit != nil {
		hs.internalAuthEmit(MetricInternalAuthFailPermit)
	}
	return true
}
