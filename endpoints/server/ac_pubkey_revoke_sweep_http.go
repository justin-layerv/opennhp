package server

import (
	"bytes"
	"context"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/OpenNHP/opennhp/nhp/log"
	"github.com/layervai/nhp/internalauth"
)

const maxInternalACRevocationSweepRequestSize int64 = 1 << 10 // 1 KiB

func (hs *HttpServer) handleInternalACRevocationSweep(ctx *gin.Context) {
	if !hs.authorizeInternalACRevocationSweep(ctx) {
		return
	}
	if hs.udpServer == nil {
		ctx.JSON(http.StatusServiceUnavailable, gin.H{"error": "udp server unavailable"})
		return
	}
	if !hs.udpServer.acPubkeyRevokeVerifyRequire {
		ctx.JSON(http.StatusConflict, gin.H{"error": "AC pubkey revoke strict mode disabled"})
		return
	}
	if hs.udpServer.storage == nil {
		ctx.JSON(http.StatusServiceUnavailable, gin.H{"error": "storage unavailable"})
		return
	}

	sweepCtx, cancel := context.WithTimeout(ctx.Request.Context(), defaultACPubkeyRevokeSweepInterval)
	defer cancel()
	dropped, err := hs.udpServer.dropRevokedACPubkeyConnections(sweepCtx, "on-demand")
	if err != nil {
		log.Warning("internal AC revocation sweep failed after dropping %d connection(s): %v", dropped, err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "sweep failed", "dropped": dropped})
		return
	}
	ctx.JSON(http.StatusOK, gin.H{"dropped": dropped})
}

func (hs *HttpServer) authorizeInternalACRevocationSweep(ctx *gin.Context) bool {
	srcIP := extractIP(ctx.Request.RemoteAddr)
	if !isPrivateIP(srcIP) {
		log.Warning("internal AC revocation sweep rejected: non-private source IP %s", srcIP)
		ctx.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return false
	}
	if ctx.Request.URL.RawQuery != "" || ctx.Request.URL.Fragment != "" {
		log.Warning("internal AC revocation sweep rejected: URL must have no query or fragment (got query=%q fragment=%q)",
			ctx.Request.URL.RawQuery, ctx.Request.URL.Fragment)
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return false
	}

	origBody := ctx.Request.Body
	defer origBody.Close()
	body, err := io.ReadAll(io.LimitReader(origBody, maxInternalACRevocationSweepRequestSize+1))
	if err != nil {
		log.Warning("internal AC revocation sweep: read body failed src=%s reqID=%s err=%v",
			srcIP, GetRequestID(ctx), err)
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})
		return false
	}
	if int64(len(body)) > maxInternalACRevocationSweepRequestSize {
		log.Warning("internal AC revocation sweep rejected: body over limit src=%s reqID=%s size=%d limit=%d",
			srcIP, GetRequestID(ctx), len(body), maxInternalACRevocationSweepRequestSize)
		ctx.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "body too large"})
		return false
	}
	ctx.Request.Body = io.NopCloser(bytes.NewReader(body))
	ctx.Request.ContentLength = int64(len(body))

	// This endpoint is an operator-triggered, state-mutating disconnect
	// action, not a traffic-forwarding compatibility path. Require a
	// valid HMAC signature even while the shared /nhp/internal rollout
	// gate is still in permit mode; unsigned callers can wait for the
	// periodic strict-mode sweep.
	if hs.internalAuthSigner == nil {
		log.Warning("internal AC revocation sweep rejected: internal auth signer unavailable src=%s reqID=%s", srcIP, GetRequestID(ctx))
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": internalauth.ErrInternalAuth.Error()})
		return false
	}
	authErr := hs.internalAuthSigner.Verify(
		ctx.GetHeader(internalauth.Header),
		ctx.Request.Method,
		ctx.Request.URL.Path,
		body,
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
	log.Warning("internal AC revocation sweep rejected: src=%s stage=%s reqID=%s", srcIP, stage, reqID)
	if hs.internalAuthEmit != nil {
		hs.internalAuthEmit(MetricInternalAuthFailStrict)
	}
	ctx.JSON(http.StatusUnauthorized, gin.H{"error": internalauth.ErrInternalAuth.Error()})
	return false
}
