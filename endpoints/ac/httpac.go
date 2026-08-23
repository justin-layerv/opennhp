package ac

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/log"
)

const acReadinessPath = "/nhp-ac/ready"

// defaultHTTPListenPort is the loopback TCP port nhp-acd serves plugin HTTP on
// when HttpListenPort is unset. It shares the NHP server's listen port number
// for historical reasons only — it is a localhost TCP listener with no relation
// to the UDP client edge, so it must not follow common.DefaultNHPClientPort
// (binding TCP/443 would need CAP_NET_BIND_SERVICE and collide with any local
// TLS listener).
const defaultHTTPListenPort = common.DefaultNHPPort

type HttpAC struct {
	id         string
	ua         *UdpAC
	httpServer *http.Server
	ginEngine  *gin.Engine
	listenAddr *net.TCPAddr

	wg                               sync.WaitGroup
	running                          atomic.Bool
	beforeSessionControlRefreshFence func()

	// signals
	signals struct {
		stop chan struct{}
	}
}

// Note HttpServer must be started after starting UdpAC, when log and config have been setup
func (hs *HttpAC) Start(uac *UdpAC, hc *HttpConfig) error {
	hs.id = time.Now().Format("2006-01-02 15:04:05")
	log.Info("==================================================")
	log.Info("===  HttpServer (%s) started  ===", hs.id)
	log.Info("==================================================")

	hs.ua = uac

	port := hc.HttpListenPort
	if hc.HttpListenPort == 0 {
		port = defaultHTTPListenPort
	}
	// only listen to localhost for security reason.
	hs.listenAddr = &net.TCPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: port,
	}

	hs.signals.stop = make(chan struct{})

	gin.SetMode(gin.ReleaseMode)
	hs.ginEngine = gin.New()
	hs.ginEngine.Use(gin.LoggerWithWriter(uac.log.Writer()))
	hs.ginEngine.Use(gin.Recovery())

	hs.initRouter()

	hs.httpServer = &http.Server{
		Addr:         hs.listenAddr.String(),
		Handler:      hs.ginEngine,
		ReadTimeout:  4500 * time.Millisecond,
		WriteTimeout: 4000 * time.Millisecond,
		IdleTimeout:  5000 * time.Millisecond,
	}

	hs.wg.Add(1)
	if hc.EnableTLS {
		certFilePath := filepath.Join(ExeDirPath, hc.TLSCertFile)
		keyFilePath := filepath.Join(ExeDirPath, hc.TLSKeyFile)
		_, err1 := os.Stat(certFilePath)
		_, err2 := os.Stat(keyFilePath)
		if err1 == nil && err2 == nil {
			go func() {
				defer hs.wg.Done()
				log.Info("Listening https on %s", hs.listenAddr.String())
				var err = hs.httpServer.ListenAndServeTLS(certFilePath, keyFilePath)
				if err != nil && !errors.Is(err, http.ErrServerClosed) {
					log.Error("https server close error: %v", err)
				}
			}()

			return nil
		}
	}

	go func() {
		defer hs.wg.Done()
		log.Info("Listening http on %s", hs.listenAddr.String())
		var err = hs.httpServer.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("http server close error: %v", err)
		}
	}()

	hs.running.Store(true)
	return nil
}

// Stop stops the HttpServer by setting the running flag to false,
// closing the stop channel, shutting down the underlying http server,
// waiting for all goroutines to finish, and logging a message indicating
// that the HttpServer has been stopped.
func (hs *HttpAC) Stop() {
	if !hs.running.Load() {
		// already stopped, do nothing
		return
	}

	hs.running.Store(false)
	close(hs.signals.stop)
	ctx, cancel := context.WithTimeout(context.Background(), 5500*time.Millisecond)
	_ = hs.httpServer.Shutdown(ctx)

	hs.wg.Wait()
	cancel()
	cancel = nil
	log.Info("==================================================")
	log.Info("===  HttpServer (%s) stopped  ===", hs.id)
	log.Info("==================================================")
}

func (hs *HttpAC) IsRunning() bool {
	return hs.running.Load()
}

// init gin engine. Must be called at initialization
func (ha *HttpAC) initRouter() {
	g := ha.ginEngine

	g.GET(acReadinessPath, ha.handleReadiness)

	refreshGrp := g.Group("refresh")
	refreshGrp.GET("/:token", func(ctx *gin.Context) {
		var err error
		token := ctx.Param("token")

		if len(token) == 0 {
			err = common.ErrUrlPathInvalid
			log.Error("path error: %v", err)
			ctx.JSON(http.StatusOK, gin.H{"errMsg": fmt.Sprintf("path error: %v", err)})
			return
		}

		if token, err = url.QueryUnescape(token); err != nil {
			// Do not log err: url.QueryUnescape's EscapeError echoes the
			// malformed percent-escape (1-3 token bytes), and post-1124 the
			// token is the auth secret. See #1424 and docs/SECURITY_TOKEN_TOUCH_INVENTORY.md.
			log.Error("token unescape failed: malformed percent-encoding in path")
			err = common.ErrUrlPathInvalid
			ctx.JSON(http.StatusOK, gin.H{"errMsg": fmt.Sprintf("token error: %v", err)})
			return
		}

		// Redact post-unescape: base64-StdEncoding tokens contain '+' and
		// '/' which arrive percent-encoded ('%2B' / '%2F'), so logging the
		// raw URL parameter would burn the first two characters of the
		// redaction prefix on a single base64 byte and weaken the entropy
		// budget the tokenLogPrefixLen comment commits to. Post-1124 the
		// token is the entire auth secret — see common.RedactToken.
		log.Info("get refresh request. token: %s, query: %v", common.RedactToken(token), ctx.Request.URL.RawQuery)

		req := &common.HttpRefreshRequest{
			Token: token,
			SrcIp: ctx.Query("srcip"),
		}

		ha.HandleHttpRefreshOperations(ctx, req)
	})
}

// handleReadiness backs the AC NLB health check. It proves both halves of
// admission readiness: nhp-acd has a healthy assigned-server path for receiving
// AOP fanout, and this AC boot has completed its durable session-control flush
// while holding the admission lease. That matches today's qURL fanout contract:
// handleHttpOpenResource fans the knock to assigned peer servers, and
// processACOperationBroadcast sends the AOP to every local AC connection before
// the origin ACK is released. If delivery ever becomes targeted to one AC, this
// target health check is no longer sufficient to prove a specific admission can
// land on the selected AC.
func (ha *HttpAC) handleReadiness(c *gin.Context) {
	if ha == nil || ha.ua == nil || !ha.ua.registration.hasHealthyServer() {
		c.String(http.StatusServiceUnavailable, "no healthy assigned server\n")
		return
	}
	if !ha.ua.sessionAdmissionReady() {
		c.String(http.StatusServiceUnavailable, "session admission not ready\n")
		return
	}

	c.String(http.StatusOK, "ready\n")
}

func (ha *HttpAC) HandleHttpRefreshOperations(c *gin.Context, req *common.HttpRefreshRequest) {
	if len(req.SrcIp) == 0 {
		log.Error("empty source ip")
		c.JSON(http.StatusOK, gin.H{"errMsg": "empty source ip"})
		return
	}

	netIp := net.ParseIP(req.SrcIp)
	if netIp == nil {
		log.Error("invalid source ip")
		c.JSON(http.StatusOK, gin.H{"errMsg": "invalid source ip"})
		return
	}

	buf, err := base64.StdEncoding.DecodeString(req.Token)
	if err != nil || len(buf) != 32 {
		log.Error("invalid token format")
		c.JSON(http.StatusOK, gin.H{"errMsg": "invalid token format"})
		return
	}

	entry := ha.ua.VerifyAccessToken(req.Token)
	if entry == nil {
		// Response body intentionally identical to the firewall-deadline
		// branch (~30 lines below) so a token-holder cannot distinguish
		// "this token is past the absolute deadline" from "this token is
		// inside the late-packet buffer window but past the firewall
		// deadline" — see #1960 (the cr-flagged buffer-edge oracle).
		// Operator triage stays distinguishable via the log line.
		log.Error("token verification failed")
		c.JSON(http.StatusOK, gin.H{"errMsg": "token expired"})
		return
	}
	if ha.beforeSessionControlRefreshFence != nil {
		ha.beforeSessionControlRefreshFence()
	}

	// VerifyAccessToken releases its session-control fence before returning.
	// Reacquire it and bind the pointer to current token/index membership across
	// the complete kernel mutation below. A close may have won in that narrow
	// gap; in that case the token is absent or marked closing and refresh must
	// not resurrect the stale AccessEntry after the close already converged.
	ha.ua.sessionControlFlushMu.Lock()
	defer ha.ua.sessionControlFlushMu.Unlock()
	current, currentFound := ha.ua.tokenStore.Load(req.Token)
	if !currentFound || current != entry || entry.sessionControlClosing.Load() ||
		(entry.NHPSessionId != 0 && (!ha.ua.sessionAdmissionReady() || ha.ua.nhpSessions == nil ||
			!ha.ua.nhpSessions.containsExactToken(req.Token, entry) || !ha.ua.nhpSessions.admitsSession(entry))) {
		log.Error("token lost session-control membership before refresh")
		c.JSON(http.StatusOK, gin.H{"errMsg": "token expired"})
		return
	}

	// Cap re-issued firewall window at the absolute deadline (#1942); 0 =
	// refuse re-open. Residual at small remainingSec: ipset.Add inside
	// HandleAccessControl uses remainingSec as a relative timeout, so any
	// Go-level latency between this call and the kernel-level Add overshoots
	// FirstKnockTime+OpenTime. <100ms in practice, swamped by
	// truncate-toward-zero at OpenTime>buffer; visible only at the
	// qurl-service#498 self-destruct floor (OpenTime=1), where the
	// degenerate-floor test already documents the session as effectively
	// un-refreshable. A strict-ceiling fix would thread the deadline through
	// HandleAccessControl — not done here.
	remainingSec := entry.RemainingFirewallSeconds()
	if remainingSec <= 0 {
		// src_ip + user_id only — token is intentionally omitted (post-#1124
		// the token is the entire auth secret). nil-guard the User deref:
		// every issue path populates User, but a security log line on a
		// rare deny branch panicking via gin.Recovery would mask exactly
		// the failure operators need to triage.
		userID := "<unknown>"
		if entry.User != nil {
			userID = entry.User.UserId
		}
		log.Error("firewall deadline passed; refusing extension (src_ip=%s user_id=%s)", req.SrcIp, userID)
		// Drop scheduler entries whose kernel rule already expired
		// naturally — without this Cancel, processEntry fires Flush on
		// gone state, inflating metricFlushTotal and exposing the
		// breaker. tokenStore.Delete is intentionally NOT called here;
		// CleanExpired's sweep (which fires the same OnExpire hook +
		// silent re-Cancels these tuples) remains the canonical
		// removal path. A future caller that adds Delete from this
		// branch must also fire the hook (or extend TokenStore.Delete
		// to do so) — see cancelAllScheduledFlows godoc for the
		// multi-session and NAT'd-temp-access caveats.
		ha.ua.cancelAllScheduledFlows(entry)
		c.JSON(http.StatusOK, gin.H{"errMsg": "token expired"})
		return
	}

	var found bool
	var newSrcAddr *common.NetAddress
	for _, addr := range entry.SrcAddrs {
		if addr.Ip == req.SrcIp {
			found = true
			break
		}
	}
	if !found {
		newSrcAddr = &common.NetAddress{
			Ip:       req.SrcIp,
			Port:     entry.SrcAddrs[0].Port,
			Protocol: entry.SrcAddrs[0].Protocol,
		}
		// Pre-existing unbounded slice-append race; tracked in #1951.
		//
		// TEST FIXTURE NOTE (#2209): the cancel path
		// (cancelAllScheduledFlows + latestOtherFirewallDeadline)
		// currently reads only entry.firewallDeadline() (immutable
		// FirstKnockTime + OpenTime) and entry.holdsScheduledKey
		// (RWMutex-guarded). Neither touches SrcAddrs, so this in-
		// place append is benign for the L3-flush walk today. PR
		// #2209 widened the surface (refresh now threads the same
		// *AccessEntry into HandleAccessControl while it's in the
		// Snapshot pool); a future cancel-path change that starts
		// reading SrcAddrs makes #1951's fix (copy-then-append +
		// atomic pointer, or e.mu protection) load-bearing.
		entry.SrcAddrs = append(entry.SrcAddrs, newSrcAddr)
	}

	// Pass entry (not the decomposed fields) so scheduleFlushIfEnabled
	// inside HandleAccessControl records new FlowKeys on the same
	// tokenStore-resident entry. When that entry's OnExpire later fires,
	// cancelAllScheduledFlows drains the union of admission + refresh
	// schedules. #2201/#2205.
	_, err = ha.ua.HandleAccessControl(entry, remainingSec, nil)
	if err != nil {
		log.Error("HandleAccessControl failed: %v", err)
		c.JSON(http.StatusOK, gin.H{"errMsg": err.Error()})
		return
	}

	c.JSON(http.StatusOK, entry)
}
