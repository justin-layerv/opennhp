package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"

	"github.com/OpenNHP/opennhp/endpoints/server/health"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/log"
	"github.com/OpenNHP/opennhp/nhp/plugins"
	"github.com/OpenNHP/opennhp/nhp/version"
	"github.com/layervai/nhp/internalauth"
)

type HttpServer struct {
	id         string
	udpServer  *UdpServer
	httpServer *http.Server
	ginEngine  *gin.Engine
	listenAddr *net.TCPAddr
	// tlsEnabled records the protocol of the listener actually launched by
	// Start. It deliberately does not follow later httpConfig replacement while
	// updateHttpConfig leaves an already-running listener in place.
	tlsEnabled    bool
	healthManager *health.Manager
	knockManager  *health.Manager // includes AC peer check for knock-traffic readiness

	// internalAuthSigner and internalAuthRequire together specify the
	// internal-auth rollout state for rollout-gated /nhp/internal
	// handlers. Permanently strict handlers such as
	// /nhp/internal/ac-revocations/sweep require a signer regardless of
	// internalAuthRequire. Both fields are set
	// once in Start before request serving begins and read concurrently
	// by request-handler goroutines thereafter. The happens-before edge
	// is the `go func(){ ListenAndServe() }()` launch in Start — the
	// Go memory model guarantees that every write sequenced before a
	// `go` statement is visible to the launched goroutine, so the
	// field writes at the top of Start synchronize-with every handler
	// invocation the server dispatches afterwards. `running.Store(true)`
	// at the bottom of Start is a ready-probe signal for Stop(), not
	// the synchronization primitive for these fields.
	//
	// Three effective modes:
	//   signer == nil              → legacy (source-IP gate only)
	//   signer != nil, require=false → permit (verify + warn + allow)
	//   signer != nil, require=true  → strict (verify + reject unsigned)
	// Permanently strict handlers skip legacy/permit behavior.
	// The {signer=nil, require=true} combo is unreachable — Start only
	// reads internalAuthRequire when a signer was constructed successfully
	// — but even if it were reached, handleInternalKnock short-circuits
	// on the signer==nil check before consulting require.
	internalAuthSigner  *internalauth.Signer
	internalAuthRequire bool
	// internalAuthEmit is the counter-emit callback for internal
	// auth rollout metrics. In production it's bound to
	// us.metrics.IncrCounter at Start time; tests plumb a capturing
	// function to assert increment counts without spinning up a real
	// metrics Publisher. Nil is fine (no-op).
	internalAuthEmit MetricCounter

	// forwardHopRequire is the strict/permit toggle for cross-server
	// hop attestation (issue #1127), read once from
	// NHP_INTERNAL_FORWARD_ATTEST_REQUIRE at Start. false (permit) warns
	// and allows an unverifiable hop during rollout; true (strict)
	// rejects it. Verification itself is only attempted in cloud mode
	// (device + Cloud Map present) — see hopVerifyEcdh. Same
	// happens-before edge as internalAuthRequire (Start → goroutine).
	forwardHopRequire bool

	// fleetTrust is the hop-attestation trust anchor (the sticky set of
	// fleet pubkeys trusted as forward senders). nil when verification is
	// inactive (legacy/local mode, no device or Cloud Map). Constructed in
	// Start; tests construct one with an injected discovery source + clock.
	// See fleetTrustAnchor in forward_hop_attest.go.
	fleetTrust *fleetTrustAnchor

	wg      sync.WaitGroup
	running atomic.Bool

	// signals
	signals struct {
		stop chan struct{}
	}
}

func (hs *HttpServer) installHTTPMiddleware(store sessions.Store, corsOrigins []string, logOutput io.Writer) {
	hs.ginEngine.Use(requestIDMiddleware())
	hs.ginEngine.Use(sessions.Sessions("nhpsessions", store))
	hs.ginEngine.Use(securityHeadersMiddleware())
	// Do not add response-compression middleware without updating
	// /nhp/internal/token/validate response auth; its signature covers the
	// exact JSON bytes written by ctx.Data.
	hs.ginEngine.Use(corsMiddleware(corsOrigins))
	hs.ginEngine.Use(gin.LoggerWithConfig(gin.LoggerConfig{
		Output:    logOutput,
		Formatter: ginLogFormatter,
	}))
	hs.ginEngine.Use(gin.Recovery())
}

// Note HttpServer must be started after starting UdpServer, when log and config have been setup
func (hs *HttpServer) Start(us *UdpServer, hc *HttpConfig) error {
	hs.id = time.Now().Format("2006-01-02 15:04:05")
	log.Info("==================================================")
	log.Info("===  HttpServer (%s) started  ===", hs.id)
	log.Info("==================================================")

	hs.udpServer = us

	ipStr := hc.HttpListenIp
	var netIP net.IP
	if len(ipStr) > 0 {
		netIP = net.ParseIP(ipStr)
		if netIP == nil {
			log.Error("http listen ip address is incorrect! using udp listening ip")
			netIP = us.listenAddr.IP
		}
	} else {
		netIP = net.IPv4zero // will both listen on ipv4 0.0.0.0:port and ipv6 [::]:port
	}

	listenPort := us.listenAddr.Port // use the same port as udp server if HttpListenPort is not specified
	if hc.HttpListenPort > 0 && hc.HttpListenPort < 65536 {
		listenPort = hc.HttpListenPort
	}
	hs.listenAddr = &net.TCPAddr{
		IP:   netIP,
		Port: listenPort,
	}

	hs.signals.stop = make(chan struct{})

	gin.SetMode(gin.ReleaseMode)
	hs.ginEngine = gin.New()

	// Configure trusted proxies for correct client IP via X-Forwarded-For.
	// - With CloudFront: trust origin-facing CIDRs → extract real client IP
	// - Without CloudFront: trust nobody → use RemoteAddr (NLB-preserved source IP)
	// This also fixes a pre-existing issue: Gin v1.11 trusts ALL proxies by default,
	// allowing X-Forwarded-For spoofing on plugin and internal HTTP routes.
	// Those routes use ClientIP for source gates, audit attribution, and plugin
	// authentication inputs, so fail loudly rather than trusting Gin's default.
	if validCIDRs := parseTrustedCIDRs(os.Getenv("NHP_TRUSTED_PROXY_CIDRS")); len(validCIDRs) > 0 {
		if err := hs.ginEngine.SetTrustedProxies(validCIDRs); err != nil {
			return fmt.Errorf("failed to set trusted proxies: %w", err)
		}
		log.Info("Trusted proxies configured with %d CIDRs (first: %s)", len(validCIDRs), validCIDRs[0])
	} else {
		// SetTrustedProxies(nil) returns nil today (gin v1.11), but
		// don't rely on that — a future gin bump could change it, and
		// trusting all proxies silently is the failure mode the whole
		// block exists to prevent.
		if err := hs.ginEngine.SetTrustedProxies(nil); err != nil {
			return fmt.Errorf("failed to clear trusted proxies (no NHP_TRUSTED_PROXY_CIDRS set): %w", err)
		}
	}

	// Internal service auth for /nhp/internal/*. Three modes:
	//   secret unset                         → legacy (no verification)
	//   secret set, require unset/false      → permit (verify + warn)
	//   secret set, require=true             → strict (verify + reject)
	// Rollout order is secret-first-on-both-services (nhp-server and
	// qurl-service), confirm no permit-mode warn logs, then flip
	// require=true. Ship permit as default so the first deploy of
	// either side doesn't break the other.
	signer, require, mode, authCfgErr := loadInternalAuthConfig(
		os.Getenv("NHP_INTERNAL_AUTH_SECRET"),
		os.Getenv("NHP_INTERNAL_AUTH_REQUIRE"),
	)
	if authCfgErr != nil {
		return authCfgErr
	}
	hs.internalAuthSigner = signer
	hs.internalAuthRequire = require
	switch mode {
	case "legacy":
		log.Warning("NHP_INTERNAL_AUTH_SECRET unset — /nhp/internal/* uses the RFC-1918 source-IP check only (legacy mode)")
	default:
		// "strict" / "permit" — line up with the rest of the operator-visible
		// surface: "strict" matches MetricInternalAuthFailStrict, the
		// reject-path log line ("rejected (strict)"), and the PR docs.
		// "permit" matches MetricInternalAuthFailPermit and the warn-
		// path log. Operators grep one token across logs + metrics.
		log.Info("internal auth enabled (mode=%s)", mode)
	}

	// Cross-server hop attestation gate (issue #1127). Independent of the
	// shared-secret gate above: it binds each server-to-server forward to
	// the forwarding server's NHP identity. Same permit→strict rollout
	// discipline — ship permit so a mixed-version fleet keeps forwarding,
	// confirm ForwardHopAttestPermit drops to zero, then flip
	// NHP_INTERNAL_FORWARD_ATTEST_REQUIRE=true. Verification only runs in
	// cloud mode (device + Cloud Map present); the parsed value is inert
	// otherwise.
	//
	// Kept as a separate gate (not unified with the shared-secret gate)
	// deliberately: the two protect the same endpoint but with different
	// trust models — a fleet-wide shared secret vs. per-pair ECDH identity
	// — and roll out on independent env flags so one can flip to strict
	// without the other. A premature "rollout gate" abstraction over two
	// instances would couple their lifecycles; revisit if a third gate
	// appears.
	forwardHopRequire, fhErr := parsePermitStrictEnv(os.Getenv("NHP_INTERNAL_FORWARD_ATTEST_REQUIRE"))
	if fhErr != nil {
		return fmt.Errorf("NHP_INTERNAL_FORWARD_ATTEST_REQUIRE: %w", fhErr)
	}
	hs.forwardHopRequire = forwardHopRequire

	cookieKeys, err := parseCookieKeys(os.Getenv("NHP_COOKIE_KEYS"))
	if err != nil {
		return fmt.Errorf("NHP_COOKIE_KEYS: %w", err)
	}
	store := cookie.NewStore(cookieKeys...)
	corsOrigins := parseAllowedOrigins(os.Getenv("NHP_CORS_ALLOWED_ORIGINS"))
	hs.installHTTPMiddleware(store, corsOrigins, us.log.Writer())

	// Initialize health check manager (fail-fast if no storage backend)
	if err := hs.initHealthManager(); err != nil {
		return err
	}

	// Bind the internal-auth metric emitter now that udpServer is plumbed.
	// Nil-safe: handleInternalKnock guards on hs.internalAuthEmit == nil.
	if us.metrics != nil {
		hs.internalAuthEmit = us.metrics.IncrCounter
	}

	// Build the receiver trust anchor for legacy internal-HTTP hop attestation.
	// The direct HTTP admission/forwarding sender is retired, but verifying an
	// inbound envelope remains fail-closed during rollout overlap.
	hs.initForwardHopAttestation(us)

	hs.initRouter()

	hs.httpServer = &http.Server{
		Addr:    hs.listenAddr.String(),
		Handler: hs.ginEngine,
		// ReadHeaderTimeout caps the slowloris-headers attack surface
		// independently of ReadTimeout. With ReadTimeout=30s (sized for
		// slow client *body* uploads under degraded networks), an attacker
		// trickling headers byte-by-byte could otherwise hold a socket for
		// the full 30s. 5s is well above any legitimate cross-region
		// header-write RTT × overhead and short enough to evict slow
		// readers promptly. Defaults to ReadTimeout when unset, which
		// would defeat the point.
		//
		// Intentionally NOT exposed via http.toml. The right value is
		// the same everywhere; making it tunable would invite the wrong
		// knob being turned (operator looking to lengthen ReadTimeout
		// shouldn't accidentally also widen the slowloris window).
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       time.Duration(hc.ReadTimeoutMs) * time.Millisecond,
		WriteTimeout:      time.Duration(hc.WriteTimeoutMs) * time.Millisecond,
		IdleTimeout:       time.Duration(hc.IdleTimeoutMs) * time.Millisecond,
	}

	hs.wg.Add(1)
	hs.tlsEnabled = false
	if hc.EnableTLS {
		certFilePath := filepath.Join(ExeDirPath, hc.TLSCertFile)
		keyFilePath := filepath.Join(ExeDirPath, hc.TLSKeyFile)
		_, err1 := os.Stat(certFilePath)
		_, err2 := os.Stat(keyFilePath)
		if err1 == nil && err2 == nil {
			hs.tlsEnabled = true
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

	// Warm the startup probe. The health manager's startupReady flag is
	// only flipped from inside CheckStartup when readiness comes back
	// healthy, and after StartupTimeout elapses CheckStartup short-circuits
	// to 503 forever without running the probes. Without an in-process
	// warmer, /health/startup never reaches a healthy state because the
	// first external call typically arrives after the 60s grace window.
	// Closes #1011.
	//
	// Add to WaitGroup BEFORE flipping running=true to avoid a race where
	// Stop() observes running=true, calls wg.Wait() with the counter still
	// zero, and the warmer's wg.Add(1) lands concurrently with Wait —
	// sync.WaitGroup documents that combination as misuse and may panic.
	// Same ordering as the http-server goroutine wg.Add(1) earlier in Start.
	hs.wg.Add(1)
	go hs.warmStartupProbe()

	hs.running.Store(true)
	return nil
}

// Startup warmer cadence. Tick interval is fast enough that a healthy
// server flips ready well before any external prober's first call;
// per-probe timeout bounds the storage check (etcd / DynamoDB) latency
// independently of the outer StartupTimeout deadline.
const (
	startupWarmerTickInterval = 2 * time.Second
	startupWarmerProbeTimeout = 5 * time.Second
)

// warmStartupProbe polls CheckStartup on the main healthManager every
// startupWarmerTickInterval during the StartupTimeout window so that the
// readiness probes have a chance to flip startupReady. Returns once startup
// is marked complete, the deadline passes, or shutdown fires. Knock
// readiness has its own gating via the AC peer checker on knockManager, so
// we deliberately do NOT warm that one — it must stay failing until ACs
// actually connect.
//
// healthManager is guaranteed non-nil here: Start() calls initHealthManager
// (which always assigns it) before spawning the warmer goroutine, and
// returns early if init failed.
func (hs *HttpServer) warmStartupProbe() {
	defer hs.wg.Done()

	// Probe context derives from a parent that's canceled on shutdown,
	// so a Stop() landing mid-probe propagates immediately into the in-
	// flight CheckStartup instead of waiting up to startupWarmerProbeTimeout.
	probeCtx, cancelProbeCtx := context.WithCancel(context.Background())
	defer cancelProbeCtx()
	go func() {
		select {
		case <-hs.signals.stop:
			cancelProbeCtx()
		case <-probeCtx.Done():
		}
	}()

	timeout := hs.healthManager.StartupTimeout()
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(startupWarmerTickInterval)
	defer ticker.Stop()

	// First probe immediately so a fast-booting server doesn't wait the
	// full tick interval before flipping ready.
	if hs.checkStartupOnce(probeCtx) {
		log.Info("Startup probe complete on first check")
		return
	}

	for {
		select {
		case <-hs.signals.stop:
			return
		case <-ticker.C:
			// Check the deadline before probing: once `Manager.startedAt +
			// startupTimeout` has elapsed, CheckStartup short-circuits to
			// 503 unconditionally (health.go: CheckStartupWithRequestID),
			// so a post-deadline probe is wasted work that doesn't change
			// the warmer's outcome.
			if time.Now().After(deadline) {
				log.Warning("Startup probe did not become healthy within %v; /health/startup will return 503 until next process restart", timeout)
				return
			}
			if hs.checkStartupOnce(probeCtx) {
				log.Info("Startup probe complete")
				return
			}
		}
	}
}

// checkStartupOnce runs CheckStartup with a bounded context and returns
// whether startup is now marked complete. The CheckStartup return is
// intentionally discarded — its side effect (flipping startupReady when
// readiness comes back healthy) is what we care about; IsStartupComplete
// reads the resulting flag.
func (hs *HttpServer) checkStartupOnce(parent context.Context) bool {
	if hs.healthManager.IsStartupComplete() {
		return true
	}
	ctx, cancel := context.WithTimeout(parent, startupWarmerProbeTimeout)
	defer cancel()
	_ = hs.healthManager.CheckStartup(ctx)
	return hs.healthManager.IsStartupComplete()
}

// Stop stops the HttpServer by setting the running flag to false,
// closing the stop channel, shutting down the underlying http server,
// waiting for all goroutines to finish, and logging a message indicating
// that the HttpServer has been stopped.
func (hs *HttpServer) Stop() {
	if !hs.running.Load() {
		// already stopped, do nothing
		return
	}

	hs.running.Store(false)
	close(hs.signals.stop)
	ctx, cancel := context.WithTimeout(context.Background(), 5500*time.Millisecond)
	defer cancel() // Always cancel context to release resources
	_ = hs.httpServer.Shutdown(ctx)

	hs.wg.Wait()
	log.Info("==================================================")
	log.Info("===  HttpServer (%s) stopped  ===", hs.id)
	log.Info("==================================================")
}

func (hs *HttpServer) IsRunning() bool {
	return hs.running.Load()
}

// ErrNoStorageBackend is returned when the server starts without a configured storage backend.
var ErrNoStorageBackend = errors.New("no storage backend configured (etcd or DynamoDB required)")

// initHealthManager initializes the health check manager with appropriate checkers.
// In non-cloud mode (etcd backend), registers an etcd checker.
// In cloud mode (DynamoDB backend), registers a DynamoDB checker.
//
// Returns an error if no storage backend is configured (fail-fast).
//
// Health check timeouts can be configured via environment variables:
// - HEALTH_CHECK_TIMEOUT_SECONDS: Timeout for individual checks (default: 10)
// - HEALTH_STARTUP_TIMEOUT_SECONDS: Startup probe timeout (default: 60)
func (hs *HttpServer) initHealthManager() error {
	// Default timeouts
	timeout := 10 * time.Second
	startupTimeout := 60 * time.Second

	// Allow override via environment variables
	if envTimeout := os.Getenv("HEALTH_CHECK_TIMEOUT_SECONDS"); envTimeout != "" {
		if seconds, err := strconv.Atoi(envTimeout); err == nil && seconds > 0 {
			timeout = time.Duration(seconds) * time.Second
			log.Info("Health check timeout configured: %v", timeout)
		}
	}
	if envStartup := os.Getenv("HEALTH_STARTUP_TIMEOUT_SECONDS"); envStartup != "" {
		if seconds, err := strconv.Atoi(envStartup); err == nil && seconds > 0 {
			startupTimeout = time.Duration(seconds) * time.Second
			log.Info("Health check startup timeout configured: %v", startupTimeout)
		}
	}

	managerCfg := &health.ManagerConfig{
		Service:        "nhp-server",
		Version:        version.Version,
		Timeout:        timeout,
		StartupTimeout: startupTimeout,
	}
	hs.healthManager = health.NewManager(managerCfg)

	backendName := hs.udpServer.GetStorageBackendName()

	// Create knock readiness manager — includes AC peer check for NLB knock-traffic routing.
	// Separate from the main healthManager so /health/ready (used by ASG/Docker) doesn't
	// mark servers unhealthy just because ACs haven't connected yet.
	hs.knockManager = health.NewManager(managerCfg)

	// AC peer checker — critical for knock readiness, not registered on the main manager.
	// Grace period from Config.ACPeerGracePeriodSeconds absorbs single-keepalive-cycle
	// flickers (see ACPeerChecker doc); zero/unset uses the package default.
	// acPeerGracePeriodFromConfig clamps into [Min, Max] and warns on clamp.
	acGrace := acPeerGracePeriodFromConfig(hs.udpServer.config.ACPeerGracePeriodSeconds, log.Warning)
	// MetricACGraceAbsorbed fires once per grace-window pass so operators
	// can separate "debounce is absorbing single-keepalive flickers"
	// (rollout healthy) from "AC cluster is actually broken and the grace
	// window is hiding it" (page oncall — pair with KnockNoAC trend).
	// Nil-safe if metrics is unplumbed (tests).
	var onGraceAbsorbed func()
	if hs.udpServer.metrics != nil {
		onGraceAbsorbed = func() {
			hs.udpServer.metrics.IncrCounter(MetricACGraceAbsorbed)
		}
	}
	acChecker := health.NewACPeerChecker(&health.ACPeerCheckerConfig{
		Counter:         hs.udpServer,
		GracePeriod:     acGrace,
		OnGraceAbsorbed: onGraceAbsorbed,
	})
	hs.knockManager.Register(acChecker)
	// Log the effective value — clamp/disabled/default handling may have
	// adjusted the configured input, so the runtime-truth source is the
	// checker itself, not the config int.
	log.Info("Health check: AC peer checker registered on knock-ready endpoint (grace=%s)",
		formatGraceLabel(acChecker.GracePeriod()))

	// Publish ACPeerCount gauge every flush interval for CloudWatch monitoring.
	hs.udpServer.metrics.RegisterGaugeFunc(MetricACPeerCount, func() float64 {
		return float64(hs.udpServer.ACPeerCount())
	})

	// Publish multi-AC broadcast gauges (issue #376).
	hs.udpServer.metrics.RegisterGaugeFunc(MetricACConnsPerID, func() float64 {
		return float64(hs.udpServer.MaxACConnsForAnyID())
	})
	hs.udpServer.metrics.RegisterGaugeFunc(MetricTotalACConns, func() float64 {
		return float64(hs.udpServer.TotalACConns())
	})

	// Register etcd health checker for non-cloud mode
	if pinger := hs.udpServer.GetEtcdPinger(); pinger != nil {
		etcdChecker := health.NewEtcdChecker(&health.EtcdCheckerConfig{
			Client:  pinger,
			Timeout: 5 * time.Second,
		})
		hs.healthManager.Register(etcdChecker)
		hs.knockManager.Register(etcdChecker)
		// Wire storage health probe into metrics publisher for StorageHealthy metric
		hs.udpServer.metrics.SetHealthProbe(func(ctx context.Context) bool {
			return pinger.Ping(ctx) == nil
		})
		log.Info("Health check: etcd checker registered (storage backend: %s)", backendName)
		return nil
	}

	// Register DynamoDB health checker for cloud mode
	if pinger := hs.udpServer.GetDynamoDBPinger(); pinger != nil {
		dynamoChecker := health.NewDynamoDBChecker(&health.DynamoDBCheckerConfig{
			Client:  pinger,
			Timeout: 5 * time.Second,
		})
		hs.healthManager.Register(dynamoChecker)
		hs.knockManager.Register(dynamoChecker)
		// Wire storage health probe into metrics publisher for StorageHealthy metric
		hs.udpServer.metrics.SetHealthProbe(func(ctx context.Context) bool {
			return pinger.Ping(ctx) == nil
		})
		log.Info("Health check: DynamoDB checker registered (storage backend: %s)", backendName)
		return nil
	}

	// Fail-fast: no storage backend means the server cannot function properly
	log.Error("Health check: no storage checker registered (storage backend: %s) - server cannot start without storage", backendName)
	return ErrNoStorageBackend
}

// acPeerGracePeriodFromConfig maps Config.ACPeerGracePeriodSeconds to
// the duration passed into health.ACPeerCheckerConfig.GracePeriod. The
// checker honors the tri-valued semantic on its input (0 → default, <0
// → disabled, >0 → as-is); this function owns the operator-safety
// clamp into [health.MinACPeerGracePeriod, health.MaxACPeerGracePeriod]
// and logs a warning on clamp so misconfigurations surface at boot.
//
//   - configSeconds == 0               → 0 (checker picks DefaultACPeerGracePeriod)
//   - configSeconds  < 0               → -time.Second (checker treats as disabled)
//   - 0 < val < Min                    → clamped up to Min, warn
//   - Min <= val <= Max                → as-is
//   - val > Max                        → clamped down to Max, warn
//
// logf receives the warning; pass nil to suppress (tests).
func acPeerGracePeriodFromConfig(configSeconds int, logf func(string, ...any)) time.Duration {
	if configSeconds == 0 {
		return 0 // checker picks DefaultACPeerGracePeriod
	}
	if configSeconds < 0 {
		// Any negative signals disabled. Normalize to -1s so the checker
		// sees a consistent sentinel; tests can assert this exact value
		// when they need to verify "disabled was requested."
		return -time.Second
	}
	// Overflow guard: time.Duration is int64 nanoseconds, so values above
	// MaxInt64 / 1e9 (~9.2e9 seconds, ~292 years) wrap to negative when
	// multiplied. Without this, the wrapped value would fall through to the
	// "below floor" branch and emit a misleading warning, instead of
	// surfacing the actual problem (malformed / fat-fingered config).
	const maxSafeSeconds = int(math.MaxInt64 / int64(time.Second))
	if configSeconds > maxSafeSeconds {
		if logf != nil {
			logf("Config.ACPeerGracePeriodSeconds=%d overflows time.Duration (max safe value is %d seconds); clamped to %s",
				configSeconds, maxSafeSeconds, health.MaxACPeerGracePeriod)
		}
		return health.MaxACPeerGracePeriod
	}
	d := time.Duration(configSeconds) * time.Second
	switch {
	case d < health.MinACPeerGracePeriod:
		if logf != nil {
			logf("Config.ACPeerGracePeriodSeconds=%d below floor %s, clamped to %s",
				configSeconds, health.MinACPeerGracePeriod, health.MinACPeerGracePeriod)
		}
		return health.MinACPeerGracePeriod
	case d > health.MaxACPeerGracePeriod:
		if logf != nil {
			logf("Config.ACPeerGracePeriodSeconds=%d above ceiling %s, clamped to %s",
				configSeconds, health.MaxACPeerGracePeriod, health.MaxACPeerGracePeriod)
		}
		return health.MaxACPeerGracePeriod
	default:
		return d
	}
}

// formatGraceLabel renders the effective grace window for the boot log.
// Reads the checker's actual value rather than reformatting the config
// input so label and behavior can't diverge.
func formatGraceLabel(d time.Duration) string {
	if d == 0 {
		return "disabled"
	}
	return d.String()
}

// LoadFilesRecursively loads HTML and template files recursively from the specified directory and adds them to the given gin.Engine.
// It walks through the directory and its subdirectories, and for each file with a .html or .tmpl extension, it reads the file content,
// creates a new template with the file path as the template name, and parses the content into the template.
// The loaded templates are set as the HTML templates for the gin.Engine.
// The directory path should be a clean absolute path.
// If any error occurs during the file loading or template parsing, the function returns the error.
func LoadFilesRecursively(g *gin.Engine, dir string) {
	_, err := os.Stat(dir)
	if os.IsNotExist(err) {
		// dir does not exist
		return
	}

	cleanRootDir := filepath.Clean(dir)
	rootTmpl := template.New("").Funcs(g.FuncMap)
	f := os.DirFS(cleanRootDir)

	err = fs.WalkDir(f, ".", func(path string, info fs.DirEntry, walkErr error) error {
		// add *.html and *.tmpl files
		if !info.IsDir() && (strings.HasSuffix(path, ".html") || strings.HasSuffix(path, ".tmpl")) {
			if walkErr != nil {
				return walkErr
			}

			absPath := filepath.Join(cleanRootDir, path)
			content, err := os.ReadFile(absPath)
			if err != nil {
				return err
			}

			t := rootTmpl.New(path) // template name is relative path separated by slash on all platforms
			_, err = t.Parse(string(content))
			if err != nil {
				return err
			}
			log.Info("gin load file %s from %s", path, cleanRootDir)
			g.SetHTMLTemplate(t)
		}

		return nil
	})

	if err != nil {
		log.Error("load files to web engine failed. %v", err)
		return
	}
}

// init gin engine. Must be called at initialization
func (hs *HttpServer) initRouter() {
	g := hs.ginEngine

	// Register health check endpoints (internal use only - VPC restricted by security group)
	// These endpoints are used by:
	// - NLB target group health checks
	// - Container orchestration (Docker/ECS)
	// - Internal monitoring systems
	if hs.healthManager != nil {
		healthHandler := health.NewHandler(hs.healthManager)
		if hs.knockManager != nil {
			healthHandler.SetKnockManager(hs.knockManager)
		}
		healthHandler.RegisterRoutes(g)
		log.Info("Health check endpoints registered: /health, /health/live, /health/ready, /health/knock-ready, /health/startup")
	}

	// load templates. won't trigger panic if file does not exist
	staticPath := filepath.Join(ExeDirPath, "static")
	LoadFilesRecursively(g, staticPath)
	templatePath := filepath.Join(ExeDirPath, "templates")
	LoadFilesRecursively(g, templatePath)

	pluginGrp := g.Group("plugins")
	pluginGrp.Use(pluginBodySizeMiddleware(maxPluginRequestSize))
	// Plugin handler supports both GET (legacy, deprecated) and POST (preferred).
	// POST keeps the access token out of URL query strings and server access logs.
	pluginHandler := func(ctx *gin.Context) {
		var err error
		aspId := ctx.Param("aspid")
		log.Info("plugins request. aspId: %s, method: %s, query: %v", aspId, ctx.Request.Method, redactSensitiveQuery(ctx.Request.URL.RawQuery))

		if len(aspId) == 0 {
			err = common.ErrUrlPathInvalid
			log.Error("path error: %v", err)
			ctx.JSON(http.StatusOK, gin.H{"errMsg": fmt.Sprintf("path error: %v", err)})
			return
		}

		req := &common.HttpKnockRequest{
			AuthServiceId: aspId,
			DeviceId:      ctx.Request.UserAgent(),
			SrcIp:         ctx.ClientIP(),
			Url:           ctx.Request.URL,
		}

		hs.authWithAspPlugin(ctx, req)
	}
	pluginGrp.GET("/:aspid", pluginHandler)
	pluginGrp.POST("/:aspid", pluginHandler)

	// legacy api
	pluginGrp.GET("/:aspid/:resid/valid", func(ctx *gin.Context) {
		// parse url parameters
		aspId := ctx.Param("aspid")
		resId := ctx.Param("resid")
		log.Info("get plugins request. aspId: %s, resId: %s, query: %v", aspId, resId, redactSensitiveQuery(ctx.Request.URL.RawQuery))

		if len(aspId) == 0 {
			log.Error("no aspId provided")
			ctx.JSON(http.StatusOK, gin.H{"errMsg": "no aspId provided"})
			return
		}

		if len(resId) == 0 {
			log.Error("no resId provided")
			ctx.JSON(http.StatusOK, gin.H{"errMsg": "no resId provided"})
			return
		}

		req := &common.HttpKnockRequest{
			AuthServiceId: aspId,
			ResourceId:    resId,
			DeviceId:      ctx.Request.UserAgent(),
			SrcIp:         ctx.ClientIP(),
			Url:           ctx.Request.URL,
		}
		hs.authWithAspPlugin(ctx, req)
	})

	// Internal endpoints (VPC-only, RFC 1918 source IP check + HMAC).
	// /knock        — forwards a knock to the assigned server
	// /token/validate — validates an AC-issued knock token (PR-2b);
	//                   used by tunnel-server PR-2c to verify the
	//                   knock token attached to FRP login Metas.
	//                   Wire-shape note: the request body field is
	//                   `agent_run_id`, the response field is `run_id`
	//                   (correlation key the tunnel-server may merge
	//                   with its own run_id sources). The asymmetry
	//                   is documented on internalTokenValidateResponse.RunID
	//                   — readers chasing wireshark/log captures
	//                   should expect both names.
	nhpInternal := g.Group("/nhp/internal")
	nhpInternal.POST("/knock", hs.handleInternalKnock)
	nhpInternal.POST("/agent-sessions/close", hs.handleInternalAgentSessionClose)
	nhpInternal.POST("/agent-sessions/close-exact", hs.handleInternalExactSessionClose)
	nhpInternal.POST("/token/validate", hs.handleInternalTokenValidate)
	nhpInternal.POST("/ac-revocations/sweep", hs.handleInternalACRevocationSweep)
	nhpInternal.POST("/ac-revocations/sweep/:ac_id", hs.handleInternalACRevocationSweep)
	nhpInternal.POST("/revocation", hs.handleInternalRevocation)

	hs.initStorageRouter()

	hs.initKbsRouter()
}

// cookieKeySet represents a pair of cookie signing/encryption keys.
// Gorilla securecookie uses auth_key for HMAC-SHA256 and encrypt_key for AES-256.
type cookieKeySet struct {
	AuthKey    string `json:"auth_key"` //nolint:gosec // G117: JSON tag required — deserialized from Secrets Manager, never marshaled out
	EncryptKey string `json:"encrypt_key"`
}

// cookieKeysConfig is the JSON structure stored in Secrets Manager.
// Current keys are used for writing new cookies. Previous keys (if present)
// are used for reading only, enabling graceful key rotation without
// invalidating active sessions during rolling deployments.
type cookieKeysConfig struct {
	Current  cookieKeySet  `json:"current"`
	Previous *cookieKeySet `json:"previous,omitempty"`
}

// parseCookieKeys decodes a base64-encoded JSON string containing cookie session
// keys and returns them in the order expected by gorilla/sessions cookie.NewStore:
// [currentAuth, currentEncrypt, previousAuth, previousEncrypt]
func parseCookieKeys(raw string) ([][]byte, error) {
	if raw == "" {
		return nil, errors.New("environment variable is required")
	}

	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid base64: %w", err)
	}

	var cfg cookieKeysConfig
	if err := json.Unmarshal(decoded, &cfg); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	if cfg.Current.AuthKey == "" || cfg.Current.EncryptKey == "" {
		return nil, errors.New("current.auth_key and current.encrypt_key are required")
	}

	if err := validateKeyLengths("current", cfg.Current); err != nil {
		return nil, err
	}

	keys := [][]byte{
		[]byte(cfg.Current.AuthKey),
		[]byte(cfg.Current.EncryptKey),
	}

	if cfg.Previous != nil && cfg.Previous.AuthKey != "" && cfg.Previous.EncryptKey != "" {
		if err := validateKeyLengths("previous", *cfg.Previous); err != nil {
			return nil, err
		}
		keys = append(keys, []byte(cfg.Previous.AuthKey), []byte(cfg.Previous.EncryptKey))
	}

	return keys, nil
}

// validateKeyLengths checks that auth and encrypt keys have valid lengths
// for gorilla/securecookie: auth key must be 32 or 64 bytes (HMAC-SHA256/512),
// encrypt key must be 16, 24, or 32 bytes (AES-128/192/256).
func validateKeyLengths(label string, ks cookieKeySet) error {
	authLen := len(ks.AuthKey)
	if authLen != 32 && authLen != 64 {
		return fmt.Errorf("%s.auth_key must be 32 or 64 bytes, got %d", label, authLen)
	}
	encLen := len(ks.EncryptKey)
	if encLen != 16 && encLen != 24 && encLen != 32 {
		return fmt.Errorf("%s.encrypt_key must be 16, 24, or 32 bytes, got %d", label, encLen)
	}
	return nil
}

// parseTrustedCIDRs splits a comma-separated CIDR string, trims whitespace,
// and filters empty entries. Returns nil if input is empty or contains no valid entries.
func parseTrustedCIDRs(raw string) []string {
	if raw == "" {
		return nil
	}
	cidrs := strings.Split(raw, ",")
	var valid []string
	for _, cidr := range cidrs {
		if c := strings.TrimSpace(cidr); c != "" {
			valid = append(valid, c)
		}
	}
	return valid
}

// loadInternalAuthConfig decodes the env pair that configures the
// /nhp/internal/knock auth gate. Returns (signer, require, mode, err)
// where mode is one of {"legacy", "permit", "strict"} for operator
// logging. Separated from Start so the three misconfiguration paths
// — empty secret under require=true, malformed require token, short
// secret — can be fenced in unit tests without stubbing the whole
// server bring-up.
//
// Read once at Start: flipping NHP_INTERNAL_AUTH_REQUIRE via Terraform
// updates the EC2 launch template/user_data only; running nhp-server
// processes keep their old EnvironmentFile until the server ASG is rolled
// by a deploy or explicit instance refresh. That's intentional (no
// in-process env re-read surface to spoof), but operators should not expect
// a Terraform-only apply to flip live instances immediately. See #1233.
func loadInternalAuthConfig(envSecret, envRequire string) (*internalauth.Signer, bool, string, error) {
	// Trim the secret at the loader boundary (not at the os.Getenv
	// call site) so every entry point — Start, tests, a hypothetical
	// second bootstrap caller — gets the same whitespace semantics.
	// A Secrets Manager template with a trailing '\n' or leading
	// whitespace would otherwise produce a subtly-wrong HMAC on both
	// sides (sender and receiver agree, but the operator can't
	// reproduce the signature by hand). Whitespace-only values are
	// treated as empty → legacy mode, consistent with the REQUIRE
	// parser's whitespace tolerance.
	envSecret = strings.TrimSpace(envSecret)
	require, parseErr := parseInternalAuthRequire(envRequire)
	if parseErr != nil {
		// Fail loud on an unrecognized value rather than silently
		// defaulting to permit — an operator who types =1 or =yes
		// in Terraform thinks they flipped to strict and must not
		// end up with the VPC-wide bypass still live.
		return nil, false, "", fmt.Errorf("NHP_INTERNAL_AUTH_REQUIRE: %w", parseErr)
	}
	if require && envSecret == "" {
		// Same class as the typo guard above — the operator thinks
		// they enabled strict mode but the runtime would fall back
		// to legacy (no verification) because no signer is constructed.
		// Fail Start so the misconfig surfaces in the deploy log
		// instead of as a silent VPC-wide bypass.
		return nil, false, "", fmt.Errorf("NHP_INTERNAL_AUTH_REQUIRE=true requires NHP_INTERNAL_AUTH_SECRET to be set")
	}
	if envSecret == "" {
		return nil, false, "legacy", nil
	}
	signer, authErr := internalauth.New(envSecret)
	if authErr != nil {
		return nil, false, "", fmt.Errorf("NHP_INTERNAL_AUTH_SECRET: %w", authErr)
	}
	mode := "permit"
	if require {
		mode = "strict"
	}
	return signer, require, mode, nil
}

// parseInternalAuthRequire decodes the NHP_INTERNAL_AUTH_REQUIRE env
// var. Thin wrapper around parsePermitStrictEnv so the two
// fail-closed gates on the server (NHP_INTERNAL_AUTH_REQUIRE and
// NHP_KNOCK_HEADERTYPE_VERIFY) share a single token grammar —
// operators editing one gate's Terraform value don't need to re-
// learn the accepted tokens for the other.
func parseInternalAuthRequire(raw string) (bool, error) {
	return parsePermitStrictEnv(raw)
}

// parseAllowedOrigins splits a comma-separated list of allowed CORS origins,
// trims whitespace, and filters empty entries. Returns nil if input is empty.
// Supports wildcard entries like "https://*.example.com" which match any
// subdomain (e.g., "https://foo.example.com", "https://bar.example.com").
func parseAllowedOrigins(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	var origins []string
	for _, p := range parts {
		if o := strings.TrimSpace(p); o != "" {
			origins = append(origins, o)
		}
	}
	return origins
}

// splitOriginPatterns separates a list of origin patterns into exact matches
// and wildcard suffix patterns. Wildcard patterns use "https://*." prefix
// (e.g., "https://*.nhp.layerv.xyz") and are returned as suffix strings
// (e.g., ".nhp.layerv.xyz") with their required scheme.
type wildcardPattern struct {
	scheme string // "https" or "http"
	suffix string // e.g., ".nhp.layerv.xyz"
}

func splitOriginPatterns(origins []string) (exact map[string]bool, wildcards []wildcardPattern) {
	exact = make(map[string]bool, len(origins))
	for _, o := range origins {
		// Check for wildcard pattern: scheme://*.domain
		for _, scheme := range []string{"https://", "http://"} {
			if strings.HasPrefix(o, scheme+"*.") {
				host := strings.TrimPrefix(o, scheme+"*")
				wildcards = append(wildcards, wildcardPattern{
					scheme: strings.TrimSuffix(scheme, "://"),
					suffix: host, // e.g., ".nhp.layerv.xyz"
				})
				goto next
			}
		}
		exact[o] = true
	next:
	}
	return
}

// matchOrigin checks if an origin matches any exact origin or wildcard pattern.
func matchOrigin(origin string, exact map[string]bool, wildcards []wildcardPattern) bool {
	if exact[origin] {
		return true
	}
	for _, w := range wildcards {
		prefix := w.scheme + "://"
		if !strings.HasPrefix(origin, prefix) {
			continue
		}
		host := strings.TrimPrefix(origin, prefix)
		// Host must end with the wildcard suffix and have at least one char before it.
		// e.g., suffix=".nhp.layerv.xyz" matches "demo.nhp.layerv.xyz" but not ".nhp.layerv.xyz" or "nhp.layerv.xyz"
		if strings.HasSuffix(host, w.suffix) && len(host) > len(w.suffix) {
			// Ensure the subdomain part has no additional dots (single-level match).
			sub := host[:len(host)-len(w.suffix)]
			if !strings.Contains(sub, ".") {
				return true
			}
		}
	}
	return false
}

// redactSensitiveQuery replaces the value of the "token" query parameter with
// "[REDACTED]" to prevent access tokens from leaking into server logs during
// the GET→POST migration period.
//
// Behavior notes: only a query that actually carries a non-empty token= is
// rewritten; in that case the result is re-encoded and key-sorted
// (url.Values.Encode) so it won't match the raw wire form byte-for-byte. A
// query with nothing to redact (no token, empty token=, or a "to%6ben="-style
// lookalike that passed the substring gate) is returned unchanged to keep
// operator-facing query logs faithful. The gate matches a literal "token=" —
// the form the legacy GET plugin path and legitimate clients send; a
// percent-encoded key falls through unredacted, which is not a real-client
// shape and a self-encoding attacker gains nothing by hiding their own key.
func redactSensitiveQuery(rawQuery string) string {
	if rawQuery == "" || !strings.Contains(rawQuery, "token=") {
		return rawQuery
	}
	if v, err := url.ParseQuery(rawQuery); err == nil {
		if v.Get("token") == "" {
			return rawQuery // nothing to redact — preserve the wire form
		}
		v.Set("token", "[REDACTED]")
		return v.Encode()
	}
	// url.ParseQuery fails on a malformed percent-escape in ANY param (e.g.
	// ?token=<secret>&x=%ZZ), so we must NOT fall through to the raw string —
	// it still contains the token. Strip the token param by hand; an access
	// token value never contains '&', so splitting on '&' isolates it.
	parts := strings.Split(rawQuery, "&")
	for i, p := range parts {
		// Redact only a non-empty token value, matching the parse-ok branch
		// (an empty "token=" carries no secret).
		if strings.HasPrefix(p, "token=") && p != "token=" {
			parts[i] = "token=[REDACTED]"
		}
	}
	return strings.Join(parts, "&")
}

// ginLogFormatter formats Gin access log lines with request ID and error context.
func ginLogFormatter(param gin.LogFormatterParams) string {
	reqID := ""
	if v, ok := param.Keys[RequestIDKey].(string); ok {
		reqID = v
	}
	errMsg := ""
	if param.ErrorMessage != "" {
		errMsg = fmt.Sprintf(" | err=%s", param.ErrorMessage)
	}
	return fmt.Sprintf("[GIN] %s | %3d | %13v | %15s | %-7s %s | req_id=%s%s\n",
		param.TimeStamp.Format("2006/01/02 - 15:04:05"),
		param.StatusCode,
		param.Latency,
		param.ClientIP,
		param.Method,
		param.Path,
		reqID,
		errMsg,
	)
}

// securityHeadersMiddleware adds standard security headers to all responses.
func securityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		c.Writer.Header().Set("X-Content-Type-Options", "nosniff")
		c.Writer.Header().Set("X-Frame-Options", "DENY")
		c.Writer.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Next()
	}
}

// corsMiddleware adds CORS headers to the HTTP response.
// When allowedOrigins is configured, it validates the request Origin header against
// the allowlist (supporting both exact matches and wildcard patterns like "https://*.example.com"),
// echoes the matching origin back, and enables credentials.
// When allowedOrigins is empty (dev mode), it allows all origins with wildcard "*"
// but omits Access-Control-Allow-Credentials (wildcard + credentials is a spec violation).
// For OPTIONS preflight requests with a non-matching origin, returns 403.
func corsMiddleware(allowedOrigins []string) gin.HandlerFunc {
	// Separate exact matches from wildcard suffix patterns.
	exactSet, wildcards := splitOriginPatterns(allowedOrigins)

	// Log a warning once if running with wildcard CORS (no origins configured).
	var wildcardWarningOnce sync.Once

	return func(c *gin.Context) {
		// NHP version header is always set regardless of origin match.
		c.Writer.Header().Set("Access-Control-NHP-Ver", version.Version+"/"+version.CommitId)

		origin := c.GetHeader("Origin")

		// Determine allowed origin.
		var allowOrigin string
		if len(allowedOrigins) == 0 {
			// Development mode: allow all origins.
			allowOrigin = "*"
			wildcardWarningOnce.Do(func() {
				log.Warning("CORS: NHP_CORS_ALLOWED_ORIGINS is not set — using wildcard '*' (dev mode). Set allowed origins for production.")
			})
		} else if matchOrigin(origin, exactSet, wildcards) {
			// Origin matches exact or wildcard pattern.
			allowOrigin = origin
		} else if origin != "" {
			log.Debug("CORS: rejected origin %q (not in allowed list)", origin)
		}

		if allowOrigin != "" {
			c.Writer.Header().Set("Access-Control-Allow-Origin", allowOrigin)
			c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS, POST")
			c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Authorization, X-NHP-Ver, Cookie, X-Request-ID")
			c.Writer.Header().Set("Access-Control-Expose-Headers", "Content-Type, Content-Length, Set-Cookie, X-Request-ID, Access-Control-NHP-Ver")
			c.Writer.Header().Set("Access-Control-Max-Age", "300")

			// Allow credentials only when not using wildcard (spec compliance).
			if allowOrigin != "*" {
				c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
				// Vary header is required when Access-Control-Allow-Origin is dynamic.
				// This ensures proper caching by proxies/CDNs.
				c.Writer.Header().Set("Vary", "Origin")
			}
		}

		if c.Request.Method == "OPTIONS" {
			if allowOrigin != "" {
				c.AbortWithStatus(http.StatusNoContent)
			} else {
				c.AbortWithStatus(http.StatusForbidden)
			}
			return
		}

		c.Next()
	}
}

// filterLiveACConns returns the subset of conns safe to broadcast NHP-AOP
// on: not IsClosed(), and received a packet within the staleness threshold.
// Also returns the count of dropped entries so the caller can emit a metric
// and log once without re-walking the slice.
//
// Pure function — callers hold the map mutex only for the lookup, not the
// filter. The server holds AC connections until something explicitly closes
// them, but an AC instance can disappear silently (ASG replace, NAT rebind,
// EC2 shutdown without clean teardown) and the server has no inbound signal
// to prune it. Including those dead connections in the broadcast wastes the
// transaction timeout per dead peer. Callers that drop every connection handle
// the resulting native no-AC outcome without invoking direct HTTP admission.
func filterLiveACConns(conns []*ACConn, threshold time.Duration) (kept []*ACConn, dropped int) {
	if len(conns) == 0 {
		return nil, 0
	}
	cutoffNanos := time.Now().Add(-threshold).UnixNano()
	kept = make([]*ACConn, 0, len(conns))
	for _, c := range conns {
		if !acConnTransportLiveAt(c, cutoffNanos) {
			dropped++
			continue
		}
		kept = append(kept, c)
	}
	return kept, dropped
}

func acConnTransportLiveAt(conn *ACConn, cutoffNanos int64) bool {
	return conn != nil && conn.ConnData != nil && !conn.ConnData.IsClosed() &&
		atomic.LoadInt64(&conn.ConnData.LastLocalRecvTime) >= cutoffNanos
}

// acConnAuthorityEligibleAt is the single live-serving predicate shared by
// knock routing and critical AC health. Cloud authority additionally requires
// the local ready bit set only after durable authorization and success-AAK
// enqueue; non-cloud topology retains transport-only behavior.
func acConnAuthorityEligibleAt(conn *ACConn, cutoffNanos int64, authorityRequired bool) bool {
	return acConnTransportLiveAt(conn, cutoffNanos) && conn.sessionControlReady(authorityRequired)
}

// staleACConnThreshold returns the effective staleness threshold for this
// server, applying the Config.StaleACConnThresholdSeconds override (if > 0)
// and clamping up to MinStaleACConnThreshold so a misconfiguration cannot
// filter every connection on every knock. nil-safe so tests that construct
// a bare UdpServer without a Config get the default behavior.
func (s *UdpServer) staleACConnThreshold() time.Duration {
	if s.config == nil || s.config.StaleACConnThresholdSeconds <= 0 {
		return DefaultStaleACConnThreshold
	}
	t := time.Duration(s.config.StaleACConnThresholdSeconds) * time.Second
	if t < MinStaleACConnThreshold {
		return MinStaleACConnThreshold
	}
	return t
}

// snapshotLiveACConns is the lock-aware wrapper around filterLiveACConns
// used by NHP-AOP broadcast sites. Reads s.acConnectionMap[acId] under
// RLock, clones the backing slice (removeACConnectionRecord mutates the
// underlying slice in place via append(conns[:i], conns[i+1:]...) under
// the write lock — a reference held past RUnlock would otherwise observe
// a shifted slice), runs the filter, and emits MetricACConnStaleFiltered
// once with the dropped count.
//
// Returns (kept, droppedCount). Callers add their own context-rich log
// line; the metric is emitted here so call sites cannot forget it.
//
// For pre-broadcast liveness checks (e.g., a UDP-knock forwarding gate
// that only needs to know whether *any* live conn exists), use the cheap
// hasLiveACConn predicate instead — calling snapshotLiveACConns there
// would double-emit the metric for the same acId on the same knock.
//
// Race window with hasLiveACConn: the gate can return true (a live conn
// exists at time T0) and a subsequent snapshotLiveACConns can return zero
// (every live conn was closed/removed between T0 and T1). This is
// intentional and bounded: the broadcast loop's `len(connsCopy) == 0`
// check then falls through to the no-AC path, which forwards the knock.
// The window is bounded by KeepaliveInterval since the AC will have to
// re-register before its next conn is removed.
func (s *UdpServer) snapshotLiveACConns(acId string) (kept []*ACConn, droppedCount int) {
	s.acConnectionMapMutex.RLock()
	snapshot := slices.Clone(s.acConnectionMap[acId])
	s.acConnectionMapMutex.RUnlock()

	kept, droppedCount = filterLiveACConns(snapshot, s.staleACConnThreshold())
	if droppedCount > 0 {
		s.metrics.AddCounterWithDims(MetricACConnStaleFiltered, float64(droppedCount), nil)
	}
	if s.sessionControlAuthorityRequired() {
		authoritative := kept[:0]
		authorityDropped := 0
		for _, conn := range kept {
			if !conn.sessionControlReady(true) {
				authorityDropped++
				continue
			}
			authoritative = append(authoritative, conn)
		}
		kept = authoritative
		droppedCount += authorityDropped
		if authorityDropped > 0 {
			s.metrics.AddCounterWithDims(MetricACConnAuthorityNotReadyFiltered, float64(authorityDropped), nil)
		}
	}
	return kept, droppedCount
}

// hasLiveACConn reports whether s.acConnectionMap[acId] contains at least
// one connection that would survive snapshotLiveACConns's filter. Used by
// pre-broadcast decision points (e.g., UDP-knock forwarding gate) that
// only need a yes/no liveness signal — short-circuits on the first live
// conn, allocates nothing, and does not emit the staleness metric (the
// matching broadcast call will do that if it runs).
func (s *UdpServer) hasLiveACConn(acId string) bool {
	s.acConnectionMapMutex.RLock()
	defer s.acConnectionMapMutex.RUnlock()

	cutoffNanos := time.Now().Add(-s.staleACConnThreshold()).UnixNano()
	for _, c := range s.acConnectionMap[acId] {
		if acConnAuthorityEligibleAt(c, cutoffNanos, s.sessionControlAuthorityRequired()) {
			return true
		}
	}
	return false
}

func (hs *HttpServer) handleHttpOpenResource(_ *common.HttpKnockRequest, _ *common.ResourceData) (*common.ServerKnockAckMsg, error) {
	// HTTP application admission used to synthesize an AOP without an
	// authenticated NHP-Agent public key. NHP 1.2 has one strict AOP identity
	// contract, so this compatibility path is intentionally retired. HTTP packet
	// relay remains available for a real authenticated NHP KNK/RKN envelope.
	return &common.ServerKnockAckMsg{
		ErrCode: common.ErrHTTPAccessOperationUnsupported.ErrorCode(),
		ErrMsg:  common.ErrHTTPAccessOperationUnsupported.Error(),
	}, common.ErrHTTPAccessOperationUnsupported
}

func (hs *HttpServer) NewHttpServerHelper() *plugins.HttpServerPluginHelper {
	h := &plugins.HttpServerPluginHelper{}
	h.StopSignal = hs.signals.stop

	h.AuthWithHttpCallbackFunc = func(req *common.HttpKnockRequest, res *common.ResourceData) (*common.ServerKnockAckMsg, error) {
		return hs.handleHttpOpenResource(req, res)
	}

	// ResolveResourceFunc mirrors the headless /nhp/internal/knock resolver:
	// it routes (aspId, resId) through the server-owned catalog
	// (resolveInternalKnockResource) so HTTP plugins consume
	// catalog-authoritative resource metadata instead of trusting routing they
	// received in an upstream response body (#2540). Direct HTTP admission is
	// retired independently by AuthWithHttpCallbackFunc above.
	//
	// The lookup context is the lifecycle context (internalKnockResourceLookupContext),
	// NOT the plugin's per-request context — same as the headless caller. The
	// catalog lookup singleflights concurrent knocks for the same hot resource
	// and its closure captures the first caller's context (see LookupResource's
	// CONTRACT), so a per-request context would fan one client's disconnect out
	// to every piggybacked live caller. callerResource is nil because the plugin
	// supplies no override here (qURL clamps its own OpenTime locally). The
	// throwaway lookup request carries only the lookup identity;
	// resolveInternalKnockResource never retains it.
	h.ResolveResourceFunc = func(aspId, resId, srcIP string) (*common.ResourceData, error) {
		lookup := &common.HttpKnockRequest{AuthServiceId: aspId, ResourceId: resId, SrcIp: srcIP}
		return hs.resolveInternalKnockResource(hs.internalKnockResourceLookupContext(), lookup, nil)
	}

	// Bind metric emitters for plugins (mirrors the internalAuthEmit /
	// emitMetric precedents above — gate on metrics != nil before binding).
	if hs.udpServer != nil && hs.udpServer.metrics != nil {
		h.RecordLatency = hs.udpServer.metrics.RecordLatency
		h.IncrCounter = hs.udpServer.metrics.IncrCounter
	}
	return h
}

// FindPluginHandler returns the plugin handler for the given ASP ID
// It delegates the task to the underlying UDP server's FindPluginHandler method.
func (hs *HttpServer) FindPluginHandler(aspId string) plugins.PluginHandler {
	return hs.udpServer.FindPluginHandler(aspId)
}

// handleInternalKnock processes forwarded knock requests from other
// servers and service-to-server callers (e.g., qurl-service).
//
// Auth layers, in order of application:
//  1. RFC-1918 / loopback source-IP check (defense in depth; port 8888
//     is open to 0.0.0.0/0 via NLB with preserve_client_ip=true).
//  2. HMAC verification of the X-Nhp-Auth header. Permit- or strict-
//     mode per NHP_INTERNAL_AUTH_REQUIRE; see the Start-time config
//     block that initializes internalAuthSigner / internalAuthRequire.
//
// The layer-1 check alone is not an auth gate — any VPC workload can
// hit this path with a private source IP. Layer 2 binds requests to
// parties holding the shared secret. Removing either without replacing
// it would open the knock API to the full VPC attack surface.
func (hs *HttpServer) handleInternalKnock(ctx *gin.Context) {
	// Source IP check: reject non-RFC-1918 IPs.
	//
	// Deliberately uses RemoteAddr (not ctx.ClientIP()) because this
	// endpoint receives only same-VPC traffic and must not trust any
	// X-Forwarded-For header regardless of the server-wide
	// NHP_TRUSTED_PROXY_CIDRS setting. If an operator ever configures
	// a VPC-wide CIDR as trusted, ctx.ClientIP() would walk an
	// attacker-supplied XFF and a workload at 8.8.8.8 could spoof
	// 10.0.0.1, passing this gate. RemoteAddr is the socket peer —
	// unspoofable at layer 4 — which is the correct primitive for
	// the internal surface.
	host, _, splitErr := net.SplitHostPort(ctx.Request.RemoteAddr)
	srcIP := host
	if splitErr != nil {
		// If SplitHostPort fails the address is malformed; just log
		// and fall through to isPrivateIP which rejects empty.
		srcIP = ctx.Request.RemoteAddr
	}
	if !isPrivateIP(srcIP) {
		log.Warning("internal knock rejected: non-private source IP %s", srcIP)
		ctx.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}

	// Query and fragment are not part of the signed string (see
	// internalauth.Signer godoc). Reject requests that carry them
	// rather than silently accept an un-protected segment — closes
	// the footgun class where a future endpoint consumes a query
	// param and would have it unsigned. If query-signing is ever
	// required, bump internalauth.Scheme and add the field to the
	// signing string on both halves.
	//
	// The Fragment clause is defensive-only: fragments are client-
	// side per RFC 3986 and don't traverse the wire. It catches
	// programmatic callers that build http.Request directly with
	// a populated URL.Fragment (tests, library misuse) — cheaper
	// to reject up front than to audit every client library's
	// fragment-handling behavior.
	if ctx.Request.URL.RawQuery != "" || ctx.Request.URL.Fragment != "" {
		log.Warning("internal knock rejected: URL must have no query or fragment (got query=%q fragment=%q)", redactSensitiveQuery(ctx.Request.URL.RawQuery), ctx.Request.URL.Fragment)
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}

	// In legacy mode (no signer configured — initial rollout state),
	// skip the full-body buffer. ShouldBindJSON downstream streams
	// directly off ctx.Request.Body; the 413 cap is still enforced
	// via MaxBytesReader, which is O(1) extra memory.
	//
	// In permit/strict mode we must buffer so the HMAC verify sees
	// exactly the bytes JSON bind will see — otherwise a streaming
	// reader could let the verifier and parser diverge on partially-
	// read input.
	//
	// Response-code asymmetry: legacy-mode oversized body surfaces as
	// 400 "invalid request body" (MaxBytesReader's error hits
	// ShouldBindJSON, not the 413 branch below), while permit/strict
	// mode returns 413. Acceptable for the rollout window — legacy is
	// transitional and operators see 413 on the post-flip steady
	// state. Unifying would require read-and-measure in legacy mode.
	if hs.internalAuthSigner == nil {
		ctx.Request.Body = http.MaxBytesReader(ctx.Writer, ctx.Request.Body, maxInternalKnockRequestSize)
	} else {
		// We close the original reader explicitly so the lifecycle is
		// independent of the net/http server's post-handler Close; a
		// future transport wrapping the body in a pooled-buffer closer
		// still frees its resources. Gin's post-handler cleanup closes
		// the swapped NopCloser (no-op); origBody.Close() covers the
		// real reader regardless of which arm below fires.
		origBody := ctx.Request.Body
		defer origBody.Close()
		body, err := io.ReadAll(io.LimitReader(origBody, maxInternalKnockRequestSize+1))
		if err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})
			return
		}
		if int64(len(body)) > maxInternalKnockRequestSize {
			// Log src=<ip> + reqID symmetric with the strict-reject log line so
			// "is one caller misbehaving or are we under a wave?" stays
			// answerable from logs alone.
			log.Warning("internal knock rejected: body over limit src=%s reqID=%s size=%d limit=%d",
				srcIP, GetRequestID(ctx), len(body), maxInternalKnockRequestSize)
			ctx.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "body too large"})
			return
		}
		// Reset both the body reader and ContentLength so any downstream
		// consumer that trusts ContentLength sees the buffered length.
		ctx.Request.Body = io.NopCloser(bytes.NewReader(body))
		ctx.Request.ContentLength = int64(len(body))

		// HMAC verification. In permit-mode (signer set, require=false) a
		// verification failure logs a warning but allows the request
		// through — this is the rollout-window behavior that lets unsigned
		// callers continue working while operators confirm the signing
		// path is live before flipping to strict. Strict mode rejects
		// with 401; the response body carries only ErrInternalAuth so the
		// attacker learns nothing about which sub-check failed.
		authErr := hs.internalAuthSigner.Verify(
			ctx.GetHeader(internalauth.Header),
			ctx.Request.Method,
			ctx.Request.URL.Path,
			body,
			0, // use default skew window
		)
		if authErr != nil {
			// Log stage-only to avoid creating a sub-check oracle for
			// anyone with read access to the log stack. The sentinel-
			// only 401 body already hides which arm failed; echoing
			// the full wrapped error here would partially undo that.
			stage := internalauth.ClassifyAuthFailure(authErr)
			reqID := GetRequestID(ctx)
			if hs.internalAuthRequire {
				log.Warning("internal knock rejected (strict): src=%s stage=%s reqID=%s", srcIP, stage, reqID)
				if hs.internalAuthEmit != nil {
					hs.internalAuthEmit(MetricInternalAuthFailStrict)
				}
				ctx.JSON(http.StatusUnauthorized, gin.H{"error": internalauth.ErrInternalAuth.Error()})
				return
			}
			// Counter (MetricInternalAuthFailPermit) is the alarm
			// signal for the rollout; this log line is for per-
			// request debugging only — don't plumb it into a
			// regex alert. Logged at Info (not Warning) because
			// during the rollout window every pre-upgrade caller
			// emits one per request, and that volume at Warning
			// severity would either drown real warnings or train
			// operators to ignore them. Phrased as "unverified"
			// not "failed" so a log aggregator grepping for
			// "auth failed" doesn't trip on rollout-window noise —
			// the grep should hit the strict-mode reject line only.
			log.Info("internal knock permit-mode unverified (allowing through): src=%s stage=%s reqID=%s", srcIP, stage, reqID)
			// Counter is the rollout signal: alarm on Permit > 0
			// during the qurl-service signing rollout. When it
			// drops to zero across a stable window, it's safe to
			// flip NHP_INTERNAL_AUTH_REQUIRE=true.
			if hs.internalAuthEmit != nil {
				hs.internalAuthEmit(MetricInternalAuthFailPermit)
			}
		} else if hs.internalAuthEmit != nil {
			// Success paired with FailPermit/FailStrict. Operators
			// watching the rollout need a positive signal ("signed
			// traffic arriving") to distinguish "everyone signed"
			// from "no traffic" before flipping require=true.
			hs.internalAuthEmit(MetricInternalAuthSuccess)
		}
	}

	var fwdReq HttpKnockForwardRequest
	if err := ctx.ShouldBindJSON(&fwdReq); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	if fwdReq.Request == nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "missing request"})
		return
	}

	// Count internal knock requests after the request-auth gate, but before
	// resource resolution and forwarded-hop attestation. In permit mode, the
	// gate logs invalid/missing signatures and continues during rollout, so
	// this includes permitted unsigned callers. Downstream reject logs/metrics
	// carry the outcome.
	hs.recordInternalKnockRequest(fwdReq.Source, srcIP)

	resolvedResource, err := hs.resolveInternalKnockResource(hs.internalKnockResourceLookupContext(), fwdReq.Request, fwdReq.Resource)
	if err != nil {
		switch {
		case errors.Is(err, errInvalidInternalKnockRequest):
			log.Warning("handleInternalKnock: invalid resource resolution request: %v", err)
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		case errors.Is(err, common.ErrAuthServiceProviderNotFound), errors.Is(err, common.ErrResourceNotFound):
			ctx.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		default:
			log.Error("handleInternalKnock: resource resolution failed: %v", err)
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "resource resolution failed"})
		}
		return
	}

	// Verify the cross-server hop attestation (issue #1127). This binds a
	// server-to-server forward to the forwarding server's NHP identity so
	// a compromised fleet member cannot forge or conceal the forward
	// chain, and bounds re-forwarding via maxForwardHops. API origins
	// (Source==SourceAPI) start the chain and carry no attestation. Only
	// runs in cloud mode (device + Cloud Map present); legacy/local mode
	// skips it entirely. See docs/design/INTERNAL_FORWARD_HOP_ATTESTATION.md.
	// hopVerifyEcdh returns nil unless udpServer/device/fleetTrust are all set.
	// Fetch the static ECDH once (also reused below). A constructed device
	// always has a scheme-0 ECDH (core.NewDevice returns nil otherwise), so
	// the nil branch is defensive — if it were ever nil, skip verification
	// (legacy posture) rather than strict-reject every forward on
	// errForwardHopECDHFailed. Historical senders and this receiver use scheme 0.
	if selfEcdh := hs.hopVerifyEcdh(); selfEcdh != nil {
		// fwdReq.Source is bound into the MAC, so a verified attestation is
		// pinned to the Source it was minted with (a flip is a MAC mismatch).
		//
		// Resolve the trust set only when an attestation is actually present:
		// the common API-origin path (Attestation == nil) is rejected on the
		// nil check inside verify before the set is consulted, so computing it
		// eagerly would copy the sticky map on every origin knock for nothing.
		var trusted map[string]bool
		if fwdReq.Attestation != nil {
			trusted = hs.fleetTrust.known(ctx.Request.Context())
		}
		hopErr := verifyForwardHopAttestation(
			selfEcdh,
			fwdReq.Attestation,
			trusted,
			time.Now(),
			forwardHopMaxSkew,
			fwdReq.Source,
			fwdReq.Request,
		)
		reqID := GetRequestID(ctx)
		switch {
		case hopErr == nil:
			// A valid attestation governs even on an API origin: a legitimate
			// origin (qurl-service) never attests, so an attestation carried
			// with Source="api" can only come from a fleet member, and its
			// hop is bounded by maxForwardHops like any other.
			hs.emitForwardHop(MetricForwardHopAttestSuccess)
		case errors.Is(hopErr, errForwardHopMissing) && fwdReq.Source == SourceAPI:
			// Origin request: no attestation expected. Hop stays 0.
			// Deliberately keyed on errForwardHopMissing specifically, not
			// "any error when Source==api": an API origin that somehow
			// carried a malformed attestation should NOT be waved through —
			// it falls to the default branch and is permit/strict-judged
			// like any other unverifiable hop.
		case errors.Is(hopErr, errForwardHopBadHop):
			// Over the loop ceiling (or hop < 1) — a hard loop bound;
			// refuse regardless of rollout mode. Only an attestation that
			// explicitly claimed an out-of-range hop reaches here. Counted
			// separately from the strict reject so this real loop signal
			// isn't masked by rollout-window noise.
			log.Warning("internal knock rejected: forward hop ceiling src=%s reqID=%s", srcIP, reqID)
			hs.emitForwardHop(MetricForwardHopCeilingReject)
			ctx.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		default:
			if hs.forwardHopRequire {
				log.Warning("internal knock rejected (strict hop): src=%s reqID=%s stage=%s", srcIP, reqID, forwardHopStage(hopErr))
				hs.emitForwardHop(MetricForwardHopAttestReject)
				ctx.JSON(http.StatusUnauthorized, gin.H{"error": internalauth.ErrInternalAuth.Error()})
				return
			}
			// Permit mode: warn-and-allow during rollout. The counter is
			// the rollout signal — alarm on ForwardHopAttestPermit > 0;
			// when it holds at zero across a stable window it's safe to
			// flip NHP_INTERNAL_FORWARD_ATTEST_REQUIRE=true.
			log.Info("internal knock permit-mode hop unverified (allowing): src=%s reqID=%s stage=%s", srcIP, reqID, forwardHopStage(hopErr))
			hs.emitForwardHop(MetricForwardHopAttestPermit)
		}
	}

	// Preserve the bounded-processing context established by this authenticated
	// pre-handler. The terminal is deliberately synchronous and fail-closed; it
	// must not forward or dispatch an AC operation.
	knockCtx, cancel := withKnockProcessingBudget(ctx.Request.Context())
	defer cancel()
	fwdReq.Request.Ctx = knockCtx

	ackMsg, err := hs.handleHttpOpenResource(fwdReq.Request, resolvedResource)
	resp := HttpKnockForwardResponse{AckMsg: ackMsg}
	if err != nil {
		resp.Error = err.Error()
	}

	ctx.JSON(http.StatusOK, resp)
}
