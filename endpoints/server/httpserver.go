package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

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
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/log"
	"github.com/OpenNHP/opennhp/nhp/plugins"
	"github.com/OpenNHP/opennhp/nhp/version"
)

type HttpServer struct {
	id            string
	udpServer     *UdpServer
	httpServer    *http.Server
	ginEngine     *gin.Engine
	listenAddr    *net.TCPAddr
	healthManager *health.Manager
	knockManager  *health.Manager // includes AC peer check for knock-traffic readiness
	httpForwarder *HttpKnockForwarder

	wg      sync.WaitGroup
	running atomic.Bool

	// signals
	signals struct {
		stop chan struct{}
	}
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
	// allowing X-Forwarded-For spoofing for NHP knocks.
	if validCIDRs := parseTrustedCIDRs(os.Getenv("NHP_TRUSTED_PROXY_CIDRS")); len(validCIDRs) > 0 {
		if err := hs.ginEngine.SetTrustedProxies(validCIDRs); err != nil {
			return fmt.Errorf("failed to set trusted proxies: %w", err)
		}
		log.Info("Trusted proxies configured with %d CIDRs (first: %s)", len(validCIDRs), validCIDRs[0])
	} else {
		_ = hs.ginEngine.SetTrustedProxies(nil)
	}

	cookieKeys, err := parseCookieKeys(os.Getenv("NHP_COOKIE_KEYS"))
	if err != nil {
		return fmt.Errorf("NHP_COOKIE_KEYS: %w", err)
	}
	store := cookie.NewStore(cookieKeys...)
	hs.ginEngine.Use(requestIDMiddleware())
	hs.ginEngine.Use(sessions.Sessions("nhpsessions", store))
	hs.ginEngine.Use(securityHeadersMiddleware())
	corsOrigins := parseAllowedOrigins(os.Getenv("NHP_CORS_ALLOWED_ORIGINS"))
	hs.ginEngine.Use(corsMiddleware(corsOrigins))
	hs.ginEngine.Use(gin.LoggerWithConfig(gin.LoggerConfig{
		Output:    us.log.Writer(),
		Formatter: ginLogFormatter,
	}))
	hs.ginEngine.Use(gin.Recovery())

	// Initialize health check manager (fail-fast if no storage backend)
	if err := hs.initHealthManager(); err != nil {
		return err
	}

	// Initialize HTTP knock forwarder for server-to-server forwarding.
	// Requires storage backend (for AC assignment lookup). CloudMap is optional
	// (used for health filtering of stale assignments if enabled).
	if us.storage != nil {
		var emitMetric MetricCounter
		if us.metrics != nil {
			emitMetric = us.metrics.IncrCounter
		}
		hs.httpForwarder = NewHttpKnockForwarder(us.storage, us.cloudMap, us.localIp, listenPort, emitMetric)
		log.Info("HTTP knock forwarder initialized (localIP=%s, port=%d, cloudMap=%t)", us.localIp, listenPort, us.cloudMap != nil)
	}

	hs.initRouter()

	hs.httpServer = &http.Server{
		Addr:         hs.listenAddr.String(),
		Handler:      hs.ginEngine,
		ReadTimeout:  time.Duration(hc.ReadTimeoutMs) * time.Millisecond,
		WriteTimeout: time.Duration(hc.WriteTimeoutMs) * time.Millisecond,
		IdleTimeout:  time.Duration(hc.IdleTimeoutMs) * time.Millisecond,
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

	// Stop accepting new forwards and wait for in-flight ones to complete
	if hs.httpForwarder != nil {
		hs.httpForwarder.Stop()
	}

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
		log.Info("get plugins request. aspId: %s, resId: %s, query: %v", aspId, resId, ctx.Request.URL.RawQuery)

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

	// Internal knock forwarding endpoint (VPC-only, RFC 1918 source IP check)
	nhpInternal := g.Group("/nhp/internal")
	nhpInternal.POST("/knock", hs.handleInternalKnock)

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
func redactSensitiveQuery(rawQuery string) string {
	if rawQuery == "" || !strings.Contains(rawQuery, "token=") {
		return rawQuery
	}
	v, err := url.ParseQuery(rawQuery)
	if err != nil {
		return rawQuery
	}
	if v.Get("token") != "" {
		v.Set("token", "[REDACTED]")
	}
	return v.Encode()
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

func (hs *HttpServer) handleHttpOpenResource(req *common.HttpKnockRequest, res *common.ResourceData) (ackMsg *common.ServerKnockAckMsg, err error) {
	hs.wg.Add(1)
	defer hs.wg.Done()
	s := hs.udpServer
	srcIp := req.SrcIp

	// req.Ctx is set by runPluginAuth and handleInternalKnock — every code
	// path that reaches handleHttpOpenResource sets it. Fall back to
	// context.Background() defensively rather than panicking on a future
	// regression that forgets to populate the field.
	ctx := req.Ctx
	if ctx == nil {
		log.Warning("httpserver-agent(%s#%s)[handleHttpOpenResource] req.Ctx unexpectedly nil; using Background()", req.UserId, req.DeviceId)
		ctx = context.Background()
	}

	knkMsg := &common.AgentKnockMsg{
		UserId:         req.UserId,
		DeviceId:       req.DeviceId,
		OrganizationId: req.OrganizationId,
		AuthServiceId:  req.AuthServiceId,
		ResourceId:     res.ResourceId,
	}

	if req.Command == "exit" {
		knkMsg.HeaderType = core.NHP_EXT
	}

	ackMsg = &common.ServerKnockAckMsg{
		AuthProviderToken: req.Token,
		AgentAddr:         srcIp,
		OpenTime:          res.OpenTime,
	}

	if len(res.Resources) == 0 {
		err = common.ErrResourceNotFound
		ackMsg.ErrCode = common.ErrResourceNotFound.ErrorCode()
		ackMsg.ErrMsg = err.Error()
		return
	}

	// PART II: determine knock src ip address and resource dst ip addresses
	srcAddr := &common.NetAddress{Ip: srcIp}

	acDstIpMap := make(map[string][]*common.NetAddress)
	for resName, info := range res.Resources {
		addrs, exist := acDstIpMap[resName]
		if exist {
			addrs = append(addrs, info.Addr)
			acDstIpMap[resName] = addrs
		} else {
			acDstIpMap[resName] = []*common.NetAddress{info.Addr}
		}
	}

	// PART III: request ac operation for each resource and block for response
	var acWg sync.WaitGroup
	var artMsgsMutex sync.Mutex
	artMsgs := make(map[string]*common.ACOpsResultMsg)
	ackMsg.ResourceHost = make(map[string]string)
	ackMsg.ACTokens = make(map[string]string)
	ackMsg.PreAccessActions = make(map[string]*common.PreAccessInfo)

	knockHadNoAC := false

	for resName, addrs := range acDstIpMap {
		resInfo := res.Resources[resName]
		if resInfo == nil {
			continue
		}
		acId := resInfo.ACId
		s.acConnectionMapMutex.RLock()
		acConns, found := s.acConnectionMap[acId]
		var connsCopy []*ACConn
		if found {
			// Filter out connections that have already been closed to avoid
			// sending NHP-AOP on stale connections (which would fail immediately
			// with ErrTransactionFailedByClosedConnection).
			for _, c := range acConns {
				if !c.ConnData.IsClosed() {
					connsCopy = append(connsCopy, c)
				}
			}
		}
		s.acConnectionMapMutex.RUnlock()
		if !found || len(connsCopy) == 0 {
			// No local AC connection — try HTTP forwarding to an assigned server
			if hs.httpForwarder != nil && !req.Forwarded {
				fwdCtx, fwdCancel := context.WithTimeout(ctx, DefaultForwardTimeout)
				fwdAck, fwdErr := hs.httpForwarder.ForwardHttpKnock(fwdCtx, acId, req, res)
				fwdCancel() // cancel immediately; defer would accumulate across loop iterations
				if fwdErr == nil && fwdAck != nil && fwdAck.ErrCode == common.ErrSuccess.ErrorCode() {
					log.Info("httpserver-agent(%s#%s@%s)-ac(%s)[HandleHttpKnockRequest] knock forwarded successfully", knkMsg.UserId, knkMsg.DeviceId, srcIp, acId)
					s.metrics.IncrCounter(MetricKnockForwardSuccess)
					return fwdAck, nil
				}
				if fwdErr != nil {
					log.Warning("httpserver-agent(%s#%s@%s)-ac(%s)[HandleHttpKnockRequest] forward failed: %v", knkMsg.UserId, knkMsg.DeviceId, srcIp, acId, fwdErr)
					s.metrics.IncrCounter(MetricKnockForwardFailure)
				}
			}

			knockHadNoAC = true
			log.Warning("httpserver-agent(%s#%s@%s)-ac(%s)[HandleHttpKnockRequest] no ac connection is available", knkMsg.UserId, knkMsg.DeviceId, srcIp, acId)
			artMsg := &common.ACOpsResultMsg{}
			err = common.ErrACConnectionNotFound
			artMsg.ErrCode = common.ErrACConnectionNotFound.ErrorCode()
			artMsg.ErrMsg = err.Error()
			artMsgsMutex.Lock()
			artMsgs[resName] = artMsg
			artMsgsMutex.Unlock()
			continue
		}

		acWg.Add(1)
		go func(name string, info *common.ResourceInfo, dstAddrs []*common.NetAddress) {
			defer acWg.Done()

			openTime := res.OpenTime
			if knkMsg.HeaderType == core.NHP_EXT {
				openTime = 1 // timeout in 1 second
			}
			artMsg, err := s.processACOperationBroadcast(ctx, knkMsg, connsCopy, srcAddr, dstAddrs, openTime)
			artMsgsMutex.Lock()
			artMsgs[name] = artMsg
			if err == nil {
				ackMsg.ResourceHost[name] = info.DestHost()
				ackMsg.ACTokens[name] = artMsg.ACToken
				ackMsg.PreAccessActions[name] = artMsg.PreAccessAction
			}
			artMsgsMutex.Unlock()
		}(resName, resInfo, addrs)
	}
	acWg.Wait()

	// Increment once per knock request (not per resource) for alarm accuracy
	if knockHadNoAC {
		s.metrics.IncrCounter(MetricKnockNoAC)
	}

	var successCount int
	for _, artMsg := range artMsgs {
		if artMsg.ErrCode == common.ErrSuccess.ErrorCode() {
			successCount++
		}
	}

	if successCount == 0 {
		// Collect specific error messages from each failed AC operation
		// so callers (e.g., QURL plugin) can surface actionable diagnostics.
		var details []string
		for resName, artMsg := range artMsgs {
			if artMsg.ErrMsg != "" {
				details = append(details, fmt.Sprintf("%s: %s", resName, artMsg.ErrMsg))
			}
		}
		log.Error("httpserver-agent(%s#%s@%s)[handleHttpOpenResource] all AC operations failed: %v", knkMsg.UserId, knkMsg.DeviceId, srcIp, details)
		if len(details) > 0 {
			err = fmt.Errorf("%w (%s)", common.ErrServerACOpsFailed, strings.Join(details, "; "))
		} else {
			err = common.ErrServerACOpsFailed
		}
		ackMsg.ErrCode = common.ErrServerACOpsFailed.ErrorCode()
		ackMsg.ErrMsg = err.Error()
		return
	}

	log.Info("httpserver-agent(%s#%s@%s)[handleHttpOpenResource] succeed", knkMsg.UserId, knkMsg.DeviceId, srcIp)
	ackMsg.ErrCode = common.ErrSuccess.ErrorCode()
	ackMsg.ErrMsg = common.ErrSuccess.Error()

	return ackMsg, nil
}

func (hs *HttpServer) NewHttpServerHelper() *plugins.HttpServerPluginHelper {
	h := &plugins.HttpServerPluginHelper{}
	h.StopSignal = hs.signals.stop

	h.AuthWithHttpCallbackFunc = func(req *common.HttpKnockRequest, res *common.ResourceData) (*common.ServerKnockAckMsg, error) {
		return hs.handleHttpOpenResource(req, res)
	}
	return h
}

// FindPluginHandler returns the plugin handler for the given ASP ID
// It delegates the task to the underlying UDP server's FindPluginHandler method.
func (hs *HttpServer) FindPluginHandler(aspId string) plugins.PluginHandler {
	return hs.udpServer.FindPluginHandler(aspId)
}

// handleInternalKnock processes forwarded knock requests from other servers.
// Security: Only accepts requests from VPC private IPs (port 8888 is open to 0.0.0.0/0 via NLB).
func (hs *HttpServer) handleInternalKnock(ctx *gin.Context) {
	// Source IP check: reject non-RFC-1918 IPs
	srcIP := ctx.ClientIP()
	if !isPrivateIP(srcIP) {
		log.Warning("Internal knock rejected: non-private source IP %s", srcIP)
		ctx.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}

	var fwdReq HttpKnockForwardRequest
	if err := ctx.ShouldBindJSON(&fwdReq); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	if fwdReq.Request == nil || fwdReq.Resource == nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "missing request or resource"})
		return
	}

	// Decide whether to mark as forwarded based on the request source.
	// API callers (e.g., qurl-service) set Source="api" so the receiving server
	// can forward to the correct server if the AC isn't connected locally.
	// Server-to-server forwards (empty Source) set Forwarded=true to prevent loops.
	switch fwdReq.Source {
	case SourceAPI:
		// API-originated: allow forwarding to find the correct server
	case "":
		// Server-to-server: block re-forwarding (loop prevention)
		fwdReq.Request.Forwarded = true
	default:
		log.Warning("handleInternalKnock: unexpected Source value %q, treating as server-to-server", fwdReq.Source)
		fwdReq.Request.Forwarded = true
	}
	fwdReq.Request.Ctx = ctx.Request.Context()

	ackMsg, err := hs.handleHttpOpenResource(fwdReq.Request, fwdReq.Resource)
	resp := HttpKnockForwardResponse{AckMsg: ackMsg}
	if err != nil {
		resp.Error = err.Error()
	}

	ctx.JSON(http.StatusOK, resp)
}
