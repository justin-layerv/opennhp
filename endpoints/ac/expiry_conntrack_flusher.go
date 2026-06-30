package ac

// Backend selection + construction options for ConntrackFlusher, in a
// build-tag-free file so config.go / udpac.go (both cross-platform) can
// name BackendNetlink and WithBackend without pulling in the Linux-only
// netlink datapath. The two NewConntrackFlusher implementations (the
// real one in expiry_conntrack_flusher_linux.go, the stub in
// expiry_conntrack_flusher_stub.go) both consume these.

// ConntrackBackend selects how ConntrackFlusher tears down kernel
// conntrack entries. The two backends are behaviorally equivalent for
// the IPv4 flush set (the WithBackend toggle's premise — see #2165);
// netlink additionally handles IPv6 and drops the fork+exec + the
// locale-fragile stderr scrape of the exec path.
type ConntrackBackend uint8

const (
	// BackendExec is the v1 path: fork+exec the `conntrack -D` userspace
	// tool per Flush. Default, so an AC that enables L3 flush without
	// opting into netlink keeps today's exact behavior until the netlink
	// path is soak-validated per the #2165 rollout plan.
	BackendExec ConntrackBackend = iota
	// BackendNetlink talks NFNL_SUBSYS_CTNETLINK directly via a pool of
	// pre-warmed netlink sockets — no fork, no userspace tool dependency,
	// and IPv6-capable (closing the iptables-mode IPv6 immediate-teardown
	// gap, #2794/#2797). Opt-in until soak-validated.
	BackendNetlink
)

// String renders a ConntrackBackend for logs / config echo.
func (b ConntrackBackend) String() string {
	switch b {
	case BackendNetlink:
		return "netlink"
	case BackendExec:
		return "exec"
	default:
		return "exec"
	}
}

// ParseConntrackBackend maps a config string to a backend. The empty
// string (field omitted in ac.toml) defaults to exec — the safe v1
// behavior. Unknown values return ok=false so the caller can warn and
// fall back rather than silently mis-select.
func ParseConntrackBackend(s string) (ConntrackBackend, bool) {
	switch s {
	case "", "exec":
		return BackendExec, true
	case "netlink":
		return BackendNetlink, true
	default:
		return BackendExec, false
	}
}

// defaultConntrackNetlinkPoolSize is the netlink socket pool size. Sized per
// the #2165 sketch — one socket per ~4 flush workers. A netlink socket
// serializes request→response by sequence number and so is single-flight; the
// pool is what provides concurrency. The default is deliberately conservative
// for the first opt-in: each holder owns its socket across the O(table) dump
// and matching deletes, and the rollout ledger must explicitly accept or tune
// this ratio under representative burst + fan-out before the prod flip.
const (
	conntrackNetlinkWorkersPerSocket = 4
	defaultConntrackNetlinkPoolSize  = defaultWorkerCount / conntrackNetlinkWorkersPerSocket
)

// maxConntrackNetlinkPoolSize caps the operator-tunable pool size so a
// config typo (e.g. 100000) can't exhaust file descriptors at Start. Two
// sockets per worker is already far past the single-flight bottleneck;
// anything beyond is a mistake.
const maxConntrackNetlinkPoolSize = defaultWorkerCount * 2

// normalizeConntrackPoolSize maps a config value to a usable pool size:
// ≤0 → the default, and any value above the cap → the cap. Pure so it can
// be unit-tested without constructing a flusher.
func normalizeConntrackPoolSize(n int) int {
	if n <= 0 {
		return defaultConntrackNetlinkPoolSize
	}
	if n > maxConntrackNetlinkPoolSize {
		return maxConntrackNetlinkPoolSize
	}
	return n
}

// conntrackFlusherConfig is the resolved option set for
// NewConntrackFlusher. Defaults: exec backend, default pool size (only
// consulted by the netlink backend).
type conntrackFlusherConfig struct {
	backend  ConntrackBackend
	poolSize int
}

// ConntrackFlusherOption tunes NewConntrackFlusher.
type ConntrackFlusherOption func(*conntrackFlusherConfig)

// WithBackend selects the conntrack teardown backend. Default BackendExec.
func WithBackend(b ConntrackBackend) ConntrackFlusherOption {
	return func(c *conntrackFlusherConfig) { c.backend = b }
}

// WithNetlinkPoolSize overrides the netlink socket pool size (netlink
// backend only). Uses the same normalization as config: values <= 0 map to
// defaultConntrackNetlinkPoolSize, and oversized values are capped.
func WithNetlinkPoolSize(n int) ConntrackFlusherOption {
	return func(c *conntrackFlusherConfig) { c.poolSize = n }
}

// resolveConntrackFlusherConfig applies opts over the defaults.
func resolveConntrackFlusherConfig(opts ...ConntrackFlusherOption) conntrackFlusherConfig {
	cfg := conntrackFlusherConfig{backend: BackendExec, poolSize: defaultConntrackNetlinkPoolSize}
	for _, o := range opts {
		o(&cfg)
	}
	cfg.poolSize = normalizeConntrackPoolSize(cfg.poolSize)
	return cfg
}
