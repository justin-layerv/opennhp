package ac

import (
	"encoding/base64"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/log"
)

// firstLoadTestAC wires a no-op logger onto the minimal AC so that
// updateBaseConfig's first-load path (which calls a.log.SetLogLevel)
// doesn't panic on a nil *Logger. Level 0 = silent; no file output.
func firstLoadTestAC() *UdpAC {
	ac := ardTestAC(nil)
	ac.log = log.NewLogger("test", 0, "", "")
	return ac
}

// isServerPubKeyAllowed is the test-only single-pubkey wrapper
// around ardTrustSnapshot. Filter loops in production
// (filterRedispatchTargets) use the snapshot directly to avoid
// rebuilding the trusted set per target; tests use this for
// readability when checking one pubkey at a time.
func (a *UdpAC) isServerPubKeyAllowed(pubKey string) bool {
	return a.ardTrustSnapshot().contains(pubKey)
}

// rebuildServerPubKeyAllowlist is the test-only shim for priming
// the allowlist map directly, bypassing the TOML config path. The
// production allowlist-mutation paths live in updateBaseConfig
// (first load) and reloadARDTrust (hot reload); both inline the
// normalize-and-swap-under-lock sequence this helper wraps.
//
// Kept on *UdpAC so tests read naturally (ac.rebuildServerPubKeyAllowlist(...))
// and can exercise the same locking contract production uses. Lives
// in _test.go so it's not visible to production code — the
// helper had no prod callers after the first-load path was
// inlined in updateBaseConfig.
func (a *UdpAC) rebuildServerPubKeyAllowlist(raw []string) {
	set := normalizeAllowlist(raw)
	a.serverPeerMutex.Lock()
	a.serverPubKeyAllowlist = set
	a.serverPeerMutex.Unlock()
}

// b64 returns the base64-encoded form of s. `ServerPubKeyAllowlist`
// entries go through `normalizeAllowlist`, which drops anything that
// fails `base64.StdEncoding.DecodeString` (the defense-in-depth fence
// added in #1239), so allowlist fixtures must be
// valid base64. Keys stored in `ServerPubKeyBase64` or
// `serverPeerMap` bypass normalization and can stay as free-form
// strings — but using the helper uniformly keeps the test fixtures
// readable.
func b64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// ardTestAC builds a minimal UdpAC suitable for exercising the pubkey
// allowlist and the filterRedispatchTargets helper. It wires every
// field that the code under test touches (mutex, allowlist set, peer
// map) so a test can mutate the allowlist without reproducing the
// Start/Stop plumbing.
func ardTestAC(cfg *Config) *UdpAC {
	ac := &UdpAC{
		config:                cfg,
		serverPeerMap:         make(map[string]*core.UdpPeer),
		serverPubKeyAllowlist: make(map[string]struct{}),
	}
	return ac
}

// TestIsServerPubKeyAllowed_EmptyPubKey pins the hard reject on empty
// pubkeys. RedirectTarget.Validate() already rejects empty pubkeys
// upstream, but the allowlist helper is the defense-in-depth layer
// that catches a refactor which skips the outer shape check.
func TestIsServerPubKeyAllowed_EmptyPubKey(t *testing.T) {
	ac := ardTestAC(&Config{ServerPubKeyBase64: "registrationKey"})
	if ac.isServerPubKeyAllowed("") {
		t.Fatal("empty pubkey must be rejected regardless of allowlist contents")
	}
}

// TestIsServerPubKeyAllowed_RegistrationKey fences source 1: the
// shared registration pubkey from config.toml is always trusted. This
// mirrors the current operational reality (all servers in an ASG
// share a single keypair).
func TestIsServerPubKeyAllowed_RegistrationKey(t *testing.T) {
	ac := ardTestAC(&Config{ServerPubKeyBase64: "registrationKey"})
	if !ac.isServerPubKeyAllowed("registrationKey") {
		t.Fatal("registration pubkey must be trusted without explicit allowlist entry")
	}
	if ac.isServerPubKeyAllowed("some-other-key") {
		t.Fatal("non-registration key must not be trusted when allowlist is empty")
	}
}

// TestIsServerPubKeyAllowed_ServerTomlPeer fences source 2: any pubkey
// loaded from server.toml (UdpAC.serverPeerMap) is trusted. This is
// how operators have always declared "which NHP servers are ours" and
// #1156 reuses that list rather than introducing a parallel one.
func TestIsServerPubKeyAllowed_ServerTomlPeer(t *testing.T) {
	ac := ardTestAC(&Config{ServerPubKeyBase64: "registrationKey"})
	ac.serverPeerMap["peer-from-server-toml"] = &core.UdpPeer{PubKeyBase64: "peer-from-server-toml"}

	if !ac.isServerPubKeyAllowed("peer-from-server-toml") {
		t.Fatal("server.toml pubkey must be trusted")
	}
}

// TestIsServerPubKeyAllowed_ExtraAllowlist fences source 3: the
// ServerPubKeyAllowlist config slot. This is the forward-compat
// escape hatch for per-region / per-tenant server pubkeys that are
// rotated out-of-band and shouldn't require editing server.toml.
func TestIsServerPubKeyAllowed_ExtraAllowlist(t *testing.T) {
	extra := b64("extra-key")
	ac := ardTestAC(&Config{ServerPubKeyBase64: "registrationKey"})
	ac.rebuildServerPubKeyAllowlist([]string{extra})

	if !ac.isServerPubKeyAllowed(extra) {
		t.Fatal("ServerPubKeyAllowlist entry must be trusted")
	}
	if ac.isServerPubKeyAllowed(b64("not-in-any-source")) {
		t.Fatal("pubkey not in any of the three sources must be rejected")
	}
}

// TestNormalizeAllowlist_DropsInvalidBase64 fences the
// defense-in-depth fence added in #1239: an operator typo in
// config.toml (e.g. a truncated pubkey) must be dropped at load
// time with a warning, not accepted silently to fail-match in prod.
func TestNormalizeAllowlist_DropsInvalidBase64(t *testing.T) {
	valid := b64("valid-pubkey")
	set := normalizeAllowlist([]string{
		valid,
		"not-valid-base64!", // illegal char '!'
		"SGVsbG8gV29ybGQ",   // missing padding (length not multiple of 4)
		"",                  // empty
	})
	if len(set) != 1 {
		t.Fatalf("expected only the valid entry, got %d: %v", len(set), set)
	}
	if _, ok := set[valid]; !ok {
		t.Fatalf("valid base64 entry missing from set: %v", set)
	}
}

// TestAllowlistRebuild_Normalization pins the cleanup
// semantics for operator-supplied lists: whitespace trimmed,
// empties dropped, duplicates collapsed. Operators edit config.toml
// by hand; a trailing newline or accidental blank line must not
// silently become a catch-all or an extra meaningless entry.
func TestAllowlistRebuild_Normalization(t *testing.T) {
	ac := ardTestAC(&Config{})
	alpha, beta, gamma := b64("alpha"), b64("beta"), b64("gamma")

	ac.rebuildServerPubKeyAllowlist([]string{
		alpha,
		"  " + beta + "  ",  // whitespace must be trimmed
		"",                  // empty must be dropped
		"   ",               // whitespace-only must be dropped
		alpha,               // duplicate must collapse
		"\t" + gamma + "\n", // tabs and newlines must be trimmed
	})

	want := map[string]struct{}{alpha: {}, beta: {}, gamma: {}}
	ac.serverPeerMutex.RLock()
	got := ac.serverPubKeyAllowlist
	ac.serverPeerMutex.RUnlock()

	if len(got) != len(want) {
		t.Fatalf("allowlist size mismatch: want %d, got %d (%v)", len(want), len(got), got)
	}
	for k := range want {
		if _, ok := got[k]; !ok {
			t.Errorf("missing expected allowlist entry %q", k)
		}
	}
}

// TestAllowlistRebuild_ReplacesNotMerges fences the
// rollback path: an operator removing a pubkey from the TOML list
// and reloading must shrink the trusted set, not merge the old and
// new. Silent merge would mean a "rotated-out" pubkey stays trusted
// forever.
func TestAllowlistRebuild_ReplacesNotMerges(t *testing.T) {
	ac := ardTestAC(&Config{})
	oldKey1, oldKey2, newKey := b64("old-key-1"), b64("old-key-2"), b64("new-key-only")

	ac.rebuildServerPubKeyAllowlist([]string{oldKey1, oldKey2})
	ac.rebuildServerPubKeyAllowlist([]string{newKey})

	if ac.isServerPubKeyAllowed(oldKey1) {
		t.Error("old-key-1 must no longer be trusted after reload")
	}
	if ac.isServerPubKeyAllowed(oldKey2) {
		t.Error("old-key-2 must no longer be trusted after reload")
	}
	if !ac.isServerPubKeyAllowed(newKey) {
		t.Error("new-key-only must be trusted after reload")
	}
}

// TestAllowlistRebuild_ConcurrentReads exercises the
// reader/writer contract between a running ARD evaluation and a
// concurrent config reload. The serverPeerMutex is the shared lock;
// a missed lock acquisition here would surface as a race under -race.
func TestAllowlistRebuild_ConcurrentReads(t *testing.T) {
	keyA, keyB, missing := b64("key-a"), b64("key-b"), b64("not-in-set")
	ac := ardTestAC(&Config{ServerPubKeyBase64: "registrationKey"})
	ac.rebuildServerPubKeyAllowlist([]string{keyA, keyB})

	done := make(chan struct{})
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
				_ = ac.isServerPubKeyAllowed(keyA)
				_ = ac.isServerPubKeyAllowed(keyB)
				_ = ac.isServerPubKeyAllowed(missing)
			}
		}
	}()

	for i := 0; i < 200; i++ {
		ac.rebuildServerPubKeyAllowlist([]string{keyA, keyB})
	}
	close(done)
	wg.Wait()
}

// TestFilterRedispatchTargets_ConcurrentStrictFlip fences the cr
// round-1 finding that surfaced the underlying data race: a flip of
// `RequireServerPubKeyAllowlist` via updateBaseConfig is concurrent
// with a goroutine running filterRedispatchTargets. Pre-fix, both
// sides read/wrote `a.config.RequireServerPubKeyAllowlist` without
// the mutex and `-race` tripped. Post-fix, the snapshot taken at
// the top of filterRedispatchTargets + the grouped write in
// updateBaseConfig both hold serverPeerMutex.
func TestFilterRedispatchTargets_ConcurrentStrictFlip(t *testing.T) {
	ac := ardTestAC(&Config{
		ACId:                         "test-ac-1156",
		ServerPubKeyBase64:           "knownKey",
		RequireServerPubKeyAllowlist: false,
	})
	reg := mustNewACRegistration(t, ac)

	targets := []common.RedirectTarget{
		{IP: "10.0.0.1", Port: 62206, PubKeyBase64: "unknownKey"},
	}

	var stop atomic.Bool
	var wg sync.WaitGroup

	// Reader: run filterRedispatchTargets in a tight loop.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for !stop.Load() {
			_ = reg.filterRedispatchTargets(targets)
		}
	}()

	// Writer: flip strict via the same path production uses. Each
	// flip writes a.config.RequireServerPubKeyAllowlist under the
	// serverPeerMutex (grouped with the allowlist rebuild).
	//
	// defer stop.Store(true) at the top so any exit path — nominal
	// loop end, a t.Errorf early return, or a panic — unblocks the
	// reader and wg.Wait(). Otherwise the test hangs until the
	// suite-level timeout on any writer-side failure.
	//
	// The `cfg := *ac.config` copy happens BEFORE the reader
	// goroutine races with the writer — at this line no writer is
	// running yet. If a future refactor kicks off a setup-time
	// reload the copy would need to move inside the lock; for now
	// the ordering is the race-clean invariant.
	//
	// Load-bearing: if anyone adds a map-typed or pointer-typed
	// field to Config that ardTrustSnapshot reads AND reloadARDTrust
	// mutates, the shallow copy here would alias the backing
	// structure and produce a very confusing race under -race. In
	// that case the copy must move inside a.serverPeerMutex or
	// clone the field explicitly.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer stop.Store(true)
		cfg := *ac.config // shallow copy — all ARD-trust fields are scalar or slice
		for i := 0; i < 500; i++ {
			cfg.RequireServerPubKeyAllowlist = !cfg.RequireServerPubKeyAllowlist
			if err := ac.updateBaseConfig(cfg); err != nil {
				t.Errorf("updateBaseConfig failed: %v", err)
				return
			}
		}
	}()

	wg.Wait()
}

// TestFilterRedispatchTargets_PermitMode_UnknownPubkeyPassesThrough
// fences the permit-mode contract: an unknown pubkey is logged + a
// metric is emitted, but the target still makes it into the valid
// set. This is the burn-in mode — operators need time to verify
// the allowlist matches reality before flipping to strict.
func TestFilterRedispatchTargets_PermitMode_UnknownPubkeyPassesThrough(t *testing.T) {
	ac := ardTestAC(&Config{
		ACId:                         "test-ac-1156",
		ServerPubKeyBase64:           "knownKey",
		RequireServerPubKeyAllowlist: false, // permit mode (default)
	})
	reg := mustNewACRegistration(t, ac)

	targets := []common.RedirectTarget{
		{IP: "10.0.0.1", Port: 62206, PubKeyBase64: "unknownKey"},
	}

	valid := reg.filterRedispatchTargets(targets)
	if len(valid) != 1 {
		t.Fatalf("permit mode: unknown pubkey must pass through, got %d valid (want 1)", len(valid))
	}
	if valid[0].PubKeyBase64 != "unknownKey" {
		t.Errorf("permit mode: wrong target passed through: %+v", valid[0])
	}
}

// TestFilterRedispatchTargets_StrictMode_UnknownPubkeyRejected fences
// the strict-mode contract: unknown pubkeys are dropped from the
// valid set. This is the security-effective configuration — the
// whole point of #1156.
func TestFilterRedispatchTargets_StrictMode_UnknownPubkeyRejected(t *testing.T) {
	ac := ardTestAC(&Config{
		ACId:                         "test-ac-1156",
		ServerPubKeyBase64:           "knownKey",
		RequireServerPubKeyAllowlist: true, // strict mode
	})
	reg := mustNewACRegistration(t, ac)

	targets := []common.RedirectTarget{
		{IP: "10.0.0.1", Port: 62206, PubKeyBase64: "unknownKey"},
	}

	valid := reg.filterRedispatchTargets(targets)
	if len(valid) != 0 {
		t.Fatalf("strict mode: unknown pubkey must be rejected, got %d valid (want 0)", len(valid))
	}
}

// TestFilterRedispatchTargets_StrictMode_MixAcceptsKnownOnly fences
// the security-critical case: a malicious ARD can include real
// pubkeys alongside attacker-controlled ones to try to slip past a
// coarser filter. The filter must reject individual bad pubkeys
// while accepting the good ones — otherwise a single bad entry
// would either (a) pass silently or (b) take the whole ARD down,
// both of which are worse than per-target enforcement.
func TestFilterRedispatchTargets_StrictMode_MixAcceptsKnownOnly(t *testing.T) {
	extraKey := b64("extraKey")
	ac := ardTestAC(&Config{
		ACId:                         "test-ac-1156",
		ServerPubKeyBase64:           "registrationKey",
		RequireServerPubKeyAllowlist: true,
	})
	ac.rebuildServerPubKeyAllowlist([]string{extraKey})
	reg := mustNewACRegistration(t, ac)

	targets := []common.RedirectTarget{
		{IP: "10.0.0.1", Port: 62206, PubKeyBase64: "registrationKey"}, // source 1
		{IP: "10.0.0.2", Port: 62206, PubKeyBase64: "attackerKey"},     // should be rejected
		{IP: "10.0.0.3", Port: 62206, PubKeyBase64: extraKey},          // source 3
	}

	valid := reg.filterRedispatchTargets(targets)
	if len(valid) != 2 {
		t.Fatalf("strict mode: expected 2 valid (registrationKey + extraKey), got %d", len(valid))
	}
	var ips []string
	for _, v := range valid {
		ips = append(ips, v.IP)
	}
	joined := strings.Join(ips, ",")
	if !strings.Contains(joined, "10.0.0.1") || !strings.Contains(joined, "10.0.0.3") {
		t.Errorf("expected 10.0.0.1 and 10.0.0.3, got %s", joined)
	}
	if strings.Contains(joined, "10.0.0.2") {
		t.Error("attacker target 10.0.0.2 must not survive strict-mode filter")
	}
}

// TestFilterRedispatchTargets_StrictMode_AllUnknownDropsAll fences
// the "blast radius" property: a malicious ARD with only
// attacker-controlled pubkeys must leave the valid set empty, which
// HandleRedispatch then translates to a "no valid targets" error.
// This is the end-state behavior that stops the exfiltration chain.
func TestFilterRedispatchTargets_StrictMode_AllUnknownDropsAll(t *testing.T) {
	ac := ardTestAC(&Config{
		ACId:                         "test-ac-1156",
		ServerPubKeyBase64:           "knownKey",
		RequireServerPubKeyAllowlist: true,
	})
	reg := mustNewACRegistration(t, ac)

	targets := []common.RedirectTarget{
		{IP: "10.0.0.1", Port: 62206, PubKeyBase64: "evil-a"},
		{IP: "10.0.0.2", Port: 62206, PubKeyBase64: "evil-b"},
		{IP: "10.0.0.3", Port: 62206, PubKeyBase64: "evil-c"},
	}

	valid := reg.filterRedispatchTargets(targets)
	if len(valid) != 0 {
		t.Fatalf("strict mode: all unknown targets must be dropped, got %d valid", len(valid))
	}
}

// TestHandleRedispatch_StrictMode_AllUnknownReturnsError fences the
// end-to-end contract: the HandleRedispatch caller sees a
// "no valid targets" error, which callers already handle (they keep
// the existing NLB registration peer). No new error path needed.
// This is the test that explicitly proves #1156 is closed for the
// all-unknown case.
func TestHandleRedispatch_StrictMode_AllUnknownReturnsError(t *testing.T) {
	ac := ardTestAC(&Config{
		ACId:                         "test-ac-1156",
		ServerPubKeyBase64:           "knownKey",
		RequireServerPubKeyAllowlist: true,
		ServerEndpoint:               "test.internal",
	})
	reg := mustNewACRegistration(t, ac)

	ardMsg := &common.ACRedispatchMsg{
		Targets: []common.RedirectTarget{
			{IP: "10.0.0.1", Port: 62206, PubKeyBase64: "evil-key"},
		},
	}

	err := reg.HandleRedispatch(ardMsg)
	if err == nil {
		t.Fatal("expected error in strict mode with only unknown pubkeys")
	}
	if !strings.Contains(err.Error(), "no valid targets") {
		t.Errorf("expected 'no valid targets' error, got %q", err.Error())
	}
}

// TestAllowlistPubkeySources_DedupesAcrossSources pins the diagnostic
// helper: when the same pubkey appears in multiple sources (e.g.,
// registration key also listed in ServerPubKeyAllowlist), the
// diagnostic output must show it once. This is for operator-facing
// log lines where duplicates would mislead.
func TestAllowlistPubkeySources_DedupesAcrossSources(t *testing.T) {
	shared := b64("sharedKey")
	extra := b64("unique-extra")
	ac := ardTestAC(&Config{ServerPubKeyBase64: shared})
	ac.serverPeerMap[shared] = &core.UdpPeer{PubKeyBase64: shared}
	ac.rebuildServerPubKeyAllowlist([]string{shared, extra})

	sources := ac.allowlistPubkeySources()
	if len(sources) != 2 {
		t.Fatalf("expected 2 deduplicated sources, got %d: %v", len(sources), sources)
	}
	seen := map[string]bool{}
	for _, s := range sources {
		if seen[s] {
			t.Errorf("duplicate source in output: %s", s)
		}
		seen[s] = true
	}
}

// TestFilterRedispatchTargets_MetricsEmitted fences the contract
// that the per-mode counters must actually be incremented, not silently
// no-op'd. The metrics.Publisher is nil-safe, so a test that only
// checks returned slices would miss a regression where the metric
// emit was removed. Use the in-memory test hook.
func TestFilterRedispatchTargets_MetricsEmitted(t *testing.T) {
	t.Run("permit_mode_emits_permit_counter", func(t *testing.T) {
		ac := ardTestAC(&Config{
			ACId:                         "test-ac-1156",
			ServerPubKeyBase64:           "knownKey",
			RequireServerPubKeyAllowlist: false,
		})
		reg := mustNewACRegistration(t, ac)
		reg.metrics = metrics.NewPublisherForTest(t)

		targets := []common.RedirectTarget{
			{IP: "10.0.0.1", Port: 62206, PubKeyBase64: "unknown-a"},
			{IP: "10.0.0.2", Port: 62206, PubKeyBase64: "unknown-b"},
		}
		_ = reg.filterRedispatchTargets(targets)

		_, dimCounters := reg.metrics.CountersForTest(t)
		var permitHits, rejectHits float64
		for k, v := range dimCounters {
			if strings.Contains(k, MetricARDPubkeyPermitUnknown) {
				permitHits += v
			}
			if strings.Contains(k, MetricARDPubkeyRejected) {
				rejectHits += v
			}
		}
		if permitHits != 2 {
			t.Errorf("permit mode: expected MetricARDPubkeyPermitUnknown=2, got %v (counters=%v)", permitHits, dimCounters)
		}
		if rejectHits != 0 {
			t.Errorf("permit mode: MetricARDPubkeyRejected must not fire, got %v", rejectHits)
		}
	})

	t.Run("strict_mode_emits_reject_counter", func(t *testing.T) {
		ac := ardTestAC(&Config{
			ACId:                         "test-ac-1156",
			ServerPubKeyBase64:           "knownKey",
			RequireServerPubKeyAllowlist: true,
		})
		reg := mustNewACRegistration(t, ac)
		reg.metrics = metrics.NewPublisherForTest(t)

		targets := []common.RedirectTarget{
			{IP: "10.0.0.1", Port: 62206, PubKeyBase64: "evil-a"},
			{IP: "10.0.0.2", Port: 62206, PubKeyBase64: "evil-b"},
			{IP: "10.0.0.3", Port: 62206, PubKeyBase64: "evil-c"},
		}
		_ = reg.filterRedispatchTargets(targets)

		_, dimCounters := reg.metrics.CountersForTest(t)
		var permitHits, rejectHits float64
		for k, v := range dimCounters {
			if strings.Contains(k, MetricARDPubkeyPermitUnknown) {
				permitHits += v
			}
			if strings.Contains(k, MetricARDPubkeyRejected) {
				rejectHits += v
			}
		}
		if rejectHits != 3 {
			t.Errorf("strict mode: expected MetricARDPubkeyRejected=3, got %v (counters=%v)", rejectHits, dimCounters)
		}
		if permitHits != 0 {
			t.Errorf("strict mode: MetricARDPubkeyPermitUnknown must not fire, got %v", permitHits)
		}
	})

	t.Run("all_trusted_no_metric", func(t *testing.T) {
		ac := ardTestAC(&Config{
			ACId:                         "test-ac-1156",
			ServerPubKeyBase64:           "knownKey",
			RequireServerPubKeyAllowlist: true,
		})
		reg := mustNewACRegistration(t, ac)
		reg.metrics = metrics.NewPublisherForTest(t)

		targets := []common.RedirectTarget{
			{IP: "10.0.0.1", Port: 62206, PubKeyBase64: "knownKey"},
		}
		_ = reg.filterRedispatchTargets(targets)

		_, dimCounters := reg.metrics.CountersForTest(t)
		for k, v := range dimCounters {
			if strings.Contains(k, MetricARDPubkeyPermitUnknown) || strings.Contains(k, MetricARDPubkeyRejected) {
				t.Errorf("all-trusted path must not emit ARD pubkey counters; got %s=%v", k, v)
			}
		}
	})
}

// TestUpdateBaseConfig_FirstLoadPopulatesExtrasAllowlist is the
// direct regression fence for the allowlist-wipe bug caught in
// review of #1239: the Start path re-initialized
// a.serverPubKeyAllowlist AFTER loadBaseConfig populated it, so
// source 3 was dead on fresh boot until someone edited config.toml.
// Fails without the udpac.go wipe removal; passes after.
func TestUpdateBaseConfig_FirstLoadPopulatesExtrasAllowlist(t *testing.T) {
	extra := b64("extra-first-load")
	ac := firstLoadTestAC()

	if err := ac.updateBaseConfig(Config{
		ACId:                  "test-ac-1156",
		ServerPubKeyBase64:    "registrationKey",
		ServerPubKeyAllowlist: []string{extra},
	}); err != nil {
		t.Fatalf("first-load updateBaseConfig failed: %v", err)
	}

	if !ac.isServerPubKeyAllowed(extra) {
		t.Errorf("source 3 extras-list entry %s not trusted after first-load (allowlist-wipe regression)", extra)
	}
}

// TestUpdateBaseConfig_ReloadDoesNotChangeServerPubKeyBase64 fences
// the immutability invariant for source 1: ardTrustSnapshot reads
// a.config.ServerPubKeyBase64 outside the grouped-under-lock write
// set on the premise that this field never changes after first
// load. A future PR that adds it to the reload-patched set would
// silently break the snapshot — this test catches that.
func TestUpdateBaseConfig_ReloadDoesNotChangeServerPubKeyBase64(t *testing.T) {
	ac := firstLoadTestAC()
	initial := "originalRegistrationKey"
	if err := ac.updateBaseConfig(Config{ACId: "t", ServerPubKeyBase64: initial}); err != nil {
		t.Fatalf("first load failed: %v", err)
	}

	// Simulate a reload that attempts to change the registration
	// key. updateBaseConfig silently preserves the pre-load value
	// (logging log.Error but not returning an error) — the test
	// asserts that silent preservation.
	if err := ac.updateBaseConfig(Config{ACId: "t", ServerPubKeyBase64: "rotatedRegistrationKey"}); err != nil {
		t.Fatalf("reload failed: %v", err)
	}

	if ac.config.ServerPubKeyBase64 != initial {
		t.Errorf("ServerPubKeyBase64 silently changed on reload: got %q, want %q", ac.config.ServerPubKeyBase64, initial)
	}
}

// TestUpdateBaseConfig_StrictWithMalformedAllowlistFailsStart fences
// the deploy-time safety net: an operator who sets strict mode AND
// includes a malformed pubkey in the allowlist should find out at
// Start, not at the next ARD. The AC refuses to come up.
func TestUpdateBaseConfig_StrictWithMalformedAllowlistFailsStart(t *testing.T) {
	ac := firstLoadTestAC()

	err := ac.updateBaseConfig(Config{
		ACId:                         "t",
		RequireServerPubKeyAllowlist: true,
		ServerPubKeyAllowlist:        []string{"not-valid-base64!"},
	})
	if err == nil {
		t.Fatal("expected Start-time failure when strict=true and allowlist has malformed entries")
	}
	if !strings.Contains(err.Error(), "malformed base64") {
		t.Errorf("expected error to mention malformed base64, got %q", err.Error())
	}
}

// TestUpdateBaseConfig_PermitWithMalformedAllowlistSucceeds fences
// the other side of the Start-gate contract: permit
// mode tolerates malformed entries (they're logged via
// normalizeAllowlist's summary but the AC still comes up). Only
// strict mode fails Start. This pins the asymmetry as intentional —
// a future change that tightened permit mode to fail Start too
// would surprise operators who rely on permit-mode burn-in being
// lenient.
func TestUpdateBaseConfig_PermitWithMalformedAllowlistSucceeds(t *testing.T) {
	ac := firstLoadTestAC()
	validExtra := b64("valid-extra")

	err := ac.updateBaseConfig(Config{
		ACId:                         "t",
		ServerPubKeyBase64:           "registrationKey",
		RequireServerPubKeyAllowlist: false, // permit mode
		ServerPubKeyAllowlist:        []string{validExtra, "not-valid-base64!"},
	})
	if err != nil {
		t.Fatalf("permit mode with malformed entries must not fail Start, got %v", err)
	}

	// Valid entry survived; malformed entry did not.
	if !ac.isServerPubKeyAllowed(validExtra) {
		t.Error("valid entry must be trusted after permit-mode Start")
	}
	if ac.isServerPubKeyAllowed("not-valid-base64!") {
		t.Error("malformed entry must not be trusted (dropped at load time)")
	}
}

// TestUpdateBaseConfig_ReloadWipesAllowlist_Source1StillTrusted
// fences the rollback path: an operator removing the entire
// ServerPubKeyAllowlist from config.toml must not leave the
// registration pubkey (source 1) in a broken state. Empty extras
// is a legitimate configuration.
func TestUpdateBaseConfig_ReloadWipesAllowlist_Source1StillTrusted(t *testing.T) {
	ac := firstLoadTestAC()
	extra := b64("extra-key")
	if err := ac.updateBaseConfig(Config{
		ACId:                  "t",
		ServerPubKeyBase64:    "registrationKey",
		ServerPubKeyAllowlist: []string{extra},
	}); err != nil {
		t.Fatalf("first load failed: %v", err)
	}

	// Reload with empty ServerPubKeyAllowlist (operator removed it).
	if err := ac.updateBaseConfig(Config{
		ACId:                  "t",
		ServerPubKeyBase64:    "registrationKey",
		ServerPubKeyAllowlist: nil,
	}); err != nil {
		t.Fatalf("reload failed: %v", err)
	}

	if ac.isServerPubKeyAllowed(extra) {
		t.Error("removed extras-list entry must not be trusted after reload")
	}
	if !ac.isServerPubKeyAllowed("registrationKey") {
		t.Error("source 1 (ServerPubKeyBase64) must still be trusted after extras wipe")
	}
}

// TestPubKeyPrefix_ShortPassthrough and _LongTruncated fence the
// logging helper contract. Twelve chars is the sweet spot: enough to
// disambiguate typical base64 Curve25519 pubkeys in a fleet of a few
// hundred without bloating log lines.
func TestPubKeyPrefix_ShortPassthrough(t *testing.T) {
	short := "abc"
	if got := pubKeyPrefix(short); got != short {
		t.Errorf("short pubkey must pass through: got %q, want %q", got, short)
	}
}

func TestPubKeyPrefix_LongTruncated(t *testing.T) {
	long := "AAAABBBBCCCCDDDDEEEEFFFF"
	got := pubKeyPrefix(long)
	if !strings.HasPrefix(got, "AAAABBBBCCCC") {
		t.Errorf("prefix missing head: %q", got)
	}
	if !strings.HasSuffix(got, "…") {
		t.Errorf("prefix missing ellipsis marker: %q", got)
	}
}

// TestPubKeyPrefix_NonASCII_RuneSafe fences the belt-and-braces
// rune-boundary walk in pubKeyPrefix: a caller that violates the
// ASCII-only contract must still produce valid UTF-8, not slice
// mid-rune. The fixture prefixes one ASCII byte so byte 12 lands
// mid-rune and actually exercises the walk-back loop; a fixture
// aligned to rune boundaries at byte 12 would let the loop exit
// on the first iteration without exercising the guard.
func TestPubKeyPrefix_NonASCII_RuneSafe(t *testing.T) {
	// 1 ASCII byte + 8 CJK runes × 3 bytes = 25 bytes total.
	// Bytes 0..0   = 'a' (rune start)
	// Bytes 1..3   = first CJK rune, start at byte 1
	// Bytes 4..6   = second CJK rune, start at byte 4
	// Bytes 7..9   = third CJK rune, start at byte 7
	// Bytes 10..12 = fourth CJK rune, start at byte 10
	// Byte 12 is the third byte of the fourth rune — a
	// continuation byte, NOT a rune start. The walk-back loop
	// must step back to byte 10 (the start of that rune) before
	// slicing.
	input := "a你好世界你好世界"
	got := pubKeyPrefix(input)
	for i, r := range got {
		if r == '\uFFFD' {
			t.Errorf("rune-safe truncation emitted replacement char at byte %d in %q", i, got)
		}
	}
	// The walk-back must land ON a rune boundary strictly before
	// byte 12. Confirm by re-parsing: every rune in the prefix
	// (excluding the final ellipsis) is a valid decode.
	prefix := strings.TrimSuffix(got, "…")
	if prefix == "" {
		t.Fatalf("walk-back produced empty prefix (lost all content): %q", got)
	}
	for i, r := range prefix {
		if r == '\uFFFD' {
			t.Errorf("prefix contains replacement char at byte %d (%q)", i, prefix)
		}
	}
}
