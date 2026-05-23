package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	toml "github.com/pelletier/go-toml/v2"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/log"
)

func TestParseACRegistryEntry(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		check   func(*ACRegistryEntry) bool
	}{
		{
			name: "valid TOML entry",
			input: `# AC Registry Entry
PublicKey = "dGVzdHB1YmtleWJhc2U2NA=="
InstanceId = "i-1234567890abcdef0"
Ip = "10.0.0.100"
Port = 62206
RegisteredAt = 1703980800
`,
			wantErr: false,
			check: func(e *ACRegistryEntry) bool {
				return e.PublicKey == "dGVzdHB1YmtleWJhc2U2NA==" &&
					e.InstanceId == "i-1234567890abcdef0" &&
					e.Ip == "10.0.0.100" &&
					e.Port == common.DefaultNHPPort &&
					e.RegisteredAt == 1703980800
			},
		},
		{
			name:    "invalid TOML",
			input:   `not valid toml [[[`,
			wantErr: true,
		},
		{
			name: "minimal entry",
			input: `PublicKey = "abc123"
InstanceId = "i-test"
`,
			wantErr: false,
			check: func(e *ACRegistryEntry) bool {
				return e.PublicKey == "abc123" && e.InstanceId == "i-test"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry, err := parseACRegistryEntry([]byte(tt.input))
			if (err != nil) != tt.wantErr {
				t.Errorf("parseACRegistryEntry() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.check != nil && !tt.check(entry) {
				t.Errorf("parseACRegistryEntry() check failed, got %+v", entry)
			}
		})
	}
}

func TestACRegistryPrefix(t *testing.T) {
	if ACRegistryPrefix != "/nhp/ac-registry/" {
		t.Errorf("ACRegistryPrefix = %q, want %q", ACRegistryPrefix, "/nhp/ac-registry/")
	}
}

// TestUpdateBaseConfig_DoesNotHotReloadACPeerGracePeriodSeconds fences
// the "restart required" contract documented on
// Config.ACPeerGracePeriodSeconds. updateBaseConfig's reload branch
// does NOT propagate the value — the ACPeerChecker is built once at
// initHealthManager. If a future contributor adds propagation here
// without also wiring a checker-side Set, or adds checker propagation
// without dropping the restart-required docstring, this test fails.
//
// Plumbs a real *log.Logger onto the UdpServer so any future
// unconditional s.log.* call inside updateBaseConfig (e.g. a new
// info-log on every reload) doesn't nil-deref and mask the actual
// contract assertion. The logger writes to no directory (empty dir
// arg) and is Closed via t.Cleanup so its background writer
// goroutines don't outlive the test.
func TestUpdateBaseConfig_DoesNotHotReloadACPeerGracePeriodSeconds(t *testing.T) {
	const initialGrace = 60
	const newGrace = 120

	// Level 0 (silent) gates every log-writing method
	// (Info/Warning/Error/…) before the write path, so this plumbing
	// only guards the nil-method-ref boundary — the test's intent.
	// A future contributor who adds an unconditional s.log.Info(...)
	// to the reload branch will exercise the method lookup (no
	// panic), and the contract assertion below runs on its merits.
	// Setter methods on the logger (e.g., SetLogLevel) aren't level-
	// gated, but they also don't nil-deref on a real *log.Logger.
	//
	// Defense-in-depth: dir is t.TempDir() rather than "", so any
	// future test-level change that bumps the log level above 0 (or
	// any change to NewLogger's silent-level gating) won't leave
	// evaluate/audit log files littering the test's working
	// directory. t.TempDir cleans up automatically.
	logger := log.NewLogger("test", 0, t.TempDir(), "")
	t.Cleanup(logger.Close)

	s := &UdpServer{
		log:    logger,
		config: &Config{ACPeerGracePeriodSeconds: initialGrace},
	}
	incoming := Config{ACPeerGracePeriodSeconds: newGrace}

	if err := s.updateBaseConfig(incoming); err != nil {
		t.Fatalf("updateBaseConfig: %v", err)
	}

	if got := s.config.ACPeerGracePeriodSeconds; got != initialGrace {
		t.Errorf("s.config.ACPeerGracePeriodSeconds = %d after hot-reload, want %d "+
			"(restart-required contract). If propagation was intentionally added, "+
			"also wire a checker-side Set so the live checker adopts the new value, "+
			"and drop the restart-required docstring on Config.ACPeerGracePeriodSeconds.",
			got, initialGrace)
	}
}

// TestUpdateBaseConfig_DisableAgentValidationHotReloadPreservesCloudModeOverride
// fences the hot-reload regression on DisableAgentValidation in
// cloud mode. Start() resolves DisableAgentValidation against the
// cloud-mode override (operator || (cloudMode && agentPeerLookup
// != nil)) and feeds the result into device.NewDevice, but the
// pre-fix updateBaseConfig hot-reload path passed
// conf.DisableAgentValidation unmodified to device.SetOption. On
// a server.toml edit in cloud mode, the device flipped back to
// the operator literal `false` — every cloud-mode agent
// first-knock then failed at the responder layer with no metric
// to alarm on (the lookup is wired, just never reached).
//
// Fix: updateBaseConfig now re-applies the override via
// computeEffectiveDisableAgentValidation. This test reproduces
// the scenario:
//   - cloud mode is on (storageConfig.Backend == dynamodb)
//   - agentPeerLookup is non-nil
//   - operator's DisableAgentValidation flips false→true→false
//   - device.Option().DisableAgentPeerValidation must stay TRUE
//     on every reload (the override is non-negotiable while the
//     lookup is wired).
func TestUpdateBaseConfig_DisableAgentValidationHotReloadPreservesCloudModeOverride(t *testing.T) {
	logger := log.NewLogger("test", 0, t.TempDir(), "")
	t.Cleanup(logger.Close)

	device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), &core.DeviceOptions{
		// Start at the resolved value as Start() would have left it.
		DisableAgentPeerValidation: true,
	})
	if device == nil {
		t.Fatal("core.NewDevice returned nil")
	}
	defer device.Stop()

	// Construct a minimal lookup; non-nil is all the helper checks.
	inner := newFakeAgentKeysQuerier()
	lookup, err := NewAgentPeerLookup(inner, "qurl-agent-keys-test")
	if err != nil {
		t.Fatalf("NewAgentPeerLookup: %v", err)
	}

	s := &UdpServer{
		log:             logger,
		config:          &Config{DisableAgentValidation: true}, // matches what Start would have observed
		device:          device,
		agentPeerLookup: lookup,
		storageConfig:   &StorageConfig{Backend: StorageBackendDynamoDB},
	}

	// Hot-reload #1: operator drops DisableAgentValidation back to
	// false. Pre-fix this flipped the device option to false; the
	// cloud-mode override must keep it true.
	if err := s.updateBaseConfig(Config{DisableAgentValidation: false}); err != nil {
		t.Fatalf("updateBaseConfig: %v", err)
	}
	if got := device.Option().DisableAgentPeerValidation; !got {
		t.Errorf("after hot-reload to operator=false in cloud mode, device.Option().DisableAgentPeerValidation=%v want true (cloud-mode override must be re-applied; otherwise every agent first-knock fails at the responder layer)", got)
	}
	if got := s.config.DisableAgentValidation; got != false {
		t.Errorf("s.config.DisableAgentValidation=%v want false (cached file state must reflect operator's literal so the next delta-compare works)", got)
	}

	// Hot-reload #2: operator flips back to true (matches override).
	// Device stays at true.
	if err := s.updateBaseConfig(Config{DisableAgentValidation: true}); err != nil {
		t.Fatalf("updateBaseConfig: %v", err)
	}
	if got := device.Option().DisableAgentPeerValidation; !got {
		t.Errorf("after hot-reload to operator=true, device option=%v want true", got)
	}
}

// TestLoadPeers_RefusesCloudModeWithAgentTomlCoexistence fences
// the agent.toml + cloud-mode coexistence guard. The two paths
// cannot coexist: updateAgentPeers (called from loadPeers and the
// agent.toml WatchFile callback) builds a fresh peer map and
// removes from device.peerMap any pubkey absent from the new map
// — wiping every DDB-resolved peer on each agent.toml touch.
// loadPeers must refuse boot when both are wired.
func TestLoadPeers_RefusesCloudModeWithAgentTomlCoexistence(t *testing.T) {
	tmpDir := t.TempDir()
	etcDir := filepath.Join(tmpDir, "etc")
	if err := os.MkdirAll(etcDir, 0o755); err != nil {
		t.Fatalf("mkdir etc: %v", err)
	}
	// Empty agent.toml — even an empty [[Agents]] block triggers
	// the watcher-wipe hazard the guard fences.
	if err := os.WriteFile(filepath.Join(etcDir, "agent.toml"), []byte("[[Agents]]\n"), 0o644); err != nil {
		t.Fatalf("write agent.toml: %v", err)
	}
	// server.toml is required by loadPeers' earlier sections; provide
	// a minimal valid file so we reach the agent.toml branch.
	if err := os.WriteFile(filepath.Join(etcDir, "server.toml"), []byte(""), 0o644); err != nil {
		t.Fatalf("write server.toml: %v", err)
	}

	orig := ExeDirPath
	t.Cleanup(func() { ExeDirPath = orig })
	ExeDirPath = tmpDir

	inner := newFakeAgentKeysQuerier()
	lookup, err := NewAgentPeerLookup(inner, "qurl-agent-keys-test")
	if err != nil {
		t.Fatalf("NewAgentPeerLookup: %v", err)
	}

	logger := log.NewLogger("test", 0, t.TempDir(), "")
	t.Cleanup(logger.Close)

	s := &UdpServer{
		log:             logger,
		config:          &Config{},
		agentPeerLookup: lookup,
		storageConfig:   &StorageConfig{Backend: StorageBackendDynamoDB},
	}

	loadErr := s.loadPeers()
	if loadErr == nil {
		t.Fatal("loadPeers returned nil error; expected coexistence-conflict refusal")
	}
	if !strings.Contains(loadErr.Error(), "agent peer registry conflict") {
		t.Errorf("loadPeers err=%q does not mention 'agent peer registry conflict' — guard message regressed", loadErr.Error())
	}
}

func TestUpdateResources_NilAspData(t *testing.T) {
	// This test verifies that updateResources handles nil aspData entries gracefully.
	// TOML unmarshals empty tables (e.g., "[passcode]" with no fields) as nil pointers.
	// The server should skip these entries without panicking.

	s := &UdpServer{}

	// Create a map with nil entry (simulates TOML empty table)
	aspMap := common.AuthSvcProviderMap{
		"passcode": nil, // Simulate TOML empty table like "[passcode]\n# comment only"
	}

	// Should not panic
	err := s.updateResources(aspMap)
	if err != nil {
		t.Errorf("updateResources() unexpected error = %v", err)
	}

	// Verify the nil entry is preserved in the map (for static plugin lookup)
	if len(s.authServiceMap) != 1 {
		t.Errorf("authServiceMap length = %d, want 1", len(s.authServiceMap))
	}
}

func TestUpdateResources_MixedNilAndValid(t *testing.T) {
	// Test that valid entries are processed even when nil entries exist

	s := &UdpServer{}

	aspMap := common.AuthSvcProviderMap{
		"nil-plugin":   nil, // Empty table
		"valid-plugin": &common.AuthServiceProviderData{PluginPath: ""},
	}

	err := s.updateResources(aspMap)
	if err != nil {
		t.Errorf("updateResources() unexpected error = %v", err)
	}

	// Both entries should be in the map
	if len(s.authServiceMap) != 2 {
		t.Errorf("authServiceMap length = %d, want 2", len(s.authServiceMap))
	}

	// Valid entry should have AuthSvcId set
	if s.authServiceMap["valid-plugin"] != nil && s.authServiceMap["valid-plugin"].AuthSvcId != "valid-plugin" {
		t.Errorf("valid-plugin AuthSvcId = %q, want %q", s.authServiceMap["valid-plugin"].AuthSvcId, "valid-plugin")
	}
}

// TestTunnelServerResourceTOMLOverlay_SchemaMatchesAuthSvcProviderMap fences
// the rendered TOML shape that `terraform/resources.tf`'s
// `local.tunnel_server_resource_toml_overlay` produces against the Go
// struct `loadResources` unmarshals into.
//
// Why this test exists: `pelletier/go-toml/v2` maps TOML keys to Go
// field NAMES (it doesn't honor `json:` tags). The overlay must spell
// out `ResourceGroups."<resId>".Resources."<resName>"` — NOT the
// shallower `Resources."<resName>"` shape used by plugin-side
// `examples/server_plugin/etc/resource.toml`. The shallower shape
// parses as valid TOML and `aspMap["layerv"]` ends up non-nil, but
// `aspMap["layerv"].ResourceGroups` is empty and every FRPS knock
// short-circuits with `ErrACConnectionNotFound`. The negative-shape
// sibling test below locks that bug class in.
//
// If the TF rendering ever changes shape, update both halves of the
// schema in lockstep: this test, the heredoc body in
// `terraform/resources.tf::local.tunnel_server_resource_toml_overlay`,
// and the schema comment above that local. See SLACK_QURL_ROLLOUT.md §6.
func TestTunnelServerResourceTOMLOverlay_SchemaMatchesAuthSvcProviderMap(t *testing.T) {
	// Mirrors the production tfvar values
	// (`terraform/environments/{sandbox,prod}/terraform.tfvars`):
	//   ac_auth_service_id  = "layerv"
	//   qurl_default_ac_id  = "layerv-ac-tf"
	//   connect_layerv_host = "connect.layerv.{ai,xyz}"
	// ResourceID mirrors `local.tunnel_server_res_id` —
	// `qurl-tunnel-server`, the spec-aligned name for the protected
	// reverse-tunnel control channel. Single fixed value across all
	// environments (the prior pre-spec deploy rendered a region-keyed
	// alias + env-canonical alias under `frps-*`; that was a spec
	// violation per CSA "Stealth Mode SDP" Appendix 2 — resId names
	// the protected resource, not its placement).
	//
	// The leading sentinel comment matches `local.frps_overlay_sentinel`
	// in `terraform/resources.tf` (used by `user_data.sh.tpl`'s
	// self-healing sed-strip on user_data re-exec).
	//
	// Hostname is the customer-facing dial target the agent's
	// `DestHost()` prefers over `Addr.Ip`. The fixture below carries
	// the current TRANSITIONAL value (`connect.layerv.ai`, the public
	// AC ingress fronting FRPS today); the assertion is a literal
	// round-trip of that value, NOT a load-bearing invariant on the
	// target shape. Per nhp #2019 ("AC out of the FRPS data path"),
	// the long-term target points Hostname at FRPS directly — at which
	// point this fixture (and the variable + AC-NLB plumbing it
	// mirrors) is removal work, not edit work. Do NOT add structural
	// fences here that would reject a non-AC-ingress Hostname; the
	// fence we DO want is the `Addr.Ip == ""` round-trip below, which
	// codifies the DefaultIp sentinel mechanism — that mechanism is
	// independent of where Hostname points and survives the redesign.
	//
	// OpenTime in the fixture is HARDCODED to 120 — the literal TF-side
	// value in `local.tunnel_server_open_time = 120` (terraform/resources.tf).
	// The round-trip assert below compares the unmarshaled value against
	// the Go constant `DefaultIpOpenTime`.
	//
	// What this fences and what it doesn't:
	//   - Go-side drift (`DefaultIpOpenTime` moves) IS fenced: the
	//     assertion fails until either the constant moves back or the
	//     fixture literal is updated alongside it. Forces a Go-side
	//     coordinated update.
	//   - Fixture-vs-Go drift (a future edit changes 120 in the
	//     fixture without moving the constant) IS fenced for the
	//     same reason.
	//   - TF-side drift (`local.tunnel_server_open_time` moves) is NOT
	//     fenced by this test. Without shelling out to `terraform console`
	//     from Go, the fixture can't sample the live TF render. A future
	//     PR that moves the TF local without moving the Go constant +
	//     fixture would silently produce a TF-Go mismatch at boot. The
	//     single-source-of-truth comment on the TF local
	//     (terraform/resources.tf::tunnel_server_open_time) flags this
	//     as a coordinated-update requirement; a live render-vs-Go
	//     drift fence is tracked in #2008.
	//
	// Using `fmt.Sprintf` to inject `DefaultIpOpenTime` into the
	// fixture would make even the Go-side leg a tautology (both sides
	// the same constant) — DO NOT do that.
	overlay := `
# FRPS bootstrap overlay v2
# Wave 5 prep — SLACK_QURL_ROLLOUT.md §6 (FRPS-behind-AC redesign 2026-05-18).
# INVARIANT: inner ` + "`Resources.\"<resName>\"`" + ` key MUST equal outer
# ` + "`ResourceGroups.\"<resId>\"`" + ` key — see resources.tf for rationale.

["layerv".ResourceGroups."qurl-tunnel-server"]
OpenTime = 120
SkipAuth = true

["layerv".ResourceGroups."qurl-tunnel-server".Resources."qurl-tunnel-server"]
ACId = "layerv-ac-tf"
Hostname = "connect.layerv.ai"
# Addr.Ip intentionally empty — AC substitutes DefaultIp at ipset-write time.
# Hostname above is what the agent dials (DestHost() prefers Hostname over Ip).
Addr.Ip = ""
Addr.Port = 7000
Addr.Protocol = "tcp"

# FRPS bootstrap overlay end
`

	aspMap := make(common.AuthSvcProviderMap)
	if err := toml.Unmarshal([]byte(overlay), &aspMap); err != nil {
		t.Fatalf("toml.Unmarshal: %v", err)
	}

	asp := aspMap["layerv"]
	if asp == nil {
		t.Fatal("aspMap[\"layerv\"] is nil — top-level table not unmarshaled")
	}

	if got, want := len(asp.ResourceGroups), 1; got != want {
		t.Fatalf("ResourceGroups len=%d want=%d (single spec-aligned qurl-tunnel-server resId) — schema regression?", got, want)
	}

	rg := asp.ResourceGroups["qurl-tunnel-server"]
	if rg == nil {
		t.Fatal("ResourceGroups[\"qurl-tunnel-server\"] is nil — nesting regression?")
	}
	// Fences drift between `local.tunnel_server_open_time = 120` in
	// terraform/resources.tf and `DefaultIpOpenTime = 120` in
	// endpoints/server/constants.go. If either side is bumped without
	// the other, this assertion fails and forces a coordinated update
	// (the test fixture above still hardcodes 120 in the rendered TOML
	// string; the failure surfaces here, and the fix is to bump the TF
	// local AND the test fixture in lockstep with the constant). See
	// the `tunnel_server_open_time` doc in terraform/resources.tf for
	// the AC-constant-mirror rationale.
	if got, want := rg.OpenTime, uint32(DefaultIpOpenTime); got != want {
		t.Errorf("ResourceGroups[\"qurl-tunnel-server\"].OpenTime = %d, want %d (DefaultIpOpenTime). The three-way chain is: TF `local.tunnel_server_open_time` (terraform/resources.tf) → rendered TOML literal in the fixture above → `DefaultIpOpenTime` constant (endpoints/server/constants.go). A drift on any leg fails this assertion; the fix is to update all three in lockstep.", got, want)
	}
	// SkipAuth = true is load-bearing: the layerv static plugin
	// (`endpoints/server/staticplugins/layerv/main.go::AuthWithNHP`)
	// fences on `res.SkipAuth` and refuses with
	// `ErrBackendAuthRequired` (52007) if it's false. The agent-
	// bootstrap flow has no backend-auth path — X25519+DDB pubkey
	// resolution upstream IS the access control — so the TF render
	// MUST flag SkipAuth on the qurl-tunnel-server resource. A TF-side
	// regression that drops `SkipAuth = true` from
	// `local.tunnel_server_resource_toml_overlay` would silently turn
	// every production knock into a 52007. This assertion fails first.
	if !rg.SkipAuth {
		t.Errorf("ResourceGroups[\"qurl-tunnel-server\"].SkipAuth = false, want true. The layerv plugin fences on res.SkipAuth; a missing SkipAuth=true in the FRPS overlay rendering surfaces here, not at first prod knock. Restore the `SkipAuth = true` line in `local.tunnel_server_resource_toml_overlay` (terraform/resources.tf) alongside OpenTime.")
	}
	// Critical: the inner Resources map MUST be populated. `handleNhpOpenResource`
	// iterates `res.Resources`; an empty Resources map silently yields zero
	// AC operations and zero ackMsg.ResourceHost / ackMsg.ACTokens entries —
	// the bug class this regression test exists to fence.
	if got, want := len(rg.Resources), 1; got != want {
		t.Fatalf("ResourceGroups[\"qurl-tunnel-server\"].Resources len=%d want=%d", got, want)
	}
	// Inner resourceName matches outer resourceId so the agent's
	// `ackMsg.ResourceHost[resource_id]` lookup resolves
	// (`pkg/tunnel/knock.go::pickResourceHost`).
	ri := rg.Resources["qurl-tunnel-server"]
	if ri == nil {
		t.Fatal("ResourceGroups[\"qurl-tunnel-server\"].Resources[\"qurl-tunnel-server\"] is nil — inner-key collapse regression?")
	}
	if ri.ACId != "layerv-ac-tf" {
		t.Errorf("ResourceInfo.ACId = %q, want %q", ri.ACId, "layerv-ac-tf")
	}
	// Literal round-trip of the fixture's Hostname — NOT a structural
	// invariant on what Hostname must be (see nhp #2019 — Hostname
	// will point at FRPS directly once AC is out of the data path).
	if ri.Hostname != "connect.layerv.ai" {
		t.Errorf("ResourceInfo.Hostname = %q, want %q", ri.Hostname, "connect.layerv.ai")
	}
	// Addr.Ip MUST round-trip as empty so the AC substitutes its DefaultIp
	// at ipset-write time. A non-empty Addr.Ip would pin the ipset entry
	// to whatever was rendered, breaking the load-bearing fence semantics.
	if ri.Addr == nil {
		t.Fatal("ResourceInfo.Addr is nil")
	}
	if ri.Addr.Ip != "" {
		t.Errorf("ResourceInfo.Addr.Ip = %q, want empty (AC DefaultIp substitution sentinel)", ri.Addr.Ip)
	}
	if ri.Addr.Port != 7000 {
		t.Errorf("ResourceInfo.Addr.Port = %d, want 7000", ri.Addr.Port)
	}
	if ri.Addr.Protocol != "tcp" {
		t.Errorf("ResourceInfo.Addr.Protocol = %q, want %q", ri.Addr.Protocol, "tcp")
	}
}

// TODO(nhp #2019 — "AC out of the FRPS data path"): a future
// regression test belongs here that fences the L3-ONLY target shape,
// once AC is no longer in the FRPS data plane. Target invariants
// (not yet codifiable):
//   - Hostname points directly at FRPS's own controlled public
//     ingress (NOT the AC ingress; NOT `connect.layerv.{ai,xyz}`).
//   - The AC pushes ipset deltas to FRPS out-of-band (no AC NLB:7000
//     listener, no AC Traefik TCP forwarder, no AC autoscaling
//     attachment on the FRPS-control TG).
//
// Why this test is intentionally absent today: the FRPS-behind-AC
// shape this PR introduces is a TRANSITIONAL accommodation
// (`connect.layerv.{ai,xyz}` → AC NLB:7000 → AC Traefik → private
// FRPS). Codifying "Hostname must NOT end in `.internal` AND must
// NOT start with `frps-`" — the prior round of this test — would
// pin the transitional shape into the source tree as a protocol
// invariant and steer future contributors away from the L3-only
// target. The `Addr.Ip == ""` round-trip fence in
// `TestTunnelServerResourceTOMLOverlay_SchemaMatchesAuthSvcProviderMap`
// above stays, because the DefaultIp sentinel mechanism is sound
// independent of where the AC sits in the data plane.
//
// When nhp #2019 lands, write the replacement test here.

// TestTunnelServerResourceTOMLOverlay_ShallowSchemaProducesEmptyResourceGroups
// is the negative-shape companion to the positive test above. It pins
// the bug class itself: feeding `loadResources` the shallower
// `["aspId".Resources."<resName>"]` shape used by plugin-side configs
// MUST leave `aspMap["layerv"].ResourceGroups` empty, because
// `pelletier/go-toml/v2` maps `Resources` to a field that doesn't
// exist on `AuthServiceProviderData` (the field is `ResourceGroups`)
// and silently drops it.
//
// If this assertion ever stops holding — e.g., a future TOML library
// swap adds a JSON-tag fallback heuristic — both the positive test
// above AND this one need a coordinated rewrite. Either direction
// alone is a silent semantic change.
func TestTunnelServerResourceTOMLOverlay_ShallowSchemaProducesEmptyResourceGroups(t *testing.T) {
	// The exact shape the previous round of this overlay rendered —
	// fenced here so a future maintainer can see "this is what NOT to
	// render" alongside the positive test.
	wrong := `
["layerv"]
OpenTime = 120

["layerv".Resources."qurl-tunnel-server"]
ACId = "layerv-ac-tf"
Hostname = "connect.layerv.ai"
# Addr.Ip intentionally empty — AC substitutes DefaultIp at ipset-write time.
Addr.Ip = ""
Addr.Port = 7000
Addr.Protocol = "tcp"
`

	aspMap := make(common.AuthSvcProviderMap)
	if err := toml.Unmarshal([]byte(wrong), &aspMap); err != nil {
		t.Fatalf("toml.Unmarshal of shallow shape unexpectedly failed: %v", err)
	}

	asp := aspMap["layerv"]
	if asp == nil {
		t.Fatal("aspMap[\"layerv\"] is nil — shallow shape should still create the top-level table")
	}
	if got := len(asp.ResourceGroups); got != 0 {
		t.Fatalf("shallow shape unexpectedly populated ResourceGroups (len=%d) — TOML decoder behavior changed; both this test and the positive test need a coordinated update. Got: %+v", got, asp.ResourceGroups)
	}
}

// TestApplyHttpTimeoutDefaults table-drives the floor-up logic that
// guards the CloudFront keep-alive contract (see PR #1795). Pure logic,
// no UdpServer required.
func TestApplyHttpTimeoutDefaults(t *testing.T) {
	tests := []struct {
		name      string
		in        HttpConfig
		wantRead  int
		wantWrite int
		wantIdle  int
	}{
		{
			name:      "zero values get defaulted (normal not-set case)",
			in:        HttpConfig{},
			wantRead:  DefaultHttpRequestReadTimeoutMs,
			wantWrite: DefaultHttpResponseWriteTimeoutMs,
			wantIdle:  DefaultHttpServerIdleTimeoutMs,
		},
		{
			name:      "below-floor positive values get defaulted up",
			in:        HttpConfig{ReadTimeoutMs: 100, WriteTimeoutMs: 500, IdleTimeoutMs: 999},
			wantRead:  DefaultHttpRequestReadTimeoutMs,
			wantWrite: DefaultHttpResponseWriteTimeoutMs,
			wantIdle:  DefaultHttpServerIdleTimeoutMs,
		},
		{
			name:      "exact floor (1000) carries through unchanged",
			in:        HttpConfig{ReadTimeoutMs: 1000, WriteTimeoutMs: 1000, IdleTimeoutMs: 1000},
			wantRead:  1000,
			wantWrite: 1000,
			wantIdle:  1000,
		},
		{
			name:      "above-floor values carry through unchanged",
			in:        HttpConfig{ReadTimeoutMs: 60000, WriteTimeoutMs: 45000, IdleTimeoutMs: 90000},
			wantRead:  60000,
			wantWrite: 45000,
			wantIdle:  90000,
		},
		{
			// IdleTimeoutMs > 1000 but < DefaultHttpServerIdleTimeoutMs:
			// permitted (carries through) but emits a separate Warning
			// about the keep-alive contract risk. The Warning side-effect
			// isn't asserted here (capturing log output cleanly is more
			// plumbing than the test warrants); just verify the value
			// itself isn't silently floored, which would mask any
			// deliberate operator override.
			name:      "above-1000ms-floor but below safe default carries through",
			in:        HttpConfig{ReadTimeoutMs: 30000, WriteTimeoutMs: 30000, IdleTimeoutMs: 5000},
			wantRead:  30000,
			wantWrite: 30000,
			wantIdle:  5000,
		},
		{
			name:      "mixed: one below floor, others above",
			in:        HttpConfig{ReadTimeoutMs: 50, WriteTimeoutMs: 30000, IdleTimeoutMs: 36000},
			wantRead:  DefaultHttpRequestReadTimeoutMs,
			wantWrite: 30000,
			wantIdle:  36000,
		},
		{
			name:      "negative values get defaulted (treated as below-floor)",
			in:        HttpConfig{ReadTimeoutMs: -1, WriteTimeoutMs: -100, IdleTimeoutMs: -1},
			wantRead:  DefaultHttpRequestReadTimeoutMs,
			wantWrite: DefaultHttpResponseWriteTimeoutMs,
			wantIdle:  DefaultHttpServerIdleTimeoutMs,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conf := tc.in
			applyHttpTimeoutDefaults(&conf)
			if conf.ReadTimeoutMs != tc.wantRead {
				t.Errorf("ReadTimeoutMs: got %d, want %d", conf.ReadTimeoutMs, tc.wantRead)
			}
			if conf.WriteTimeoutMs != tc.wantWrite {
				t.Errorf("WriteTimeoutMs: got %d, want %d", conf.WriteTimeoutMs, tc.wantWrite)
			}
			if conf.IdleTimeoutMs != tc.wantIdle {
				t.Errorf("IdleTimeoutMs: got %d, want %d", conf.IdleTimeoutMs, tc.wantIdle)
			}
		})
	}

	// Sanity check: defaults themselves carry the keep-alive contract.
	// Any future bump to the constants must keep idle >= 30000 (CF
	// origin_keepalive_timeout) + a buffer. This isn't a contract test
	// per se — that lives in TF — but a regression here would mean the
	// constants no longer satisfy the LayerV deployment topology.
	if DefaultHttpServerIdleTimeoutMs < 30000 {
		t.Errorf("DefaultHttpServerIdleTimeoutMs = %d is below CloudFront origin_keepalive_timeout (30000ms); contract violation. See PR #1795.", DefaultHttpServerIdleTimeoutMs)
	}
}
