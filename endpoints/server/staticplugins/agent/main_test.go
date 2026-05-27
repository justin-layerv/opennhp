package agent

import (
	"errors"
	"fmt"
	"testing"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/plugins"
)

// callbackCapture records the inputs newHelper's stub callback receives,
// so a test can assert AuthWithNHP plumbs the looked-up ResourceData
// through to handleNhpOpenResource intact.
type callbackCapture struct {
	calls int
	req   *common.NhpAuthRequest
	res   *common.ResourceData
	// resourceHostAtEntry snapshots req.Ack.ResourceHost at the moment
	// the callback is invoked. The plugin contract is to NOT pre-write
	// ResourceHost (handleNhpOpenResource re-initializes it from per-AC
	// ops); a future maintainer who "fixes" this by adding a pre-write
	// would surface here.
	resourceHostAtEntry map[string]string
}

func newHelper(asp *common.AuthServiceProviderData, capture *callbackCapture, returnErr error) *plugins.NhpServerPluginHelper {
	return &plugins.NhpServerPluginHelper{
		AspData: asp,
		AuthWithNhpCallbackFunc: func(req *common.NhpAuthRequest, res *common.ResourceData) (*common.ServerKnockAckMsg, error) {
			capture.calls++
			capture.req = req
			capture.res = res
			capture.resourceHostAtEntry = req.Ack.ResourceHost
			// Successful dispatch normally fills these in; mirror handleNhpOpenResource's
			// shape (success errCode) so a passing test reflects production.
			if returnErr == nil {
				req.Ack.ErrCode = common.ErrSuccess.ErrorCode()
				req.Ack.ErrMsg = common.ErrSuccess.Error()
			}
			return req.Ack, returnErr
		},
	}
}

// newAspWithTunnelServer builds a direct-row fixture for the defensive
// normalization path. Standard qURL tunnel rows are per-AZ suffix rows, but if
// a manual/test catalog includes a placement-neutral row, AuthWithNHP must
// still force the ACK host into explicit host:port form.
func newAspWithTunnelServer() *common.AuthServiceProviderData {
	return &common.AuthServiceProviderData{
		AuthSvcId: "agent",
		ResourceGroups: common.ResourceGroupMap{
			"qurl-tunnel-server": &common.ResourceData{
				ResourceGroup: common.ResourceGroup{
					AuthServiceId: "agent",
					ResourceId:    "qurl-tunnel-server",
					OpenTime:      120,
					Resources: map[string]*common.ResourceInfo{
						"qurl-tunnel-server": {
							ACId:     "layerv-ac-tf",
							Hostname: "connect.test",
							// Ip is empty intentionally so DestHost() falls back to
							// Hostname (see nhpmsg.go DestHost / Hosts). The
							// agent flow carries Hostname (customer-facing AC
							// ingress), not Ip.
							Addr: &common.NetAddress{
								Ip:       "",
								Port:     7000,
								Protocol: "tcp",
							},
						},
					},
				},
				SkipAuth: true, // load-bearing: AuthWithNHP fences on this.
			},
		},
	}
}

func newAspWithTunnelServerAZRows() *common.AuthServiceProviderData {
	return &common.AuthServiceProviderData{
		AuthSvcId: "agent",
		ResourceGroups: common.ResourceGroupMap{
			"qurl-tunnel-server-a": newTunnelServerAZResource("qurl-tunnel-server-a", 7000),
			"qurl-tunnel-server-b": newTunnelServerAZResource("qurl-tunnel-server-b", 7001),
			"qurl-tunnel-server-c": newTunnelServerAZResource("qurl-tunnel-server-c", 7002),
		},
	}
}

func newTunnelServerAZResource(resourceID string, port int) *common.ResourceData {
	return &common.ResourceData{
		ResourceGroup: common.ResourceGroup{
			AuthServiceId: "agent",
			ResourceId:    resourceID,
			OpenTime:      120,
			Resources: map[string]*common.ResourceInfo{
				resourceID: {
					ACId:       "layerv-ac-tf",
					Hostname:   "connect.test",
					PortSuffix: true,
					Addr: &common.NetAddress{
						Ip:       "",
						Port:     port,
						Protocol: "tcp",
					},
				},
			},
		},
		SkipAuth: true,
	}
}

func newKnockReq(resourceId string) *common.NhpAuthRequest {
	return &common.NhpAuthRequest{
		Msg: &common.AgentKnockMsg{
			UserId:        "test-agent",
			AuthServiceId: "agent",
			ResourceId:    resourceId,
		},
		Ack: &common.ServerKnockAckMsg{},
		// Clearly-sentinel non-pubkey. The `!` is intentional — it's
		// NOT a valid base64 character, so any future plugin code
		// that base64-decodes this field will fail loud with a parse
		// error rather than silently returning 32 garbage bytes.
		PublicKey: "PLACEHOLDER!NOT-A-REAL-X25519-PUBKEY",
	}
}

func TestAuthWithNHP_QURLTunnelServerPlacementIsServerOwned(t *testing.T) {
	capture := &callbackCapture{}
	helper := newHelper(newAspWithTunnelServerAZRows(), capture, nil)
	req := newKnockReq("qurl-tunnel-server")
	req.PublicKey = "client-instance-public-key-a"

	ack, err := AuthWithNHP(req, helper)
	if err != nil {
		t.Fatalf("AuthWithNHP returned err: %v", err)
	}
	if ack.ErrCode != common.ErrSuccess.ErrorCode() {
		t.Fatalf("ack.ErrCode=%q want success", ack.ErrCode)
	}
	if capture.calls != 1 {
		t.Fatalf("callback calls=%d want=1", capture.calls)
	}
	if capture.res == nil {
		t.Fatal("callback res=nil")
	}
	if got := capture.res.ResourceId; got != "qurl-tunnel-server" {
		t.Fatalf("callback resource_id=%q want placement-neutral qurl-tunnel-server", got)
	}
	if _, leaked := capture.res.Resources["qurl-tunnel-server-a"]; leaked {
		t.Fatalf("callback Resources leaked per-AZ key qurl-tunnel-server-a: %+v", capture.res.Resources)
	}
	if _, leaked := capture.res.Resources["qurl-tunnel-server-b"]; leaked {
		t.Fatalf("callback Resources leaked per-AZ key qurl-tunnel-server-b: %+v", capture.res.Resources)
	}
	if _, leaked := capture.res.Resources["qurl-tunnel-server-c"]; leaked {
		t.Fatalf("callback Resources leaked per-AZ key qurl-tunnel-server-c: %+v", capture.res.Resources)
	}
	info := capture.res.Resources["qurl-tunnel-server"]
	if info == nil {
		t.Fatalf("callback Resources missing placement-neutral key: %+v", capture.res.Resources)
	}
	if got := info.DestHost(); got == "" || got == "connect.test" {
		t.Fatalf("DestHost()=%q want explicit public host:port from selected AZ row", got)
	}
	if !info.PortSuffix {
		t.Fatal("PortSuffix=false want true so ACK carries an explicit port")
	}
	if capture.resourceHostAtEntry != nil {
		t.Errorf("ackMsg.ResourceHost at callback entry=%v want nil — callback owns ACK host map population", capture.resourceHostAtEntry)
	}
}

func TestAuthWithNHP_QURLTunnelServerPlacementDistributesByClientIdentity(t *testing.T) {
	asp := newAspWithTunnelServerAZRows()
	counts := map[string]int{}

	for i := 0; i < 600; i++ {
		req := newKnockReq("qurl-tunnel-server")
		req.PublicKey = fmt.Sprintf("client-instance-public-key-%03d", i)
		res := resolveResourceForRequest(req, asp)
		if res == nil {
			t.Fatalf("resolveResourceForRequest(%d) returned nil", i)
		}
		info := res.Resources["qurl-tunnel-server"]
		if info == nil {
			t.Fatalf("resolveResourceForRequest(%d) missing qurl-tunnel-server resource: %+v", i, res.Resources)
		}
		counts[info.DestHost()]++
	}

	if len(counts) != 3 {
		t.Fatalf("placement counts=%v want all three AZ ports represented", counts)
	}
	for host, count := range counts {
		if count < 150 || count > 250 {
			t.Fatalf("placement counts=%v; host %q got %d of 600, want rough even spread", counts, host, count)
		}
	}
}

// Happy path: aspData has the requested resource, no additional plugin auth,
// callback is invoked once carrying the looked-up ResourceData, ack carries
// OpenTime, and the success errCode survives. ResourceHost is asserted via
// the captured res — the plugin doesn't pre-populate ackMsg.ResourceHost
// because handleNhpOpenResource re-initializes that map and writes it from
// per-resource AC ops; a pre-callback write would be silently overwritten.
func TestAuthWithNHP_DispatchesAgentKnock(t *testing.T) {
	capture := &callbackCapture{}
	helper := newHelper(newAspWithTunnelServer(), capture, nil)
	req := newKnockReq("qurl-tunnel-server")

	ack, err := AuthWithNHP(req, helper)
	if err != nil {
		t.Fatalf("AuthWithNHP returned err: %v", err)
	}
	if capture.calls != 1 {
		t.Fatalf("AuthWithNhpCallbackFunc calls=%d want=1 — agent path must call through to handleNhpOpenResource", capture.calls)
	}
	if capture.res == nil || capture.res.ResourceId != "qurl-tunnel-server" {
		t.Fatalf("callback got res=%+v, want non-nil with ResourceId=\"qurl-tunnel-server\"", capture.res)
	}
	if hosts := capture.res.Hosts(); hosts["qurl-tunnel-server"] != "connect.test:7000" {
		t.Errorf("captured res.Hosts()=%v want explicit qurl-tunnel-server host:port entry", hosts)
	}
	if info := capture.res.Resources["qurl-tunnel-server"]; info == nil || !info.PortSuffix {
		t.Fatalf("callback info=%+v want PortSuffix=true so the ACK never relies on client YAML/server.port fallback", info)
	}
	// Pin the no-pre-write contract: `handleNhpOpenResource` re-inits
	// ackMsg.ResourceHost via `make(map[string]string)` and populates
	// it per-AC. A future "fix" that adds `ackMsg.ResourceHost = res.Hosts()`
	// before the callback would silently get overwritten in production,
	// and this assertion fences the regression.
	if capture.resourceHostAtEntry != nil {
		t.Errorf("ackMsg.ResourceHost at callback entry=%v want nil — plugin must NOT pre-write ResourceHost (callback re-inits the map at udpserver.go:3069)", capture.resourceHostAtEntry)
	}
	if ack.OpenTime != 120 {
		t.Errorf("ack.OpenTime=%d want=120 — the DDB row's OpenTime must reach the agent's ack", ack.OpenTime)
	}
	if ack.ErrCode != common.ErrSuccess.ErrorCode() {
		t.Errorf("ack.ErrCode=%q want=%q — callback success path must stamp success", ack.ErrCode, common.ErrSuccess.ErrorCode())
	}
}

// Callback failure: when handleNhpOpenResource returns an error (e.g., the
// AC is unreachable, the resource's AC pool is empty, or a token-mint fails),
// the plugin propagates that error verbatim with whatever ack state the
// callback left behind. Realistic post-resolve failure mode.
func TestAuthWithNHP_CallbackErrorPropagates(t *testing.T) {
	capture := &callbackCapture{}
	wantErr := errors.New("ac dispatch failed: connection refused")
	helper := newHelper(newAspWithTunnelServer(), capture, wantErr)
	req := newKnockReq("qurl-tunnel-server")

	ack, err := AuthWithNHP(req, helper)
	if !errors.Is(err, wantErr) {
		t.Fatalf("AuthWithNHP err=%v want=%v — callback error must propagate unwrapped", err, wantErr)
	}
	if capture.calls != 1 {
		t.Errorf("callback calls=%d want=1 — callback must still be invoked on the error path", capture.calls)
	}
	if ack == nil {
		t.Fatal("ack=nil on callback-error path; want the callback's ack returned so the caller can inspect partial state")
	}
	if ack.OpenTime != 120 {
		t.Errorf("ack.OpenTime=%d want=120 — OpenTime is stamped pre-callback and must survive a callback error", ack.OpenTime)
	}
}

// Resource the agent asked for isn't in the loaded catalog → 52004. This is the
// path a stale agent state hits when DDB ships a resource the agent doesn't
// know about (or vice versa, more commonly: agent asks for a resource the
// host server doesn't have wired up yet).
func TestAuthWithNHP_ResourceNotFoundReturnsErrResourceNotFound(t *testing.T) {
	capture := &callbackCapture{}
	helper := newHelper(newAspWithTunnelServer(), capture, nil)
	req := newKnockReq("unknown-resource")

	ack, err := AuthWithNHP(req, helper)
	if !errors.Is(err, common.ErrResourceNotFound) {
		t.Fatalf("AuthWithNHP err=%v want=ErrResourceNotFound (52004) — agent asked for a resource not in helper.AspData", err)
	}
	if ack.ErrCode != common.ErrResourceNotFound.ErrorCode() {
		t.Errorf("ack.ErrCode=%q want=%q — the agent-side error mapping branches on ack.ErrCode, must mirror the err sentinel", ack.ErrCode, common.ErrResourceNotFound.ErrorCode())
	}
	if capture.calls != 0 {
		t.Errorf("callback calls=%d want=0 — handleNhpOpenResource must NOT be invoked for a missing resource (it would issue a token for a resource the agent doesn't get to dial)", capture.calls)
	}
}

// AspData present but ResourceGroups is nil → existing res-nil branch
// catches it as ErrResourceNotFound. A pathological aspData shape
// (manually constructed test helper, malformed DDB row that loaded a
// top-level table but no nested resource block) shouldn't panic on the
// lock-free map read; pin the safety net.
func TestAuthWithNHP_NilResourceGroupsReturnsErrResourceNotFound(t *testing.T) {
	capture := &callbackCapture{}
	helper := newHelper(&common.AuthServiceProviderData{AuthSvcId: "agent"}, capture, nil)
	req := newKnockReq("qurl-tunnel-server")

	ack, err := AuthWithNHP(req, helper)
	if !errors.Is(err, common.ErrResourceNotFound) {
		t.Fatalf("AuthWithNHP err=%v want=ErrResourceNotFound (52004) — nil ResourceGroups must read as missing-resource", err)
	}
	if ack.ErrCode != common.ErrResourceNotFound.ErrorCode() {
		t.Errorf("ack.ErrCode=%q want=%q", ack.ErrCode, common.ErrResourceNotFound.ErrorCode())
	}
	if capture.calls != 0 {
		t.Errorf("callback calls=%d want=0", capture.calls)
	}
}

// Defensive: a caller constructing the helper outside the host server's
// NewNhpServerHelper (e.g. a future server-to-server forwarder path that
// reuses the plugin interface) must not silently mis-route — fail loud.
func TestAuthWithNHP_NilAspDataReturnsErrAuthServiceProviderNotFound(t *testing.T) {
	capture := &callbackCapture{}
	helper := newHelper(nil, capture, nil)
	req := newKnockReq("qurl-tunnel-server")

	ack, err := AuthWithNHP(req, helper)
	if !errors.Is(err, common.ErrAuthServiceProviderNotFound) {
		t.Fatalf("AuthWithNHP err=%v want=ErrAuthServiceProviderNotFound (52002) — nil AspData must fail loud not silently fall through", err)
	}
	if ack.ErrCode != common.ErrAuthServiceProviderNotFound.ErrorCode() {
		t.Errorf("ack.ErrCode=%q want=%q", ack.ErrCode, common.ErrAuthServiceProviderNotFound.ErrorCode())
	}
	if capture.calls != 0 {
		t.Errorf("callback calls=%d want=0 on nil-aspData", capture.calls)
	}
}

func TestAuthWithNHP_EmptyPublicKeyReturnsErrInvalidInput(t *testing.T) {
	capture := &callbackCapture{}
	helper := newHelper(newAspWithTunnelServerAZRows(), capture, nil)
	req := newKnockReq("qurl-tunnel-server")
	req.PublicKey = ""

	ack, err := AuthWithNHP(req, helper)
	if !errors.Is(err, common.ErrInvalidInput) {
		t.Fatalf("AuthWithNHP err=%v want=ErrInvalidInput (51101) — missing authenticated pubkey must fail closed before placement", err)
	}
	if ack.ErrCode != common.ErrInvalidInput.ErrorCode() {
		t.Fatalf("ack.ErrCode=%q want %q", ack.ErrCode, common.ErrInvalidInput.ErrorCode())
	}
	if capture.calls != 0 {
		t.Fatalf("callback calls=%d want=0 for missing public key", capture.calls)
	}
}

// Empty ResourceId: realistic stale-agent-config shape (agent doesn't
// know the tunnel-server resource id yet). Map lookup on "" returns the zero
// value, which the res-nil branch catches as ErrResourceNotFound.
// Distinct from "resource the catalog doesn't have" — pin both shapes.
func TestAuthWithNHP_EmptyResourceIdReturnsErrResourceNotFound(t *testing.T) {
	capture := &callbackCapture{}
	helper := newHelper(newAspWithTunnelServer(), capture, nil)
	req := newKnockReq("")

	ack, err := AuthWithNHP(req, helper)
	if !errors.Is(err, common.ErrResourceNotFound) {
		t.Fatalf("AuthWithNHP err=%v want=ErrResourceNotFound (52004) — empty ResourceId must read as missing-resource", err)
	}
	if ack.ErrCode != common.ErrResourceNotFound.ErrorCode() {
		t.Errorf("ack.ErrCode=%q want=%q", ack.ErrCode, common.ErrResourceNotFound.ErrorCode())
	}
	if capture.calls != 0 {
		t.Errorf("callback calls=%d want=0 on empty ResourceId", capture.calls)
	}
}

// Nil AuthWithNhpCallbackFunc: symmetric to the helper/AspData nil
// guards. A caller constructing the helper outside NewNhpServerHelper
// could leave the callback nil; the guard returns a typed sentinel
// instead of NPE'ing on the invocation.
func TestAuthWithNHP_NilCallbackReturnsErrInvalidInput(t *testing.T) {
	helper := &plugins.NhpServerPluginHelper{
		AspData: newAspWithTunnelServer(),
		// AuthWithNhpCallbackFunc intentionally nil.
	}
	req := newKnockReq("qurl-tunnel-server")

	ack, err := AuthWithNHP(req, helper)
	if !errors.Is(err, common.ErrInvalidInput) {
		t.Fatalf("AuthWithNHP err=%v want=ErrInvalidInput (51101) — nil callback must fail loud, not NPE", err)
	}
	if ack.ErrCode != common.ErrInvalidInput.ErrorCode() {
		t.Errorf("ack.ErrCode=%q want=%q", ack.ErrCode, common.ErrInvalidInput.ErrorCode())
	}
}

// Init-time registration must wire `plugins.GetPluginHandler("agent", "")`
// to a non-nil handler. Fences a future refactor that decouples `init()`
// from the package and the closely-related failure mode where the blank
// import in `endpoints/server/main/main.go` gets dropped.
func TestInitRegistersPluginHandler(t *testing.T) {
	h := plugins.GetPluginHandler("agent", "")
	if h == nil {
		t.Fatal("plugins.GetPluginHandler(\"agent\", \"\") = nil — init() must register the agent static plugin so FindPluginHandler resolves it at knock time")
	}
}

// Defense-in-depth: a DDB writer regression that drops SkipAuth=true must
// NOT silently grant the knock — the agent plugin carries no backend-auth
// path, so a SkipAuth=false resource is a config bug we have to refuse.
// (Today the bridge hardcodes SkipAuth=true; this fence is forward-looking
// for a future per-row SkipAuth field.) Matches passcode/oidc.
func TestAuthWithNHP_SkipAuthFalseReturnsErrBackendAuthRequired(t *testing.T) {
	asp := newAspWithTunnelServer()
	asp.ResourceGroups["qurl-tunnel-server"].SkipAuth = false

	capture := &callbackCapture{}
	helper := newHelper(asp, capture, nil)
	req := newKnockReq("qurl-tunnel-server")

	ack, err := AuthWithNHP(req, helper)
	if !errors.Is(err, common.ErrBackendAuthRequired) {
		t.Fatalf("AuthWithNHP err=%v want=ErrBackendAuthRequired (52007) — SkipAuth=false must be refused", err)
	}
	if ack.ErrCode != common.ErrBackendAuthRequired.ErrorCode() {
		t.Errorf("ack.ErrCode=%q want=%q", ack.ErrCode, common.ErrBackendAuthRequired.ErrorCode())
	}
	if capture.calls != 0 {
		t.Errorf("callback calls=%d want=0 — refused knocks must not reach handleNhpOpenResource", capture.calls)
	}
}

func TestAuthWithNHP_NilHelperFailsLoud(t *testing.T) {
	req := newKnockReq("qurl-tunnel-server")
	ack, err := AuthWithNHP(req, nil)
	if !errors.Is(err, common.ErrInvalidInput) {
		t.Fatalf("AuthWithNHP(req, nil) err=%v want=ErrInvalidInput (51101) — nil helper must surface a typed sentinel, not opaque errors.New", err)
	}
	if ack == nil {
		t.Fatal("ack=nil on nil-helper path; want req.Ack returned so caller branches on ack.ErrCode like every other error path")
	}
	if ack.ErrCode != common.ErrInvalidInput.ErrorCode() {
		t.Errorf("ack.ErrCode=%q want=%q — agent-side error mapping branches on ack.ErrCode", ack.ErrCode, common.ErrInvalidInput.ErrorCode())
	}
}

func TestPluginID_IsAgent(t *testing.T) {
	// PluginID is "agent" — the registered plugin id and the
	// AuthServiceId the agent's knock keys on. The Go ↔ terraform
	// lockstep against `var.ac_auth_service_id` is enforced at PR
	// time by `scripts/check-asp-and-ac-id-lockstep.sh`; this test
	// is the Go-side anchor (literal-match fence) so a rename of
	// this constant fails Go CI loud at the in-package edit, before
	// the cross-repo TF lint catches the surviving drift on TF
	// surfaces.
	if PluginID != "agent" {
		t.Fatalf("PluginID=%q want=%q — keep in lockstep with var.ac_auth_service_id default in terraform/variables.tf (CI lint: scripts/check-asp-and-ac-id-lockstep.sh)", PluginID, "agent")
	}
}
