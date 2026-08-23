package agent

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

const canonicalAgentRunID = "0123456789abcdef"

func TestNativeKnockRunIDValidationPrecedesNetworkPaths(t *testing.T) {
	tests := []struct {
		name                string
		authServiceID       string
		runID               string
		runAttempt          uint64
		wantInvalid         bool
		dnsLookupShouldFail bool
	}{
		{name: "registered agent missing", authServiceID: common.RegisteredAgentAuthServiceID, runAttempt: 1, wantInvalid: true},
		{name: "registered agent malformed", authServiceID: common.RegisteredAgentAuthServiceID, runID: "ABCDEF0123456789", runAttempt: 1, wantInvalid: true},
		{name: "registered agent malformed before DNS", authServiceID: common.RegisteredAgentAuthServiceID, runID: "bad", runAttempt: 1, wantInvalid: true, dnsLookupShouldFail: true},
		{name: "legacy malformed supplied", authServiceID: "legacy", runID: "short", wantInvalid: true},
		{name: "registered agent canonical", authServiceID: common.RegisteredAgentAuthServiceID, runID: canonicalAgentRunID, runAttempt: 1},
		{name: "legacy missing", authServiceID: "legacy"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &UdpAgent{knockUser: &KnockUser{UserId: "caller"}}
			target := &KnockTarget{KnockResource: KnockResource{
				AuthServiceId: tt.authServiceID,
				ResourceId:    "resource",
				RunID:         tt.runID,
				RunAttempt:    tt.runAttempt,
			}}
			if tt.wantInvalid {
				// Make the send boundary live and the destination resolvable. A
				// regression that validates after message queueing would leave an
				// observable entry here instead of merely falling into a nil-peer
				// early return.
				a.running.Store(true)
				a.sendMsgCh = make(chan *core.MsgData, 2)
				a.signals.stop = make(chan struct{})
				target.ServerPeer = &core.UdpPeer{
					Type: core.NHP_SERVER,
					Ip:   "127.0.0.1",
					Port: common.DefaultNHPPort,
				}
				if tt.dnsLookupShouldFail {
					target.ServerPeer.Ip = ""
					target.ServerPeer.Hostname = "run-id-validation-must-precede.invalid"
					target.ServerPeer.LookupHostFunc = func(string) ([]string, error) {
						t.Fatal("invalid RunID reached DNS resolution")
						return nil, errors.New("unexpected DNS lookup")
					}
				}
			}

			knockAck, knockErr := a.Knock(target)
			exitAck, exitErr := a.ExitKnockRequest(target)
			if tt.wantInvalid {
				assertRunIDInvalid(t, "Knock", knockAck, knockErr, tt.runID)
				assertExactRunIDInvalid(t, "ExitKnockRequest", exitAck, exitErr, tt.runID)
				if got := len(a.sendMsgCh); got != 0 {
					t.Fatalf("invalid RunID enqueued %d network message(s), want zero", got)
				}
				return
			}

			// The zero-value agent has no running message routine and no server
			// peer. Reaching those errors proves canonical or intentionally omitted
			// legacy input passed the local RunID gate.
			if errors.Is(knockErr, common.ErrKnockRunIDInvalid) {
				t.Fatalf("Knock rejected valid/legacy runID: %v", knockErr)
			}
			if errors.Is(exitErr, common.ErrKnockRunIDInvalid) {
				t.Fatalf("ExitKnockRequest rejected valid/legacy runID: %v", exitErr)
			}
		})
	}
}

func assertExactRunIDInvalid(t *testing.T, operation string, ack *common.ServerExactSessionCloseAckMsg, err error, rejected string) {
	t.Helper()
	if !errors.Is(err, common.ErrKnockRunIDInvalid) {
		t.Fatalf("%s error = %v, want ErrKnockRunIDInvalid (rejected value %q)", operation, err, rejected)
	}
	if ack == nil || ack.ErrCode != common.ErrKnockRunIDInvalid.ErrorCode() || ack.ErrMsg != common.ErrKnockRunIDInvalid.Error() {
		t.Fatalf("%s ack = %#v, want stable ErrKnockRunIDInvalid response", operation, ack)
	}
}

func assertRunIDInvalid(t *testing.T, operation string, ack *common.ServerKnockAckMsg, err error, rejected string) {
	t.Helper()
	if !errors.Is(err, common.ErrKnockRunIDInvalid) {
		t.Fatalf("%s error = %v, want ErrKnockRunIDInvalid", operation, err)
	}
	if ack == nil {
		t.Fatalf("%s ack is nil", operation)
	}
	if ack.ErrCode != common.ErrKnockRunIDInvalid.ErrorCode() || ack.ErrMsg != common.ErrKnockRunIDInvalid.Error() {
		t.Fatalf("%s ack = (%q, %q), want stable ErrKnockRunIDInvalid response", operation, ack.ErrCode, ack.ErrMsg)
	}
	if rejected != "" && (strings.Contains(err.Error(), rejected) || strings.Contains(ack.ErrMsg, rejected)) {
		t.Fatalf("%s leaked rejected runID in public error", operation)
	}
}

func TestKnockCookieRetryReusesImmutableRunIDSnapshot(t *testing.T) {
	a := &UdpAgent{knockUser: &KnockUser{UserId: "caller"}, deviceId: "device"}
	a.running.Store(true)
	a.signals.stop = make(chan struct{})
	target := &KnockTarget{KnockResource: KnockResource{
		AuthServiceId: common.RegisteredAgentAuthServiceID,
		ResourceId:    "resource",
		RunID:         canonicalAgentRunID,
		RunAttempt:    1,
	}}

	var bodies [][]byte
	call := 0
	ack, err := a.knockWithRequest(target, func(snapshot *KnockTarget, useCookie bool) (*common.ServerKnockAckMsg, error) {
		headerType := core.NHP_KNK
		if useCookie {
			headerType = core.NHP_RKN
		}
		body, marshalErr := json.Marshal(a.buildAgentKnockMsg(snapshot, headerType))
		if marshalErr != nil {
			t.Fatalf("marshal application body: %v", marshalErr)
		}
		bodies = append(bodies, body)
		call++
		if call == 1 {
			target.SetResource(&KnockResource{
				AuthServiceId: common.RegisteredAgentAuthServiceID,
				ResourceId:    "resource",
				RunID:         "fedcba9876543210",
				RunAttempt:    9,
			})
			return &common.ServerKnockAckMsg{
				ErrCode: common.ErrKnockTerminatedByCookie.ErrorCode(),
				ErrMsg:  common.ErrKnockTerminatedByCookie.Error(),
			}, common.ErrKnockTerminatedByCookie
		}
		return &common.ServerKnockAckMsg{
			ErrCode: common.ErrSuccess.ErrorCode(), SessionId: 77, CellId: "cell-01",
			SessionIssuedAtMillis: 1_700_000_000_000, RunID: canonicalAgentRunID, RunAttempt: 1, OpenTime: 30,
			AgentAddr: "198.51.100.8:44444", ResourceHost: map[string]string{"resource": "127.0.0.1:443"},
			ACTokens: map[string]string{"resource": "token"},
		}, nil
	})
	if err != nil {
		t.Fatalf("Knock: %v", err)
	}
	if ack == nil || ack.ErrCode != common.ErrSuccess.ErrorCode() {
		t.Fatalf("ack = %#v, want success", ack)
	}
	if len(bodies) != 2 {
		t.Fatalf("application bodies = %d, want KNK and RKN", len(bodies))
	}
	wants := []string{
		`{"headerType":1,"usrId":"caller","devId":"device","aspId":"agent","resId":"resource","runId":"0123456789abcdef","runAttempt":1}`,
		`{"headerType":8,"usrId":"caller","devId":"device","aspId":"agent","resId":"resource","runId":"0123456789abcdef","runAttempt":1}`,
	}
	for i, want := range wants {
		if string(bodies[i]) != want {
			t.Fatalf("application body %d = %s, want exact %s", i, bodies[i], want)
		}
	}
}

func TestRegisteredAgentBackgroundLoopInputsFailClosed(t *testing.T) {
	a := &UdpAgent{}
	if err := a.AddResource(&KnockResource{
		AuthServiceId: common.RegisteredAgentAuthServiceID,
		ResourceId:    "resource",
		RunID:         canonicalAgentRunID,
	}); !errors.Is(err, ErrRegisteredAgentKnockLoopUnsupported) {
		t.Fatalf("AddResource error = %v, want ErrRegisteredAgentKnockLoopUnsupported", err)
	}
}

func TestRegisteredAgentResourceConfigFailsClosed(t *testing.T) {
	dir := t.TempDir()
	etcDir := filepath.Join(dir, "etc")
	if err := os.MkdirAll(etcDir, 0o755); err != nil {
		t.Fatalf("mkdir etc: %v", err)
	}
	config := []byte(`PrivateKeyBase64 = "` + testAgentPrivKey + `"` + "\n")
	if err := os.WriteFile(filepath.Join(etcDir, "config.toml"), config, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	content := `[[Resources]]
AuthServiceId = "agent"
ResourceId = "resource"
RunID = "0123456789abcdef"
ServerIp = "127.0.0.1"
ServerPort = 62206
`
	if err := os.WriteFile(filepath.Join(etcDir, "resource.toml"), []byte(content), 0o600); err != nil {
		t.Fatalf("write resource config: %v", err)
	}
	a := &UdpAgent{}
	if err := a.Start(dir, 0); !errors.Is(err, ErrRegisteredAgentKnockLoopUnsupported) {
		if err == nil {
			a.Stop()
		}
		t.Fatalf("Start error = %v, want ErrRegisteredAgentKnockLoopUnsupported", err)
	}
}

func TestRegisteredAgentResourceReloadIsTransactional(t *testing.T) {
	dir := t.TempDir()
	resourceFile := filepath.Join(dir, "resource.toml")
	content := `[[Resources]]
AuthServiceId = "legacy"
ResourceId = "would-partially-apply"
ServerIp = "127.0.0.1"
ServerPort = 62206

[[Resources]]
AuthServiceId = "agent"
ResourceId = "must-fail"
RunID = "0123456789abcdef"
ServerIp = "127.0.0.1"
ServerPort = 62206
`
	if err := os.WriteFile(resourceFile, []byte(content), 0o600); err != nil {
		t.Fatalf("write resource config: %v", err)
	}

	const sentinelID = "legacy/already-installed"
	a := &UdpAgent{
		knockTargetMap: map[string]*KnockTarget{
			sentinelID: {KnockResource: KnockResource{AuthServiceId: "legacy", ResourceId: "already-installed"}},
		},
		serverPeerMap: map[string]*core.UdpPeer{
			"server": {Type: core.NHP_SERVER, Ip: "127.0.0.1", Port: 62206},
		},
	}
	if err := a.updateResources(resourceFile); !errors.Is(err, ErrRegisteredAgentKnockLoopUnsupported) {
		t.Fatalf("updateResources error = %v, want ErrRegisteredAgentKnockLoopUnsupported", err)
	}

	a.knockTargetMapMutex.Lock()
	defer a.knockTargetMapMutex.Unlock()
	if len(a.knockTargetMap) != 1 || a.knockTargetMap[sentinelID] == nil {
		t.Fatalf("failed reload changed installed resources: %#v", a.knockTargetMap)
	}
	if a.knockTargetMap["legacy/would-partially-apply"] != nil {
		t.Fatal("failed reload partially applied a resource parsed before the registered-agent entry")
	}
}

func TestBuildAgentKnockMsgCarriesExactRunIDForKnockReknockAndExit(t *testing.T) {
	a := &UdpAgent{
		knockUser: &KnockUser{
			UserId:         "user",
			OrganizationId: "org",
			UserData:       map[string]any{"role": "connector"},
		},
		deviceId:     "device",
		checkResults: map[string]any{"posture": "ok"},
	}
	target := &KnockTarget{KnockResource: KnockResource{
		AuthServiceId: common.RegisteredAgentAuthServiceID,
		ResourceId:    "resource",
		RunID:         canonicalAgentRunID,
		RunAttempt:    1,
	}}

	tests := []struct {
		name       string
		headerType int
		want       string
	}{
		{
			name:       "KNK",
			headerType: core.NHP_KNK,
			want:       `{"headerType":1,"usrId":"user","devId":"device","orgId":"org","aspId":"agent","resId":"resource","runId":"0123456789abcdef","runAttempt":1,"results":{"posture":"ok"},"usrData":{"role":"connector"}}`,
		},
		{
			name:       "RKN",
			headerType: core.NHP_RKN,
			want:       `{"headerType":8,"usrId":"user","devId":"device","orgId":"org","aspId":"agent","resId":"resource","runId":"0123456789abcdef","runAttempt":1,"results":{"posture":"ok"},"usrData":{"role":"connector"}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(a.buildAgentKnockMsg(target, tt.headerType))
			if err != nil {
				t.Fatalf("json.Marshal: %v", err)
			}
			if string(got) != tt.want {
				t.Fatalf("application body = %s, want exact %s", got, tt.want)
			}
		})
	}
}

func TestBuildAgentKnockMsgNilUserIsSafe(t *testing.T) {
	a := &UdpAgent{
		deviceId:     "device",
		checkResults: map[string]any{"posture": "ok"},
	}
	target := &KnockTarget{KnockResource: KnockResource{
		AuthServiceId: common.RegisteredAgentAuthServiceID,
		ResourceId:    "resource",
		RunID:         canonicalAgentRunID,
		RunAttempt:    1,
	}}

	msg := a.buildAgentKnockMsg(target, core.NHP_KNK)
	if msg.UserId != "" || msg.OrganizationId != "" || msg.UserData != nil {
		t.Fatalf("nil knock user produced user fields: %+v", msg)
	}
	if msg.DeviceId != "device" || msg.CheckResults["posture"] != "ok" || msg.RunID != canonicalAgentRunID || msg.RunAttempt != 1 {
		t.Fatalf("nil knock user dropped independent message fields: %+v", msg)
	}
}
