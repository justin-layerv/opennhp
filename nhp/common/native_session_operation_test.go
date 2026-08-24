package common

import (
	"encoding/base64"
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"
)

func testNativeSessionOperationKnock(t *testing.T) (AgentKnockMsg, string, NativeSessionOperationServerBinding, time.Time) {
	t.Helper()
	publicKey := base64.StdEncoding.EncodeToString(bytesOf(0x42, 32))
	now := time.UnixMilli(1_800_000_010_000).UTC()
	server := NativeSessionOperationServerBinding{
		AWSAccountID: "111122223333", AWSRegion: "us-east-2", CellID: "cell-01",
		SessionControlTable: "sandbox-session-control", AgentKeysTable: "control-agent-keys",
		AgentKeySchema:   NativeSessionOperationAgentKeySchema,
		CredentialKind:   NativeSessionOperationCredentialKind,
		ConnectorIDClaim: NativeSessionOperationConnectorIDClaim,
	}
	msg := AgentKnockMsg{
		HeaderType: 1, UserId: "agent-a", DeviceId: "agent-a", AuthServiceId: RegisteredAgentAuthServiceID,
		ResourceId: "resource-a", RunID: "0123456789abcdef", RunAttempt: 7,
		NativeSessionOperationOwnerID:   "auth0|canary-owner",
		NativeSessionOperationPrepared:  now.Add(-time.Second).UnixMilli(),
		NativeSessionOperationExpiresAt: now.Add(20 * time.Minute).UnixMilli(),
	}
	operationID, err := NativeSessionOperationID(publicKey, msg.RunID, msg.RunAttempt)
	if err != nil {
		t.Fatal(err)
	}
	msg.NativeSessionOperationID = operationID
	binding, err := NativeSessionOperationBindingSHA256(msg, publicKey, server)
	if err != nil {
		t.Fatal(err)
	}
	msg.NativeSessionOperationBinding = binding
	return msg, publicKey, server, now
}

func bytesOf(value byte, count int) []byte {
	result := make([]byte, count)
	for i := range result {
		result[i] = value
	}
	return result
}

func TestNativeSessionOperationSelectorStableAndBindingClosed(t *testing.T) {
	msg, publicKey, server, now := testNativeSessionOperationKnock(t)
	if err := ValidateNativeSessionOperation(msg, publicKey, server, now); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*NativeSessionOperationServerBinding){
		"schema":     func(value *NativeSessionOperationServerBinding) { value.AgentKeySchema++ },
		"credential": func(value *NativeSessionOperationServerBinding) { value.CredentialKind = "bootstrap" },
		"connector":  func(value *NativeSessionOperationServerBinding) { value.ConnectorIDClaim = "connector-a" },
	} {
		t.Run("fixed agent row semantics reject "+name, func(t *testing.T) {
			drifted := server
			mutate(&drifted)
			if _, err := NativeSessionOperationBindingSHA256(msg, publicKey, drifted); err == nil {
				t.Fatal("drifted fixed agent-row semantics produced a binding")
			}
		})
	}
	wantID := msg.NativeSessionOperationID
	wantBinding := msg.NativeSessionOperationBinding
	if wantID != "3b2a3a9eabea3af78d8c317ea710e7f0601580163e25c98d50d5e2e17b68f3cc" ||
		wantBinding != "73add3ded83c588697131214c3e362ecc651512afa9c2ff4bad7d790a43593d8" {
		t.Fatalf("canonical selector/binding drifted: %s/%s", wantID, wantBinding)
	}
	for _, mutate := range []func(*AgentKnockMsg){
		func(value *AgentKnockMsg) { value.NativeSessionOperationOwnerID += "-drift" },
		func(value *AgentKnockMsg) { value.ResourceId += "-drift" },
		func(value *AgentKnockMsg) { value.AuthServiceId = "agent-drift" },
		func(value *AgentKnockMsg) { value.NativeSessionOperationPrepared++ },
		func(value *AgentKnockMsg) { value.NativeSessionOperationExpiresAt++ },
	} {
		drifted := msg
		mutate(&drifted)
		gotID, err := NativeSessionOperationID(publicKey, drifted.RunID, drifted.RunAttempt)
		if err != nil || gotID != wantID {
			t.Fatalf("full-binding drift changed selector: %q, %v", gotID, err)
		}
		gotBinding, err := NativeSessionOperationBindingSHA256(drifted, publicKey, server)
		if drifted.AuthServiceId != RegisteredAgentAuthServiceID {
			if err == nil {
				t.Fatal("wrong auth service produced a binding")
			}
			continue
		}
		if err != nil || gotBinding == wantBinding {
			t.Fatalf("full-binding drift was not detected: %q, %v", gotBinding, err)
		}
	}
	for _, mutate := range []func(*AgentKnockMsg){
		func(value *AgentKnockMsg) { value.RunID = "1123456789abcdef" },
		func(value *AgentKnockMsg) { value.RunAttempt++ },
	} {
		drifted := msg
		mutate(&drifted)
		got, err := NativeSessionOperationID(publicKey, drifted.RunID, drifted.RunAttempt)
		if err != nil || got == wantID {
			t.Fatalf("selector authority drift was not detected: %q, %v", got, err)
		}
	}
}

func TestNativeSessionOperationAdmissionAndRecoveryBoundaries(t *testing.T) {
	msg, publicKey, server, now := testNativeSessionOperationKnock(t)
	for _, test := range []struct {
		name    string
		now     time.Time
		wantErr bool
	}{
		{name: "before expiry", now: time.UnixMilli(msg.NativeSessionOperationExpiresAt - 1)},
		{name: "at expiry", now: time.UnixMilli(msg.NativeSessionOperationExpiresAt), wantErr: true},
		{name: "after expiry", now: time.UnixMilli(msg.NativeSessionOperationExpiresAt + 1), wantErr: true},
		{name: "max future preparation", now: time.UnixMilli(msg.NativeSessionOperationPrepared - NativeSessionOperationMaxClockSkew.Milliseconds())},
		{name: "past future preparation", now: time.UnixMilli(msg.NativeSessionOperationPrepared - NativeSessionOperationMaxClockSkew.Milliseconds() - 1), wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateNativeSessionOperation(msg, publicKey, server, test.now)
			if test.wantErr != (err != nil) {
				t.Fatalf("validation error = %v, want error=%v", err, test.wantErr)
			}
		})
	}
	deadline, err := NativeSessionOperationAbsentRecoveryDeadline(msg.NativeSessionOperationPrepared, msg.NativeSessionOperationExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	want := msg.NativeSessionOperationPrepared + NativeSessionOperationResumeHorizon.Milliseconds()
	if packet := msg.NativeSessionOperationExpiresAt + NativeSessionOperationPacketMargin.Milliseconds(); packet > want {
		want = packet
	}
	if deadline != want {
		t.Fatalf("recovery deadline = %d, want %d", deadline, want)
	}
	if _, err := NativeSessionOperationAbsentRecoveryDeadline(math.MaxInt64-1, math.MaxInt64); err == nil {
		t.Fatal("overflowing recovery horizon accepted")
	}
	_ = now
}

func TestNativeSessionOperationKnockWireRejectsPartialDuplicateAndAliases(t *testing.T) {
	msg, _, _, _ := testNativeSessionOperationKnock(t)
	body, err := json.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	var decoded AgentKnockMsg
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("canonical operation rejected: %v\n%s", err, body)
	}
	canonical := string(body)
	for _, field := range []string{"operation_id", "binding_sha256", "owner_id", "prepared_at_ms", "expires_at_ms"} {
		var object map[string]any
		if err := json.Unmarshal(body, &object); err != nil {
			t.Fatal(err)
		}
		delete(object, field)
		partial, _ := json.Marshal(object)
		if err := json.Unmarshal(partial, &decoded); err == nil {
			t.Fatalf("partial operation without %s accepted", field)
		}
	}
	for _, alias := range []string{"operationId", "OperationID", "bindingSha256", "ownerId", "preparedAtMs", "expiresAtMs", "OPERATION_ID"} {
		mutated := strings.TrimSuffix(canonical, "}") + `,"` + alias + `":"drift"}`
		if err := json.Unmarshal([]byte(mutated), &decoded); err == nil {
			t.Fatalf("operation alias %q accepted", alias)
		}
	}
	duplicate := strings.TrimSuffix(canonical, "}") + `,"operation_id":"` + msg.NativeSessionOperationID + `"}`
	if err := json.Unmarshal([]byte(duplicate), &decoded); err == nil {
		t.Fatal("duplicate operation_id accepted")
	}
	for _, unknown := range []string{
		strings.TrimSuffix(canonical, "}") + `,"unexpected":true}`,
		strings.Replace(canonical, `"usrId"`, `"\u0075srId"`, 1),
	} {
		if err := json.Unmarshal([]byte(unknown), &decoded); err == nil {
			t.Fatalf("operation wire with unknown or noncanonical field accepted: %s", unknown)
		}
	}
	legacyUnknown := `{"headerType":1,"usrId":"a","devId":"a","aspId":"agent","resId":"r","future":true}`
	if err := json.Unmarshal([]byte(legacyUnknown), &decoded); err != nil {
		t.Fatalf("additive legacy field was not preserved outside the OP contract: %v", err)
	}
	oversized := strings.TrimSuffix(canonical, "}") + `,"usrData":{"padding":"` +
		strings.Repeat("x", NativeSessionOperationMaxKnockJSONBytes) + `"}}`
	if err := json.Unmarshal([]byte(oversized), &decoded); err == nil {
		t.Fatal("oversized native operation knock accepted")
	}
}

func TestNativeSessionOperationRecoveryWireIsExact(t *testing.T) {
	msg, publicKey, server, _ := testNativeSessionOperationKnock(t)
	// Plugin posture and credential data are authenticated by the KNK but are
	// deliberately not durable operation authority: recovery carries no bearer
	// and never re-enters the plugin. The same minimal binding must therefore be
	// reconstructable after those volatile fields are gone.
	msg.OrganizationId = "volatile-org"
	msg.CheckResults = map[string]any{"posture": "ok"}
	msg.UserData = map[string]any{"qurl_access_token": "secret-not-persisted"}
	binding, err := NativeSessionOperationBindingSHA256(msg, publicKey, server)
	if err != nil {
		t.Fatal(err)
	}
	msg.NativeSessionOperationBinding = binding
	recovery := AgentNativeSessionOperationRecoveryMsg{
		HeaderType: 8, UserID: msg.UserId, DeviceID: msg.DeviceId, AuthServiceID: msg.AuthServiceId,
		ResourceID: msg.ResourceId, RunID: msg.RunID, RunAttempt: msg.RunAttempt,
		OperationID: msg.NativeSessionOperationID, BindingSHA256: msg.NativeSessionOperationBinding,
		OwnerID: msg.NativeSessionOperationOwnerID, PreparedAtMS: msg.NativeSessionOperationPrepared,
		ExpiresAtMS: msg.NativeSessionOperationExpiresAt,
	}
	body, err := json.Marshal(recovery)
	if err != nil {
		t.Fatal(err)
	}
	var decoded AgentNativeSessionOperationRecoveryMsg
	if err := DecodeAgentNativeSessionOperationRecoveryMsg(body, &decoded); err != nil || decoded != recovery {
		t.Fatalf("canonical recovery decode = %#v, %v", decoded, err)
	}
	projectedBinding, err := NativeSessionOperationBindingSHA256(decoded.KnockProjection(), publicKey, server)
	if err != nil || projectedBinding != binding {
		t.Fatalf("bearer-free recovery binding = %q, %v, want %q", projectedBinding, err, binding)
	}
	unknown := strings.TrimSuffix(string(body), "}") + `,"unexpected":true}`
	if err := DecodeAgentNativeSessionOperationRecoveryMsg([]byte(unknown), &decoded); err == nil {
		t.Fatal("unknown recovery field accepted")
	}
	duplicate := strings.TrimSuffix(string(body), "}") + `,"operation_id":"` + recovery.OperationID + `"}`
	if err := DecodeAgentNativeSessionOperationRecoveryMsg([]byte(duplicate), &decoded); err == nil {
		t.Fatal("duplicate recovery field accepted")
	}
}
