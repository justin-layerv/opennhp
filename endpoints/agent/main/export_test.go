package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/OpenNHP/opennhp/endpoints/agent/sdk"
	"github.com/OpenNHP/opennhp/nhp/common"
)

func TestCGoRetireSessionWrapperReturnsStrictRouteDenial(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "etc", "config.toml"), []byte("PrivateKeyBase64 = \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !sdk.Init(dir, 0) {
		t.Fatal("sdk.Init returned false")
	}
	t.Cleanup(sdk.Close)
	keys := strings.Split(sdk.GenerateKeys(), "|")
	if len(keys) != 2 || !sdk.AddServer(keys[1], "999.999.999.999", "", common.DefaultNHPPort, 0) {
		t.Fatal("failed to add unresolvable route")
	}
	raw := retireSessionJSON(validWrapperKnockACK(), "999.999.999.999", "", common.DefaultNHPPort)
	var ack common.ServerExactSessionCloseAckMsg
	if err := common.DecodeServerExactSessionCloseAckMsg([]byte(raw), &ack); err != nil {
		t.Fatalf("wrapper returned non-strict JSON %q: %v", raw, err)
	}
	if ack.ErrCode != common.ErrKnockServerNotFound.ErrorCode() {
		t.Fatalf("wrapper denial = %#v", ack)
	}
}

func validWrapperKnockACK() string {
	value := map[string]any{
		"errCode": "0", "sessId": uint64(77), "cellId": "cell-01",
		"sessIssuedAtMillis": int64(1_700_000_000_000), "runId": "0123456789abcdef", "runAttempt": uint64(3),
		"resHost": map[string]string{"resource": "127.0.0.1:443"}, "opnTime": uint32(30),
		"agentAddr": "198.51.100.8:44444", "acTokens": map[string]string{"resource": "token"},
	}
	raw, _ := json.Marshal(value)
	return string(raw)
}
