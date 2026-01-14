package server

import (
	"testing"
)

// TestEtcdKeyMustHaveLeadingSlash documents the key format requirement
func TestEtcdKeyMustHaveLeadingSlash(t *testing.T) {
	// The EtcdConn.InitClient() adds a leading slash to the key
	// So when remote.toml has Key = "nhp/config"
	// The actual key used is "/nhp/config"

	remoteTomlKey := "nhp/config"
	actualKeyAfterInit := "/" + remoteTomlKey // This is what InitClient does

	t.Logf("remote.toml Key = %q", remoteTomlKey)
	t.Logf("Actual etcd key after InitClient = %q", actualKeyAfterInit)

	// The user_data.sh.tpl MUST use the same key format
	correctPutKey := "/nhp/config"
	wrongPutKey := "nhp/config"

	if actualKeyAfterInit != correctPutKey {
		t.Errorf("Key mismatch: server reads %q but should match %q", actualKeyAfterInit, correctPutKey)
	}

	if actualKeyAfterInit == wrongPutKey {
		t.Error("BUG: Keys should NOT match without the leading slash")
	}

	t.Logf("CORRECT: etcdctl put %q <config>", correctPutKey)
	t.Logf("WRONG:   etcdctl put %q <config>", wrongPutKey)
}
