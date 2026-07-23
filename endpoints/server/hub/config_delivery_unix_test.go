//go:build unix

package hub

import (
	"os"
	"syscall"
	"testing"
)

func assertTestFileOwner(t *testing.T, info os.FileInfo, wantUID, wantGID int) {
	t.Helper()
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("config stat does not expose Unix ownership")
	}
	if int(stat.Uid) != wantUID || int(stat.Gid) != wantGID {
		t.Fatalf("config owner = %d:%d, want %d:%d", stat.Uid, stat.Gid, wantUID, wantGID)
	}
}
