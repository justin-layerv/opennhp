//go:build windows

package hub

import (
	"os"
	"testing"
)

func assertTestFileOwner(t *testing.T, _ os.FileInfo, _, _ int) {
	t.Helper()
}
