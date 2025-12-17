package test

import (
	"os"
	"testing"

	log "github.com/OpenNHP/opennhp/nhp/log"
)

func TestLog(t *testing.T) {
	// Create temp directory for log files
	tmpDir, err := os.MkdirTemp("", "nhp-log-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// init logger with temp directory
	tlog := log.NewLogger("NHP-LogTest", log.LogLevelDebug, tmpDir, "logtest")
	log.SetGlobalLogger(tlog)

	log.Info("Info log test")
	log.Debug("Debug log test")
	log.Close()
}
