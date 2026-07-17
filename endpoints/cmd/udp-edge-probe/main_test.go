package main

import (
	"bytes"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
)

func TestRunReturnsSetupErrorInsteadOfPanicking(t *testing.T) {
	missingTempRoot := filepath.Join(t.TempDir(), "missing")
	t.Setenv("TMPDIR", missingTempRoot)

	_, err := run(config{StartAt: time.Now()})
	if err == nil {
		t.Fatal("run returned nil error with an unusable temporary root")
	}
	if !strings.Contains(err.Error(), "create temporary SDK root") {
		t.Fatalf("run error = %q, want clean temporary-root context", err)
	}
}

func TestGenerateProbeRunID(t *testing.T) {
	t.Parallel()

	got, err := generateProbeRunID(bytes.NewReader([]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}))
	if err != nil {
		t.Fatalf("generateProbeRunID: %v", err)
	}
	if got != "0123456789abcdef" {
		t.Fatalf("RunID = %q, want exact lowercase hexadecimal encoding", got)
	}
	if err := common.ValidateAgentKnockRunID(got); err != nil {
		t.Fatalf("generated RunID is not canonical: %v", err)
	}

	_, err = generateProbeRunID(bytes.NewReader(make([]byte, 7)))
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("short randomness error = %v, want io.ErrUnexpectedEOF", err)
	}
}

func TestKnockWithFreshRunIDPassesExactValueToExplicitSDKPath(t *testing.T) {
	t.Parallel()

	cfg := config{ASP: common.RegisteredAgentAuthServiceID, Resource: "connector", ServerHost: "cell0.nhp.layerv.ai"}
	const wantRunID = "0123456789abcdef"
	called := false
	raw, err := knockWithFreshRunID(cfg, func() (string, error) {
		return wantRunID, nil
	}, func(aspID, resourceID, runID, serverIP, serverHostname string, serverPort int) string {
		called = true
		if aspID != cfg.ASP || resourceID != cfg.Resource || runID != wantRunID || serverIP != "" || serverHostname != cfg.ServerHost || serverPort != 62206 {
			t.Fatalf("knock args = (%q, %q, %q, %q, %q, %d), want exact configured endpoint and generated RunID", aspID, resourceID, runID, serverIP, serverHostname, serverPort)
		}
		return `{"errCode":"0"}`
	})
	if err != nil {
		t.Fatalf("knockWithFreshRunID: %v", err)
	}
	if !called || raw != `{"errCode":"0"}` {
		t.Fatalf("knock called = %t raw = %q, want explicit SDK result", called, raw)
	}
}

func TestKnockWithFreshRunIDStopsBeforeSDKOnRandomnessFailure(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("entropy unavailable")
	called := false
	_, err := knockWithFreshRunID(config{}, func() (string, error) {
		return "", wantErr
	}, func(_, _, _, _, _ string, _ int) string {
		called = true
		return ""
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want entropy failure", err)
	}
	if called {
		t.Fatal("SDK knock was called after RunID generation failure")
	}
}
