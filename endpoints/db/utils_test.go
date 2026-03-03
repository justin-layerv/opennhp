package db

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/OpenNHP/opennhp/nhp/core"
)

// newTestDevice creates a UdpDevice with a single server peer pointing at the given host:port.
func newTestDevice(t *testing.T, host string, port int) *UdpDevice {
	t.Helper()
	peer := &core.UdpPeer{
		Ip:   host,
		Port: port,
	}
	d := &UdpDevice{
		serverPeerMap: map[string]*core.UdpPeer{
			"test": peer,
		},
	}
	return d
}

func TestUploadFileToNHPServer_Success(t *testing.T) {
	// Create a test server that accepts uploads and returns a valid response.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/storage/upload" {
			// Consume the body
			if _, err := io.ReadAll(r.Body); err != nil {
				t.Errorf("failed to read request body: %v", err)
			}
			resp := ServerResponse{
				Message: "ok",
				FileURI: "files/test.bin",
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				t.Errorf("failed to encode response: %v", err)
			}
			return
		}
		// Probe request — just return 200
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("failed to parse test server URL: %v", err)
	}

	// The test server is HTTP, so the HTTPS probe will fail and it will fall back to HTTP.
	// We need to set the peer host to the test server's host:port.
	host := u.Hostname()
	portInt := mustParsePort(t, u.Port())

	d := newTestDevice(t, host, portInt)

	// Create a temp file to upload
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.bin")
	if err := os.WriteFile(tmpFile, []byte("hello world"), 0600); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	result, err := d.UploadFileToNHPServer(context.Background(), tmpFile)
	if err != nil {
		t.Fatalf("UploadFileToNHPServer failed: %v", err)
	}

	if !strings.Contains(result, "files/test.bin") {
		t.Errorf("expected result to contain 'files/test.bin', got %q", result)
	}
}

func TestUploadFileToNHPServer_ContextCanceled(t *testing.T) {
	// Use a canceled context — the probe should fail with context error.
	d := newTestDevice(t, "127.0.0.1", 1)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.bin")
	if err := os.WriteFile(tmpFile, []byte("data"), 0600); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	_, err := d.UploadFileToNHPServer(ctx, tmpFile)
	if err == nil {
		t.Fatal("expected error for canceled context, got nil")
	}
	if !strings.Contains(err.Error(), "canceled") {
		t.Errorf("expected 'canceled' in error, got %q", err.Error())
	}
}

func TestUploadFileToNHPServer_FileNotFound(t *testing.T) {
	// HTTPS probe will fail (no server), falls back to HTTP,
	// then file open should fail.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("failed to parse test server URL: %v", err)
	}
	host := u.Hostname()
	portInt := mustParsePort(t, u.Port())

	d := newTestDevice(t, host, portInt)

	_, err = d.UploadFileToNHPServer(context.Background(), "/nonexistent/file.bin")
	if err == nil {
		t.Fatal("expected error for nonexistent file, got nil")
	}
	if !strings.Contains(err.Error(), "could not open file") {
		t.Errorf("expected 'could not open file' in error, got %q", err.Error())
	}
}

func TestUploadFileToNHPServer_ServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/storage/upload" {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("internal error"))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("failed to parse test server URL: %v", err)
	}
	host := u.Hostname()
	portInt := mustParsePort(t, u.Port())

	d := newTestDevice(t, host, portInt)

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.bin")
	if err := os.WriteFile(tmpFile, []byte("data"), 0600); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	_, err = d.UploadFileToNHPServer(context.Background(), tmpFile)
	if err == nil {
		t.Fatal("expected error for server 500, got nil")
	}
	if !strings.Contains(err.Error(), "unexpected status code: 500") {
		t.Errorf("expected 'unexpected status code: 500' in error, got %q", err.Error())
	}
}

// mustParsePort converts a string port to int, failing the test on error.
func mustParsePort(t *testing.T, s string) int {
	t.Helper()
	port, err := strconv.Atoi(s)
	if err != nil {
		t.Fatalf("failed to parse port %q: %v", s, err)
	}
	return port
}

func TestProgressReader(t *testing.T) {
	data := "hello world test data for progress"
	reader := strings.NewReader(data)
	progress := &UploadProgress{
		TotalSize: int64(len(data)),
	}

	pr := &ProgressReader{
		Reader:   reader,
		Progress: progress,
	}

	buf := make([]byte, 10)
	totalRead := 0
	for {
		n, err := pr.Read(buf)
		totalRead += n
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	if totalRead != len(data) {
		t.Errorf("expected to read %d bytes, got %d", len(data), totalRead)
	}
	if progress.BytesRead != int64(len(data)) {
		t.Errorf("expected BytesRead=%d, got %d", len(data), progress.BytesRead)
	}
}
