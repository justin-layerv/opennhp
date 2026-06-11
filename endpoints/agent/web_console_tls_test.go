package agent

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestEnsureWebConsoleTLSCertGeneratesLoadablePair(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "certs")
	certFile := filepath.Join(dir, "server.crt")
	keyFile := filepath.Join(dir, "server.key")

	generated, err := ensureWebConsoleTLSCert(certFile, keyFile, false)
	if err != nil {
		t.Fatalf("ensureWebConsoleTLSCert returned error: %v", err)
	}
	if !generated {
		t.Fatal("ensureWebConsoleTLSCert did not report generated certs")
	}

	if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		t.Fatalf("generated cert/key pair is not loadable: %v", err)
	}

	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat cert directory: %v", err)
	}
	if got := dirInfo.Mode().Perm(); got != 0700 {
		t.Fatalf("cert directory permissions = %o, want 0700", got)
	}

	keyInfo, err := os.Stat(keyFile)
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	if got := keyInfo.Mode().Perm(); got != 0600 {
		t.Fatalf("key permissions = %o, want 0600", got)
	}
}

func TestEnsureWebConsoleTLSCertReusesExistingPair(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "server.crt")
	keyFile := filepath.Join(dir, "server.key")

	if generated, err := ensureWebConsoleTLSCert(certFile, keyFile, false); err != nil || !generated {
		t.Fatalf("initial ensure generated=%v err=%v, want generated with nil err", generated, err)
	}

	certBefore, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatalf("read generated cert: %v", err)
	}
	keyBefore, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatalf("read generated key: %v", err)
	}

	generated, err := ensureWebConsoleTLSCert(certFile, keyFile, false)
	if err != nil {
		t.Fatalf("second ensure returned error: %v", err)
	}
	if generated {
		t.Fatal("second ensure unexpectedly regenerated certs")
	}

	certAfter, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatalf("read reused cert: %v", err)
	}
	keyAfter, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatalf("read reused key: %v", err)
	}
	if !bytes.Equal(certBefore, certAfter) || !bytes.Equal(keyBefore, keyAfter) {
		t.Fatal("existing cert/key pair changed")
	}
}

func TestEnsureWebConsoleTLSCertRegeneratesMismatchedPair(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "server.crt")
	keyFile := filepath.Join(dir, "server.key")
	otherCertFile := filepath.Join(dir, "other.crt")
	otherKeyFile := filepath.Join(dir, "other.key")

	if err := writeSelfSignedWebConsoleCert(certFile, keyFile, time.Now()); err != nil {
		t.Fatalf("write first pair: %v", err)
	}
	if err := writeSelfSignedWebConsoleCert(otherCertFile, otherKeyFile, time.Now()); err != nil {
		t.Fatalf("write second pair: %v", err)
	}
	otherKey, err := os.ReadFile(otherKeyFile)
	if err != nil {
		t.Fatalf("read mismatched key: %v", err)
	}
	if err := os.WriteFile(keyFile, otherKey, 0600); err != nil {
		t.Fatalf("write mismatched key: %v", err)
	}

	generated, err := ensureWebConsoleTLSCert(certFile, keyFile, false)
	if err != nil {
		t.Fatalf("ensureWebConsoleTLSCert returned error: %v", err)
	}
	if !generated {
		t.Fatal("ensureWebConsoleTLSCert did not report regenerated certs")
	}
	if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		t.Fatalf("regenerated cert/key pair is not loadable: %v", err)
	}
}

func TestEnsureWebConsoleTLSCertRegeneratesExpiredPair(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "server.crt")
	keyFile := filepath.Join(dir, "server.key")

	expiredStart := time.Now().Add(-(webConsoleCertValidity + 2*time.Hour))
	if err := writeSelfSignedWebConsoleCert(certFile, keyFile, expiredStart); err != nil {
		t.Fatalf("write expired pair: %v", err)
	}

	generated, err := ensureWebConsoleTLSCert(certFile, keyFile, false)
	if err != nil {
		t.Fatalf("ensureWebConsoleTLSCert returned error: %v", err)
	}
	if !generated {
		t.Fatal("ensureWebConsoleTLSCert did not report regenerated certs")
	}
	if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		t.Fatalf("regenerated cert/key pair is not loadable: %v", err)
	}
}

func TestEnsureWebConsoleTLSCertRegeneratesUnexpectedSANPair(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "server.crt")
	keyFile := filepath.Join(dir, "server.key")

	err := writeSelfSignedWebConsoleCertForHosts(
		certFile,
		keyFile,
		time.Now(),
		"stale.local",
		[]string{"stale.local"},
		[]net.IP{net.ParseIP("203.0.113.10")},
	)
	if err != nil {
		t.Fatalf("write stale SAN pair: %v", err)
	}

	generated, err := ensureWebConsoleTLSCert(certFile, keyFile, false)
	if err != nil {
		t.Fatalf("ensureWebConsoleTLSCert returned error: %v", err)
	}
	if !generated {
		t.Fatal("ensureWebConsoleTLSCert did not report regenerated certs")
	}
	if !existingWebConsoleTLSCertReady(certFile, keyFile, time.Now()) {
		t.Fatal("regenerated cert/key pair is not ready")
	}
}

func TestEnsureWebConsoleTLSCertPreservingExistingGeneratesMissingPair(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "server.crt")
	keyFile := filepath.Join(dir, "server.key")

	generated, err := ensureWebConsoleTLSCert(certFile, keyFile, true)
	if err != nil {
		t.Fatalf("preserve-mode ensureWebConsoleTLSCert returned error: %v", err)
	}
	if !generated {
		t.Fatal("preserve-mode ensureWebConsoleTLSCert did not report generated certs")
	}
	if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		t.Fatalf("generated cert/key pair is not loadable: %v", err)
	}
}

func TestEnsureWebConsoleTLSCertPreservingExistingRejectsUnexpectedPair(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "server.crt")
	keyFile := filepath.Join(dir, "server.key")

	err := writeSelfSignedWebConsoleCertForHosts(
		certFile,
		keyFile,
		time.Now(),
		"real.example",
		[]string{"real.example"},
		[]net.IP{net.ParseIP("203.0.113.10")},
	)
	if err != nil {
		t.Fatalf("write unexpected pair: %v", err)
	}
	certBefore, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatalf("read unexpected cert: %v", err)
	}
	keyBefore, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatalf("read unexpected key: %v", err)
	}

	generated, err := ensureWebConsoleTLSCert(certFile, keyFile, true)
	if err == nil {
		t.Fatal("preserve-mode ensureWebConsoleTLSCert returned nil error for unexpected existing pair")
	}
	if generated {
		t.Fatal("preserve-mode ensureWebConsoleTLSCert reported generated certs after rejecting existing pair")
	}
	if !strings.Contains(err.Error(), "refusing to overwrite explicit cert path") {
		t.Fatalf("error = %q, want refusal to overwrite explicit path", err)
	}

	certAfter, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatalf("read cert after rejection: %v", err)
	}
	keyAfter, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatalf("read key after rejection: %v", err)
	}
	if !bytes.Equal(certBefore, certAfter) || !bytes.Equal(keyBefore, keyAfter) {
		t.Fatal("unexpected existing cert/key pair changed")
	}
}

func TestDockerEntrypointCertIsReadyForGoValidator(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "certs")
	runDockerEntrypointForCertDir(t, dir)

	certFile := filepath.Join(dir, "server.crt")
	keyFile := filepath.Join(dir, "server.key")
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat docker entrypoint cert directory: %v", err)
	}
	if got := dirInfo.Mode().Perm(); got != 0700 {
		t.Fatalf("docker entrypoint cert directory permissions = %o, want 0700", got)
	}
	if !existingWebConsoleTLSCertReady(certFile, keyFile, time.Now()) {
		t.Fatal("docker entrypoint cert/key pair is not ready for Go validator")
	}
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("load docker entrypoint cert/key pair: %v", err)
	}
	if pair.Leaf.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Fatalf("docker entrypoint cert key usage = %v, want DigitalSignature", pair.Leaf.KeyUsage)
	}
	if !slices.Contains(pair.Leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		t.Fatalf("docker entrypoint cert ext key usage = %v, want ServerAuth", pair.Leaf.ExtKeyUsage)
	}
}

func TestGoGeneratedCertIsReadyForDockerEntrypoint(t *testing.T) {
	skipIfMissingDockerEntrypointTools(t)

	dir := t.TempDir()
	certFile := filepath.Join(dir, "server.crt")
	keyFile := filepath.Join(dir, "server.key")
	if err := writeSelfSignedWebConsoleCert(certFile, keyFile, time.Now()); err != nil {
		t.Fatalf("write Go-generated cert/key pair: %v", err)
	}

	certBefore, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatalf("read Go-generated cert: %v", err)
	}
	keyBefore, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatalf("read Go-generated key: %v", err)
	}

	runDockerEntrypointForCertDir(t, dir)

	certAfter, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatalf("read cert after docker entrypoint: %v", err)
	}
	keyAfter, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatalf("read key after docker entrypoint: %v", err)
	}
	if !bytes.Equal(certBefore, certAfter) || !bytes.Equal(keyBefore, keyAfter) {
		t.Fatal("docker entrypoint regenerated Go-generated cert/key pair")
	}
}

func runDockerEntrypointForCertDir(t *testing.T, dir string) {
	t.Helper()
	skipIfMissingDockerEntrypointTools(t)

	script := filepath.Join("..", "..", "docker", "agent-entrypoint.sh")
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("stat docker entrypoint: %v", err)
	}

	cmd := exec.Command("sh", script, "true")
	cmd.Env = append(envWithoutWebConsoleTLSOverrides(),
		"NHP_AGENT_CERT_DIR="+dir,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run docker entrypoint: %v\n%s", err, output)
	}
}

func skipIfMissingDockerEntrypointTools(t *testing.T) {
	t.Helper()
	for _, bin := range []string{"sh", "openssl"} {
		if _, err := exec.LookPath(bin); err != nil {
			if os.Getenv("CI") != "" {
				t.Fatalf("%s not available in CI: %v", bin, err)
			}
			t.Skipf("%s not available: %v", bin, err)
		}
	}
}

func envWithoutWebConsoleTLSOverrides() []string {
	env := os.Environ()
	filtered := make([]string, 0, len(env))
	for _, entry := range env {
		if strings.HasPrefix(entry, "NHP_AGENT_CERT_") || strings.HasPrefix(entry, "NHP_AGENT_KEY_") {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered
}

func TestEnsureWebConsoleTLSCertRegeneratesPartialPair(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "server.crt")
	keyFile := filepath.Join(dir, "server.key")

	if err := os.WriteFile(certFile, []byte("stale cert"), 0644); err != nil {
		t.Fatalf("write partial cert: %v", err)
	}

	generated, err := ensureWebConsoleTLSCert(certFile, keyFile, false)
	if err != nil {
		t.Fatalf("ensureWebConsoleTLSCert returned error: %v", err)
	}
	if !generated {
		t.Fatal("ensureWebConsoleTLSCert did not report regenerated certs")
	}
	if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		t.Fatalf("regenerated cert/key pair is not loadable: %v", err)
	}
}

func TestEnsureWebConsoleTLSCertSurfacesStatErrors(t *testing.T) {
	dir := t.TempDir()
	notDir := filepath.Join(dir, "not-dir")
	if err := os.WriteFile(notDir, []byte("file"), 0644); err != nil {
		t.Fatalf("write non-directory parent: %v", err)
	}

	generated, err := ensureWebConsoleTLSCert(filepath.Join(notDir, "server.crt"), filepath.Join(dir, "server.key"), false)
	if err == nil {
		t.Fatal("ensureWebConsoleTLSCert returned nil error for non-directory cert parent")
	}
	if generated {
		t.Fatal("ensureWebConsoleTLSCert reported generated certs after stat error")
	}
}

func TestWebConsoleTLSFilesUsesCertDirOverride(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("NHP_AGENT_CERT_DIR", dir)
	t.Setenv("NHP_AGENT_CERT_FILE", "")
	t.Setenv("NHP_AGENT_KEY_FILE", "")

	certFile, keyFile, preserveExistingCerts := webConsoleTLSFiles()
	if certFile != filepath.Join(dir, "server.crt") {
		t.Fatalf("cert file = %q, want cert dir override", certFile)
	}
	if keyFile != filepath.Join(dir, "server.key") {
		t.Fatalf("key file = %q, want cert dir override", keyFile)
	}
	if preserveExistingCerts {
		t.Fatal("cert dir override should not preserve unexpected existing certs")
	}
}

func TestWebConsoleTLSFilesUsesFileOverrides(t *testing.T) {
	dir := t.TempDir()
	certOverride := filepath.Join(dir, "custom.crt")
	keyOverride := filepath.Join(dir, "custom.key")
	t.Setenv("NHP_AGENT_CERT_DIR", filepath.Join(dir, "ignored"))
	t.Setenv("NHP_AGENT_CERT_FILE", certOverride)
	t.Setenv("NHP_AGENT_KEY_FILE", keyOverride)

	certFile, keyFile, preserveExistingCerts := webConsoleTLSFiles()
	if certFile != certOverride {
		t.Fatalf("cert file = %q, want explicit override %q", certFile, certOverride)
	}
	if keyFile != keyOverride {
		t.Fatalf("key file = %q, want explicit override %q", keyFile, keyOverride)
	}
	if !preserveExistingCerts {
		t.Fatal("explicit file overrides should preserve unexpected existing certs")
	}
}
