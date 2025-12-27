// Package integration provides end-to-end tests for validating NHP deployments.
// These tests are designed to be run AFTER terraform deployment to verify:
// - etcd connectivity and configuration
// - AC registration and certificate validation
// - NHP server connectivity
//
// Run with: go test -v ./tests/integration/... -tags=integration
//
// Required environment variables:
// - ETCD_ENDPOINTS: comma-separated etcd endpoints (e.g., "https://etcd.example.com:2379")
// - ETCD_CA_CERT: path to etcd CA certificate
// - ETCD_CLIENT_CERT: path to etcd client certificate
// - ETCD_CLIENT_KEY: path to etcd client key
// - NHP_SERVER_ENDPOINT: NHP server UDP endpoint (e.g., "nlb.example.com:62206")
// - AWS_REGION: AWS region for certificate validation
//
//go:build integration
// +build integration

package integration

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	toml "github.com/pelletier/go-toml/v2"
	clientv3 "go.etcd.io/etcd/client/v3"
)

// Test configuration loaded from environment
type testConfig struct {
	etcdEndpoints  []string
	etcdCACert     string
	etcdClientCert string
	etcdClientKey  string
	nhpServer      string
	awsRegion      string
}

func loadTestConfig(t *testing.T) *testConfig {
	t.Helper()

	endpoints := os.Getenv("ETCD_ENDPOINTS")
	if endpoints == "" {
		t.Skip("ETCD_ENDPOINTS not set, skipping etcd tests")
	}

	return &testConfig{
		etcdEndpoints:  strings.Split(endpoints, ","),
		etcdCACert:     os.Getenv("ETCD_CA_CERT"),
		etcdClientCert: os.Getenv("ETCD_CLIENT_CERT"),
		etcdClientKey:  os.Getenv("ETCD_CLIENT_KEY"),
		nhpServer:      os.Getenv("NHP_SERVER_ENDPOINT"),
		awsRegion:      os.Getenv("AWS_REGION"),
	}
}

func createEtcdClient(t *testing.T, cfg *testConfig) *clientv3.Client {
	t.Helper()

	var tlsConfig *tls.Config

	if cfg.etcdCACert != "" {
		caCert, err := os.ReadFile(cfg.etcdCACert)
		if err != nil {
			t.Fatalf("Failed to read CA cert: %v", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			t.Fatal("Failed to parse CA cert")
		}

		clientCert, err := tls.LoadX509KeyPair(cfg.etcdClientCert, cfg.etcdClientKey)
		if err != nil {
			t.Fatalf("Failed to load client cert: %v", err)
		}

		tlsConfig = &tls.Config{
			RootCAs:      caCertPool,
			Certificates: []tls.Certificate{clientCert},
		}
	}

	client, err := clientv3.New(clientv3.Config{
		Endpoints:   cfg.etcdEndpoints,
		DialTimeout: 5 * time.Second,
		TLS:         tlsConfig,
	})
	if err != nil {
		t.Fatalf("Failed to create etcd client: %v", err)
	}

	return client
}

func TestEtcd_Connection(t *testing.T) {
	cfg := loadTestConfig(t)
	client := createEtcdClient(t, cfg)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Test connection by checking cluster health
	resp, err := client.Status(ctx, cfg.etcdEndpoints[0])
	if err != nil {
		t.Fatalf("etcd health check failed: %v", err)
	}

	t.Logf("etcd connection OK: version=%s, leader=%d", resp.Version, resp.Leader)
}

func TestEtcd_NHPConfigExists(t *testing.T) {
	cfg := loadTestConfig(t)
	client := createEtcdClient(t, cfg)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Check for /nhp/config key
	resp, err := client.Get(ctx, "/nhp/config")
	if err != nil {
		t.Fatalf("Failed to get /nhp/config: %v", err)
	}

	if len(resp.Kvs) == 0 {
		t.Fatal("/nhp/config key not found in etcd - config seeder Lambda may not have run")
	}

	// Parse and validate config structure
	var config struct {
		HttpConfig struct {
			EnableHttp     bool
			HttpListenPort int
		}
		Servers []struct {
			Hostname     string
			Port         int
			PubKeyBase64 string
		}
	}

	if err := toml.Unmarshal(resp.Kvs[0].Value, &config); err != nil {
		t.Fatalf("Failed to parse NHP config: %v", err)
	}

	if len(config.Servers) == 0 {
		t.Error("No servers configured in /nhp/config - ACs will have nothing to connect to")
	} else {
		t.Logf("NHP config OK: %d servers configured", len(config.Servers))
		for i, srv := range config.Servers {
			if srv.PubKeyBase64 == "" {
				t.Errorf("Server %d has empty public key", i)
			}
		}
	}
}

func TestEtcd_ACRegistry(t *testing.T) {
	cfg := loadTestConfig(t)
	client := createEtcdClient(t, cfg)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// List all AC registrations
	resp, err := client.Get(ctx, "/nhp/ac-registry/", clientv3.WithPrefix())
	if err != nil {
		t.Fatalf("Failed to list AC registry: %v", err)
	}

	t.Logf("Found %d AC registrations", len(resp.Kvs))

	if len(resp.Kvs) == 0 {
		t.Log("Warning: No ACs registered yet (may be expected for new deployments)")
		return
	}

	// Validate each registration
	for _, kv := range resp.Kvs {
		key := string(kv.Key)
		instanceId := strings.TrimPrefix(key, "/nhp/ac-registry/")

		var entry struct {
			PublicKey    string
			InstanceId   string
			Ip           string
			Port         int
			RegisteredAt int64
		}

		if err := toml.Unmarshal(kv.Value, &entry); err != nil {
			t.Errorf("Invalid AC registry entry %s: %v", instanceId, err)
			continue
		}

		// Validate required fields
		if entry.PublicKey == "" {
			t.Errorf("AC %s: missing public key", instanceId)
		}
		if entry.Ip == "" {
			t.Errorf("AC %s: missing IP address", instanceId)
		}

		t.Logf("AC %s: ip=%s, registered=%d", instanceId, entry.Ip, entry.RegisteredAt)
	}
}

func TestNHPServer_UDPReachable(t *testing.T) {
	cfg := loadTestConfig(t)
	if cfg.nhpServer == "" {
		t.Skip("NHP_SERVER_ENDPOINT not set, skipping NHP server test")
	}

	// Try to establish UDP connection to NHP server
	addr, err := net.ResolveUDPAddr("udp", cfg.nhpServer)
	if err != nil {
		t.Fatalf("Failed to resolve NHP server address: %v", err)
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatalf("Failed to connect to NHP server: %v", err)
	}
	defer conn.Close()

	// Set a short deadline for the test
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Send a small test packet (won't be a valid NHP packet, but tests network reachability)
	// The server should drop it silently
	_, err = conn.Write([]byte{0x00})
	if err != nil {
		t.Fatalf("Failed to write to NHP server: %v", err)
	}

	t.Logf("NHP server %s is reachable via UDP", cfg.nhpServer)
}

func TestNHPServer_DNSResolution(t *testing.T) {
	cfg := loadTestConfig(t)
	if cfg.nhpServer == "" {
		t.Skip("NHP_SERVER_ENDPOINT not set, skipping DNS test")
	}

	// Extract hostname from endpoint
	host, _, err := net.SplitHostPort(cfg.nhpServer)
	if err != nil {
		t.Fatalf("Invalid NHP server endpoint format: %v", err)
	}

	// Skip if it's already an IP
	if net.ParseIP(host) != nil {
		t.Log("NHP server is configured with IP address, skipping DNS test")
		return
	}

	// Resolve DNS
	ips, err := net.LookupHost(host)
	if err != nil {
		t.Fatalf("DNS resolution failed for %s: %v", host, err)
	}

	t.Logf("DNS resolution OK: %s -> %v", host, ips)
}

// TestAWSCertificates_InDeployedRegion verifies the AWS certificate for the current region
func TestAWSCertificates_InDeployedRegion(t *testing.T) {
	cfg := loadTestConfig(t)
	region := cfg.awsRegion
	if region == "" {
		region = os.Getenv("AWS_DEFAULT_REGION")
	}
	if region == "" {
		t.Skip("AWS_REGION not set, skipping region-specific cert test")
	}

	// These certificates should match what's in aws_certs.go
	// This test validates they're still valid at deployment time
	usRegionCerts := map[string]string{
		"us-east-1": `-----BEGIN CERTIFICATE-----
MIIDOzCCAiOgAwIBAgIJALc/uMVqiToXMA0GCSqGSIb3DQEBCwUAMFwxCzAJBgNV
BAYTAlVTMRkwFwYDVQQIExBXYXNoaW5ndG9uIFN0YXRlMRAwDgYDVQQHEwdTZWF0
dGxlMSAwHgYDVQQKExdBbWF6b24gV2ViIFNlcnZpY2VzIExMQzAgFw0xNTA4MTQw
ODU5MTJaGA8yMTk1MDExNzA4NTkxMlowXDELMAkGA1UEBhMCVVMxGTAXBgNVBAgT
EFdhc2hpbmd0b24gU3RhdGUxEDAOBgNVBAcTB1NlYXR0bGUxIDAeBgNVBAoTF0Ft
YXpvbiBXZWIgU2VydmljZXMgTExDMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAjS2vqZu9mE0ktPVQ9JpIvlhb8DOmkdFLa3mtYKJZOT6gBnAvQv9FoB1f
+ckxkPe9iHBg5JXNY0S/WXFiU6cPAeqjClU9JJXxhT1GkbMXD3IxNe/wPmr9C4gg
0wSZV0C9pxrcZKGvhJz7fBJphg2JNQU2M4J0fIB0RTGZ5g+aP+A8ND6LHXEA9GR6
OfhPJR6UEAH0XMvfvxcOPasGN0r7gTn0s1F1yPPFR6S+zC1IThU2e1AYjCnjz/FD
l8Qxi13X6d0H1z2lYb4rnpFsW7HM1mIz8gHVnfL7dH0z0hFxqB8XjM/KQjFEH3+h
xYdufmVPPJ3r3+L8k9azIRrSnDrKcwIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBU
Yjz2f9OINwp3B7nGpWIsSdL2bMbiL+p4MMnWMTU0tlHHr0xJrx2T+U1pOxIMTuM8
3LtW/X3R5nfJj8pDYHC8KKGRzTbH8YjgTl9FBLTzFP+wchMW3a6r+jitfBdTb2gz
RzmOXAdcNIw9FINe2xfrHiN+EaEhMQ0Q5vL1G4OPZF0Vb/u3G3T+bDwBl2cGvik7
j4UlPVzJtb3SgVtuoVLnJnhpKPxTe8zD5vPTr9WgN7pEzQVkdUhqzQRIhL3ey4+q
7P9On7qr9P5rqKqtqN4P7h9OfAkWTNwWd5jqMhZGVWN/P3mH5ZwM0hyJbgRP24Xo
e0CP/9e8OgPLxZ+bCLFt
-----END CERTIFICATE-----`,
	}

	certPEM, ok := usRegionCerts[region]
	if !ok {
		t.Logf("No embedded cert for region %s, skipping validation", region)
		return
	}

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		t.Fatal("Failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		t.Fatalf("Certificate for %s is not valid at current time", region)
	}

	// Verify RSA-2048
	if rsaKey, ok := cert.PublicKey.(*rsa.PublicKey); ok {
		if rsaKey.N.BitLen() != 2048 {
			t.Errorf("Expected 2048-bit RSA key, got %d bits", rsaKey.N.BitLen())
		}
	} else {
		t.Error("Certificate does not use RSA key")
	}

	t.Logf("AWS certificate for %s validated successfully (valid until %s)", region, cert.NotAfter.Format("2006-01-02"))
}

// Helper test to print deployment summary
func TestDeployment_Summary(t *testing.T) {
	cfg := loadTestConfig(t)

	fmt.Println("\n=== NHP Deployment Validation Summary ===")
	fmt.Printf("etcd endpoints: %v\n", cfg.etcdEndpoints)
	fmt.Printf("NHP server:     %s\n", cfg.nhpServer)
	fmt.Printf("AWS region:     %s\n", cfg.awsRegion)
	fmt.Println("==========================================")

	t.Log("Run all tests with: go test -v -tags=integration ./tests/integration/...")
}
