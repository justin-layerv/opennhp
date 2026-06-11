package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

const webConsoleCertValidity = 365 * 24 * time.Hour

var (
	webConsoleCertDNSNames    = []string{"localhost", "loginlocal.opennhp.org"}
	webConsoleCertIPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback}
)

func ensureWebConsoleTLSCert(certFile, keyFile string, preserveExisting bool) (bool, error) {
	now := time.Now()
	_, certErr := os.Stat(certFile)
	_, keyErr := os.Stat(keyFile)
	certPairReady := certErr == nil &&
		keyErr == nil &&
		existingWebConsoleTLSCertReady(certFile, keyFile, now)
	if certPairReady {
		return false, nil
	}
	if certErr != nil && !errors.Is(certErr, os.ErrNotExist) {
		return false, fmt.Errorf("stat web console cert: %w", certErr)
	}
	if keyErr != nil && !errors.Is(keyErr, os.ErrNotExist) {
		return false, fmt.Errorf("stat web console key: %w", keyErr)
	}
	if preserveExisting && (certErr == nil || keyErr == nil) {
		return false, fmt.Errorf("existing web console cert/key pair is not ready; refusing to overwrite explicit cert path (cert=%q key=%q)", certFile, keyFile)
	}

	certDir := filepath.Dir(certFile)
	keyDir := filepath.Dir(keyFile)
	if err := os.MkdirAll(certDir, 0700); err != nil {
		return false, fmt.Errorf("create web console cert directory: %w", err)
	}
	if keyDir != certDir {
		if err := os.MkdirAll(keyDir, 0700); err != nil {
			return false, fmt.Errorf("create web console key directory: %w", err)
		}
	}

	if err := writeSelfSignedWebConsoleCert(certFile, keyFile, now); err != nil {
		return false, err
	}
	return true, nil
}

func existingWebConsoleTLSCertReady(certFile, keyFile string, now time.Time) bool {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return false
	}
	// endpoints/go.mod pins Go 1.26; tls.LoadX509KeyPair populates Leaf on Go 1.23+.
	leaf := cert.Leaf
	if leaf == nil {
		return false
	}
	if leaf.Subject.CommonName != "localhost" {
		return false
	}
	// The checks below accept extra SANs on user-managed certs as long as the
	// cert still covers the required local web-console DNS names and IPs.
	for _, hostname := range webConsoleCertDNSNames {
		if err := leaf.VerifyHostname(hostname); err != nil {
			return false
		}
	}
	for _, ip := range webConsoleCertIPAddresses {
		if err := leaf.VerifyHostname(ip.String()); err != nil {
			return false
		}
	}
	return !now.Before(leaf.NotBefore) && !now.After(leaf.NotAfter)
}

// Keep validation, key type, duration, and SANs in sync with docker/agent-entrypoint.sh.
func writeSelfSignedWebConsoleCert(certFile, keyFile string, now time.Time) error {
	return writeSelfSignedWebConsoleCertForHosts(
		certFile,
		keyFile,
		now,
		"localhost",
		webConsoleCertDNSNames,
		webConsoleCertIPAddresses,
	)
}

func writeSelfSignedWebConsoleCertForHosts(certFile, keyFile string, now time.Time, commonName string, dnsNames []string, ipAddresses []net.IP) error {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate web console key: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return fmt.Errorf("generate web console cert serial: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		// Backdate Go-generated certs for local clock skew; the validator also accepts
		// the Docker entrypoint's current-second OpenSSL NotBefore value.
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(webConsoleCertValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddresses,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("create web console cert: %w", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("marshal web console key: %w", err)
	}

	if err := writePEMFile(certFile, 0644, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return fmt.Errorf("write web console cert: %w", err)
	}
	if err := writePEMFile(keyFile, 0600, &pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}); err != nil {
		return fmt.Errorf("write web console key: %w", err)
	}

	return nil
}

func writePEMFile(path string, perm os.FileMode, block *pem.Block) (err error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := file.Close(); err == nil {
			err = closeErr
		} else if closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()
	if err := file.Chmod(perm); err != nil {
		return err
	}
	_, err = file.Write(pem.EncodeToMemory(block))
	return err
}
