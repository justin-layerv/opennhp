//go:build smoke

package smoke

// Tier 3: NHP protocol surface — TLS cert validity and NLB listener
// reachability from the runner.

import (
	"crypto/tls"
	"net"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

// letsEncryptIntermediateCN matches Let's Encrypt's intermediate
// certificate naming scheme (R3, R10, R11, E1, E5, E6, …). Tight match
// rather than HasPrefix("R"/"E") so a cert with an unrelated issuer
// CN starting with those letters doesn't accidentally pass.
var letsEncryptIntermediateCN = regexp.MustCompile(`^[RE]\d+$`)

// TestProtocol_NLBTLSCertValid connects to the NHP server's HTTPS
// endpoint, captures the TLS certificate, and asserts:
//
//  1. Issuer is a trusted CA (Amazon or Let's Encrypt)
//  2. SAN includes the server hostname
//  3. NotAfter is at least 30 days in the future
//
// A cert approaching expiry would trigger this test 30 days before
// the actual outage, giving the team a month to act.
func TestProtocol_NLBTLSCertValid(t *testing.T) {
	requireRemote(t) // remote-only: asserts the real NLB TLS cert (local stack is plain HTTP).
	parsed, err := url.Parse(testConfig.NHPServerBaseURL)
	if err != nil {
		t.Fatalf("parse NHPServerBaseURL %q: %v", testConfig.NHPServerBaseURL, err)
	}
	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		port = "443"
	}

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp",
		net.JoinHostPort(host, port),
		&tls.Config{ServerName: host},
	)
	if err != nil {
		t.Fatalf("TLS dial %s:%s: %v", host, port, err)
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		t.Fatal("no peer certificates returned")
	}
	leaf := certs[0]

	// Check issuer — Amazon ACM or Let's Encrypt.
	// Match on Organization first (stable across LE intermediate rotations),
	// then fall back to CN for older certs that only populate CN. The
	// LE intermediate CN regex (letsEncryptIntermediateCN) matches R\d+ /
	// E\d+ only, not any CN that happens to start with R or E.
	issuerCN := leaf.Issuer.CommonName
	issuerOrg := strings.Join(leaf.Issuer.Organization, " ")
	trusted := strings.Contains(issuerOrg, "Amazon") ||
		strings.Contains(issuerOrg, "Let's Encrypt") ||
		strings.HasPrefix(issuerCN, "Amazon") ||
		strings.HasPrefix(issuerCN, "Let's Encrypt") ||
		letsEncryptIntermediateCN.MatchString(issuerCN)
	if !trusted {
		t.Errorf("cert issuer CN=%q Org=%q — not a recognized CA (expected Amazon or Let's Encrypt)", issuerCN, issuerOrg)
	}

	// Check SAN includes the server hostname. Accept exact match and
	// wildcard match (*.foo.example → anything.foo.example). Go's TLS
	// stack already accepted the handshake, so this is a shape assertion
	// rather than a trust decision.
	sanMatch := false
	for _, san := range leaf.DNSNames {
		if san == host {
			sanMatch = true
			break
		}
		if strings.HasPrefix(san, "*.") && strings.HasSuffix(host, san[1:]) {
			sanMatch = true
			break
		}
	}
	if !sanMatch {
		t.Errorf("cert SANs %v do not include %q (exact or wildcard)", leaf.DNSNames, host)
	}

	// Check expiry has at least 30 days headroom
	daysUntilExpiry := time.Until(leaf.NotAfter).Hours() / 24
	if daysUntilExpiry < 30 {
		t.Fatalf("cert expires in %.0f days (NotAfter=%s) — less than 30 day headroom",
			daysUntilExpiry, leaf.NotAfter.Format(time.RFC3339))
	}
	t.Logf("TLS cert: issuer=%q, SAN includes %q, expires in %.0f days", issuerCN, host, daysUntilExpiry)
}
