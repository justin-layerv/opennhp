package server

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func TestAWSRegionCertificates_AllParse(t *testing.T) {
	// Verify all certificates can be parsed as valid X.509 certificates
	for region, certPEM := range AWSRegionCertificates {
		t.Run(region, func(t *testing.T) {
			block, _ := pem.Decode([]byte(certPEM))
			if block == nil {
				t.Fatalf("Failed to decode PEM block for region %s", region)
			}

			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatalf("Failed to parse certificate for region %s: %v", region, err)
			}

			// Verify it's issued by Amazon Web Services
			if len(cert.Issuer.Organization) == 0 || cert.Issuer.Organization[0] != "Amazon Web Services LLC" {
				t.Errorf("Certificate for %s has unexpected issuer: %v", region, cert.Issuer.Organization)
			}
		})
	}
}

func TestAWSRegionCertificates_AllValid(t *testing.T) {
	now := time.Now()

	for region, certPEM := range AWSRegionCertificates {
		t.Run(region, func(t *testing.T) {
			block, _ := pem.Decode([]byte(certPEM))
			if block == nil {
				t.Fatalf("Failed to decode PEM for region %s", region)
			}

			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatalf("Failed to parse certificate for region %s: %v", region, err)
			}

			// Check certificate is currently valid
			if now.Before(cert.NotBefore) {
				t.Errorf("Certificate for %s not yet valid (starts %s)", region, cert.NotBefore)
			}
			if now.After(cert.NotAfter) {
				t.Errorf("Certificate for %s EXPIRED on %s", region, cert.NotAfter)
			}

			// Verify certificates are valid for at least another 100 years (AWS certs expire 2195+)
			hundredYearsFromNow := now.Add(100 * 365 * 24 * time.Hour)
			if cert.NotAfter.Before(hundredYearsFromNow) {
				t.Errorf("Certificate for %s expires too soon: %s", region, cert.NotAfter)
			}
		})
	}
}

func TestAWSRegionCertificates_RSA2048(t *testing.T) {
	for region, certPEM := range AWSRegionCertificates {
		t.Run(region, func(t *testing.T) {
			block, _ := pem.Decode([]byte(certPEM))
			if block == nil {
				t.Fatalf("Failed to decode PEM for region %s", region)
			}

			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatalf("Failed to parse certificate for region %s: %v", region, err)
			}

			// Verify key is RSA
			rsaKey, ok := cert.PublicKey.(*rsa.PublicKey)
			if !ok {
				t.Fatalf("Certificate for %s does not use RSA key", region)
			}

			// Verify key size is 2048 bits
			keySize := rsaKey.N.BitLen()
			if keySize != 2048 {
				t.Errorf("Certificate for %s has key size %d bits, expected 2048", region, keySize)
			}

			// Verify signature algorithm is SHA256WithRSA
			if cert.SignatureAlgorithm != x509.SHA256WithRSA {
				t.Errorf("Certificate for %s uses %s, expected SHA256WithRSA", region, cert.SignatureAlgorithm)
			}
		})
	}
}

func TestAWSRegionCertificates_USRegionsCovered(t *testing.T) {
	// Verify all US regions we need are covered
	requiredRegions := []string{
		"us-east-1",
		"us-east-2",
		"us-west-1",
		"us-west-2",
	}

	for _, region := range requiredRegions {
		t.Run(region, func(t *testing.T) {
			cert := GetAWSCertificate(region)
			if cert == "" {
				t.Errorf("Missing certificate for required region %s", region)
			}
		})
	}
}

func TestGetAWSCertificate(t *testing.T) {
	tests := []struct {
		region    string
		wantEmpty bool
	}{
		{"us-east-1", false},
		{"us-east-2", false},
		{"us-west-1", false},
		{"us-west-2", false},
		{"eu-west-1", true},  // Not configured
		{"ap-south-1", true}, // Not configured
		{"invalid", true},
	}

	for _, tt := range tests {
		t.Run(tt.region, func(t *testing.T) {
			cert := GetAWSCertificate(tt.region)
			gotEmpty := cert == ""
			if gotEmpty != tt.wantEmpty {
				t.Errorf("GetAWSCertificate(%q) empty=%v, want empty=%v", tt.region, gotEmpty, tt.wantEmpty)
			}
		})
	}
}

func TestSupportedAWSRegions(t *testing.T) {
	regions := SupportedAWSRegions()

	// Should return at least 4 US regions
	if len(regions) < 4 {
		t.Errorf("SupportedAWSRegions() returned %d regions, expected at least 4", len(regions))
	}

	// Verify we can look up each returned region
	for _, region := range regions {
		cert := GetAWSCertificate(region)
		if cert == "" {
			t.Errorf("SupportedAWSRegions() returned %s but GetAWSCertificate returns empty", region)
		}
	}
}

func TestAWSCertificates_UniqueSerialNumbers(t *testing.T) {
	// Verify each certificate has a unique serial number
	serials := make(map[string]string) // serial -> region

	for region, certPEM := range AWSRegionCertificates {
		block, _ := pem.Decode([]byte(certPEM))
		if block == nil {
			t.Fatalf("Failed to decode PEM for region %s", region)
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("Failed to parse certificate for region %s: %v", region, err)
		}

		serialStr := cert.SerialNumber.String()
		if existingRegion, found := serials[serialStr]; found {
			t.Errorf("Certificate serial number collision: %s and %s have same serial %s",
				region, existingRegion, serialStr)
		}
		serials[serialStr] = region
	}
}
