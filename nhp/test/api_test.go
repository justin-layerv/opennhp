package test

import (
	"net/url"
	"testing"
)

func TestUrlEncoding(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		encoded string
	}{
		{"chinese", "中文", "%E4%B8%AD%E6%96%87"},
		{"empty", "", ""},
		{"space", "hello world", "hello+world"},
		{"reserved", "a+b&c=d", "a%2Bb%26c%3Dd"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := url.QueryEscape(tt.input)
			if encoded != tt.encoded {
				t.Errorf("QueryEscape(%q) = %q, want %q", tt.input, encoded, tt.encoded)
			}

			decoded, err := url.QueryUnescape(encoded)
			if err != nil {
				t.Fatalf("QueryUnescape(%q) returned error: %v", encoded, err)
			}
			if decoded != tt.input {
				t.Errorf("round-trip mismatch: QueryUnescape(%q) = %q, want %q", encoded, decoded, tt.input)
			}
		})
	}
}
