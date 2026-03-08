package utils

import (
	"encoding/base64"
	"testing"
)

func TestDecompression(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "invalid base64 input",
			input:   "!!!not-valid-base64!!!",
			wantErr: true,
		},
		{
			name:    "valid base64 but not gzip data",
			input:   base64.StdEncoding.EncodeToString([]byte("not gzip")),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Decompression(tt.input)
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestCompressionDecompressionRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "simple string",
			input: "hello, world!",
		},
		{
			name:  "empty string",
			input: "",
		},
		{
			name:  "long repeating string",
			input: "abcdefghij" + "abcdefghij" + "abcdefghij" + "abcdefghij" + "abcdefghij",
		},
		{
			name:  "unicode content",
			input: "unicode test data",
		},
		{
			name:  "single character",
			input: "x",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compressed, err := Compression(tt.input)
			if err != nil {
				t.Fatalf("Compression error: %v", err)
			}

			// Decompression expects base64-encoded input
			encoded := base64.StdEncoding.EncodeToString(compressed)

			result, err := Decompression(encoded)
			if err != nil {
				t.Fatalf("Decompression error: %v", err)
			}

			if result != tt.input {
				t.Fatalf("round-trip mismatch:\n  got:  %q\n  want: %q", result, tt.input)
			}
		})
	}
}

func TestCompression(t *testing.T) {
	t.Run("compressed output is not empty for non-empty input", func(t *testing.T) {
		data, err := Compression("test data")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(data) == 0 {
			t.Fatal("compressed output should not be empty")
		}
	})

	t.Run("empty string produces valid gzip output", func(t *testing.T) {
		data, err := Compression("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Even empty gzip has headers
		if len(data) == 0 {
			t.Fatal("compressed output for empty string should have gzip headers")
		}
	})
}
