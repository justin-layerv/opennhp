package core

import (
	"bytes"
	"compress/zlib"
	"io"
	"testing"
)

// TestDecompressionSizeLimit tests the decompression bomb protection logic.
// This mirrors the implementation in responder.go:DecryptBody()
func TestDecompressionSizeLimit(t *testing.T) {
	const maxDecompressedSize = 10 * 1024 * 1024 // 10MB - same as responder.go

	tests := []struct {
		name          string
		dataSize      int
		expectError   bool
		errorContains string
	}{
		{
			name:        "small data within limit",
			dataSize:    1024, // 1KB
			expectError: false,
		},
		{
			name:        "data at 90% of limit",
			dataSize:    9 * 1024 * 1024, // 9MB
			expectError: false,
		},
		{
			name:        "data exactly at limit",
			dataSize:    maxDecompressedSize, // 10MB
			expectError: false,
		},
		{
			name:          "data exceeds limit by 1 byte",
			dataSize:      maxDecompressedSize + 1,
			expectError:   true,
			errorContains: "exceeds limit",
		},
		{
			name:          "data significantly exceeds limit",
			dataSize:      maxDecompressedSize + 1024*1024, // 11MB
			expectError:   true,
			errorContains: "exceeds limit",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create compressible test data (repeating pattern compresses well)
			originalData := bytes.Repeat([]byte("ABCDEFGHIJ"), tt.dataSize/10+1)
			originalData = originalData[:tt.dataSize]

			// Compress the data
			var compressedBuf bytes.Buffer
			w := zlib.NewWriter(&compressedBuf)
			_, err := w.Write(originalData)
			if err != nil {
				t.Fatalf("failed to compress test data: %v", err)
			}
			if err := w.Close(); err != nil {
				t.Fatalf("failed to close zlib writer: %v", err)
			}

			// Decompress with size limit (mirrors responder.go logic)
			br := bytes.NewReader(compressedBuf.Bytes())
			r, err := zlib.NewReader(br)
			if err != nil {
				t.Fatalf("failed to create zlib reader: %v", err)
			}
			defer func() { _ = r.Close() }()

			var decompressedBuf bytes.Buffer
			limitedReader := io.LimitReader(r, maxDecompressedSize+1)
			n, err := io.Copy(&decompressedBuf, limitedReader)

			// Check for read errors
			if err != nil {
				t.Fatalf("unexpected decompression error: %v", err)
			}

			// Check size limit
			if n > int64(maxDecompressedSize) {
				if !tt.expectError {
					t.Errorf("decompressed size %d exceeds limit %d, but no error expected", n, maxDecompressedSize)
				}
				// Error case - size exceeded (this is the expected path for oversized data)
				return
			}

			if tt.expectError {
				t.Errorf("expected error for data size %d, but decompression succeeded with size %d", tt.dataSize, n)
			}

			// Verify data integrity for successful cases
			if !tt.expectError && !bytes.Equal(decompressedBuf.Bytes(), originalData) {
				t.Errorf("decompressed data doesn't match original")
			}
		})
	}
}

// TestDecompressionInvalidData tests handling of malformed compressed data
func TestDecompressionInvalidData(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		expectError bool
	}{
		{
			name:        "empty data",
			data:        []byte{},
			expectError: true,
		},
		{
			name:        "random garbage",
			data:        []byte{0x01, 0x02, 0x03, 0x04, 0x05},
			expectError: true,
		},
		{
			name:        "truncated zlib header",
			data:        []byte{0x78}, // zlib magic byte without rest
			expectError: true,
		},
		{
			name:        "invalid zlib header",
			data:        []byte{0xFF, 0xFF, 0xFF, 0xFF},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			br := bytes.NewReader(tt.data)
			r, err := zlib.NewReader(br)

			if tt.expectError {
				if err == nil {
					// If NewReader succeeded, try to read - it should fail
					var buf bytes.Buffer
					_, readErr := io.Copy(&buf, r)
					_ = r.Close()
					if readErr == nil && buf.Len() > 0 {
						t.Errorf("expected error for invalid data, but got valid output")
					}
				}
				// Error during NewReader is expected
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if r != nil {
				_ = r.Close()
			}
		})
	}
}

// TestDecompressionValidData verifies valid zlib data decompresses correctly
func TestDecompressionValidData(t *testing.T) {
	originalData := []byte("Hello, World! This is a test message for compression.")

	// Compress
	var compressedBuf bytes.Buffer
	w := zlib.NewWriter(&compressedBuf)
	_, err := w.Write(originalData)
	if err != nil {
		t.Fatalf("compression failed: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("failed to close zlib writer: %v", err)
	}

	// Decompress
	br := bytes.NewReader(compressedBuf.Bytes())
	r, err := zlib.NewReader(br)
	if err != nil {
		t.Fatalf("failed to create zlib reader: %v", err)
	}
	defer func() { _ = r.Close() }()

	var decompressedBuf bytes.Buffer
	_, err = io.Copy(&decompressedBuf, r)
	if err != nil {
		t.Fatalf("decompression failed: %v", err)
	}

	if !bytes.Equal(decompressedBuf.Bytes(), originalData) {
		t.Errorf("decompressed data doesn't match original\ngot: %s\nwant: %s",
			decompressedBuf.String(), string(originalData))
	}
}
