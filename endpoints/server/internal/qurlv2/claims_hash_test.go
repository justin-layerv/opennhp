/*
 * Copyright (c) 2024 OpenNHP Authors. All Rights Reserved.
 *
 * This file is part of OpenNHP.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package qurlv2

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"
)

// TestPublicKeyHashFromB64_KnownVector pins the canonical revocation-index hash
// format: lowercase-hex SHA-256 of the DECODED unpadded-base64url key bytes. The
// expected digest is computed here independently of the implementation (decode
// the same bytes, hash them) so a change to the hash format, the casing, or the
// decode step is caught. This format is load-bearing: the AOP metadata (P4a) and
// the AC's secondary indexes (P4b) both key off it, so it must never silently
// drift.
func TestPublicKeyHashFromB64_KnownVector(t *testing.T) {
	// A 32-byte X25519-shaped key, encoded the way the signed claims carry it.
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i)
	}
	b64 := base64.RawURLEncoding.EncodeToString(raw)

	sum := sha256.Sum256(raw)
	want := hex.EncodeToString(sum[:])

	got, err := PublicKeyHashFromB64(b64)
	if err != nil {
		t.Fatalf("PublicKeyHashFromB64(%q): %v", b64, err)
	}
	if got != want {
		t.Errorf("hash = %q, want %q (lowercase-hex SHA-256 of decoded bytes)", got, want)
	}
	if len(got) != 64 {
		t.Errorf("hash len = %d, want 64 hex chars for SHA-256", len(got))
	}
}

// TestPublicKeyHashFromB64_HashesDecodedBytesNotString proves the hash preimage
// is the DECODED key bytes, not the base64url string. If the implementation ever
// regressed to hashing the encoded string, this would fail.
func TestPublicKeyHashFromB64_HashesDecodedBytesNotString(t *testing.T) {
	raw := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	b64 := base64.RawURLEncoding.EncodeToString(raw)

	got, err := PublicKeyHashFromB64(b64)
	if err != nil {
		t.Fatalf("PublicKeyHashFromB64(%q): %v", b64, err)
	}

	sumOfString := sha256.Sum256([]byte(b64))
	if got == hex.EncodeToString(sumOfString[:]) {
		t.Error("hash must be over the DECODED bytes, not the base64url string")
	}
	sumOfBytes := sha256.Sum256(raw)
	if got != hex.EncodeToString(sumOfBytes[:]) {
		t.Errorf("hash = %q, want hash of decoded bytes %q", got, hex.EncodeToString(sumOfBytes[:]))
	}
}

// TestPublicKeyHashFromB64_RejectsBadEncoding ensures a non-base64url input
// surfaces the strict-decoder error (ErrEncoding) rather than hashing garbage.
// On the admission path the caller logs and proceeds with an empty hash, so the
// error must be returned, not swallowed inside the hasher.
func TestPublicKeyHashFromB64_RejectsBadEncoding(t *testing.T) {
	// Padding is rejected by the strict unpadded-base64url decoder.
	_, err := PublicKeyHashFromB64("AAAA====")
	if err == nil {
		t.Fatal("expected an error for padded / invalid base64url input")
	}
	if !errors.Is(err, ErrEncoding) {
		t.Errorf("error = %v, want it to wrap ErrEncoding", err)
	}
}
