package core

import (
	"bytes"
	"compress/zlib"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
	"unsafe"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core/scheme/curve"
)

// testMaxDecompressedSize tracks the production decompression ceiling so these
// tests can never silently pass against a stale value — it is the real
// constant, not a hand-copied mirror. See MaxDecompressedBodySize in
// constants.go for the sizing rationale (#1131).
const testMaxDecompressedSize = MaxDecompressedBodySize

// assertNHPError checks that err is a *core.Error with the expected error code.
func assertNHPError(t testing.TB, err error, expected *Error) {
	t.Helper()
	var nhpErr *Error
	if !errors.As(err, &nhpErr) {
		t.Fatalf("expected *core.Error, got %T: %v", err, err)
	}
	if nhpErr.ErrorNumber() != expected.ErrorNumber() {
		t.Errorf("expected error code %d, got %d: %v",
			expected.ErrorNumber(), nhpErr.ErrorNumber(), err)
	}
}

// createZlibCompressed compresses data using zlib and returns the compressed bytes.
func createZlibCompressed(t testing.TB, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		t.Fatalf("zlib write failed: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("zlib close failed: %v", err)
	}
	return buf.Bytes()
}

// buildDecryptBodyPPD constructs a PacketParserData whose decryptBody() method
// will decrypt to the given plaintext body. It uses a real AEAD cipher to
// encrypt the body into a dynamically-sized buffer so that the decryption path
// in decryptBody() is fully exercised, including payloads larger than the
// standard PacketBufferSize (4096 bytes).
//
// In production, packet size is limited by the UDP receive buffer and
// PacketBufferSize. This test helper bypasses that constraint to allow testing
// the decompression limit protection with realistic zip-bomb payloads.
func buildDecryptBodyPPD(t testing.TB, body []byte, compress bool) *PacketParserData {
	t.Helper()

	ciphers := NewCipherSuite()

	// Create a deterministic AEAD key for the body cipher.
	var key [SymmetricKeySize]byte
	for i := range key {
		key[i] = byte(i + 42)
	}
	bodyAead, err := AeadFromKey(ciphers.GcmType, &key)
	if err != nil {
		t.Fatalf("AeadFromKey failed: %v", err)
	}

	// Determine header size from the curve header struct.
	headerSize := int(unsafe.Sizeof(curve.HeaderCurve{}))

	// Allocate a buffer large enough for header + AEAD ciphertext.
	// The ciphertext is len(body) + GCMTagSize.
	ciphertextLen := len(body) + GCMTagSize
	totalLen := headerSize + ciphertextLen
	packetBuf := make([]byte, totalLen)

	// Set up the header at the start of the buffer.
	header := (*curve.HeaderCurve)(unsafe.Pointer(&packetBuf[0]))

	// Set the nonce (counter) so NonceBytes() returns a usable 12-byte nonce.
	header.SetCounter(1)
	nonce := header.NonceBytes()

	// Set the compress flag if requested.
	if compress {
		header.SetFlag(common.NHP_FLAG_COMPRESS)
	}

	// Set type and payload size before sealing: decryptBody folds the finalized
	// HeaderCommon into the body AAD, so every byte of it must be in place first.
	header.SetTypeAndPayloadSize(NHP_KNK, ciphertextLen)

	// Build associated data from chainHash (matches decryptBody's usage:
	// the seed write stands in for the handshake evolution, then the HeaderCommon
	// fold that binds the header under the body tag, then Sum as the AEAD AD).
	chainHash, err := NewHash(ciphers.HashType)
	if err != nil {
		t.Fatalf("NewHash failed: %v", err)
	}
	chainHash.Write([]byte("test-chain-hash-data"))
	chainHash.Write(header.Bytes()[:HeaderCommonSize])
	ad := chainHash.Sum(nil)

	// Encrypt the body using AEAD. The ciphertext (including GCM tag) is
	// written directly into the packet buffer after the header.
	bodyAead.Seal(packetBuf[headerSize:headerSize], nonce, body, ad)

	// Build the Packet. Buf is nil since we are not using the pool allocator;
	// Content points to our dynamically-sized slice.
	pkt := &Packet{
		Buf:        nil, // not pool-allocated
		Content:    packetBuf[:totalLen],
		HeaderType: NHP_KNK,
	}

	// Re-create the chain hash so decryptBody() can consume it.
	chainHash2, err := NewHash(ciphers.HashType)
	if err != nil {
		t.Fatalf("NewHash failed: %v", err)
	}
	chainHash2.Write([]byte("test-chain-hash-data"))

	// Build a fresh AEAD for decryption (same key).
	bodyAead2, err := AeadFromKey(ciphers.GcmType, &key)
	if err != nil {
		t.Fatalf("AeadFromKey failed: %v", err)
	}

	ppd := &PacketParserData{
		basePacket:   pkt,
		header:       header,
		bodyAead:     bodyAead2,
		chainHash:    chainHash2,
		BodyCompress: compress,
		Ciphers:      ciphers,
		BodyMessage:  nil,
	}

	return ppd
}

// TestDecryptBodyCompressedWithinLimit verifies that decryptBody() successfully
// decompresses a payload that is within the MaxDecompressedBodySize limit.
func TestDecryptBodyCompressedWithinLimit(t *testing.T) {
	// Create a payload that compresses well but stays within the limit.
	originalData := bytes.Repeat([]byte("ABCDEFGHIJ"), 100)
	compressed := createZlibCompressed(t, originalData)

	ppd := buildDecryptBodyPPD(t, compressed, true)

	err := ppd.decryptBody()
	if err != nil {
		t.Fatalf("decryptBody() failed for within-limit compressed data: %v", err)
	}

	if !bytes.Equal(ppd.BodyMessage, originalData) {
		t.Errorf("decompressed body does not match original data\n"+
			"got length: %d, want length: %d", len(ppd.BodyMessage), len(originalData))
	}
}

// TestDecryptBodyUncompressed verifies that decryptBody() correctly handles
// uncompressed body data (BodyCompress = false).
func TestDecryptBodyUncompressed(t *testing.T) {
	originalData := []byte(`{"type":"knock","resource":"test"}`)

	ppd := buildDecryptBodyPPD(t, originalData, false)

	err := ppd.decryptBody()
	if err != nil {
		t.Fatalf("decryptBody() failed for uncompressed data: %v", err)
	}

	if !bytes.Equal(ppd.BodyMessage, originalData) {
		t.Errorf("body does not match original data\n"+
			"got: %q, want: %q", string(ppd.BodyMessage), string(originalData))
	}
}

// TestDecryptBodyEmptyPacket verifies that decryptBody() handles a packet
// with no body (header only) by returning nil without error.
func TestDecryptBodyEmptyPacket(t *testing.T) {
	ciphers := NewCipherSuite()

	var key [SymmetricKeySize]byte
	bodyAead, err := AeadFromKey(ciphers.GcmType, &key)
	if err != nil {
		t.Fatalf("AeadFromKey failed: %v", err)
	}

	var packetBuf PacketBuffer
	header := (*curve.HeaderCurve)(unsafe.Pointer(&packetBuf[0]))
	headerSize := header.Size()

	// Content length equals header size -> empty body.
	pkt := &Packet{
		Buf:        &packetBuf,
		Content:    packetBuf[:headerSize],
		HeaderType: NHP_KNK,
	}

	chainHash, err := NewHash(ciphers.HashType)
	if err != nil {
		t.Fatalf("NewHash failed: %v", err)
	}
	chainHash.Write([]byte("test"))

	ppd := &PacketParserData{
		basePacket: pkt,
		header:     header,
		bodyAead:   bodyAead,
		chainHash:  chainHash,
		Ciphers:    ciphers,
	}

	err = ppd.decryptBody()
	if err != nil {
		t.Fatalf("decryptBody() should succeed for empty body, got: %v", err)
	}

	if ppd.BodyMessage != nil {
		t.Errorf("expected nil BodyMessage for empty packet, got %d bytes", len(ppd.BodyMessage))
	}
}

// TestDecryptBodyRoundTrip exercises the full encrypt-then-decrypt pipeline
// using MsgToPacket (sender) and PacketToMsg (receiver). Subtests cover both
// compressed and uncompressed paths to ensure decryptBody() handles each
// correctly through real Noise protocol encryption.
func TestDecryptBodyRoundTrip(t *testing.T) {
	// Create sender (agent) and receiver (server) devices.
	agentPrivKey := make([]byte, 32)
	for i := range agentPrivKey {
		agentPrivKey[i] = byte(i + 1)
	}
	serverPrivKey := make([]byte, 32)
	for i := range serverPrivKey {
		serverPrivKey[i] = byte(i + 33)
	}

	agentDevice := NewDevice(NHP_AGENT, agentPrivKey, nil)
	if agentDevice == nil {
		t.Fatal("failed to create agent device")
	}

	serverDevice := NewDevice(NHP_SERVER, serverPrivKey, nil)
	if serverDevice == nil {
		t.Fatal("failed to create server device")
	}

	// Register each device as a peer of the other.
	agentPeer := &UdpPeer{
		PubKeyBase64: agentDevice.PublicKeyBase64(),
		Ip:           "127.0.0.1",
		Port:         12345,
		Type:         NHP_AGENT,
	}
	serverPeer := &UdpPeer{
		PubKeyBase64: serverDevice.PublicKeyBase64(),
		Ip:           "127.0.0.1",
		Port:         12346,
		Type:         NHP_SERVER,
	}

	serverDevice.AddPeer(agentPeer)
	agentDevice.AddPeer(serverPeer)

	testMsg := []byte(`{"type":"knock","resource":"test-service","user":"alice"}`)

	tests := []struct {
		name     string
		compress bool
	}{
		{"compressed", true},
		{"uncompressed", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			connData := &ConnectionData{
				Device:           agentDevice,
				LocalAddr:        &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345},
				RemoteAddr:       &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12346},
				InitTime:         time.Now().UnixNano(),
				CookieStore:      &CookieStore{},
				SendQueue:        make(chan *Packet, 16),
				RecvQueue:        make(chan *Packet, 16),
				BlockSignal:      make(chan struct{}, 1),
				SetTimeoutSignal: make(chan struct{}, 1),
				StopSignal:       make(chan struct{}),
			}

			md := &MsgData{
				ConnData:      connData,
				PeerPk:        serverPeer.PublicKey(),
				HeaderType:    NHP_KNK,
				TransactionId: 1,
				Compress:      tt.compress,
				Message:       testMsg,
			}

			// Encrypt: agent -> packet.
			mad, err := agentDevice.MsgToPacket(md)
			if err != nil {
				t.Fatalf("MsgToPacket failed: %v", err)
			}

			// Copy encrypted packet content (MsgToPacket releases the buffer).
			encryptedContent := make([]byte, len(mad.BasePacket.Content))
			copy(encryptedContent, mad.BasePacket.Content)

			// Decrypt on the server side using PacketToMsg.
			var serverBuf PacketBuffer
			copy(serverBuf[:], encryptedContent)

			serverPkt := &Packet{
				Buf:        &serverBuf,
				Content:    serverBuf[:len(encryptedContent)],
				HeaderType: NHP_KNK,
			}

			serverConnData := &ConnectionData{
				Device:           serverDevice,
				LocalAddr:        &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12346},
				RemoteAddr:       &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345},
				InitTime:         time.Now().UnixNano(),
				CookieStore:      &CookieStore{},
				SendQueue:        make(chan *Packet, 16),
				RecvQueue:        make(chan *Packet, 16),
				BlockSignal:      make(chan struct{}, 1),
				SetTimeoutSignal: make(chan struct{}, 1),
				StopSignal:       make(chan struct{}),
			}

			pd := &PacketData{
				BasePacket: serverPkt,
				ConnData:   serverConnData,
				InitTime:   time.Now().UnixNano(),
			}

			ppd, err := serverDevice.PacketToMsg(pd)
			if err != nil {
				t.Fatalf("PacketToMsg failed: %v", err)
			}

			if ppd.Error != nil {
				t.Fatalf("PacketToMsg returned error in ppd: %v", ppd.Error)
			}

			if !bytes.Equal(ppd.BodyMessage, testMsg) {
				t.Errorf("round-trip body mismatch\ngot:  %q\nwant: %q",
					string(ppd.BodyMessage), string(testMsg))
			}

			t.Logf("Round-trip successful (%s): %d bytes message", tt.name, len(testMsg))
		})
	}
}

// TestDecryptBodyBoundarySizes tests decryptBody() behavior at sizes around
// the MaxDecompressedBodySize decompression limit to verify exact boundary
// enforcement. Includes decompression bomb cases (limit+1, 2×limit) and the
// exact boundary.
func TestDecryptBodyBoundarySizes(t *testing.T) {
	tests := []struct {
		name        string
		dataSize    int
		expectError bool
	}{
		{
			name:        "at warning threshold (still succeeds)",
			dataSize:    MaxDecompressedBodyWarnSize,
			expectError: false,
		},
		{
			name:        "exactly at limit",
			dataSize:    testMaxDecompressedSize,
			expectError: false,
		},
		{
			name:        "1 byte over limit",
			dataSize:    testMaxDecompressedSize + 1,
			expectError: true,
		},
		{
			name:        "1KB over limit",
			dataSize:    testMaxDecompressedSize + 1024,
			expectError: true,
		},
		{
			name:        "2x limit decompression bomb",
			dataSize:    2 * testMaxDecompressedSize,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use zero-filled data for maximum compression ratio.
			data := make([]byte, tt.dataSize)
			compressed := createZlibCompressed(t, data)

			t.Logf("Compressed %d bytes to %d bytes (ratio %.0f:1)",
				tt.dataSize, len(compressed),
				float64(tt.dataSize)/float64(len(compressed)))

			ppd := buildDecryptBodyPPD(t, compressed, true)

			err := ppd.decryptBody()

			if tt.expectError {
				if err == nil {
					t.Fatalf("expected error for %d-byte decompressed payload, got nil", tt.dataSize)
				}
				assertNHPError(t, err, ErrDataDecompressionFailed)
			} else {
				if err != nil {
					t.Fatalf("unexpected error for %d-byte payload: %v", tt.dataSize, err)
				}
				if len(ppd.BodyMessage) != tt.dataSize {
					t.Errorf("decompressed size mismatch: got %d, want %d",
						len(ppd.BodyMessage), tt.dataSize)
				}
			}
		})
	}
}

// TestDecompressWarnAllowedThrottle covers the near-ceiling warning throttle
// gate used by decryptBody (#1131): the first call in a fresh interval is
// allowed, repeats within the interval are suppressed, and the next interval
// re-opens the gate. Directly exercises the CAS branch that the boundary tests
// run but don't assert on, and resets the process-global throttle so it is
// order-independent of other tests that cross the warn threshold.
func TestDecompressWarnAllowedThrottle(t *testing.T) {
	lastDecompressWarnNano.Store(0)
	t.Cleanup(func() { lastDecompressWarnNano.Store(0) })

	const t0 = int64(1_700_000_000_000_000_000) // fixed synthetic ns
	if !decompressWarnAllowed(t0) {
		t.Fatal("first call in a fresh interval must be allowed")
	}
	if decompressWarnAllowed(t0 + decompressWarnInterval - 1) {
		t.Fatal("a second call within the interval must be throttled")
	}
	if !decompressWarnAllowed(t0 + decompressWarnInterval) {
		t.Fatal("a call at the interval boundary must re-open the gate")
	}
}

// TestDecryptBodyInvalidCompressedData verifies that decryptBody() handles
// invalid zlib data gracefully by returning ErrDataDecompressionFailed.
func TestDecryptBodyInvalidCompressedData(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "random garbage",
			data: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		},
		{
			name: "truncated mid-stream",
			// Valid zlib data truncated to half its length — exercises a different
			// failure mode (unexpected EOF) than invalid headers.
			data: func() []byte {
				full := createZlibCompressed(t, bytes.Repeat([]byte("ABCDEFGHIJ"), 100))
				return full[:len(full)/2]
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ppd := buildDecryptBodyPPD(t, tt.data, true)

			err := ppd.decryptBody()
			if err == nil {
				t.Fatal("decryptBody() should have returned an error for invalid compressed data")
			}

			assertNHPError(t, err, ErrDataDecompressionFailed)
		})
	}
}

// TestDecryptBodyConcurrent verifies that concurrent calls to decryptBody()
// do not race on shared state. This is a regression test for the SetExtraError
// race condition where package-level error sentinels were mutated in place.
func TestDecryptBodyConcurrent(t *testing.T) {
	const goroutines = 10

	// Mix of payloads: some valid, some bombs.
	type testCase struct {
		body        []byte
		compress    bool
		expectError bool
	}

	validData := bytes.Repeat([]byte("ABCDEFGHIJ"), 100)
	validCompressed := createZlibCompressed(t, validData)

	bombData := make([]byte, testMaxDecompressedSize+1024)
	bombCompressed := createZlibCompressed(t, bombData)

	cases := []testCase{
		{body: validCompressed, compress: true, expectError: false},
		{body: bombCompressed, compress: true, expectError: true},
		{body: []byte(`{"uncompressed":"data"}`), compress: false, expectError: false},
		{body: []byte{0x01, 0x02, 0x03}, compress: true, expectError: true},
	}

	// Build all PPDs on the main goroutine (buildDecryptBodyPPD calls
	// t.Fatalf which is unsafe from non-test goroutines).
	type readyCase struct {
		ppd         *PacketParserData
		expectError bool
	}
	var ready []readyCase
	for i := 0; i < goroutines; i++ {
		for _, tc := range cases {
			ready = append(ready, readyCase{
				ppd:         buildDecryptBodyPPD(t, tc.body, tc.compress),
				expectError: tc.expectError,
			})
		}
	}

	// Run goroutines concurrently. With -race, this detects any shared state
	// mutation on package-level error variables.
	errc := make(chan error, len(ready))
	for _, rc := range ready {
		rc := rc
		go func() {
			err := rc.ppd.decryptBody()
			if rc.expectError && err == nil {
				errc <- fmt.Errorf("expected error but got nil")
			} else if !rc.expectError && err != nil {
				errc <- fmt.Errorf("unexpected error: %w", err)
			} else {
				errc <- nil
			}
		}()
	}

	for range ready {
		if err := <-errc; err != nil {
			t.Error(err)
		}
	}
}

// TestDecryptBodyBasePacketContentByHeaderType verifies the bytes.Clone skip
// introduced by the IsForwardableKnockType guard in decryptBody: forwardable
// types (NHP_KNK, NHP_RKN, NHP_EXT) snapshot the original ciphertext so
// BasePacketContent() returns non-nil, while non-forwardable types skip the
// clone and BasePacketContent() returns nil. Fences the negative direction —
// a regression that re-added the unconditional bytes.Clone would pass every
// other test in this file because buildDecryptBodyPPD leaves ppd.HeaderType
// at zero (NHP_KPL, non-forwardable) by default.
func TestDecryptBodyBasePacketContentByHeaderType(t *testing.T) {
	body := []byte(`{"type":"knock","resource":"test"}`)

	tests := []struct {
		name       string
		headerType int
		wantNil    bool
	}{
		{"NHP_KPL (non-forwardable)", NHP_KPL, true},
		{"NHP_ACK (non-forwardable)", NHP_ACK, true},
		{"NHP_KNK (forwardable)", NHP_KNK, false},
		{"NHP_RKN (forwardable)", NHP_RKN, false},
		{"NHP_EXT (forwardable)", NHP_EXT, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ppd := buildDecryptBodyPPD(t, body, false)
			ppd.HeaderType = tt.headerType

			if err := ppd.decryptBody(); err != nil {
				t.Fatalf("decryptBody() failed: %v", err)
			}

			got := ppd.BasePacketContent()
			if tt.wantNil && got != nil {
				t.Errorf("BasePacketContent() = %d bytes, want nil for header type %d",
					len(got), tt.headerType)
			}
			if !tt.wantNil && got == nil {
				t.Errorf("BasePacketContent() = nil, want non-nil for header type %d",
					tt.headerType)
			}
		})
	}
}

// BenchmarkDecryptBodyCompressed benchmarks decryptBody() with compressed data
// to measure the cost of decompression in the decryption path.
func BenchmarkDecryptBodyCompressed(b *testing.B) {
	originalData := bytes.Repeat([]byte("ABCDEFGHIJ"), 100)
	compressed := createZlibCompressed(b, originalData)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ppd := buildDecryptBodyPPD(b, compressed, true)
		if err := ppd.decryptBody(); err != nil {
			b.Fatalf("decryptBody failed: %v", err)
		}
	}
}

// BenchmarkDecryptBodyBombRejection benchmarks how quickly decryptBody()
// rejects a decompression bomb, verifying that malicious payloads are
// rejected without allocating excessive memory.
func BenchmarkDecryptBodyBombRejection(b *testing.B) {
	bombData := make([]byte, testMaxDecompressedSize+1024)
	compressed := createZlibCompressed(b, bombData)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ppd := buildDecryptBodyPPD(b, compressed, true)
		if err := ppd.decryptBody(); err == nil {
			b.Fatal("expected error for bomb payload")
		}
	}
}
