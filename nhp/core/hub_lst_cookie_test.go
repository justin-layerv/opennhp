package core

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/log"
)

var hubLSTTestKey = func() []byte {
	key := make([]byte, SymmetricKeySize)
	for i := range key {
		key[i] = byte(i)
	}
	return key
}()

const hubLSTMaxCounter = ^uint64(0)

type hubLSTCookieFixture struct {
	agent  *Device
	server *Device
}

func newHubLSTCookieFixture(t *testing.T) hubLSTCookieFixture {
	t.Helper()
	agent := NewDevice(NHP_AGENT, validatePeerPrivateKey(0x21), &DeviceOptions{DisableServerPeerValidation: true})
	server := NewDevice(NHP_SERVER, validatePeerPrivateKey(0x61), &DeviceOptions{AllowUnregisteredAgentLST: true})
	if agent == nil || server == nil {
		t.Fatal("create Hub LST cookie devices")
	}
	if err := server.SetHubLSTCookieKeys(hubLSTTestKey, nil); err != nil {
		t.Fatalf("SetHubLSTCookieKeys: %v", err)
	}
	return hubLSTCookieFixture{agent: agent, server: server}
}

func (f hubLSTCookieFixture) sealLST(t *testing.T, body []byte, counter uint64, proof *[CookieSize]byte, compress bool) []byte {
	t.Helper()
	wire, _ := f.sealLSTWithSendTime(t, body, counter, proof, compress)
	return wire
}

func (f hubLSTCookieFixture) sealLSTWithSendTime(t *testing.T, body []byte, counter uint64, proof *[CookieSize]byte, compress bool) ([]byte, int64) {
	t.Helper()
	mad, err := f.agent.MsgToPacket(&MsgData{
		ConnData:          &ConnectionData{RemoteAddr: &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 62206}},
		CipherScheme:      common.CIPHER_SCHEME_CURVE,
		TransactionId:     counter,
		HeaderType:        NHP_LST,
		Compress:          compress,
		HubLSTCookieProof: proof,
		Message:           body,
		PeerPk:            f.server.staticEcdh.PublicKey(),
	})
	if err != nil {
		t.Fatalf("seal NHP_LST: %v", err)
	}
	return bytes.Clone(mad.BasePacket.Content), mad.LocalInitTime
}

func (f hubLSTCookieFixture) sealEmptyAEADLST(t *testing.T, counter uint64) []byte {
	t.Helper()
	mad, err := f.agent.createMsgAssemblerData(&MsgData{
		ConnData:      &ConnectionData{RemoteAddr: &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 62206}},
		CipherScheme:  common.CIPHER_SCHEME_CURVE,
		TransactionId: counter,
		HeaderType:    NHP_LST,
		PeerPk:        f.server.staticEcdh.PublicKey(),
	})
	if err != nil {
		t.Fatalf("create empty-AEAD assembler: %v", err)
	}
	defer mad.Destroy()
	if err := mad.setPeerPublicKey(nil); err != nil {
		t.Fatalf("set Hub peer key: %v", err)
	}
	mad.header.SetFlag(0)
	mad.BodySize = GCMTagSize
	mad.header.SetTypeAndPayloadSize(NHP_LST, mad.BodySize)
	mad.addHeaderDigest(false)
	buf := mad.BasePacket.writableBuffer()
	mad.bodyAead.Seal(buf[mad.header.Size():mad.header.Size()], mad.header.NonceBytes(), nil, mad.chainHash.Sum(mad.hashBuf[:0]))
	mad.BasePacket.Content = buf[:mad.header.Size()+mad.BodySize]
	return bytes.Clone(mad.BasePacket.Content)
}

func (f hubLSTCookieFixture) parseOnHub(t *testing.T, wire []byte, source *net.UDPAddr) (*PacketParserData, error) {
	t.Helper()
	return f.server.PacketToMsg(&PacketData{
		BasePacket: &Packet{Content: bytes.Clone(wire), HeaderType: NHP_LST},
		ConnData:   &ConnectionData{RemoteAddr: source},
	})
}

func (f hubLSTCookieFixture) decryptCOK(t *testing.T, wire []byte) (*PacketParserData, common.ServerCookieMsg) {
	t.Helper()
	ppd, err := f.agent.PacketToMsg(&PacketData{
		BasePacket: &Packet{Content: bytes.Clone(wire), HeaderType: NHP_COK},
		ConnData:   &ConnectionData{RemoteAddr: &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 62206}},
	})
	if err != nil {
		t.Fatalf("decrypt NHP_COK: %v", err)
	}
	var cok common.ServerCookieMsg
	if err := json.Unmarshal(ppd.BodyMessage, &cok); err != nil {
		t.Fatalf("decode NHP_COK body: %v", err)
	}
	return ppd, cok
}

func decodeCookie32(t *testing.T, encoded string) [CookieSize]byte {
	t.Helper()
	raw, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode cookie: %v", err)
	}
	if len(raw) != CookieSize {
		t.Fatalf("cookie length = %d, want %d", len(raw), CookieSize)
	}
	var cookie [CookieSize]byte
	copy(cookie[:], raw)
	return cookie
}

func TestHubLSTCookieRoundTrip(t *testing.T) {
	f := newHubLSTCookieFixture(t)
	source := &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 41000}
	body := bytes.Repeat([]byte{0xa5}, 237) // 240 header + 16 tag + 237 = 493 bytes.
	initial := f.sealLST(t, body, hubLSTMaxCounter, nil, false)
	if got := len(initial); got != 493 {
		t.Fatalf("initial LST length = %d, want 493", got)
	}

	_, err := f.parseOnHub(t, initial, source)
	if !errors.Is(err, ErrHubLSTCookieProofRequired) {
		t.Fatalf("initial LST error = %v, want proof required", err)
	}
	var challenge *HubLSTCookieChallengeError
	if !errors.As(err, &challenge) {
		t.Fatalf("initial LST error type = %T, want HubLSTCookieChallengeError", err)
	}
	cokWire := challenge.Packet()
	if got := len(cokWire); got != 342 {
		t.Fatalf("max-counter COK packet length = %d, want 342", got)
	}
	if got := (&Packet{Content: cokWire}).Flag(); got != 0 {
		t.Fatalf("COK flags = %#04x, want 0", got)
	}
	cokPPD, cok := f.decryptCOK(t, cokWire)
	if cokPPD.BodyCompress {
		t.Fatal("Hub LST challenge COK must be uncompressed")
	}
	if cok.TransactionId != hubLSTMaxCounter {
		t.Fatalf("COK trxId = %d, want %d", cok.TransactionId, hubLSTMaxCounter)
	}
	cookie := decodeCookie32(t, cok.Cookie)
	wantBody, err := json.Marshal(&common.ServerCookieMsg{TransactionId: hubLSTMaxCounter, Cookie: base64.StdEncoding.EncodeToString(cookie[:])})
	if err != nil {
		t.Fatalf("marshal expected COK: %v", err)
	}
	if !bytes.Equal(cokPPD.BodyMessage, wantBody) {
		t.Fatalf("COK body = %q, want exact compact %q", cokPPD.BodyMessage, wantBody)
	}

	proof := f.sealLST(t, body, hubLSTMaxCounter-1, &cookie, false)
	if got := (&Packet{Content: proof}).Flag(); got != common.NHP_FLAG_HUB_LST_COOKIE_PROOF {
		t.Fatalf("proof LST flags = %#04x, want %#04x", got, common.NHP_FLAG_HUB_LST_COOKIE_PROOF)
	}
	parsed, err := f.parseOnHub(t, proof, &net.UDPAddr{IP: net.ParseIP("::ffff:203.0.113.7"), Port: 41001})
	if err != nil {
		t.Fatalf("proof LST rejected: %v", err)
	}
	if !bytes.Equal(parsed.BodyMessage, body) {
		t.Fatal("proof LST application body changed")
	}
	if !bytes.Equal(parsed.RemotePubKey, f.agent.staticEcdh.PublicKey()) {
		t.Fatal("proof LST authenticated peer changed")
	}
}

func TestHubLSTCookieAntiAmplificationBoundary(t *testing.T) {
	f := newHubLSTCookieFixture(t)
	source := &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 41000}
	tests := []struct {
		name          string
		wire          func() []byte
		wantLen       int
		wantChallenge bool
	}{
		{name: "header only", wire: func() []byte { return f.sealLST(t, nil, hubLSTMaxCounter, nil, false) }, wantLen: 240},
		{name: "empty AEAD", wire: func() []byte { return f.sealEmptyAEADLST(t, hubLSTMaxCounter) }, wantLen: 256},
		{name: "one byte smaller", wire: func() []byte { return f.sealLST(t, make([]byte, 85), hubLSTMaxCounter, nil, false) }, wantLen: 341},
		{name: "equal", wire: func() []byte { return f.sealLST(t, make([]byte, 86), hubLSTMaxCounter, nil, false) }, wantLen: 342},
		{name: "one byte larger", wire: func() []byte { return f.sealLST(t, make([]byte, 87), hubLSTMaxCounter, nil, false) }, wantLen: 343, wantChallenge: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			wire := tc.wire()
			if len(wire) != tc.wantLen {
				t.Fatalf("request length = %d, want %d", len(wire), tc.wantLen)
			}
			_, err := f.parseOnHub(t, wire, source)
			if !errors.Is(err, ErrHubLSTCookieProofRequired) {
				t.Fatalf("error = %v, want proof required", err)
			}
			var challenge *HubLSTCookieChallengeError
			gotChallenge := errors.As(err, &challenge)
			if gotChallenge != tc.wantChallenge {
				t.Fatalf("challenge emitted = %v, want %v", gotChallenge, tc.wantChallenge)
			}
			if gotChallenge && len(challenge.Packet()) >= len(wire) {
				t.Fatalf("challenge length %d must be strictly less than request %d", len(challenge.Packet()), len(wire))
			}
		})
	}
}

func TestHubLSTCookieRapidProofOnSameConnection(t *testing.T) {
	f := newHubLSTCookieFixture(t)
	source := &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 41000}
	conn := &ConnectionData{RemoteAddr: source}
	body := bytes.Repeat([]byte{0x5b}, 237)
	initial := f.sealLST(t, body, 31, nil, false)
	_, err := f.server.PacketToMsg(&PacketData{
		BasePacket: &Packet{Content: bytes.Clone(initial), HeaderType: NHP_LST},
		ConnData:   conn,
	})
	var challenge *HubLSTCookieChallengeError
	if !errors.As(err, &challenge) {
		t.Fatalf("initial LST error = %v, want challenge", err)
	}
	_, cok := f.decryptCOK(t, challenge.Packet())
	cookie := decodeCookie32(t, cok.Cookie)

	proof, proofSendTime := f.sealLSTWithSendTime(t, body, 32, &cookie, false)
	// Pin the inherited connection state one millisecond behind the fresh proof.
	// Before the Hub exemption this deterministically tripped the 20 ms floor.
	atomic.StoreInt64(&conn.LastRemoteSendTime, proofSendTime-int64(time.Millisecond))
	parsed, err := f.server.PacketToMsg(&PacketData{
		BasePacket: &Packet{Content: bytes.Clone(proof), HeaderType: NHP_LST},
		ConnData:   conn,
	})
	if err != nil {
		t.Fatalf("rapid proof rejected: %v", err)
	}
	if !bytes.Equal(parsed.BodyMessage, body) {
		t.Fatal("rapid proof body changed")
	}

	if _, err := f.server.PacketToMsg(&PacketData{
		BasePacket: &Packet{Content: bytes.Clone(proof), HeaderType: NHP_LST},
		ConnData:   conn,
	}); !errors.Is(err, ErrReplayPacketReceived) {
		t.Fatalf("exact proof replay error = %v, want replay rejection", err)
	}
}

func TestHubLSTCookieDerivationKAT(t *testing.T) {
	peer, err := hex.DecodeString("0233f006ef4bed144ea0a5bb46c7067c7c2acec5f8cc811f3df59fdcd5ac7614")
	if err != nil {
		t.Fatal(err)
	}
	const window = int64(59472000)
	tests := []struct {
		name       string
		ip         net.IP
		wantFamily byte
		wantRawHex string
		wantCookie string
	}{
		{name: "IPv4", ip: net.ParseIP("203.0.113.7"), wantFamily: 0x04, wantRawHex: "cb007107", wantCookie: "606fc2b99882d8dc6254d89a8756493c5183d068c07475005127f1adf8ebacb6"},
		{name: "IPv4 mapped", ip: net.ParseIP("::ffff:203.0.113.7"), wantFamily: 0x04, wantRawHex: "cb007107", wantCookie: "606fc2b99882d8dc6254d89a8756493c5183d068c07475005127f1adf8ebacb6"},
		{name: "IPv6", ip: net.ParseIP("2001:db8::7"), wantFamily: 0x06, wantRawHex: "20010db8000000000000000000000007", wantCookie: "da0558a748b79eec892f485a11c3deeedb9041dfecd7d13b15eb37d901323f1d"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			family, source, ok := canonicalHubLSTSourceIP(&ConnectionData{RemoteAddr: &net.UDPAddr{IP: tc.ip, Port: 65535}})
			if !ok {
				t.Fatal("canonical source rejected")
			}
			if family != tc.wantFamily || hex.EncodeToString(source) != tc.wantRawHex {
				t.Fatalf("canonical source = family %#x raw %x, want %#x/%s", family, source, tc.wantFamily, tc.wantRawHex)
			}
			var got [CookieSize]byte
			deriveHubLSTCookieInto(&got, hubLSTTestKey, family, source, peer, window)
			if hex.EncodeToString(got[:]) != tc.wantCookie {
				t.Fatalf("cookie = %x, want %s", got, tc.wantCookie)
			}
		})
	}

	invalid := []*ConnectionData{
		nil,
		{},
		{RemoteAddr: &net.UDPAddr{IP: net.ParseIP("2001:db8::7"), Zone: "eth0"}},
		{RemoteAddr: &net.UDPAddr{IP: net.IP{1, 2, 3, 4, 5}}},
	}
	for i, conn := range invalid {
		if _, _, ok := canonicalHubLSTSourceIP(conn); ok {
			t.Errorf("invalid source %d accepted", i)
		}
	}
}

func TestHubLSTCookieProofDigestKAT(t *testing.T) {
	serverPublicKey, err := hex.DecodeString("4d27bcee3135c4944b28d27dd809b07be10c35160d20131caa7e85575498d07c")
	if err != nil {
		t.Fatal(err)
	}
	headerPrefix, err := hex.DecodeString("c1d2e3f4c1d7e331010000040000000000000000000000173a553d74792d727efa9b9a4cde3da1ad93f1a2d0c09cb639b1a3c0fda14cbe240000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e51c96e754bba5426ed4b5d6cf38cb3c173568c29010c70049925f42dd10c0c1cecf72766c7475288fd5da54d18c2cf7f6656361fcaefc4c25c8f5069da44db732656a2e235c7212")
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := hex.DecodeString("606fc2b99882d8dc6254d89a8756493c5183d068c07475005127f1adf8ebacb6")
	if err != nil {
		t.Fatal(err)
	}
	if len(headerPrefix) != 208 {
		t.Fatalf("header prefix length = %d, want 208", len(headerPrefix))
	}
	if !bytes.Equal(headerPrefix[10:12], []byte{0, common.NHP_FLAG_HUB_LST_COOKIE_PROOF}) {
		t.Fatalf("proof prefix flags = %x, want 0004", headerPrefix[10:12])
	}
	if !bytes.Equal(headerPrefix[16:24], []byte{0, 0, 0, 0, 0, 0, 0, 23}) {
		t.Fatalf("proof prefix counter bytes = %x, want counter 23", headerPrefix[16:24])
	}

	h, err := NewHash(HASH_BLAKE2S)
	if err != nil {
		t.Fatal(err)
	}
	h.Write(initialHashBytes)
	h.Write(serverPublicKey)
	h.Write(headerPrefix)
	h.Write(cookie)
	if got, want := hex.EncodeToString(h.Sum(nil)), "7aaa44aaf8f8876973120c8870b761603b6125bbe5322bb7c242fc9ca502efe3"; got != want {
		t.Fatalf("proof digest = %s, want %s", got, want)
	}
}

func TestHubLSTCookieProofWindowAndBindingRejects(t *testing.T) {
	f := newHubLSTCookieFixture(t)
	source := &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 41000}
	family, sourceIP, ok := canonicalHubLSTSourceIP(&ConnectionData{RemoteAddr: source})
	if !ok {
		t.Fatal("canonical source")
	}
	const currentWindow = int64(59472000)
	initTime := (currentWindow*HubLSTCookieWindowSeconds + 5) * int64(time.Second)
	tests := []struct {
		name       string
		window     int64
		source     *net.UDPAddr
		cookiePeer []byte
		wantAccept bool
	}{
		{name: "current", window: currentWindow, source: source, wantAccept: true},
		{name: "previous", window: currentWindow - 1, source: source, wantAccept: true},
		{name: "future", window: currentWindow + 1, source: source},
		{name: "two windows old", window: currentWindow - 2, source: source},
		{name: "wrong source", window: currentWindow, source: &net.UDPAddr{IP: net.ParseIP("203.0.113.8"), Port: 41000}},
		{name: "wrong authenticated peer", window: currentWindow, source: source, cookiePeer: bytes.Repeat([]byte{0x99}, PublicKeySize)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cookiePeer := tc.cookiePeer
			if cookiePeer == nil {
				cookiePeer = f.agent.staticEcdh.PublicKey()
			}
			var cookie [CookieSize]byte
			deriveHubLSTCookieInto(&cookie, hubLSTTestKey, family, sourceIP, cookiePeer, tc.window)
			wire := f.sealLST(t, []byte("same authenticated assignment body"), 99, &cookie, false)
			pkt := &Packet{Content: bytes.Clone(wire), HeaderType: NHP_LST}
			if _, _, err := f.server.RecvPrecheck(pkt); err != nil {
				t.Fatalf("RecvPrecheck: %v", err)
			}
			ppd, err := f.server.createPacketParserData(&PacketData{BasePacket: pkt, ConnData: &ConnectionData{RemoteAddr: tc.source}, InitTime: initTime})
			if ppd != nil {
				defer ppd.Destroy()
			}
			if tc.wantAccept && err != nil {
				t.Fatalf("proof digest rejected: %v", err)
			}
			if !tc.wantAccept && !errors.Is(err, ErrServerHeaderDigestCheckFailed) {
				t.Fatalf("proof digest error = %v, want server digest rejection", err)
			}
		})
	}
}

func TestHubLSTCookieFlagsAndSenderConfiguration(t *testing.T) {
	f := newHubLSTCookieFixture(t)
	source := &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 41000}
	compressed := f.sealLST(t, bytes.Repeat([]byte("compress-me"), 20), 7, nil, true)
	if got := (&Packet{Content: compressed}).Flag(); got != common.NHP_FLAG_COMPRESS {
		t.Fatalf("compressed flag = %#x, want %#x", got, common.NHP_FLAG_COMPRESS)
	}
	if _, err := f.parseOnHub(t, compressed, source); !errors.Is(err, ErrInvalidHubLSTFlags) {
		t.Fatalf("compressed Hub LST error = %v, want invalid flags", err)
	}

	unknown := f.sealLST(t, bytes.Repeat([]byte{1}, 100), 8, nil, false)
	binaryFlag := uint16(0x0008)
	unknown[10] = byte(binaryFlag >> 8)
	unknown[11] = byte(binaryFlag)
	if _, err := f.parseOnHub(t, unknown, source); !errors.Is(err, ErrInvalidHubLSTFlags) {
		t.Fatalf("unknown Hub LST flag error = %v, want invalid flags", err)
	}

	var cookie [CookieSize]byte
	if _, err := f.agent.MsgToPacket(&MsgData{HeaderType: NHP_LST, Compress: true, HubLSTCookieProof: &cookie}); !errors.Is(err, ErrInvalidHubLSTCookieProof) {
		t.Fatalf("compressed proof sender error = %v, want invalid proof configuration", err)
	}
	if _, err := f.agent.MsgToPacket(&MsgData{HeaderType: NHP_KNK, HubLSTCookieProof: &cookie}); !errors.Is(err, ErrInvalidHubLSTCookieProof) {
		t.Fatalf("non-LST proof sender error = %v, want invalid proof configuration", err)
	}
	if err := f.server.SetHubLSTCookieKeys(make([]byte, SymmetricKeySize-1), nil); err == nil {
		t.Fatal("short Hub LST cookie key accepted")
	}
}

func TestHubLSTCookiePinsAdmissionModePerPacket(t *testing.T) {
	source := &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 41000}

	t.Run("disabled at parse cannot widen mid-packet", func(t *testing.T) {
		f := newHubLSTCookieFixture(t)
		f.server.SetOption(DeviceOptions{})
		wire := f.sealLST(t, bytes.Repeat([]byte{0x41}, 237), 41, nil, false)
		pkt := &Packet{Content: bytes.Clone(wire), HeaderType: NHP_LST}
		if _, _, err := f.server.RecvPrecheck(pkt); err != nil {
			t.Fatalf("RecvPrecheck: %v", err)
		}
		ppd, err := f.server.createPacketParserData(&PacketData{
			BasePacket: pkt,
			ConnData:   &ConnectionData{RemoteAddr: source},
			InitTime:   time.Now().UnixNano(),
		})
		if err != nil {
			t.Fatalf("create parser: %v", err)
		}
		defer ppd.Destroy()
		f.server.SetOption(DeviceOptions{AllowUnregisteredAgentLST: true})
		if err := ppd.validatePeer(); !errors.Is(err, ErrPeerNotFound) {
			t.Fatalf("mid-packet enable error = %v, want registered-peer rejection", err)
		}
	})

	t.Run("enabled at parse retains cookie gate mid-packet", func(t *testing.T) {
		f := newHubLSTCookieFixture(t)
		wire := f.sealLST(t, bytes.Repeat([]byte{0x42}, 237), 42, nil, false)
		pkt := &Packet{Content: bytes.Clone(wire), HeaderType: NHP_LST}
		if _, _, err := f.server.RecvPrecheck(pkt); err != nil {
			t.Fatalf("RecvPrecheck: %v", err)
		}
		ppd, err := f.server.createPacketParserData(&PacketData{
			BasePacket: pkt,
			ConnData:   &ConnectionData{RemoteAddr: source},
			InitTime:   time.Now().UnixNano(),
		})
		if err != nil {
			t.Fatalf("create parser: %v", err)
		}
		defer ppd.Destroy()
		f.server.SetOption(DeviceOptions{})
		if err := ppd.validatePeer(); err != nil {
			t.Fatalf("pinned Hub peer validation: %v", err)
		}
		if err := ppd.decryptBody(); err != nil {
			t.Fatalf("pinned Hub body decrypt: %v", err)
		}
		if err := ppd.enforceHubLSTCookieChallenge(); !errors.Is(err, ErrHubLSTCookieProofRequired) {
			t.Fatalf("mid-packet disable error = %v, want retained proof gate", err)
		}
	})
}

func TestHubLSTCookieMissingConfigurationFailsSilent(t *testing.T) {
	f := newHubLSTCookieFixture(t)
	if err := f.server.SetHubLSTCookieKeys(nil, nil); err != nil {
		t.Fatal(err)
	}
	wire := f.sealLST(t, bytes.Repeat([]byte{1}, 237), 1, nil, false)
	_, err := f.parseOnHub(t, wire, &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 41000})
	if !errors.Is(err, ErrHubLSTCookieProofRequired) {
		t.Fatalf("missing-key error = %v, want proof required", err)
	}
	var challenge *HubLSTCookieChallengeError
	if errors.As(err, &challenge) {
		t.Fatal("missing key emitted a COK")
	}
}

func TestHubLSTCookieKeyRotationOverlap(t *testing.T) {
	f := newHubLSTCookieFixture(t)
	previous := bytes.Repeat([]byte{0x5a}, SymmetricKeySize)
	oldActiveStorage := f.server.hubLSTCookieActiveKey
	if err := f.server.SetHubLSTCookieKeys(hubLSTTestKey, previous); err != nil {
		t.Fatalf("install overlap keys: %v", err)
	}
	if !bytes.Equal(oldActiveStorage, make([]byte, SymmetricKeySize)) {
		t.Fatal("superseded active key material was not zeroed")
	}

	source := &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 41000}
	family, sourceIP, ok := canonicalHubLSTSourceIP(&ConnectionData{RemoteAddr: source})
	if !ok {
		t.Fatal("canonical source")
	}
	initial := f.sealLST(t, bytes.Repeat([]byte{0x6c}, 237), 77, nil, false)
	_, challengeErr := f.parseOnHub(t, initial, source)
	var challenge *HubLSTCookieChallengeError
	if !errors.As(challengeErr, &challenge) {
		t.Fatalf("overlap challenge error = %v", challengeErr)
	}
	_, cok := f.decryptCOK(t, challenge.Packet())
	minted := decodeCookie32(t, cok.Cookie)
	nowWindow := time.Now().Unix() / HubLSTCookieWindowSeconds
	activeMatch := false
	previousMatch := false
	for _, window := range [2]int64{nowWindow, nowWindow - 1} {
		var candidate [CookieSize]byte
		deriveHubLSTCookieInto(&candidate, hubLSTTestKey, family, sourceIP, f.agent.staticEcdh.PublicKey(), window)
		activeMatch = activeMatch || bytes.Equal(minted[:], candidate[:])
		deriveHubLSTCookieInto(&candidate, previous, family, sourceIP, f.agent.staticEcdh.PublicKey(), window)
		previousMatch = previousMatch || bytes.Equal(minted[:], candidate[:])
	}
	if !activeMatch || previousMatch {
		t.Fatalf("challenge mint key selection: active match=%v previous match=%v", activeMatch, previousMatch)
	}

	const currentWindow = int64(59472000)
	initTime := (currentWindow*HubLSTCookieWindowSeconds + 5) * int64(time.Second)
	for _, window := range []int64{currentWindow, currentWindow - 1} {
		var cookie [CookieSize]byte
		deriveHubLSTCookieInto(&cookie, previous, family, sourceIP, f.agent.staticEcdh.PublicKey(), window)
		wire := f.sealLST(t, []byte("rotation-overlap-body"), uint64(window), &cookie, false)
		pkt := &Packet{Content: bytes.Clone(wire), HeaderType: NHP_LST}
		if _, _, err := f.server.RecvPrecheck(pkt); err != nil {
			t.Fatalf("RecvPrecheck: %v", err)
		}
		ppd, err := f.server.createPacketParserData(&PacketData{BasePacket: pkt, ConnData: &ConnectionData{RemoteAddr: source}, InitTime: initTime})
		if ppd != nil {
			ppd.Destroy()
		}
		if err != nil {
			t.Fatalf("previous-key window %d rejected: %v", window, err)
		}
	}

	beforeActive := bytes.Clone(f.server.hubLSTCookieActiveKey)
	beforePrevious := bytes.Clone(f.server.hubLSTCookiePreviousKey)
	if err := f.server.SetHubLSTCookieKeys(nil, previous); err == nil {
		t.Fatal("previous key without active accepted")
	}
	if !bytes.Equal(f.server.hubLSTCookieActiveKey, beforeActive) || !bytes.Equal(f.server.hubLSTCookiePreviousKey, beforePrevious) {
		t.Fatal("rejected previous-only update mutated live keys")
	}
	if err := f.server.SetHubLSTCookieKeys(hubLSTTestKey, make([]byte, SymmetricKeySize-1)); err == nil {
		t.Fatal("short previous key accepted")
	}
	oldActiveSlot := f.server.hubLSTCookieActiveKey
	oldPreviousSlot := f.server.hubLSTCookiePreviousKey
	if err := f.server.SetHubLSTCookieKeys(bytes.Repeat([]byte{0xa4}, SymmetricKeySize), nil); err != nil {
		t.Fatalf("rotate overlap keys: %v", err)
	}
	if !IsZero(oldActiveSlot) || !IsZero(oldPreviousSlot) {
		t.Fatal("superseded overlap key material was not zeroed")
	}
}

func TestHubLSTCookieReturnedBodyOwnsStorage(t *testing.T) {
	f := newHubLSTCookieFixture(t)
	source := &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 41000}
	family, sourceIP, ok := canonicalHubLSTSourceIP(&ConnectionData{RemoteAddr: source})
	if !ok {
		t.Fatal("canonical source")
	}
	window := time.Now().Unix() / HubLSTCookieWindowSeconds
	var cookie [CookieSize]byte
	deriveHubLSTCookieInto(&cookie, hubLSTTestKey, family, sourceIP, f.agent.staticEcdh.PublicKey(), window)
	body := []byte("owned strict connectorhub assignment body")
	wire := f.sealLST(t, body, 123, &cookie, false)

	pkt := f.server.AllocatePoolPacket()
	if pkt == nil {
		t.Fatal("allocate pool packet")
	}
	backing := pkt.Buf
	copy(backing[:], wire)
	pkt.Content = backing[:len(wire)]
	pkt.HeaderType = NHP_LST
	parsed, err := f.server.PacketToMsg(&PacketData{BasePacket: pkt, ConnData: &ConnectionData{RemoteAddr: source}})
	if err != nil {
		t.Fatalf("proof LST: %v", err)
	}
	if parsed.basePacket == nil || parsed.basePacket.Buf != nil {
		t.Fatal("PacketToMsg did not release the pool-owned base packet")
	}
	for i := range backing {
		backing[i] = 0xee
	}
	if !bytes.Equal(parsed.BodyMessage, body) {
		t.Fatal("returned Hub LST body aliases released packet storage")
	}
}

func TestHubLSTCookieChallengeErrorRedactsAndCopiesPacket(t *testing.T) {
	f := newHubLSTCookieFixture(t)
	wire := f.sealLST(t, bytes.Repeat([]byte{0x7c}, 237), hubLSTMaxCounter, nil, false)
	_, err := f.parseOnHub(t, wire, &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 41000})
	var challenge *HubLSTCookieChallengeError
	if !errors.As(err, &challenge) {
		t.Fatalf("error = %v, want challenge", err)
	}
	first := challenge.Packet()
	second := challenge.Packet()
	if len(first) == 0 || !bytes.Equal(first, second) {
		t.Fatal("challenge packet accessor did not return equal independent copies")
	}
	first[0] ^= 0xff
	if bytes.Equal(first, challenge.Packet()) {
		t.Fatal("challenge packet accessor aliases internal storage")
	}
	if got := challenge.Error(); got != ErrHubLSTCookieProofRequired.Error() {
		t.Fatalf("challenge Error() = %q, want generic sentinel text", got)
	}
	_, cok := f.decryptCOK(t, second)
	if bytes.Contains([]byte(challenge.Error()), second) || bytes.Contains([]byte(challenge.Error()), []byte(cok.Cookie)) {
		t.Fatal("challenge Error() exposed packet or cookie material")
	}
}

func TestHubLSTPublicRejectsDoNotEmitPerPacketLogs(t *testing.T) {
	// Do not call t.Parallel: the logger swap is process-wide.
	f := newHubLSTCookieFixture(t)
	source := &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 41000}
	validInitial := f.sealLST(t, bytes.Repeat([]byte{0x44}, 237), 1, nil, false)
	compressed := f.sealLST(t, bytes.Repeat([]byte("compress"), 40), 2, nil, true)
	badStatic := bytes.Clone(validInitial)
	(&Packet{Content: badStatic}).Header().StaticBytes()[0] ^= 0x80
	badBody := bytes.Clone(validInitial)
	badBody[len(badBody)-1] ^= 0x80
	var wrongCookie [CookieSize]byte
	wrongProof := f.sealLST(t, bytes.Repeat([]byte{0x55}, 237), 3, &wrongCookie, false)

	logDir := t.TempDir()
	testLogger := log.NewLogger("NHP-Hub-LST-Log-Test", log.LogLevelDebug, logDir, "hub-lst")
	previousLogger := log.SwapGlobalLogger(testLogger)
	restored := false
	t.Cleanup(func() {
		if !restored {
			log.SwapGlobalLogger(previousLogger)
			testLogger.Close()
		}
	})

	for name, wire := range map[string][]byte{
		"valid source-unproven challenge": validInitial,
		"compressed":                      compressed,
		"bad static":                      badStatic,
		"bad body":                        badBody,
		"bad proof":                       wrongProof,
	} {
		if _, err := f.parseOnHub(t, wire, source); err == nil {
			t.Errorf("%s unexpectedly accepted", name)
		}
	}
	f.server.SetOverload(true)
	if _, err := f.parseOnHub(t, validInitial, source); !errors.Is(err, ErrServerOverload) {
		t.Fatalf("overload error = %v, want server overload", err)
	}
	f.server.SetOverload(false)
	log.SwapGlobalLogger(previousLogger)
	testLogger.Close()
	restored = true

	var allLogs []byte
	if err := filepath.WalkDir(logDir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		contents, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		allLogs = append(allLogs, contents...)
		return nil
	}); err != nil {
		t.Fatalf("read Hub LST logs: %v", err)
	}
	if trimmed := bytes.TrimSpace(allLogs); len(trimmed) != 0 {
		t.Fatalf("public Hub LST per-packet diagnostics must be suppressed; got logs:\n%s", trimmed)
	}
}

func TestHubLSTCookieAsyncPathFailsClosedWithoutDeliveringBody(t *testing.T) {
	f := newHubLSTCookieFixture(t)
	wire := f.sealLST(t, bytes.Repeat([]byte{0x31}, 237), 88, nil, false)
	packet := f.server.AllocatePoolPacket()
	if packet == nil {
		t.Fatal("allocate packet")
	}
	copy(packet.Buf[:], wire)
	packet.Content = packet.Buf[:len(wire)]
	packet.HeaderType = NHP_LST
	resultCh := make(chan *PacketParserData, 1)
	f.server.Start()
	t.Cleanup(f.server.Stop)
	if !f.server.RecvPacketToMsg(&PacketData{
		BasePacket:     packet,
		ConnData:       &ConnectionData{RemoteAddr: &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 41000}},
		InitTime:       time.Now().UnixNano(),
		DecryptedMsgCh: resultCh,
	}) {
		t.Fatal("async packet unexpectedly shed")
	}
	select {
	case result := <-resultCh:
		if result == nil || !errors.Is(result.Error, ErrHubLSTCookieProofRequired) {
			t.Fatalf("async result = %#v, want proof-required error", result)
		}
		if len(result.BodyMessage) != 0 {
			t.Fatal("async path delivered an unproven application body")
		}
		var challenge *HubLSTCookieChallengeError
		if errors.As(result.Error, &challenge) {
			t.Fatal("async path surfaced a sendable challenge packet")
		}
		if result.basePacket == nil || result.basePacket.Buf != nil {
			t.Fatal("async challenge error retained its pool packet")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for async proof-required result")
	}
}
