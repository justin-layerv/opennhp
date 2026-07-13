package core

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
)

func deriveStatelessCookie(signingKey []byte, remoteKey string, peerPk []byte, windowIndex int64) []byte {
	var cookie [CookieSize]byte
	deriveStatelessCookieInto(&cookie, signingKey, remoteKey, peerPk, windowIndex)
	return append([]byte(nil), cookie[:]...)
}

func referenceStatelessCookieHMAC(signingKey []byte, remoteKey string, peerPk []byte, windowIndex int64) []byte {
	mac := hmac.New(sha256.New, signingKey)
	mac.Write([]byte(statelessCookieDomain))
	var b4 [4]byte
	binary.BigEndian.PutUint32(b4[:], uint32(len(remoteKey)))
	mac.Write(b4[:])
	mac.Write([]byte(remoteKey))
	binary.BigEndian.PutUint32(b4[:], uint32(len(peerPk)))
	mac.Write(b4[:])
	mac.Write(peerPk)
	var b8 [8]byte
	binary.BigEndian.PutUint64(b8[:], uint64(windowIndex))
	mac.Write(b8[:])
	return mac.Sum(nil)
}

func TestCookieRemoteKeyPrefersRelaySourceAddr(t *testing.T) {
	cd := &ConnectionData{
		RemoteAddr:     &net.UDPAddr{IP: net.ParseIP("198.51.100.10"), Port: 62206},
		RealRemoteAddr: &net.UDPAddr{IP: net.ParseIP("203.0.113.42"), Port: 51234},
	}
	if got := cookieRemoteKey(cd); got != "203.0.113.42" {
		t.Fatalf("cookieRemoteKey = %q, want real client IP %q", got, "203.0.113.42")
	}
}

func TestCookieRemoteKeyNormalizesIPv4MappedIPv6(t *testing.T) {
	plain := &ConnectionData{RemoteAddr: &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 9000}}
	mapped := &ConnectionData{RemoteAddr: &net.UDPAddr{IP: net.ParseIP("::ffff:203.0.113.7"), Port: 9001}}
	if cookieRemoteKey(plain) != cookieRemoteKey(mapped) {
		t.Fatalf("IPv4 and IPv4-mapped IPv6 keys differ: %q vs %q", cookieRemoteKey(plain), cookieRemoteKey(mapped))
	}
}

func TestDeriveStatelessCookieBindsPeerIdentity(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, SymmetricKeySize)
	remote := "203.0.113.7"
	pkA := bytes.Repeat([]byte{0xAA}, PublicKeySize)
	pkB := bytes.Repeat([]byte{0xBB}, PublicKeySize)

	cookieA := deriveStatelessCookie(key, remote, pkA, 12345)
	cookieB := deriveStatelessCookie(key, remote, pkB, 12345)
	if bytes.Equal(cookieA, cookieB) {
		t.Fatalf("distinct peer pubkeys behind one NAT derived identical cookie %x", cookieA)
	}
}

func TestDeriveStatelessCookieWindowSeparation(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, SymmetricKeySize)
	pk := bytes.Repeat([]byte{0xAA}, PublicKeySize)
	curr := deriveStatelessCookie(key, "203.0.113.7", pk, 12345)
	next := deriveStatelessCookie(key, "203.0.113.7", pk, 12346)
	if bytes.Equal(curr, next) {
		t.Fatalf("consecutive windows derived identical cookie %x", curr)
	}
}

func TestDeriveStatelessCookieIntoMatchesReferenceHMAC(t *testing.T) {
	prodKey := bytes.Repeat([]byte{0x42}, SymmetricKeySize)
	prodRemote := "2001:db8::8:800:200c:417a"
	prodPk := bytes.Repeat([]byte{0xAA}, PublicKeySize)
	const prodWindow = int64(12345)

	for _, tc := range []struct {
		name   string
		key    []byte
		remote string
		pk     []byte
		window int64
	}{
		{
			name:   "production fast path",
			key:    prodKey,
			remote: prodRemote,
			pk:     prodPk,
			window: prodWindow,
		},
		{
			name:   "short key padding",
			key:    bytes.Repeat([]byte{0x11}, SymmetricKeySize+7),
			remote: "203.0.113.7",
			pk:     bytes.Repeat([]byte{0x22}, PublicKeySize),
			window: 7,
		},
		{
			name:   "long key hashing",
			key:    bytes.Repeat([]byte{0x33}, sha256.BlockSize+1),
			remote: "2001:db8::1",
			pk:     bytes.Repeat([]byte{0x44}, PublicKeySize),
			window: 8,
		},
		{
			name:   "oversized remote fallback",
			key:    prodKey,
			remote: string(bytes.Repeat([]byte{'r'}, maxStatelessCookieRemoteKey+1)),
			pk:     prodPk,
			window: 9,
		},
		{
			name:   "oversized peer fallback",
			key:    prodKey,
			remote: prodRemote,
			pk:     bytes.Repeat([]byte{0x55}, PublicKeySize+1),
			window: 10,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got [CookieSize]byte
			deriveStatelessCookieInto(&got, tc.key, tc.remote, tc.pk, tc.window)
			if want := referenceStatelessCookieHMAC(tc.key, tc.remote, tc.pk, tc.window); !bytes.Equal(got[:], want) {
				t.Fatalf("deriveStatelessCookieInto = %x, want reference HMAC %x", got, want)
			}
		})
	}

	var got [CookieSize]byte
	allocs := testing.AllocsPerRun(1000, func() {
		deriveStatelessCookieInto(&got, prodKey, prodRemote, prodPk, prodWindow)
	})
	if allocs != 0 {
		t.Fatalf("production deriveStatelessCookieInto allocated %.0f times, want 0", allocs)
	}
}

func FuzzDeriveStatelessCookieIntoMatchesReferenceHMAC(f *testing.F) {
	for _, seed := range []struct {
		key    []byte
		remote string
		pk     []byte
		window int64
	}{
		{bytes.Repeat([]byte{0x42}, SymmetricKeySize), "203.0.113.7", bytes.Repeat([]byte{0xAA}, PublicKeySize), 1},
		{bytes.Repeat([]byte{0x11}, 17), "", nil, -1},
		{bytes.Repeat([]byte{0x22}, sha256.BlockSize+1), string(bytes.Repeat([]byte{'r'}, maxStatelessCookieRemoteKey+1)), bytes.Repeat([]byte{0xBB}, PublicKeySize+1), 99},
	} {
		f.Add(seed.key, seed.remote, seed.pk, seed.window)
	}

	f.Fuzz(func(t *testing.T, key []byte, remote string, pk []byte, window int64) {
		if len(key) > 128 || len(remote) > 128 || len(pk) > 96 {
			t.Skip("bounded to keep fuzz-quick focused on cookie derivation")
		}

		var got [CookieSize]byte
		deriveStatelessCookieInto(&got, key, remote, pk, window)
		if want := referenceStatelessCookieHMAC(key, remote, pk, window); !bytes.Equal(got[:], want) {
			t.Fatalf("deriveStatelessCookieInto = %x, want reference HMAC %x", got, want)
		}
	})
}

func TestStatelessCookieParamsCopyOut(t *testing.T) {
	dev := newDeviceForChainKeyTest(t)
	orig := bytes.Repeat([]byte{0xAB}, SymmetricKeySize)
	dev.SetStatelessCookieParams(orig, 5)

	got, win := dev.StatelessCookieParams()
	if win != 5 || !bytes.Equal(got, orig) {
		t.Fatalf("StatelessCookieParams = (%x, %d), want (%x, 5)", got, win, orig)
	}
	got[0] ^= 0xFF
	again, _ := dev.StatelessCookieParams()
	if !bytes.Equal(again, orig) {
		t.Fatalf("returned key aliases device key: got %x want %x", again, orig)
	}
}

func TestSendCookieUsesStatelessCookieWithoutConnectionStore(t *testing.T) {
	dev := newDeviceForChainKeyTest(t)
	signingKey := bytes.Repeat([]byte{0x42}, SymmetricKeySize)
	const window = int64(60)
	dev.SetStatelessCookieParams(signingKey, int(window))

	peerPk := testPeerPk()
	remote := &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 51234}
	ppd := &PacketParserData{
		device:       dev,
		CipherScheme: common.CIPHER_SCHEME_CURVE,
		Ciphers:      NewCipherSuite(),
		RemotePubKey: peerPk,
		SenderTrxId:  0xC0FFEE,
		ConnData:     &ConnectionData{RemoteAddr: remote},
	}

	ppd.sendCookie()

	var md *MsgData
	select {
	case md = <-dev.msgToPacketQueue:
	default:
		t.Fatal("sendCookie did not enqueue MsgData")
	}

	var cok common.ServerCookieMsg
	if err := json.Unmarshal(md.Message, &cok); err != nil {
		t.Fatalf("unmarshal ServerCookieMsg: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(cok.Cookie)
	if err != nil {
		t.Fatalf("decode cookie: %v", err)
	}
	currWindow := time.Now().Unix() / window
	wantCurr := deriveStatelessCookie(signingKey, cookieRemoteKey(ppd.ConnData), peerPk, currWindow)
	wantPrev := deriveStatelessCookie(signingKey, cookieRemoteKey(ppd.ConnData), peerPk, currWindow-1)
	if !bytes.Equal(raw, wantCurr) && !bytes.Equal(raw, wantPrev) {
		t.Fatalf("stateless cookie = %x, want current %x or previous %x", raw, wantCurr, wantPrev)
	}
}

func TestSendCookieStatelessRequiresRemoteBinding(t *testing.T) {
	dev := newDeviceForChainKeyTest(t)
	signingKey := bytes.Repeat([]byte{0x42}, SymmetricKeySize)
	dev.SetStatelessCookieParams(signingKey, 60)

	ppd := &PacketParserData{
		device:       dev,
		CipherScheme: common.CIPHER_SCHEME_CURVE,
		Ciphers:      NewCipherSuite(),
		RemotePubKey: testPeerPk(),
		SenderTrxId:  0xC0FFEE,
		ConnData:     &ConnectionData{},
	}

	ppd.sendCookie()

	select {
	case md := <-dev.msgToPacketQueue:
		t.Fatalf("sendCookie enqueued %s without remote binding", HeaderTypeToString(md.HeaderType))
	default:
	}
}

func TestSendCookieReportsMintFailureReason(t *testing.T) {
	dev := newDeviceForChainKeyTest(t)
	signingKey := bytes.Repeat([]byte{0x42}, SymmetricKeySize)
	dev.SetStatelessCookieParams(signingKey, 60)

	var reasons []string
	dev.SetCookieMintFailureHook(func(reason string) {
		reasons = append(reasons, reason)
	})

	ppd := &PacketParserData{
		device:       dev,
		CipherScheme: common.CIPHER_SCHEME_CURVE,
		Ciphers:      NewCipherSuite(),
		RemotePubKey: testPeerPk(),
		SenderTrxId:  0xC0FFEE,
		ConnData:     &ConnectionData{},
	}

	ppd.sendCookie()

	if len(reasons) != 1 || reasons[0] != cookieMintFailureMissingRemoteBinding {
		t.Fatalf("mint failure reasons = %v, want [%s]", reasons, cookieMintFailureMissingRemoteBinding)
	}
}

func newCurveDevice(t *testing.T, deviceType int, seed byte) *Device {
	t.Helper()
	priv := make([]byte, PrivateKeySize)
	for i := range priv {
		priv[i] = seed
	}
	dev := NewDevice(deviceType, priv, nil)
	if dev == nil {
		t.Fatalf("NewDevice(%d) returned nil", deviceType)
	}
	t.Cleanup(dev.Stop)
	return dev
}

func curvePubKey(dev *Device) []byte {
	return dev.GetEcdhByCipherScheme(common.CIPHER_SCHEME_CURVE).PublicKey()
}

func buildAgentRKNWithCookie(t *testing.T, agentDev *Device, serverPubKey []byte, cookie *[CookieSize]byte, remote *net.UDPAddr) []byte {
	t.Helper()
	mad, err := agentDev.MsgToPacket(&MsgData{
		HeaderType:     NHP_RKN,
		CipherScheme:   common.CIPHER_SCHEME_CURVE,
		TransactionId:  0xC00C1E00DEADBEEF,
		PeerPk:         serverPubKey,
		Message:        []byte(`{"hello":"rkn"}`),
		ExternalCookie: cookie,
		ConnData:       &ConnectionData{RemoteAddr: remote},
	})
	if err != nil {
		t.Fatalf("agent MsgToPacket(NHP_RKN): %v", err)
	}
	wire := make([]byte, len(mad.BasePacket.Content))
	copy(wire, mad.BasePacket.Content)
	return wire
}

func buildAgentKNK(t *testing.T, agentDev *Device, serverPubKey []byte, remote *net.UDPAddr) []byte {
	t.Helper()
	mad, err := agentDev.MsgToPacket(&MsgData{
		HeaderType:    NHP_KNK,
		CipherScheme:  common.CIPHER_SCHEME_CURVE,
		TransactionId: 0xC0C0AC1E,
		PeerPk:        serverPubKey,
		Message:       []byte(`{"hello":"knk"}`),
		ConnData:      &ConnectionData{RemoteAddr: remote},
	})
	if err != nil {
		t.Fatalf("agent MsgToPacket(NHP_KNK): %v", err)
	}
	wire := make([]byte, len(mad.BasePacket.Content))
	copy(wire, mad.BasePacket.Content)
	return wire
}

func parseRKNOnServerDataWithOverload(t *testing.T, serverDev *Device, wire []byte, remote *net.UDPAddr, overload bool) (*PacketParserData, error) {
	t.Helper()
	pkt := serverDev.AllocatePoolPacket()
	if pkt == nil {
		t.Fatal("AllocatePoolPacket returned nil")
	}
	copy(pkt.Buf[:], wire)
	pkt.Content = pkt.Buf[:len(wire)]

	serverDev.SetOverload(overload)
	defer serverDev.SetOverload(false)

	ppd, err := serverDev.createPacketParserData(&PacketData{
		BasePacket: pkt,
		ConnData:   &ConnectionData{RemoteAddr: remote},
		InitTime:   time.Now().UnixNano(),
	})
	if ppd != nil {
		t.Cleanup(ppd.Destroy)
	}
	return ppd, err
}

func parseRKNOnServerData(t *testing.T, serverDev *Device, wire []byte, remote *net.UDPAddr) (*PacketParserData, error) {
	t.Helper()
	return parseRKNOnServerDataWithOverload(t, serverDev, wire, remote, true)
}

func parseRKNOnServer(t *testing.T, serverDev *Device, wire []byte, remote *net.UDPAddr) error {
	t.Helper()
	_, err := parseRKNOnServerData(t, serverDev, wire, remote)
	return err
}

func TestCookieVerifyEndToEnd(t *testing.T) {
	const window = 60
	signingKey := bytes.Repeat([]byte{0x42}, SymmetricKeySize)

	agentDev := newCurveDevice(t, NHP_AGENT, 0x11)
	serverDev := newCurveDevice(t, NHP_SERVER, 0x22)
	serverDev.SetOption(DeviceOptions{DisableAgentPeerValidation: true})
	serverDev.SetStatelessCookieParams(signingKey, window)

	remote := &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 51234}
	raw := deriveStatelessCookie(signingKey, cookieRemoteKey(&ConnectionData{RemoteAddr: remote}), curvePubKey(agentDev), time.Now().Unix()/window)
	var cookie [CookieSize]byte
	copy(cookie[:], raw)

	wire := buildAgentRKNWithCookie(t, agentDev, curvePubKey(serverDev), &cookie, remote)
	ppd, err := parseRKNOnServerData(t, serverDev, wire, remote)
	if err != nil {
		t.Fatalf("cookie RKN verify failed end-to-end: %v", err)
	}
	if !bytes.Equal(ppd.RemotePubKey, curvePubKey(agentDev)) {
		t.Fatalf("recovered peer static pubkey = %x, want %x", ppd.RemotePubKey, curvePubKey(agentDev))
	}
	// This validates the transcript handoff from decryptInitiatorStaticPubKey:
	// the RKN digest check has already decrypted the static field, and
	// validatePeer must continue from that cached state instead of replaying it.
	if err := ppd.validatePeer(); err != nil {
		t.Fatalf("validatePeer failed after stateless cookie verification: %v", err)
	}
}

func TestCookieRoundTripMintsCOKThenVerifiesRKN(t *testing.T) {
	const window = 60
	signingKey := bytes.Repeat([]byte{0x42}, SymmetricKeySize)

	agentDev := newCurveDevice(t, NHP_AGENT, 0x11)
	minter := newCurveDevice(t, NHP_SERVER, 0x22)
	verifier := newCurveDevice(t, NHP_SERVER, 0x33)
	minter.SetStatelessCookieParams(signingKey, window)
	verifier.SetStatelessCookieParams(signingKey, window)
	minter.AddPeer(&UdpPeer{
		PubKeyBase64: agentDev.PublicKeyBase64(),
		Ip:           "203.0.113.7",
		Port:         51234,
		Type:         NHP_AGENT,
	})

	remote := &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 51234}
	knkWire := buildAgentKNK(t, agentDev, curvePubKey(minter), remote)
	knkPacket := &Packet{Content: knkWire, HeaderType: NHP_KNK}
	minter.SetOverload(true)
	ppd, err := minter.createPacketParserData(&PacketData{
		BasePacket: knkPacket,
		ConnData:   &ConnectionData{RemoteAddr: remote},
		InitTime:   time.Now().UnixNano(),
	})
	if err != nil {
		t.Fatalf("parse overload KNK: %v", err)
	}
	defer ppd.Destroy()
	assertNHPError(t, ppd.validatePeer(), ErrServerRejectWithCookie)

	var md *MsgData
	select {
	case md = <-minter.msgToPacketQueue:
	default:
		t.Fatal("overload KNK did not enqueue NHP_COK")
	}
	if md.HeaderType != NHP_COK {
		t.Fatalf("queued message type = %s, want NHP_COK", HeaderTypeToString(md.HeaderType))
	}
	var cok common.ServerCookieMsg
	if err := json.Unmarshal(md.Message, &cok); err != nil {
		t.Fatalf("unmarshal minted COK: %v", err)
	}
	rawCookie, err := base64.StdEncoding.DecodeString(cok.Cookie)
	if err != nil {
		t.Fatalf("decode minted COK: %v", err)
	}
	if len(rawCookie) != CookieSize {
		t.Fatalf("minted cookie length = %d, want %d", len(rawCookie), CookieSize)
	}

	var cookie [CookieSize]byte
	copy(cookie[:], rawCookie)
	rknWire := buildAgentRKNWithCookie(t, agentDev, curvePubKey(verifier), &cookie, remote)
	if _, err := parseRKNOnServerDataWithOverload(t, verifier, rknWire, remote, false); err != nil {
		t.Fatalf("RKN with cookie minted from real overload KNK was rejected by non-overloaded verifier: %v", err)
	}
}

func TestCookieConfiguredDoesNotForceKNKThroughCookieDigest(t *testing.T) {
	signingKey := bytes.Repeat([]byte{0x42}, SymmetricKeySize)

	agentDev := newCurveDevice(t, NHP_AGENT, 0x11)
	serverDev := newCurveDevice(t, NHP_SERVER, 0x22)
	serverDev.SetStatelessCookieParams(signingKey, 60)

	remote := &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 51234}
	wire := buildAgentKNK(t, agentDev, curvePubKey(serverDev), remote)
	pkt := serverDev.AllocatePoolPacket()
	if pkt == nil {
		t.Fatal("AllocatePoolPacket returned nil")
	}
	copy(pkt.Buf[:], wire)
	pkt.Content = pkt.Buf[:len(wire)]

	ppd, err := serverDev.createPacketParserData(&PacketData{
		BasePacket: pkt,
		ConnData:   &ConnectionData{RemoteAddr: remote},
		InitTime:   time.Now().UnixNano(),
	})
	if err != nil {
		t.Fatalf("stateless params forced KNK through cookie digest path: %v", err)
	}
	defer ppd.Destroy()
	if ppd.peerStaticPubKeyDecrypted {
		t.Fatal("KNK parsed through the RKN stateless-cookie static decrypt path")
	}
}

func TestCookieVerifyCrossReplica(t *testing.T) {
	const window = 60
	signingKey := bytes.Repeat([]byte{0x42}, SymmetricKeySize)

	// Keep this with TestCookieVerifyEndToEnd: together they fence stateless
	// cookie verification and the shared transcript decrypt used by validatePeer.
	agentDev := newCurveDevice(t, NHP_AGENT, 0x11)
	verifier := newCurveDevice(t, NHP_SERVER, 0x33)
	verifier.SetStatelessCookieParams(signingKey, window)

	remote := &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 51234}
	raw := deriveStatelessCookie(signingKey, cookieRemoteKey(&ConnectionData{RemoteAddr: remote}), curvePubKey(agentDev), time.Now().Unix()/window)
	var cookie [CookieSize]byte
	copy(cookie[:], raw)

	wire := buildAgentRKNWithCookie(t, agentDev, curvePubKey(verifier), &cookie, remote)
	if _, err := parseRKNOnServerDataWithOverload(t, verifier, wire, remote, false); err != nil {
		t.Fatalf("cookie minted by a sibling instance failed to verify on a non-overloaded replica: %v", err)
	}
}

func TestCookieRKNReplayAcceptedOnFreshReplicaWithinWindow(t *testing.T) {
	const window = 60
	signingKey := bytes.Repeat([]byte{0x42}, SymmetricKeySize)

	agentDev := newCurveDevice(t, NHP_AGENT, 0x11)
	verifierA := newCurveDevice(t, NHP_SERVER, 0x33)
	verifierB := newCurveDevice(t, NHP_SERVER, 0x33)
	for _, verifier := range []*Device{verifierA, verifierB} {
		verifier.SetOption(DeviceOptions{DisableAgentPeerValidation: true})
		verifier.SetStatelessCookieParams(signingKey, window)
	}

	remote := &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 51234}
	raw := deriveStatelessCookie(signingKey, cookieRemoteKey(&ConnectionData{RemoteAddr: remote}), curvePubKey(agentDev), time.Now().Unix()/window)
	var cookie [CookieSize]byte
	copy(cookie[:], raw)

	wire := buildAgentRKNWithCookie(t, agentDev, curvePubKey(verifierA), &cookie, remote)
	for i, verifier := range []*Device{verifierA, verifierB} {
		ppd, err := parseRKNOnServerDataWithOverload(t, verifier, wire, remote, false)
		if err != nil {
			t.Fatalf("fresh verifier %d rejected replayed RKN header: %v", i, err)
		}
		if err := ppd.validatePeer(); err != nil {
			t.Fatalf("fresh verifier %d rejected replayed RKN peer validation: %v", i, err)
		}
	}
}

// TestCookieVerifyRejectsBadCookieOnNonOverloadedServer is also the upstream
// security fence for endpoints/server's protected handler reserve: an RKN with
// no server-issued proof must fail in core before dispatch can classify it as
// protected work. Stateless params force this check even after overload clears.
func TestCookieVerifyRejectsBadCookieOnNonOverloadedServer(t *testing.T) {
	const window = 60
	signingKey := bytes.Repeat([]byte{0x42}, SymmetricKeySize)

	agentDev := newCurveDevice(t, NHP_AGENT, 0x11)
	serverDev := newCurveDevice(t, NHP_SERVER, 0x22)
	serverDev.SetStatelessCookieParams(signingKey, window)
	remote := &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 51234}

	var cookie [CookieSize]byte
	copy(cookie[:], bytes.Repeat([]byte{0xEF}, CookieSize))
	wire := buildAgentRKNWithCookie(t, agentDev, curvePubKey(serverDev), &cookie, remote)
	if _, err := parseRKNOnServerDataWithOverload(t, serverDev, wire, remote, false); err == nil {
		t.Fatal("non-overloaded server accepted RKN with malformed stateless cookie")
	}
}

func TestCookieVerifyAcceptsPreviousWindow(t *testing.T) {
	const window = 86400
	signingKey := bytes.Repeat([]byte{0x42}, SymmetricKeySize)

	agentDev := newCurveDevice(t, NHP_AGENT, 0x11)
	serverDev := newCurveDevice(t, NHP_SERVER, 0x22)
	serverDev.SetStatelessCookieParams(signingKey, window)

	remote := &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 51234}
	raw := deriveStatelessCookie(signingKey, cookieRemoteKey(&ConnectionData{RemoteAddr: remote}), curvePubKey(agentDev), time.Now().Unix()/window-1)
	var cookie [CookieSize]byte
	copy(cookie[:], raw)

	wire := buildAgentRKNWithCookie(t, agentDev, curvePubKey(serverDev), &cookie, remote)
	if err := parseRKNOnServer(t, serverDev, wire, remote); err != nil {
		t.Fatalf("previous-window cookie was rejected: %v", err)
	}
}

func TestCookieVerifyRejectsExpiredWindow(t *testing.T) {
	const window = 86400
	signingKey := bytes.Repeat([]byte{0x42}, SymmetricKeySize)

	agentDev := newCurveDevice(t, NHP_AGENT, 0x11)
	serverDev := newCurveDevice(t, NHP_SERVER, 0x22)
	serverDev.SetStatelessCookieParams(signingKey, window)

	remote := &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 51234}
	raw := deriveStatelessCookie(signingKey, cookieRemoteKey(&ConnectionData{RemoteAddr: remote}), curvePubKey(agentDev), time.Now().Unix()/window-2)
	var cookie [CookieSize]byte
	copy(cookie[:], raw)

	wire := buildAgentRKNWithCookie(t, agentDev, curvePubKey(serverDev), &cookie, remote)
	if err := parseRKNOnServer(t, serverDev, wire, remote); err == nil {
		t.Fatal("expired-window cookie was accepted")
	}
}

// TestCookieVerifyRejectsWrongRemote proves the reserve's RKN proof is bound to
// the observed source, so copying a valid cookie onto spoofed-source traffic
// still fails before server dispatch.
func TestCookieVerifyRejectsWrongRemote(t *testing.T) {
	const window = 60
	signingKey := bytes.Repeat([]byte{0x42}, SymmetricKeySize)

	agentDev := newCurveDevice(t, NHP_AGENT, 0x11)
	serverDev := newCurveDevice(t, NHP_SERVER, 0x22)
	serverDev.SetStatelessCookieParams(signingKey, window)

	remote := &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 51234}
	raw := deriveStatelessCookie(signingKey, "198.51.100.99", curvePubKey(agentDev), time.Now().Unix()/window)
	var cookie [CookieSize]byte
	copy(cookie[:], raw)

	wire := buildAgentRKNWithCookie(t, agentDev, curvePubKey(serverDev), &cookie, remote)
	if err := parseRKNOnServer(t, serverDev, wire, remote); err == nil {
		t.Fatal("RKN with cookie bound to a different remote IP was accepted")
	}
}

func TestCookieVerifyRejectsWrongPeer(t *testing.T) {
	const window = 60
	signingKey := bytes.Repeat([]byte{0x42}, SymmetricKeySize)

	agentDev := newCurveDevice(t, NHP_AGENT, 0x11)
	wrongAgentDev := newCurveDevice(t, NHP_AGENT, 0x44)
	serverDev := newCurveDevice(t, NHP_SERVER, 0x22)
	serverDev.SetStatelessCookieParams(signingKey, window)

	remote := &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 51234}
	raw := deriveStatelessCookie(signingKey, cookieRemoteKey(&ConnectionData{RemoteAddr: remote}), curvePubKey(wrongAgentDev), time.Now().Unix()/window)
	var cookie [CookieSize]byte
	copy(cookie[:], raw)

	wire := buildAgentRKNWithCookie(t, agentDev, curvePubKey(serverDev), &cookie, remote)
	if err := parseRKNOnServer(t, serverDev, wire, remote); err == nil {
		t.Fatal("RKN with cookie bound to a different peer pubkey was accepted")
	}
}

func TestCookieVerifyRejectsMissingRemoteBinding(t *testing.T) {
	const window = 60
	signingKey := bytes.Repeat([]byte{0x42}, SymmetricKeySize)

	agentDev := newCurveDevice(t, NHP_AGENT, 0x11)
	serverDev := newCurveDevice(t, NHP_SERVER, 0x22)
	serverDev.SetStatelessCookieParams(signingKey, window)

	raw := deriveStatelessCookie(signingKey, "", curvePubKey(agentDev), time.Now().Unix()/window)
	var cookie [CookieSize]byte
	copy(cookie[:], raw)

	wire := buildAgentRKNWithCookie(t, agentDev, curvePubKey(serverDev), &cookie, nil)
	if _, err := parseRKNOnServerDataWithOverload(t, serverDev, wire, nil, true); err == nil {
		t.Fatal("RKN without remote address binding was accepted")
	}
}
