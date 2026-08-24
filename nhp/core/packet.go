package core

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"unsafe"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core/scheme/curve"
	log "github.com/OpenNHP/opennhp/nhp/log"
	utils "github.com/OpenNHP/opennhp/nhp/utils"
)

const (
	NHP_KPL = iota // general keepalive packet
	NHP_KNK        // agent sends knock to server
	NHP_ACK        // server replies knock status to agent
	NHP_AOP        // server asks ac for operation
	NHP_ART        // ac replies server for operation result
	NHP_LST        // agent requests server for listing services and applications
	NHP_LRT        // server replies to agent with services and applications result
	NHP_COK        // server sends cookie to agent
	NHP_RKN        // agent sends reknock to server
	NHP_RLY        // relay sends relayed packet to server
	NHP_AOL        // ac sends online status to server
	NHP_AAK        // server sends ack to ac after receiving ac's online status
	NHP_OTP        // agent requests server for one-time-password
	NHP_REG        // agent asks server for registering
	NHP_RAK        // server sends back ack when agent registers correctly
	NHP_ACC        // agent sends to ac/resource for actual ip access
	NHP_EXT        // agent requests immediate disconnection
	//DHP
	NHP_DRG // DB sends a message to register a data object file to the NHP Server
	NHP_DAK // NHP-Server sends a result of the NHP_DRG registration request to the DB.
	NHP_DAR // NHP Agent sends messages to get access to the file and then work with it.
	NHP_DAG // The NHP Server sends  the authorization status of the data object to NHP Agent.
	NHP_DSA // The NHP Server sends a self attestation requiestr to the NHP Agent
	NHP_DAV // The NHP Agent sends the attestation proof to the NHP Server.
	NHP_DWR // The NHP Server sends a request to the NHP DB to get the wrapping of the data private key
	NHP_DWA // The NHP DB sends the data private key to the NHP Server
	NHP_DOL // DB sends online status to server
	NHP_DBA // server send ack to db after receiving db's online status
	DHP_KNK // agent sends dhp knock to server

	// ============================================================================
	// Per-AC Server Assignment Messages (Phase 2 - Pluggable Storage Backend)
	// See docs/design/PLUGGABLE_STORAGE_BACKEND.md for architecture details.
	// ============================================================================
	NHP_FWD // server forwards knock to assigned server (server-to-server, LayerV extension)
	NHP_FRT // server returns forward result (server-to-server, LayerV extension)
	NHP_ARD // server sends AC redispatch with assigned servers (NHP spec message)

	// NHP_REV: server pushes a qURL v2 immediate-revocation event to the AC
	// (server-to-AC, LayerV extension). Mirrors the NHP_ARD precedent — the
	// revoke path is a distinct fire-and-forget message, NOT a verb on the
	// admission state machine. See docs/design/QURL_V2_KEYED_IDENTITY.md ->
	// "AC Admission and Immediate Revocation" (P4e receive side).
	NHP_REV

	// NHP_RVA: AC acknowledges an NHP_REV back to the server (AC-to-server,
	// LayerV extension). The AC sends one after it has processed an NHP_REV —
	// proof-of-delivery for DE-Risk #5: the server tracks per-AC un-acked
	// revokes and retries the NHP_REV until acked or aged out. Unlike NHP_ART
	// (a transaction RESPONSE on the AC's NHP_AOP), NHP_RVA is an UNSOLICITED
	// AC→server push on the existing server-initiated connection, the mirror of
	// NHP_REV. See docs/design/QURL_V2_KEYED_IDENTITY.md -> revocation
	// "AC ack recorded for operational proof" + "retry until all known ACs
	// acknowledge or age out" (P4e Slice 3, #2793).
	NHP_RVA
)

var nhpHeaderTypeStrings []string = []string{
	"NHP-KPL", // general keepalive packet
	"NHP-KNK", // agent sends knock to server
	"NHP-ACK", // server replies knock status to agent
	"NHP-AOP", // server asks ac for operation
	"NHP-ART", // ac replies server for operation result
	"NHP-LST", // agent requests server for listing services and applications
	"NHP-LRT", // server replies to agent with services and applications result
	"NHP-COK", // server sends cookie to agent
	"NHP-RKN", // agent sends reknock to server
	"NHP-RLY", // relay sends relayed packet to server
	"NHP-AOL", // ac sends online status to server
	"NHP-AAK", // server sends ack to ac after receiving ac's online status
	"NHP-OTP", // agent requests server for one-time-password
	"NHP-REG", // agent asks server for registering
	"NHP-RAK", // server sends back ack when agent registers correctly
	"NHP-ACC", // agent sends to ac/resource for actual ip access
	"NHP-EXT", // agent requests immediate disconnection
	"NHP_DRG", //DB sends a message to register a data object file to the NHP Server
	"NHP_DAK", //NHP-Server sends a result of the NHP_DRG registration request to the DB.
	"NHP_DAR", //NHP Agent sends messages to get access to the file and then work with it.
	"NHP_DAG", //The NHP Server sends  the authorization status of the data object to NHP Agent.
	"NHP_DSA", //The NHP Server sends a self attestation request to the NHP Agent
	"NHP_DAV", //The NHP Agent sends the attestation proof to the NHP Server.
	"NHP_DWR", //The NHP Server sends a request to the NHP DB to get the wrapping of the data private key
	"NHP_DWA", //The NHP DB sends the data private key to the NHP Server
	"NHP_DOL", //DB sends online status to server
	"NHP_DBA", //server send ack to db after receiving db's online status
	"DHP-KNK", //agent sends dhp knock to server
	// Per-AC Server Assignment Messages (Phase 2)
	"NHP-FWD", // server forwards knock to assigned server (server-to-server)
	"NHP-FRT", // server returns forward result (server-to-server)
	"NHP-ARD", // server sends AC redispatch with assigned servers
	"NHP-REV", // server pushes a qURL v2 immediate-revocation event to the AC
	"NHP-RVA", // AC acknowledges an NHP_REV back to the server (proof-of-delivery)
}

func HeaderTypeToString(t int) string {
	if t >= 0 && t < len(nhpHeaderTypeStrings) {
		return nhpHeaderTypeStrings[t]
	}
	return "UNKNOWN"
}

func HeaderTypeToDeviceType(t int) int {
	switch t {
	case NHP_KNK, NHP_LST, NHP_RKN, NHP_OTP, NHP_REG, NHP_ACC, NHP_EXT:
		return NHP_AGENT
	case NHP_ACK, NHP_AOP, NHP_LRT, NHP_COK, NHP_AAK, NHP_RAK, NHP_DAK, NHP_DAG, NHP_DBA, NHP_DWR, NHP_DSA,
		NHP_FWD, NHP_FRT, NHP_ARD, // Per-AC Server Assignment Messages (Phase 2)
		NHP_REV: // server-to-AC qURL v2 revocation push (P4e)
		return NHP_SERVER

	case NHP_AOL, NHP_ART,
		NHP_RVA: // AC→server revocation ack (P4e Slice 3)
		return NHP_AC

	case NHP_RLY:
		return NHP_RELAY
	case NHP_DRG, NHP_DOL, NHP_DWA:
		return NHP_DB
	case NHP_DAR, NHP_DAV, DHP_KNK:
		return DHP_AGENT
	}

	return NHP_NO_DEVICE
}

// IsForwardableKnockType reports whether a browser knock header can travel
// through server-to-server forwarding or the relay path. The same set also
// marks packets whose original ciphertext must be retained by decryptBody so
// BasePacketContent can re-forward the authenticated knock unchanged.
func IsForwardableKnockType(t int) bool {
	return t == NHP_KNK || t == NHP_RKN || t == NHP_EXT
}

type PacketBuffer = [PacketBufferSize]byte

// packet buffer pool
type PacketBufferPool struct {
	pool *utils.WaitPool
}

func (bp *PacketBufferPool) Init(max uint32) {
	bp.pool = utils.NewWaitPool(max, func() any { return new(PacketBuffer) })
}

// must be called after Init()
func (bp *PacketBufferPool) Get() *PacketBuffer {
	buf, ok := bp.pool.Get().(*PacketBuffer)
	if !ok {
		log.Error("PacketBufferPool.Get: unexpected type from pool")
		return nil
	}
	return buf
}

// must be called after Init()
func (bp *PacketBufferPool) Put(packet *PacketBuffer) {
	bp.pool.Put(packet)
}

type Packet struct {
	Buf           *PacketBuffer
	externalBuf   []byte
	relayBuf      *[RelayPacketBufferSize]byte
	HeaderType    int
	PoolAllocated bool
	KeepAfterSend bool // only applicable for sending
	Content       []byte
	// ReceivedAtNanos is the immutable local transport-receipt time for an
	// inbound packet, expressed as Unix nanoseconds. Outbound packets leave it
	// zero.
	ReceivedAtNanos int64
	// ReceivedFrom is the immutable source address observed by the UDP receive
	// transport for an inbound packet. It can differ from ConnectionData.RemoteAddr
	// when one socket sends through an NLB but accepts authenticated replies from
	// a target directly. Packet content cannot set this field. Non-UDP transports
	// and outbound packets leave it invalid.
	ReceivedFrom netip.AddrPort
	// SendTo is trusted, process-local transport metadata for an outbound UDP
	// packet that must leave on ConnData's existing socket but target a different
	// address. It is never serialized. The zero value preserves the connection's
	// ordinary RemoteAddr route.
	SendTo netip.AddrPort
}

var relayPacketPool = sync.Pool{
	New: func() any { return new([RelayPacketBufferSize]byte) },
}

// RelayPacketMinimalLength is the fixed Curve header size. It lets receive
// loops reject undersized datagrams without allocating a relay-sized Packet.
const RelayPacketMinimalLength = curve.HeaderSize

// NewRelayPacket returns an explicitly caller-owned packet sized for an
// authenticated NHP_RLY transport envelope. Synchronous MsgToPacket callers
// retain ExternalPacket ownership after the assembler is destroyed, so this
// constructor deliberately does not borrow from the relay pool.
func NewRelayPacket() *Packet {
	buf := make([]byte, RelayPacketBufferSize)
	return &Packet{externalBuf: buf, Content: buf}
}

// AllocateRelayPacket borrows a relay-envelope packet whose ownership is
// returned by ReleasePoolPacket / MsgAssemblerData.Destroy. Runtime relay
// forwarding and UDP receive paths use this instead of allocating 6 KiB per
// packet. Normal NHP packets remain in the device's 4096-byte pool. This
// sync.Pool has no exhaustion signal; callers must supply their own admission
// and fixed-queue bounds before borrowing from it.
func (d *Device) AllocateRelayPacket() *Packet {
	buf := relayPacketPool.Get().(*[RelayPacketBufferSize]byte)
	return &Packet{externalBuf: buf[:], relayBuf: buf, Content: buf[:]}
}

// validateWritableCapacity must run before any header accessor: those accessors
// intentionally use zero-copy unsafe views and therefore require a complete
// header-sized backing store. ExternalPacket remains public for existing stack
// buffer callers, so validate both its lower and upper bounds at the core seam.
func (pkt *Packet) validateWritableCapacity() error {
	size := len(pkt.writableBuffer())
	if size < curve.HeaderSize || size > RelayPacketBufferSize {
		return ErrPacketSizeExceedsBuffer
	}
	return nil
}

func (pkt *Packet) writableBuffer() []byte {
	if pkt == nil {
		return nil
	}
	if pkt.externalBuf != nil {
		return pkt.externalBuf
	}
	if pkt.Buf != nil {
		return pkt.Buf[:]
	}
	return pkt.Content[:cap(pkt.Content)]
}

type Header interface {
	SetTypeAndPayloadSize(int, int)
	TypeAndPayloadSize() (int, int)
	Size() int
	SetVersion(int, int)
	Version() (int, int)
	SetFlag(uint16)
	Flag() uint16
	SetCounter(uint64)
	Counter() uint64
	Bytes() []byte
	NonceBytes() []byte
	EphermeralBytes() []byte
	StaticBytes() []byte
	TimestampBytes() []byte
	IdentityBytes() []byte
	HeaderDigestBytes() []byte
	CipherScheme() int
}

func (pkt *Packet) Flag() uint16 {
	return binary.BigEndian.Uint16(pkt.Content[10:12])
}

func (pkt *Packet) Header() Header {
	return (*curve.HeaderCurve)(unsafe.Pointer(&pkt.Content[0]))
}

func (pkt *Packet) HeaderWithCipherScheme(cipherScheme int) Header {
	return (*curve.HeaderCurve)(unsafe.Pointer(&pkt.Content[0]))
}

func (pkt *Packet) HeaderTypeAndSize() (t int, s int) {
	preamble := binary.BigEndian.Uint32(pkt.Content[0:4])
	tns := preamble ^ binary.BigEndian.Uint32(pkt.Content[4:8])
	t = int((tns & 0xFFFF0000) >> 16)
	s = int(tns & 0x0000FFFF)
	pkt.HeaderType = t

	return t, s
}

func (pkt *Packet) Counter() uint64 {
	return binary.BigEndian.Uint64(pkt.Content[16:24])
}

func (pkt *Packet) MinimalLength() int {
	return pkt.HeaderWithCipherScheme(common.CIPHER_SCHEME_CURVE).Size()
}

// Data Receiver  allowed message types
func (d *Device) CheckRecvHeaderType(t int) bool {
	// NHP_KPL is handled elsewhere
	switch d.deviceType {
	case NHP_AGENT:
		switch t {
		case NHP_ACK, NHP_LRT, NHP_COK, NHP_RAK, NHP_DAG, NHP_DSA:
			return true
		}
	case NHP_SERVER:
		switch t {
		// NHP_FWD, NHP_FRT: Server-to-server forwarding (Phase 2 - Per-AC Assignment)
		// NHP_RVA: AC→server revocation ack (P4e Slice 3, #2793) — unsolicited
		// AC push on the server-initiated connection, accepted on the server's
		// receive path like NHP_AOL.
		case NHP_REG, NHP_KNK, DHP_KNK, NHP_LST, NHP_RKN, NHP_EXT, NHP_ART, NHP_RLY, NHP_AOL, NHP_OTP, NHP_DRG, NHP_DAR, NHP_DAV, NHP_DOL, NHP_DWA,
			NHP_FWD, NHP_FRT, NHP_RVA:
			return true
		}
	case NHP_AC:
		switch t {
		// NHP_ARD: AC Redispatch - server redirects AC to assigned servers (Phase 2)
		// NHP_REV: qURL v2 immediate-revocation push from the server (P4e)
		case NHP_AOP, NHP_LRT, NHP_AAK, NHP_ARD, NHP_REV:
			return true
		}
	case NHP_RELAY:
		switch t {
		// DHP_KNK is intentionally absent. DHP is supported only on the native
		// UDP/62206 path; allowing it here would also widen the unauthenticated
		// HTTPS relay allowlist used by innerType.
		case NHP_KNK, NHP_ACK, NHP_COK, NHP_RKN, NHP_EXT:
			return true
		}

	case NHP_DB:
		switch t {
		case NHP_DRG, NHP_DAG, NHP_DAK, NHP_DBA, NHP_DWR:
			return true
		}
	}
	log.Info("Device type: %d, recv header type %d not allowed", d.deviceType, t)
	return false
}

func (d *Device) RecvPrecheck(pkt *Packet) (int, int, error) {
	headerSize := pkt.Header().Size()

	// check type and payload size
	t, s := pkt.HeaderTypeAndSize()
	if t == NHP_KPL {
		if s == 0 {
			return t, s, nil
		} else {
			return t, s, errors.New("keepalive packet size is incorrect")
		}
	}
	if !d.CheckRecvHeaderType(t) {
		return t, s, errors.New("packet header type does not match device")
	}

	totalLen := len(pkt.Content)
	if totalLen != headerSize+s {
		return t, s, errors.New("packet total size is incorrect")
	}

	return t, s, nil
}

func (d *Device) AllocatePoolPacket() *Packet {
	buf := d.pool.Get()
	if buf == nil {
		return nil
	}
	return &Packet{Buf: buf, Content: buf[:], PoolAllocated: true}
}

// clonePacketForSend gives the physical sender independent ownership of a
// transaction packet. The local transaction must retain the assembler's
// packet until its response, timeout, or connection-close path completes;
// sharing that packet with an asynchronous sender lets either owner recycle
// the buffer while the other still uses it.
func (d *Device) clonePacketForSend(pkt *Packet) (*Packet, error) {
	if pkt == nil || len(pkt.Content) == 0 || len(pkt.Content) > PacketBufferSize {
		return nil, errors.New("invalid outbound transaction packet")
	}

	clone := d.AllocatePoolPacket()
	if clone == nil {
		return nil, errors.New("failed to allocate outbound transaction packet")
	}
	// Physical senders consume only HeaderType and Content. PoolAllocated comes
	// from AllocatePoolPacket, and KeepAfterSend must remain false so the sender
	// releases its independent copy.
	clone.HeaderType = pkt.HeaderType
	clone.SendTo = pkt.SendTo
	clone.Content = clone.Buf[:len(pkt.Content)]
	copy(clone.Content, pkt.Content)
	return clone, nil
}

func (d *Device) ReleasePoolPacket(pkt *Packet) {
	if pkt != nil && pkt.relayBuf != nil {
		buf := pkt.relayBuf
		pkt.relayBuf = nil
		pkt.externalBuf = nil
		pkt.Content = nil
		pkt.HeaderType = 0
		pkt.ReceivedAtNanos = 0
		pkt.ReceivedFrom = netip.AddrPort{}
		pkt.SendTo = netip.AddrPort{}
		relayPacketPool.Put(buf)
		return
	}
	if pkt != nil && pkt.Buf != nil && pkt.PoolAllocated {
		d.pool.Put(pkt.Buf)
		pkt.Buf = nil
		pkt.Content = nil
		pkt.HeaderType = 0
		pkt.ReceivedAtNanos = 0
		pkt.ReceivedFrom = netip.AddrPort{}
		pkt.SendTo = netip.AddrPort{}
	}
}
