package core

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/OpenNHP/opennhp/nhp/log"
)

// NewStoppedTimer returns a stopped timer; caller must Reset(d) before use. The 1h placeholder is arbitrary — immediately stopped. (Go 1.23+: bare Reset is correct.)
//
// Reset-placement conventions in this repo:
//   - Reset before any early-`continue` if every code path in the case must count as activity (connectionRoutine recv/send).
//   - Reset after work if the desired cycle is interval+work_time (BlockAddrRefreshRoutine).
//   - Reset before the bottom select if the cycle is fixed-interval and work above is variable (serverDiscovery, knock loops).
func NewStoppedTimer() *time.Timer {
	t := time.NewTimer(time.Hour)
	t.Stop()
	return t
}

type ConnectionData struct {
	// 8-byte-aligned block: the int64 fields below are accessed via package-level atomic.LoadInt64/StoreInt64
	// and require manual alignment on 32-bit systems. timeoutMs (atomic.Int64) self-aligns; grouped here for locality.
	InitTime           int64 // local connection setup time. immutable after created
	LastRemoteSendTime int64
	LastLocalSendTime  int64
	LastLocalRecvTime  int64
	timeoutMs          atomic.Int64 // unexported: write via SetTimeout or InitTimeoutMs only.

	sync.Mutex
	sync.WaitGroup

	// common
	Device           *Device
	LocalAddr        *net.UDPAddr
	RemoteAddr       *net.UDPAddr
	CookieStore      *CookieStore
	SendQueue        chan *Packet
	RecvQueue        chan *Packet
	BlockSignal      chan struct{}
	SetTimeoutSignal chan struct{}
	StopSignal       chan struct{}

	closed atomic.Bool

	// remote transactions
	RemoteTransactionMutex sync.Mutex
	RemoteTransactionMap   map[uint64]*RemoteTransaction

	// specific
	RecvThreatCount int32
}

func (c *ConnectionData) Equal(other *ConnectionData) bool {
	// use nanosecond timestamp for comparison
	return c.InitTime == other.InitTime
}

// TimeoutMs returns the connection idle timeout in milliseconds.
func (c *ConnectionData) TimeoutMs() int { return int(c.timeoutMs.Load()) }

// InitTimeoutMs sets the timeout at construction. Use SetTimeout once connectionRoutine is running.
func (c *ConnectionData) InitTimeoutMs(ms int) { c.timeoutMs.Store(int64(ms)) }

// SetTimeout updates the timeout and signals connectionRoutine to re-arm; blocks until the routine selects.
// TODO(#1675): not safe to call concurrently with Close() — send panics on closed channel.
// No production callers as of PR #1491; retained as the documented re-arm contract for #1675.
func (c *ConnectionData) SetTimeout(ms int) {
	c.timeoutMs.Store(int64(ms))
	c.SetTimeoutSignal <- struct{}{}
}

func (c *ConnectionData) Close() {
	if !c.closed.CompareAndSwap(false, true) {
		return
	}

	// close all running transactions
	close(c.StopSignal)

	// flush connection remaining packet and close connection thread channels
flush:
	for {
		select {
		case pkt := <-c.SendQueue:
			c.Device.ReleasePoolPacket(pkt)
		case pkt := <-c.RecvQueue:
			c.Device.ReleasePoolPacket(pkt)
		case <-c.BlockSignal:
		default:
			break flush
		}
	}

	close(c.SendQueue)
	close(c.RecvQueue)
	close(c.BlockSignal)
	close(c.SetTimeoutSignal)
	c.SendQueue = nil
	c.RecvQueue = nil
	c.BlockSignal = nil
	c.SetTimeoutSignal = nil

	c.Wait()
}

func (c *ConnectionData) IsClosed() bool {
	return c.closed.Load()
}

func (c *ConnectionData) ForwardOutboundPacket(pkt *Packet) {
	if c.IsClosed() {
		log.Warning("connection %s is closed, discard outbound packet", c.RemoteAddr.String())
		c.Device.ReleasePoolPacket(pkt)
		return
	}

	select {
	case c.SendQueue <- pkt:
		// fully encrypted packet will be forwarded to higher level entity for physical sending
		// may block when send queue is full
	case <-c.StopSignal:
		// discard pending packets when connection is closed
		log.Warning("connection %s stopped, discard pending outbound packet", c.RemoteAddr.String())
		c.Device.ReleasePoolPacket(pkt)
	}
}

func (c *ConnectionData) ForwardInboundPacket(pkt *Packet) {
	if c.IsClosed() {
		log.Warning("connection %s is closed, discard inbound packet", c.RemoteAddr.String())
		c.Device.ReleasePoolPacket(pkt)
		return
	}

	select {
	case c.RecvQueue <- pkt:
		// raw packet will be forwarded to connection routine for packet parsing and decrytion
		// may block when recv queue is full
	case <-c.StopSignal:
		// discard pending packets when connection is closed
		log.Warning("connection %s stopped, discard pending inbound packet", c.RemoteAddr.String())
		c.Device.ReleasePoolPacket(pkt)
	}
}

func (c *ConnectionData) SendBlockSignal() {
	if c.IsClosed() {
		log.Warning("connection is closed, discard block signal")
		return
	}

	select {
	case c.BlockSignal <- struct{}{}:
		// trigger connection to close itself immediately and ask higher level entity to record the blocking connection
	default:
		log.Warning("old block signal not processed")
	}
}
