package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"golang.org/x/sync/semaphore"
)

// A deadline-armed writer acquires the full weight and is exclusive with every
// physical write. Ordinary writers acquire one unit and remain concurrent. The
// bound is intentionally far above the process's possible goroutine count; it
// is a read/write gate, not an operational concurrency limit.
const udpWriteGateWeight int64 = 1 << 30

// udpWriteSocket is the narrow physical-write seam. SetWriteDeadline mutates
// socket-wide state, so every production WriteToUDP on the server listener must
// pass through UdpServer.writeUDPDatagram and its shared gate.
type udpWriteSocket interface {
	SetWriteDeadline(time.Time) error
	WriteToUDP([]byte, *net.UDPAddr) (int, error)
}

func (s *UdpServer) initUDPWriteGate() {
	s.udpWriteGateOnce.Do(func() {
		s.udpWriteGate = semaphore.NewWeighted(udpWriteGateWeight)
	})
}

func (s *UdpServer) udpSocket() udpWriteSocket {
	if s.udpWriteSocket != nil {
		return s.udpWriteSocket
	}
	if s.listenConn == nil {
		return nil
	}
	return s.listenConn
}

// writeUDPDatagram makes deadline mutation exclusive with every physical
// datagram write while preserving concurrency among ordinary writes.
// explicitDeadline may be zero; when both it and ctx carry a deadline, the
// earlier one wins. A context deadline without an explicitDeadline bounds gate
// waiting but deliberately does not mutate the shared socket deadline. A failed
// deadline reset marks the socket dirty and the next writer must exclusively
// clear that state before attempting I/O.
func (s *UdpServer) writeUDPDatagram(ctx context.Context, payload []byte, remote *net.UDPAddr, explicitDeadline time.Time) (int, error) {
	if ctx == nil {
		return 0, context.Canceled
	}
	effectiveDeadline := explicitDeadline
	deadlineArmed := !explicitDeadline.IsZero()
	if contextDeadline, ok := ctx.Deadline(); deadlineArmed && ok && contextDeadline.Before(effectiveDeadline) {
		effectiveDeadline = contextDeadline
	}

	waitCtx := ctx
	var cancel context.CancelFunc
	if !effectiveDeadline.IsZero() {
		waitCtx, cancel = context.WithDeadline(ctx, effectiveDeadline)
		defer cancel()
	}
	if err := waitCtx.Err(); err != nil {
		return 0, err
	}

	s.initUDPWriteGate()
	gateWeight := int64(1)
	if deadlineArmed || s.udpWriteDeadlineDirty.Load() {
		gateWeight = udpWriteGateWeight
	}
	if err := s.udpWriteGate.Acquire(waitCtx, gateWeight); err != nil {
		return 0, err
	}
	// A dirty reset can race the pre-acquire observation while this writer is
	// queued behind an armed writer. Upgrade before touching the socket.
	if gateWeight == 1 && s.udpWriteDeadlineDirty.Load() {
		s.udpWriteGate.Release(gateWeight)
		gateWeight = udpWriteGateWeight
		if err := s.udpWriteGate.Acquire(waitCtx, gateWeight); err != nil {
			return 0, err
		}
	}
	defer s.udpWriteGate.Release(gateWeight)
	if err := waitCtx.Err(); err != nil {
		return 0, err
	}

	socket := s.udpSocket()
	if socket == nil {
		return 0, errors.New("UDP listener is not initialized")
	}

	if s.udpWriteDeadlineDirty.Load() {
		if err := socket.SetWriteDeadline(time.Time{}); err != nil {
			return 0, fmt.Errorf("clear stale UDP write deadline: %w", err)
		}
		s.udpWriteDeadlineDirty.Store(false)
	}

	if deadlineArmed {
		// Even an error leaves the OS-level deadline state unspecified. Mark it
		// dirty before the syscall so a later writer must prove a clean reset.
		s.udpWriteDeadlineDirty.Store(true)
		if err := socket.SetWriteDeadline(effectiveDeadline); err != nil {
			return 0, fmt.Errorf("set UDP write deadline: %w", err)
		}
	}
	if err := waitCtx.Err(); err != nil {
		if deadlineArmed {
			if resetErr := socket.SetWriteDeadline(time.Time{}); resetErr != nil {
				return 0, errors.Join(err, fmt.Errorf("reset UDP write deadline after cancellation: %w", resetErr))
			}
			s.udpWriteDeadlineDirty.Store(false)
		}
		return 0, err
	}

	n, writeErr := socket.WriteToUDP(payload, remote)
	if writeErr == nil && n != len(payload) {
		writeErr = io.ErrShortWrite
	}

	var resetErr error
	if deadlineArmed {
		if err := socket.SetWriteDeadline(time.Time{}); err != nil {
			resetErr = fmt.Errorf("reset UDP write deadline: %w", err)
		} else {
			s.udpWriteDeadlineDirty.Store(false)
		}
	}
	if writeErr != nil && resetErr != nil {
		return n, errors.Join(writeErr, resetErr)
	}
	if writeErr != nil {
		return n, writeErr
	}
	if resetErr != nil {
		return n, resetErr
	}
	return n, nil
}
