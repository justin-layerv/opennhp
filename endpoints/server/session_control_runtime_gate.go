package server

import (
	"context"
	"errors"

	"golang.org/x/sync/semaphore"
)

const sessionControlCellGateWeight = int64(1 << 30)

func (s *UdpServer) acquireSessionControlCell(ctx context.Context, weight int64) (func(), error) {
	if s == nil || ctx == nil || !validSessionControlCellID(s.sessionControlCellID) ||
		(weight != 1 && weight != sessionControlCellGateWeight) {
		return nil, errors.New("invalid session-control cell gate acquisition")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.sessionControlCellGateOnce.Do(func() {
		s.sessionControlCellGate = semaphore.NewWeighted(sessionControlCellGateWeight)
	})
	if s.sessionControlCellGate == nil {
		return nil, errors.New("session-control cell gate is unavailable")
	}
	if err := s.sessionControlCellGate.Acquire(ctx, weight); err != nil {
		return nil, err
	}
	return func() { s.sessionControlCellGate.Release(weight) }, nil
}

func (s *UdpServer) acquireSessionControlCellRead(ctx context.Context) (func(), error) {
	return s.acquireSessionControlCell(ctx, 1)
}

func (s *UdpServer) acquireSessionControlCellWrite(ctx context.Context) (func(), error) {
	return s.acquireSessionControlCell(ctx, sessionControlCellGateWeight)
}
