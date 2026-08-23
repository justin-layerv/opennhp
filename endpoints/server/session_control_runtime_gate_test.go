package server

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSessionControlCellGateOrdersAdmissionAndClose(t *testing.T) {
	s := &UdpServer{sessionControlCellID: testSessionControlCellID}
	readRelease, err := s.acquireSessionControlCellRead(context.Background())
	if err != nil {
		t.Fatalf("acquire read gate: %v", err)
	}

	writerAcquired := make(chan func(), 1)
	writerCtx, writerCancel := context.WithTimeout(context.Background(), time.Second)
	defer writerCancel()
	go func() {
		release, acquireErr := s.acquireSessionControlCellWrite(writerCtx)
		if acquireErr == nil {
			writerAcquired <- release
		}
	}()
	select {
	case release := <-writerAcquired:
		release()
		t.Fatal("cell writer acquired while admission reader was held")
	case <-time.After(20 * time.Millisecond):
	}

	readRelease()
	var writeRelease func()
	select {
	case writeRelease = <-writerAcquired:
	case <-time.After(time.Second):
		t.Fatal("cell writer did not acquire after reader released")
	}

	readerCtx, readerCancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer readerCancel()
	if _, err = s.acquireSessionControlCellRead(readerCtx); !errors.Is(err, context.DeadlineExceeded) {
		writeRelease()
		t.Fatalf("read acquisition behind writer = %v, want deadline", err)
	}
	writeRelease()

	finalRelease, err := s.acquireSessionControlCellRead(context.Background())
	if err != nil {
		t.Fatalf("cell gate did not recover after cancellation: %v", err)
	}
	finalRelease()
}

func TestSessionControlCellGateRejectsUnavailableAuthority(t *testing.T) {
	for name, server := range map[string]*UdpServer{
		"nil server":   nil,
		"missing cell": {},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := server.acquireSessionControlCellRead(context.Background()); err == nil {
				t.Fatal("cell gate acquisition succeeded without canonical authority")
			}
		})
	}
}
