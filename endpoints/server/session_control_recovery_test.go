package server

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSessionControlRecoveryCapabilitiesFailBeforeRuntimeStart(t *testing.T) {
	incomplete := &UdpServer{sessionControlCellID: testSessionControlCellID,
		sessionControlStore: newAdmissionSessionControlStore(time.Now())}
	if err := incomplete.validateSessionControlRecoveryCapabilities(); err == nil ||
		!strings.Contains(err.Error(), "due-session") {
		t.Fatalf("incomplete recovery capability = %v", err)
	}
	complete := &UdpServer{sessionControlCellID: testSessionControlCellID,
		sessionControlStore: &dynamoSessionControlStore{}}
	if err := complete.validateSessionControlRecoveryCapabilities(); err != nil {
		t.Fatalf("complete recovery capability = %v", err)
	}
}

func TestSessionControlExactRetirementCapabilitiesFailBeforeRuntimeStart(t *testing.T) {
	incomplete := &UdpServer{sessionControlCellID: testSessionControlCellID,
		sessionControlStore: newAdmissionSessionControlStore(time.Now())}
	if err := incomplete.validateSessionControlExactRetirementCapabilities(); err == nil ||
		!strings.Contains(err.Error(), "exact retirement authority is incomplete") {
		t.Fatalf("incomplete exact-retirement capability = %v", err)
	}
	complete := &UdpServer{sessionControlCellID: testSessionControlCellID,
		sessionControlStore: &dynamoSessionControlStore{}}
	if err := complete.validateSessionControlExactRetirementCapabilities(); err != nil {
		t.Fatalf("complete exact-retirement capability = %v", err)
	}
}

func TestSessionControlShutdownStopsHTTPBeforeWaitingForRecovery(t *testing.T) {
	httpServer := &HttpServer{id: "session-control-stop-order", httpServer: &http.Server{}}
	httpServer.signals.stop = make(chan struct{})
	httpServer.running.Store(true)
	recoveryCtx, recoveryCancel := context.WithCancel(context.Background())
	recoveryCanceled := make(chan struct{})
	releaseRecovery := make(chan struct{})
	s := &UdpServer{httpServer: httpServer}
	s.sessionControlRecovery.cancel = recoveryCancel
	s.sessionControlRecovery.wg.Add(1)
	go func() {
		defer s.sessionControlRecovery.wg.Done()
		<-recoveryCtx.Done()
		close(recoveryCanceled)
		<-releaseRecovery
	}()
	done := make(chan struct{})
	go func() {
		s.stopHTTPAndSessionControlRecovery()
		close(done)
	}()
	select {
	case <-httpServer.signals.stop:
	case <-time.After(time.Second):
		t.Fatal("HTTP ingress did not stop before recovery wait")
	}
	select {
	case <-recoveryCanceled:
	case <-time.After(time.Second):
		t.Fatal("recovery was not canceled after HTTP shutdown")
	}
	select {
	case <-done:
		t.Fatal("shutdown did not wait for the held recovery worker")
	default:
	}
	close(releaseRecovery)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not join recovery after release")
	}
}
