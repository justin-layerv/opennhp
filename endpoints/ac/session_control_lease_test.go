package ac

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

func TestSessionControlLeaseFlushAdvancesAOLGenerationOncePerGap(t *testing.T) {
	scheduler := NewScheduler(&NoOpFlusher{}, WithTickInterval(time.Millisecond))
	scheduler.Start()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = scheduler.Shutdown(ctx)
	})
	ac := &UdpAC{
		config:                 &Config{ACId: "ac-1"},
		bootID:                 "00112233445566778899aabbccddeeff",
		expirySched:            scheduler,
		tokenStore:             common.NewTokenStore[*AccessEntry](),
		nhpSessions:            newNHPSessionIndex(),
		sessionControlStateDir: t.TempDir(),
	}
	if err := persistSessionControlGeneration(filepath.Join(ac.sessionControlStateDir, sessionControlGenerationRelativePath), 1); err != nil {
		t.Fatal(err)
	}
	ac.sessionFlushGeneration.Store(1)
	ac.sessionFlushComplete.Store(true)
	ac.sessionControlLeaseHeld.Store(true)
	registration := &ACRegistration{ac: ac}

	if err := registration.expireSessionControlLease(); err != nil {
		t.Fatalf("first expireSessionControlLease() error = %v", err)
	}
	if err := registration.expireSessionControlLease(); err != nil {
		t.Fatalf("coalesced expireSessionControlLease() error = %v", err)
	}
	if got := ac.sessionFlushGeneration.Load(); got != 2 {
		t.Fatalf("generation after one gap = %d, want 2", got)
	}
	if !ac.sessionFlushComplete.Load() {
		t.Fatal("session flush did not complete")
	}
	if ac.sessionControlLeaseHeld.Load() {
		t.Fatal("control-gap flush reacquired admission lease without a current AAK")
	}

	body, err := registration.currentAOLBytes()
	if err != nil {
		t.Fatalf("currentAOLBytes() error = %v", err)
	}
	var online common.ACOnlineMsg
	if err := common.DecodeACOnlineMsg(body, &online); err != nil {
		t.Fatalf("DecodeACOnlineMsg() error = %v", err)
	}
	if online.BootID != ac.bootID || online.SessionFlushGeneration != 2 || !online.SessionFlushComplete {
		t.Fatalf("AOL session-control tuple = %#v", online)
	}

	registration.controlLeaseExpired.Store(false)
	if err := registration.expireSessionControlLease(); err != nil {
		t.Fatalf("second episode expireSessionControlLease() error = %v", err)
	}
	if got := ac.sessionFlushGeneration.Load(); got != 3 {
		t.Fatalf("generation after second gap = %d, want 3", got)
	}
}

func TestCurrentAOLBytesRejectsNotReadyBoot(t *testing.T) {
	ac := &UdpAC{
		config: &Config{ACId: "ac-1"},
		bootID: "00112233445566778899aabbccddeeff",
	}
	ac.sessionFlushGeneration.Store(1)
	registration := &ACRegistration{ac: ac}
	if _, err := registration.currentAOLBytes(); err == nil {
		t.Fatal("currentAOLBytes() accepted a boot whose flush is incomplete")
	}
}

func TestStaleAAKCannotReacquireLeaseAcrossControlGapFlush(t *testing.T) {
	scheduler := NewScheduler(&NoOpFlusher{}, WithTickInterval(10*time.Millisecond))
	scheduler.Start()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = scheduler.Shutdown(ctx)
	})
	ac := &UdpAC{
		config:                 &Config{ACId: "ac-1"},
		bootID:                 "00112233445566778899aabbccddeeff",
		expirySched:            scheduler,
		tokenStore:             common.NewTokenStore[*AccessEntry](),
		nhpSessions:            newNHPSessionIndex(),
		sessionControlStateDir: t.TempDir(),
	}
	if err := persistSessionControlGeneration(filepath.Join(ac.sessionControlStateDir, sessionControlGenerationRelativePath), 1); err != nil {
		t.Fatal(err)
	}
	ac.sessionFlushGeneration.Store(1)
	ac.sessionFlushComplete.Store(true)
	ac.sessionControlLeaseHeld.Store(true)
	registration := &ACRegistration{ac: ac}

	reached := make(chan struct{})
	release := make(chan struct{})
	ac.sessionControlFlushBeforeGenerationFn = func() {
		close(reached)
		<-release
	}
	flushDone := make(chan error, 1)
	go func() { flushDone <- ac.flushLiveNHPSessionsForControlGap() }()
	<-reached

	acceptDone := make(chan struct{})
	go func() {
		registration.acceptCurrentSessionControlAAK(&common.ServerACAckMsg{
			ErrCode: common.ErrSuccess.ErrorCode(), Registered: true,
			BootID: ac.bootID, SessionFlushGeneration: 1, AOLTransactionID: 7,
		})
		close(acceptDone)
	}()
	select {
	case <-acceptDone:
		t.Fatal("stale AAK acceptance bypassed the in-flight flush fence")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-flushDone; err != nil {
		t.Fatalf("flushLiveNHPSessionsForControlGap() error = %v", err)
	}
	<-acceptDone
	if got := ac.sessionFlushGeneration.Load(); got != 2 {
		t.Fatalf("flush generation = %d, want 2", got)
	}
	if ac.sessionControlLeaseHeld.Load() || ac.sessionAdmissionReady() {
		t.Fatal("generation 1 AAK reopened generation 2 admission")
	}

	registration.acceptCurrentSessionControlAAK(&common.ServerACAckMsg{
		ErrCode: common.ErrSuccess.ErrorCode(), Registered: true,
		BootID: ac.bootID, SessionFlushGeneration: 2, AOLTransactionID: 8,
	})
	if !ac.sessionAdmissionReady() {
		t.Fatal("exact generation 2 AAK did not reacquire admission lease")
	}
}

func TestDecodeCurrentSessionControlAAKBindsHeaderTransaction(t *testing.T) {
	ac := &UdpAC{bootID: "00112233445566778899aabbccddeeff"}
	ac.sessionFlushGeneration.Store(3)
	registration := &ACRegistration{ac: ac}
	body, err := json.Marshal(&common.ServerACAckMsg{
		ErrCode: common.ErrSuccess.ErrorCode(), Registered: true,
		BootID: ac.bootID, SessionFlushGeneration: 3, AOLTransactionID: 11,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registration.decodeCurrentSessionControlAAK(&core.PacketParserData{SenderTrxId: 10, BodyMessage: body}); err == nil {
		t.Fatal("AAK body transaction mismatch was accepted")
	}
	if _, err := registration.decodeCurrentSessionControlAAK(&core.PacketParserData{SenderTrxId: 11, BodyMessage: body}); err != nil {
		t.Fatalf("exact current AAK rejected: %v", err)
	}
}
