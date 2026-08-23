package server

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

// These tests pin broadcastACOpenWithReknock — the single re-snapshot retry the
// UDP qURL knock path (handleNhpOpenResource) uses to absorb the blue/green
// AC-reassignment transaction timeout that surfaced as intermittent
// ErrServerACOpsFailed/52005 in qurl-service#976. They drive the helper directly
// through the processACOperationBroadcastFn injection seam so no real UDP/AC
// round-trip is needed; the retry's re-snapshot reads the real s.acConnectionMap
// via snapshotLiveACConns.

func seedLiveACConn(t *testing.T, s *UdpServer, acId, ip string, port int) {
	t.Helper()
	c := newTestACConn(t, ip, port, acId)
	atomic.StoreInt64(&c.ConnData.LastLocalRecvTime, time.Now().UnixNano())
	s.acConnectionMap[acId] = append(s.acConnectionMap[acId], c)
}

// shortenReknockBackoff makes the retry pause on s negligible so timeout-path tests
// run fast instead of sleeping the full production backoff. It sets the per-instance
// UdpServer.reknockRetryBackoff field (no cleanup needed — it dies with s), which
// broadcastACOpenWithReknock reads in preference to defaultReknockRetryBackoff. Unlike
// the old shared-package-var override this touches only s, so it is safe under
// t.Parallel(). (The budget guard reads the immutable defaultReknockRetryBackoff const.)
func shortenReknockBackoff(t *testing.T, s *UdpServer) {
	t.Helper()
	s.reknockRetryBackoff = time.Millisecond
}

func timeoutResult() (*common.ACOpsResultMsg, error) {
	// Mirrors processACOperation's timeout return: artMsg stamped with the
	// wrapping ErrServerACOpsFailed code, but the returned error is the bare
	// ErrTransactionFailedByTimeout sentinel the retry predicate keys on.
	return &common.ACOpsResultMsg{
		ErrCode: common.ErrServerACOpsFailed.ErrorCode(),
		ErrMsg:  common.ErrTransactionFailedByTimeout.Error(),
	}, common.ErrTransactionFailedByTimeout
}

func successResult() (*common.ACOpsResultMsg, error) {
	return &common.ACOpsResultMsg{ErrCode: common.ErrSuccess.ErrorCode(), ACToken: "at_ok"}, nil
}

func callReknock(t *testing.T, s *UdpServer, acId string, conns []*ACConn) (*common.ACOpsResultMsg, error) {
	t.Helper()
	return callReknockCtx(t, context.Background(), s, acId, conns)
}

func callReknockCtx(t *testing.T, ctx context.Context, s *UdpServer, acId string, conns []*ACConn) (*common.ACOpsResultMsg, error) {
	t.Helper()
	knk := &common.AgentKnockMsg{UserId: "viewer", ResourceId: "r_x"}
	src := &common.NetAddress{Ip: "20.169.72.19", Port: 443}
	dst := []*common.NetAddress{{Ip: "0.0.0.0", Port: 443}}
	return s.broadcastACOpenWithReknock(ctx, knk, acId, conns, src, dst, 60, nil, "test")
}

// The core fix: the first broadcast times out on every conn, the AC has
// re-registered by the time we re-snapshot, and the single retry succeeds — the
// 52005 is converted into a success.
func TestBroadcastACOpenWithReknock_RetriesTimeoutAndSucceeds(t *testing.T) {
	s, _ := newTestServerForBroadcast(t)
	shortenReknockBackoff(t, s)
	const acId = "sandbox-ac"
	seedLiveACConn(t, s, acId, "10.0.0.1", 62206)

	var calls int32
	s.processACOperationBroadcastFn = func(_ context.Context, _ *common.AgentKnockMsg, _ []*ACConn, _ *common.NetAddress, _ []*common.NetAddress, _ uint32, _ *common.ResourceData) (*common.ACOpsResultMsg, error) {
		if atomic.AddInt32(&calls, 1) == 1 {
			return timeoutResult()
		}
		return successResult()
	}

	art, err := callReknock(t, s, acId, s.acConnectionMap[acId])
	if err != nil {
		t.Fatalf("want success after retry, got err=%v", err)
	}
	if art == nil || art.ErrCode != common.ErrSuccess.ErrorCode() {
		t.Fatalf("want success artMsg, got %+v", art)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("want 2 broadcast calls (initial + 1 retry), got %d", got)
	}
}

// A genuine AC-returned error (not a transaction timeout) is authoritative and
// must never be retried, even though a fresh conn is available.
func TestBroadcastACOpenWithReknock_GenuineErrorNotRetried(t *testing.T) {
	s, _ := newTestServerForBroadcast(t)
	shortenReknockBackoff(t, s)
	const acId = "sandbox-ac"
	seedLiveACConn(t, s, acId, "10.0.0.1", 62206)

	var calls int32
	s.processACOperationBroadcastFn = func(_ context.Context, _ *common.AgentKnockMsg, _ []*ACConn, _ *common.NetAddress, _ []*common.NetAddress, _ uint32, _ *common.ResourceData) (*common.ACOpsResultMsg, error) {
		atomic.AddInt32(&calls, 1)
		return &common.ACOpsResultMsg{ErrCode: common.ErrACOperationFailed.ErrorCode(), ErrMsg: "ipset add failed"}, common.ErrACOperationFailed
	}

	_, err := callReknock(t, s, acId, s.acConnectionMap[acId])
	if !errors.Is(err, common.ErrACOperationFailed) {
		t.Fatalf("want ErrACOperationFailed passed through, got %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("genuine AC error must not retry: want 1 call, got %d", got)
	}
}

// Timeout, but nothing re-registered — the re-snapshot is empty, so there is no
// fresh conn to retry against; the original timeout stands with no wasted resend.
func TestBroadcastACOpenWithReknock_TimeoutNoFreshConns(t *testing.T) {
	s, _ := newTestServerForBroadcast(t)
	shortenReknockBackoff(t, s)
	const acId = "sandbox-ac"
	// acConnectionMap[acId] intentionally left empty → re-snapshot returns none.

	var calls int32
	s.processACOperationBroadcastFn = func(_ context.Context, _ *common.AgentKnockMsg, _ []*ACConn, _ *common.NetAddress, _ []*common.NetAddress, _ uint32, _ *common.ResourceData) (*common.ACOpsResultMsg, error) {
		atomic.AddInt32(&calls, 1)
		return timeoutResult()
	}

	// A non-empty initial slice so the first broadcast runs; the map stays empty
	// so the retry snapshot finds nothing.
	initial := []*ACConn{newTestACConn(t, "10.0.0.9", 62206, acId)}
	_, err := callReknock(t, s, acId, initial)
	if !errors.Is(err, common.ErrTransactionFailedByTimeout) {
		t.Fatalf("want original timeout error, got %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("no fresh conns: want 1 call (no retry), got %d", got)
	}
}

// Happy path: the first broadcast succeeds — no backoff, no re-snapshot, no retry.
func TestBroadcastACOpenWithReknock_SuccessNoRetry(t *testing.T) {
	s, _ := newTestServerForBroadcast(t)
	const acId = "sandbox-ac"
	seedLiveACConn(t, s, acId, "10.0.0.1", 62206)

	var calls int32
	s.processACOperationBroadcastFn = func(_ context.Context, _ *common.AgentKnockMsg, _ []*ACConn, _ *common.NetAddress, _ []*common.NetAddress, _ uint32, _ *common.ResourceData) (*common.ACOpsResultMsg, error) {
		atomic.AddInt32(&calls, 1)
		return successResult()
	}
	_, err := callReknock(t, s, acId, s.acConnectionMap[acId])
	if err != nil {
		t.Fatalf("want success, got %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("success must not retry: want 1 call, got %d", got)
	}
}

// Context canceled before the backoff elapses → the retry is abandoned and the
// original timeout is returned (the client already gave up; don't waste a resend
// on its behalf — the len==0 forward path and the idempotent background pinhole
// cover recovery).
func TestBroadcastACOpenWithReknock_ContextCanceledDuringBackoff(t *testing.T) {
	s, _ := newTestServerForBroadcast(t)
	const acId = "sandbox-ac"
	seedLiveACConn(t, s, acId, "10.0.0.1", 62206)
	// Keep a long backoff so cancellation deterministically wins the select.
	s.reknockRetryBackoff = 10 * time.Second

	var calls int32
	s.processACOperationBroadcastFn = func(_ context.Context, _ *common.AgentKnockMsg, _ []*ACConn, _ *common.NetAddress, _ []*common.NetAddress, _ uint32, _ *common.ResourceData) (*common.ACOpsResultMsg, error) {
		atomic.AddInt32(&calls, 1)
		return timeoutResult()
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already canceled → backoff select takes ctx.Done() immediately
	knk := &common.AgentKnockMsg{UserId: "viewer", ResourceId: "r_x"}
	src := &common.NetAddress{Ip: "20.169.72.19", Port: 443}
	dst := []*common.NetAddress{{Ip: "0.0.0.0", Port: 443}}
	_, err := s.broadcastACOpenWithReknock(ctx, knk, acId, s.acConnectionMap[acId], src, dst, 60, nil, "test")
	if !errors.Is(err, common.ErrTransactionFailedByTimeout) {
		t.Fatalf("want original timeout error on ctx cancel, got %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("ctx canceled: want 1 call (no retry), got %d", got)
	}
}

// TestHandleNhpOpenResource_ReknockRetry_ConvertsTimeoutToSuccess fences the
// WIRING (not just the helper): a qURL knock whose AC broadcast hits the
// transaction-timeout signature on its first attempt is retried once through the
// wired broadcastACOpenWithReknock inside handleNhpOpenResource, and the knock
// returns success instead of ErrServerACOpsFailed/52005. The seam
// (processACOperationBroadcastFn) returns timeout-then-success while the real
// acConnectionMap lookup + snapshotLiveACConns re-snapshot execute — so a
// regression that dropped the retry wrapper from the UDP handler would fail here.
func TestHandleNhpOpenResource_ReknockRetry_ConvertsTimeoutToSuccess(t *testing.T) {
	const (
		acId    = "sandbox-ac"
		resName = "resource-alpha"
	)

	var calls int32
	s := &UdpServer{
		tokenStore: common.NewTokenStore[*ACTokenEntry](),
		acConnectionMap: map[string][]*ACConn{
			acId: {newACConnWithLastRecv(time.Now().UnixNano())},
		},
		processACOperationBroadcastFn: func(
			_ context.Context, _ *common.AgentKnockMsg, _ []*ACConn,
			_ *common.NetAddress, _ []*common.NetAddress, openTime uint32, _ *common.ResourceData,
		) (*common.ACOpsResultMsg, error) {
			if atomic.AddInt32(&calls, 1) == 1 {
				return timeoutResult()
			}
			return &common.ACOpsResultMsg{ErrCode: common.ErrSuccess.ErrorCode(), ACToken: "at_retry_ok", OpenTime: openTime}, nil
		},
	}
	shortenReknockBackoff(t, s)

	knkMsg := &common.AgentKnockMsg{UserId: "viewer", DeviceId: "d1", ResourceId: resName, NHPSessionId: 1, NHPSessionIssuedAt: time.Now()}
	srcAddr := &common.NetAddress{Ip: "203.0.113.42", Port: 51820}
	req := &common.NhpAuthRequest{Msg: knkMsg, SrcAddr: srcAddr, Ack: &common.ServerKnockAckMsg{SessionId: 1, OpenTime: 60}, SessionId: 1, SessionIssuedAt: knkMsg.NHPSessionIssuedAt}
	res := &common.ResourceData{
		ResourceGroup: common.ResourceGroup{
			ResourceId: resName,
			OpenTime:   60,
			Resources: map[string]*common.ResourceInfo{
				resName: {ACId: acId, Addr: &common.NetAddress{Port: 443, Protocol: "tcp"}},
			},
		},
	}

	gotAck, err := s.handleNhpOpenResource(req, res)
	if err != nil {
		t.Fatalf("handleNhpOpenResource returned error despite a retryable timeout: %v", err)
	}
	if gotAck.ErrCode != common.ErrSuccess.ErrorCode() {
		t.Fatalf("ack ErrCode = %q, want success — the wired re-knock retry must convert the transaction timeout into a success (not 52005)", gotAck.ErrCode)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("broadcast called %d times, want 2 (initial timeout + 1 wired retry through handleNhpOpenResource)", got)
	}
}

// TestBroadcastTimeoutExceedsTransactionTimeout fences the ordering invariant the
// retry predicate silently depends on: the ~1.5s AC-open transaction timeout
// (ServerACOpenTransactionResponseTimeoutMs) MUST fire before the 3s
// broadcast-context deadline (DefaultBroadcastTimeout), so a timed-out AC surfaces
// the bare ErrTransactionFailedByTimeout sentinel broadcastACOpenWithReknock keys
// on — NOT context.DeadlineExceeded, which the predicate does not match. If a
// future tune of either constant inverts the ordering, the retry would silently
// stop firing (the whole mode-2 fix no-ops); this turns that regression into a red
// build instead of a silent production degradation.
func TestBroadcastTimeoutExceedsTransactionTimeout(t *testing.T) {
	transactionTimeout := time.Duration(core.ServerACOpenTransactionResponseTimeoutMs) * time.Millisecond
	if DefaultBroadcastTimeout <= transactionTimeout {
		t.Fatalf("reknock retry predicate depends on the transaction timeout (%v) firing before the broadcast timeout (%v); keep DefaultBroadcastTimeout > ServerACOpenTransactionResponseTimeoutMs. Do NOT instead broaden the predicate to context.DeadlineExceeded — see broadcastACOpenWithReknock's godoc: the ctx-cancel arm does not Close() the conn, so that would resend to un-pruned dead conns", transactionTimeout, DefaultBroadcastTimeout)
	}
}

// TestBroadcastACOpenWithReknock_MetricEmissionPoints pins WHERE each of the three
// reknock counters fires — the emission-point semantics the ledger runbook routes
// an on-call decision on. It is the regression fence for "no fresh conns" being a
// distinct counter, not conflated with "Retry without Success". Reads counters via
// the shared metrics.NewPublisherForTest / CountersForTest helpers (same idiom as
// the rest of the server suite).
func TestBroadcastACOpenWithReknock_MetricEmissionPoints(t *testing.T) {
	const acId = "sandbox-ac"

	for _, tc := range []struct {
		name        string
		seedConn    bool // seed a live conn the retry's re-snapshot will find
		retrySucc   bool // does the retry (2nd broadcast) succeed?
		wantRetry   float64
		wantSuccess float64
		wantNoFresh float64
	}{
		{name: "retry_then_succeed", seedConn: true, retrySucc: true, wantRetry: 1, wantSuccess: 1},
		{name: "retry_then_fail", seedConn: true, wantRetry: 1},
		{name: "no_fresh_conns", wantNoFresh: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newTestServerForBroadcast(t)
			s.metrics = metrics.NewPublisherForTest(t)
			shortenReknockBackoff(t, s)

			initial := s.acConnectionMap[acId]
			if tc.seedConn {
				seedLiveACConn(t, s, acId, "10.0.0.1", 62206)
				initial = s.acConnectionMap[acId]
			} else {
				// Non-empty initial slice so the first broadcast runs, but the map
				// stays empty so the retry's re-snapshot finds no fresh conn.
				initial = []*ACConn{newTestACConn(t, "10.0.0.9", 62206, acId)}
			}

			var calls int32
			s.processACOperationBroadcastFn = func(_ context.Context, _ *common.AgentKnockMsg, _ []*ACConn, _ *common.NetAddress, _ []*common.NetAddress, _ uint32, _ *common.ResourceData) (*common.ACOpsResultMsg, error) {
				// First attempt always times out; the retry (2nd call) succeeds per tc.
				if atomic.AddInt32(&calls, 1) >= 2 && tc.retrySucc {
					return successResult()
				}
				return timeoutResult()
			}

			_, _ = callReknockCtx(t, context.Background(), s, acId, initial)

			counters, _ := s.metrics.CountersForTest(t)
			for name, want := range map[string]float64{
				MetricKnockReknockRetry:        tc.wantRetry,
				MetricKnockReknockRetrySuccess: tc.wantSuccess,
				MetricKnockReknockNoFreshConns: tc.wantNoFresh,
			} {
				if got := counters[name]; got != want {
					t.Errorf("counter %s = %v, want %v", name, got, want)
				}
			}
		})
	}
}
