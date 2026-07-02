package server

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/nhp/common"
)

// These tests fence the Phase 0B WIRING at the handler level: that the single
// deferred emit in handleHttpOpenResource fires MetricKnockFailReason with the
// correct Reason at each of the three failure exits. deriveKnockFailReason is
// unit-tested as a pure function elsewhere, but a missed or mis-set exit fails
// silently by UNDER-COUNTING (the hardest observability bug to notice), so drive
// the real handler to each exit and assert the metric. (#2999 round-7 note.)

// failingACKTokenStore makes PublishACKTokens fail so the token-publish exit is
// reachable. The shared fakeACKTokenStore always succeeds on StoreACToken.
type failingACKTokenStore struct{}

func (failingACKTokenStore) StoreACToken(context.Context, string, *ACTokenEntry) error {
	return errors.New("shared-store write failed (test)")
}

func (failingACKTokenStore) LoadACToken(context.Context, string) (*ACTokenEntry, bool, error) {
	return nil, false, nil
}

// assertKnockFailReasonEmitted checks the deferred emit fired exactly once with
// the wanted Reason: base MetricKnockFailReason==1 plus the dimensioned
// {Reason=<want>} series==1.
func assertKnockFailReasonEmitted(t *testing.T, us *UdpServer, want KnockFailReason) {
	t.Helper()
	counters, dimCounters := us.metrics.CountersForTest(t)
	if got := counters[MetricKnockFailReason]; got != 1 {
		t.Errorf("base %s = %v, want 1", MetricKnockFailReason, got)
	}
	var found float64
	for k, v := range dimCounters {
		if strings.HasPrefix(k, MetricKnockFailReason+"\x00") && strings.Contains(k, "Reason="+string(want)) {
			found += v
		}
	}
	if found != 1 {
		t.Errorf("dim %s{Reason=%s} = %v, want 1 (dims: %v)", MetricKnockFailReason, want, found, dimCounters)
	}
}

// oneResourceKnock builds a req/res pair for a single-resource qURL knock.
func oneResourceKnock(resName, acId, srcIP string) (*common.HttpKnockRequest, *common.ResourceData) {
	req := &common.HttpKnockRequest{
		UserId: "u", DeviceId: "d", AuthServiceId: "asp", ResourceId: resName,
		SrcIp: srcIP, Ctx: context.Background(),
	}
	res := &common.ResourceData{
		ResourceGroup: common.ResourceGroup{
			ResourceId: resName,
			OpenTime:   45,
			Resources: map[string]*common.ResourceInfo{
				resName: {ACId: acId, Addr: &common.NetAddress{Ip: "10.0.0.7", Port: 443}},
			},
		},
	}
	return req, res
}

// Exit 1 — the defensive no-resources guard (pre-broadcast early return).
func TestHandleHttpOpenResource_EmitsKnockFailReason_NoResources(t *testing.T) {
	us := &UdpServer{metrics: metrics.NewPublisherForTest(t)}
	hs := &HttpServer{udpServer: us}

	req := &common.HttpKnockRequest{UserId: "u", DeviceId: "d", ResourceId: "r", SrcIp: "203.0.113.1", Ctx: context.Background()}
	res := &common.ResourceData{ResourceGroup: common.ResourceGroup{ResourceId: "r"}} // no Resources

	if _, err := hs.handleHttpOpenResource(req, res); err == nil {
		t.Fatal("expected error on empty Resources")
	}
	assertKnockFailReasonEmitted(t, us, KnockFailNoResources)
}

// Exit 2 — the deep all-AC-ops-failed path routes through deriveKnockFailReason;
// a broadcast that fails with a timeout must land in transaction_timeout_after_pinhole.
func TestHandleHttpOpenResource_EmitsKnockFailReason_AllACOpsFailed(t *testing.T) {
	const acId, resName = "ac-1", "r-1"
	us := &UdpServer{
		metrics:         metrics.NewPublisherForTest(t),
		tokenStore:      common.NewTokenStore[*ACTokenEntry](),
		acConnectionMap: map[string][]*ACConn{acId: {newACConnWithLastRecv(time.Now().UnixNano())}},
		processACOperationBroadcastFn: func(
			_ context.Context, _ *common.AgentKnockMsg, _ []*ACConn,
			_ *common.NetAddress, _ []*common.NetAddress, _ uint32, _ *common.ResourceData,
		) (*common.ACOpsResultMsg, error) {
			// Aggregate ErrServerACOpsFailed wrapping the timeout cause in the
			// message — the broadcast shape deriveKnockFailReason keys on.
			return &common.ACOpsResultMsg{
				ErrCode: common.ErrServerACOpsFailed.ErrorCode(),
				ErrMsg:  resName + ": " + common.ErrTransactionFailedByTimeout.Error(),
			}, common.ErrTransactionFailedByTimeout
		},
	}
	hs := &HttpServer{udpServer: us}
	req, res := oneResourceKnock(resName, acId, "203.0.113.2")

	if _, err := hs.handleHttpOpenResource(req, res); err == nil {
		t.Fatal("expected error when all AC ops fail")
	}
	assertKnockFailReasonEmitted(t, us, KnockFailTransactionTimeoutAfterPinhole)
}

// Exit 3 — a successful AC op followed by a shared-store write failure must land
// in token_publish_failed (post-admission failure).
func TestHandleHttpOpenResource_EmitsKnockFailReason_TokenPublishFailed(t *testing.T) {
	const acId, resName = "ac-1", "r-1"
	us := &UdpServer{
		metrics:         metrics.NewPublisherForTest(t),
		tokenStore:      common.NewTokenStore[*ACTokenEntry](),
		ackTokenStore:   failingACKTokenStore{},
		acConnectionMap: map[string][]*ACConn{acId: {newACConnWithLastRecv(time.Now().UnixNano())}},
		processACOperationBroadcastFn: func(
			_ context.Context, _ *common.AgentKnockMsg, _ []*ACConn,
			_ *common.NetAddress, _ []*common.NetAddress, openTime uint32, _ *common.ResourceData,
		) (*common.ACOpsResultMsg, error) {
			return &common.ACOpsResultMsg{
				ErrCode: common.ErrSuccess.ErrorCode(), ACToken: "tok-1", OpenTime: openTime,
			}, nil
		},
	}
	hs := &HttpServer{udpServer: us}
	req, res := oneResourceKnock(resName, acId, "203.0.113.3")

	if _, err := hs.handleHttpOpenResource(req, res); err == nil {
		t.Fatal("expected token-persist error")
	}
	assertKnockFailReasonEmitted(t, us, KnockFailTokenPublishFailed)
}
