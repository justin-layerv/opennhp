package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/OpenNHP/opennhp/nhp/common"
)

func assertRetiredHTTPAdmissionResponse(t *testing.T, status int, body []byte) {
	t.Helper()
	if status != http.StatusOK {
		t.Fatalf("retired HTTP admission status = %d, want 200; body=%s", status, body)
	}
	var response HttpKnockForwardResponse
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("decode retired HTTP admission response: %v; body=%s", err, body)
	}
	if response.AckMsg == nil || response.AckMsg.ErrCode != common.ErrHTTPAccessOperationUnsupported.ErrorCode() ||
		response.AckMsg.SessionId != 0 || response.AckMsg.OpenTime != 0 ||
		response.Error != common.ErrHTTPAccessOperationUnsupported.Error() {
		t.Fatalf("retired HTTP admission response = %#v", response)
	}
}

func TestInternalHTTPExitDoesNotSerializeAsNHP_EXT(t *testing.T) {
	body, err := json.Marshal(&common.AgentKnockMsg{InternalHTTPExit: true})
	if err != nil {
		t.Fatalf("marshal internal HTTP exit state: %v", err)
	}
	if bytes.Contains(body, []byte(`"headerType":16`)) || bytes.Contains(body, []byte(`"InternalHTTPExit"`)) {
		t.Fatalf("internal HTTP exit leaked into NHP wire JSON: %s", body)
	}
}

type retiredHTTPACKTokenStore struct {
	stores atomic.Int32
}

func (s *retiredHTTPACKTokenStore) StoreACToken(context.Context, string, *ACTokenEntry) error {
	s.stores.Add(1)
	return nil
}

func (*retiredHTTPACKTokenStore) LoadACToken(context.Context, string) (*ACTokenEntry, bool, error) {
	return nil, false, nil
}

func TestHandleHttpOpenResourceRetiredWithoutAdmissionSideEffects(t *testing.T) {
	sharedTokens := &retiredHTTPACKTokenStore{}
	var broadcasts atomic.Int32
	s := &UdpServer{
		tokenStore:    common.NewTokenStore[*ACTokenEntry](),
		ackTokenStore: sharedTokens,
		processACOperationBroadcastFn: func(context.Context, *common.AgentKnockMsg, []*ACConn, *common.NetAddress, []*common.NetAddress, uint32, *common.ResourceData) (*common.ACOpsResultMsg, error) {
			broadcasts.Add(1)
			return &common.ACOpsResultMsg{ErrCode: common.ErrSuccess.ErrorCode(), ACToken: "must-not-publish"}, nil
		},
	}
	registry := s.sessionRegistry()
	hs := &HttpServer{udpServer: s}

	ack, err := hs.handleHttpOpenResource(&common.HttpKnockRequest{
		UserId: "retired-http-user", SrcIp: "203.0.113.90", Ctx: context.Background(),
	}, &common.ResourceData{ResourceGroup: common.ResourceGroup{
		ResourceId: "retired-http-resource",
		OpenTime:   60,
		Resources: map[string]*common.ResourceInfo{
			"retired-http-resource": {ACId: "ac-retired", Addr: &common.NetAddress{Ip: "192.0.2.10", Port: 443}},
		},
	}})
	if !errors.Is(err, common.ErrHTTPAccessOperationUnsupported) {
		t.Fatalf("handleHttpOpenResource error = %v, want ErrHTTPAccessOperationUnsupported", err)
	}
	if ack == nil || ack.ErrCode != common.ErrHTTPAccessOperationUnsupported.ErrorCode() || ack.SessionId != 0 || ack.OpenTime != 0 {
		t.Fatalf("retired HTTP ACK = %#v", ack)
	}
	if got := broadcasts.Load(); got != 0 {
		t.Fatalf("AC broadcasts = %d, want 0", got)
	}
	registry.mu.Lock()
	reservations := len(registry.sessions)
	registry.mu.Unlock()
	if reservations != 0 {
		t.Fatalf("session reservations = %d, want 0", reservations)
	}
	if got := s.tokenStore.Size(); got != 0 {
		t.Fatalf("local token publications = %d, want 0", got)
	}
	if got := sharedTokens.stores.Load(); got != 0 {
		t.Fatalf("shared token publications = %d, want 0", got)
	}
}
