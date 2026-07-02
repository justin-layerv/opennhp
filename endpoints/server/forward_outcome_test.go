package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
)

// TestForwardHttpKnock_Outcomes wires the classifier to the real function: it
// asserts ForwardHttpKnock returns the right ForwardOutcome for the early
// terminal paths (proves the outcome plumbing, not just classifyForwardAttempt).
func TestForwardHttpKnock_Outcomes(t *testing.T) {
	ctx := context.Background()
	req, res := &common.HttpKnockRequest{}, &common.ResourceData{}

	if _, oc, err := (&HttpKnockForwarder{}).ForwardHttpKnock(ctx, "ac", req, res); err == nil || oc != ForwardNoStorage {
		t.Fatalf("no-storage: outcome=%q err=%v, want %q", oc, err, ForwardNoStorage)
	}

	storage := newMockStorageBackend()
	f := NewHttpKnockForwarder(storage, nil, "10.0.0.1", 8888, nil, nil)

	if _, oc, err := f.ForwardHttpKnock(ctx, "missing", req, res); err == nil || oc != ForwardNoAssignment {
		t.Fatalf("no-assignment: outcome=%q err=%v, want %q", oc, err, ForwardNoAssignment)
	}

	expired := time.Now().Add(-time.Hour).Unix()
	storage.assignments["exp"] = &ACAssignment{ACID: "exp", AssignedServers: []ServerInfo{{ID: "s1", InternalIP: "10.0.0.2"}}, TTL: &expired}
	if _, oc, err := f.ForwardHttpKnock(ctx, "exp", req, res); err == nil || oc != ForwardAssignmentExpired {
		t.Fatalf("expired: outcome=%q err=%v, want %q", oc, err, ForwardAssignmentExpired)
	}

	// Only self assigned → filterForwardTargets excludes it → all targets filtered.
	storage.assignments["self"] = &ACAssignment{ACID: "self", AssignedServers: []ServerInfo{{ID: "s1", InternalIP: "10.0.0.1"}}}
	if _, oc, err := f.ForwardHttpKnock(ctx, "self", req, res); err == nil || oc != ForwardAllTargetsFiltered {
		t.Fatalf("all-filtered: outcome=%q err=%v, want %q", oc, err, ForwardAllTargetsFiltered)
	}
}

// TestClassifyForwardAttempt pins the Phase 0A cause-classification of a single
// forwardToServer result. The load-bearing case is the 06:47 signature: a peer
// answers HTTP 200 but holds no AC, which arrives as the aggregate
// ErrServerACOpsFailed whose detail carries ErrACConnectionNotFound's message —
// it must bucket as remote_no_ac, not the generic ac_ops bucket.
func TestClassifyForwardAttempt(t *testing.T) {
	ackNoAC := &common.ServerKnockAckMsg{ErrCode: common.ErrACConnectionNotFound.ErrorCode()}
	ackAggNoAC := &common.ServerKnockAckMsg{
		ErrCode: common.ErrServerACOpsFailed.ErrorCode(),
		ErrMsg:  fmt.Sprintf("q_abc123: %s", common.ErrACConnectionNotFound.Error()),
	}
	ackOpsFailed := &common.ServerKnockAckMsg{
		ErrCode: common.ErrServerACOpsFailed.ErrorCode(),
		ErrMsg:  "add ipset failed",
	}
	ackOther := &common.ServerKnockAckMsg{ErrCode: "59999", ErrMsg: "something else"}

	tests := []struct {
		name string
		ack  *common.ServerKnockAckMsg
		err  error
		want ForwardOutcome
	}{
		{"success ignores ack", ackOther, nil, ForwardSuccess},
		{"remote no-ac by code", ackNoAC, fmt.Errorf("remote error: x"), ForwardRemoteNoAC},
		{"remote no-ac by aggregate msg (06:47 signature)", ackAggNoAC, fmt.Errorf("remote error: x"), ForwardRemoteNoAC},
		{"remote ac-ops failed", ackOpsFailed, fmt.Errorf("remote error: x"), ForwardRemoteACOpsFailed},
		{"remote non-success ack", ackOther, fmt.Errorf("remote error: x"), ForwardRemoteNonSuccessAck},
		{"transport decode error", nil, fmt.Errorf("unmarshal response: boom"), ForwardRemoteDecodeError},
		{"transport http error", nil, fmt.Errorf("server returned 502: boom"), ForwardRemoteHTTPError},
		{"transport response too large", nil, fmt.Errorf("response too large (99 bytes)"), ForwardRemoteHTTPError},
		{"context canceled", nil, context.Canceled, ForwardContextCanceled},
		{"generic request failed", nil, fmt.Errorf("request failed: dial tcp: refused"), ForwardRequestFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyForwardAttempt(tt.ack, tt.err); got != tt.want {
				t.Fatalf("classifyForwardAttempt = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestForwardToServer_TransportErrorPrefixes pins the coupling between the error
// strings forwardToServer produces and the prefixes classifyForwardAttempt
// string-matches on. That link is implicit — forwardToServer returns fmt.Errorf
// strings and classifyForwardAttempt greps them — so a rename on either side
// would silently dump remote_http_error / remote_decode_error into the generic
// request_failed bucket with no compile break. This drives the REAL
// forwardToServer against an httptest peer so a drift fails here loudly rather
// than quietly skewing the Phase 0A histogram. The fuller fix (typed transport
// errors instead of string-matching) is deferred to #3000.
//
// Only the three Contains-matched prefixes are pinned: request_failed and
// read_response already fall through to the same default ForwardRequestFailed
// bucket, so a prefix drift there cannot cause a misclassification.
func TestForwardToServer_TransportErrorPrefixes(t *testing.T) {
	tests := []struct {
		name        string
		handler     http.HandlerFunc
		wantPrefix  string
		wantOutcome ForwardOutcome
	}{
		{
			name: "server returned -> remote_http_error",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusBadGateway)
				_, _ = w.Write([]byte("upstream boom"))
			},
			wantPrefix:  "server returned ",
			wantOutcome: ForwardRemoteHTTPError,
		},
		{
			name: "response too large -> remote_http_error",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write(make([]byte, maxForwardResponseSize+10))
			},
			wantPrefix:  "response too large",
			wantOutcome: ForwardRemoteHTTPError,
		},
		{
			name: "unmarshal response -> remote_decode_error",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("{not valid json"))
			},
			wantPrefix:  "unmarshal response",
			wantOutcome: ForwardRemoteDecodeError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Bind the peer on 127.0.0.1 explicitly: forwardToServer rebuilds the
			// URL from srv.InternalIP (must pass isPrivateIP) + httpPort, so the
			// target IP has to be loopback and IPv4 (the URL format is host:port
			// without brackets).
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			ts := httptest.NewUnstartedServer(tt.handler)
			_ = ts.Listener.Close()
			ts.Listener = ln
			ts.Start()
			defer ts.Close()

			addr := ln.Addr().(*net.TCPAddr)
			f := NewHttpKnockForwarder(nil, nil, "10.0.0.99", addr.Port, nil, nil)
			srv := ServerInfo{ID: "peer", InternalIP: addr.IP.String()}

			ack, ferr := f.forwardToServer(context.Background(), srv, &common.HttpKnockRequest{}, &common.ResourceData{})
			if ferr == nil {
				t.Fatalf("expected error, got ack=%v", ack)
			}
			if !strings.HasPrefix(ferr.Error(), tt.wantPrefix) {
				t.Fatalf("error %q does not start with %q — forwardToServer prefix drifted from classifyForwardAttempt", ferr.Error(), tt.wantPrefix)
			}
			// ack is nil on the transport path, so classify reads the error message.
			if got := classifyForwardAttempt(nil, ferr); got != tt.wantOutcome {
				t.Fatalf("classifyForwardAttempt(%q) = %q, want %q", ferr.Error(), got, tt.wantOutcome)
			}
		})
	}
}
