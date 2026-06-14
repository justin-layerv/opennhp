package qurl

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	nhpserver "github.com/OpenNHP/opennhp/endpoints/server"
)

func newAuthorizeTestResolver(t *testing.T, h http.HandlerFunc) (*QurlResolver, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(h)
	t.Cleanup(server.Close)
	return &QurlResolver{
		httpClient:   &http.Client{Timeout: 5 * time.Second},
		baseURL:      server.URL,
		serviceToken: "test-token",
	}, server
}

func TestAuthorize_Allow_URLResource(t *testing.T) {
	var gotPath, gotQuery, gotToken, gotReqID string
	r, _ := newAuthorizeTestResolver(t, func(w http.ResponseWriter, req *http.Request) {
		gotPath = req.URL.Path
		gotQuery = req.URL.RawQuery
		gotToken = req.Header.Get(ServiceTokenHeader)
		gotReqID = req.Header.Get(nhpserver.RequestIDHeader)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"remaining_seconds":42}`))
	})

	res, err := r.Authorize(context.Background(), "r_abc123XYZ_-", "203.0.113.7", "trace-abc-123")
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if res.RemainingSeconds != 42 || res.Tunnel {
		t.Errorf("got %+v, want {RemainingSeconds:42, Tunnel:false}", res)
	}
	if gotPath != "/internal/v1/resource/r_abc123XYZ_-/authorize" {
		t.Errorf("path = %q", gotPath)
	}
	if !strings.Contains(gotQuery, "client_ip=203.0.113.7") {
		t.Errorf("query = %q, want client_ip=203.0.113.7", gotQuery)
	}
	if gotToken != "test-token" {
		t.Errorf("service token header = %q, want test-token", gotToken)
	}
	if gotReqID != "trace-abc-123" {
		t.Errorf("request-id header = %q, want trace-abc-123 (must propagate to qurl-service)", gotReqID)
	}
}

func TestAuthorize_Allow_TunnelResource(t *testing.T) {
	r, _ := newAuthorizeTestResolver(t, func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"remaining_seconds":0,"tunnel":true}`))
	})
	res, err := r.Authorize(context.Background(), "r_tunnel00000", "203.0.113.7", "")
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if !res.Tunnel || res.RemainingSeconds != 0 {
		t.Errorf("got %+v, want {RemainingSeconds:0, Tunnel:true}", res)
	}
}

func TestAuthorize_Deny(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusNotFound, http.StatusGone} {
		r, _ := newAuthorizeTestResolver(t, func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"success":false,"error":{"code":"access_denied"}}`))
		})
		_, err := r.Authorize(context.Background(), "r_denied00000", "203.0.113.7", "")
		if !errors.Is(err, ErrQurlAccessDenied) {
			t.Errorf("status %d: err = %v, want ErrQurlAccessDenied", status, err)
		}
	}
}

func TestAuthorize_MalformedOK(t *testing.T) {
	r, _ := newAuthorizeTestResolver(t, func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{ not json`))
	})
	_, err := r.Authorize(context.Background(), "r_malformed00", "203.0.113.7", "")
	if !errors.Is(err, ErrInvalidResolveResponse) {
		t.Errorf("err = %v, want ErrInvalidResolveResponse", err)
	}
}

func TestAuthorize_TransientServerError(t *testing.T) {
	r, _ := newAuthorizeTestResolver(t, func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	_, err := r.Authorize(context.Background(), "r_5xx00000000", "203.0.113.7", "")
	if err == nil || errors.Is(err, ErrQurlAccessDenied) {
		t.Errorf("err = %v, want a non-deny transient error", err)
	}
}

func TestAuthorize_EmptyServiceToken(t *testing.T) {
	r := &QurlResolver{httpClient: &http.Client{}, baseURL: "http://unused", serviceToken: ""}
	if _, err := r.Authorize(context.Background(), "r_x0000000000", "203.0.113.7", ""); err == nil {
		t.Error("expected error for empty service token")
	}
}
