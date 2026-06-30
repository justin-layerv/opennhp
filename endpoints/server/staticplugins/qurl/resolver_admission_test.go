package qurl

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newAdmissionTestResolver(t *testing.T, h http.HandlerFunc) *QurlResolver {
	t.Helper()
	server := httptest.NewServer(h)
	t.Cleanup(server.Close)
	return &QurlResolver{
		httpClient:   &http.Client{Timeout: 5 * time.Second},
		baseURL:      server.URL,
		serviceToken: "test-token",
	}
}

func TestPrepareAdmission_Success(t *testing.T) {
	r := newAdmissionTestResolver(t, func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != admissionPreparePath {
			t.Errorf("path = %s, want %s", req.URL.Path, admissionPreparePath)
		}
		if req.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", req.Method)
		}
		if got := req.Header.Get(ServiceTokenHeader); got != "test-token" {
			t.Errorf("token = %q", got)
		}
		body, _ := json.Marshal(internalAdmissionPrepareResponse{
			Success: true,
			Data: &AdmissionPrepareResponse{
				AdmissionID: "adm_1", QurlID: "q_1", OpenTime: 30,
				QurlSiteURL: "https://q.qurl.site",
				ACRouting:   &ACRouting{ACId: "ac-1", DestHost: "10.0.0.1", DestPort: 443},
			},
		})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})

	resp, err := r.PrepareAdmission(context.Background(), &AdmissionPrepareRequest{
		QurlClaimsB64: "c", QurlIssuerSigB64: "s", AuthenticatedQurlPublicKeyB64: "k", SrcIP: "1.2.3.4",
	})
	if err != nil {
		t.Fatalf("PrepareAdmission: %v", err)
	}
	if resp.AdmissionID != "adm_1" || resp.ACRouting.ACId != "ac-1" {
		t.Errorf("unexpected response: %#v", resp)
	}
}

func TestPrepareAdmission_Classification(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		body    string
		wantErr error
	}{
		{name: "410 gone -> denied", status: http.StatusGone, body: ``, wantErr: ErrAdmissionDenied},
		{name: "403 -> denied", status: http.StatusForbidden, body: ``, wantErr: ErrAdmissionDenied},
		{name: "409 lease conflict -> denied", status: http.StatusConflict, body: ``, wantErr: ErrAdmissionDenied},
		{name: "structured consumed -> denied", status: http.StatusOK, body: `{"success":false,"error":{"code":"qurl_consumed"}}`, wantErr: ErrAdmissionDenied},
		{name: "structured max sessions -> denied", status: http.StatusOK, body: `{"success":false,"error":{"code":"max_sessions_reached"}}`, wantErr: ErrAdmissionDenied},
		{name: "500 -> service", status: http.StatusInternalServerError, body: ``, wantErr: ErrAdmissionService},
		{name: "structured unknown code -> service", status: http.StatusOK, body: `{"success":false,"error":{"code":"weird"}}`, wantErr: ErrAdmissionService},
		{name: "200 success no data -> invalid", status: http.StatusOK, body: `{"success":true}`, wantErr: ErrAdmissionInvalidResponse},
		{name: "200 open_time=0 -> invalid", status: http.StatusOK, body: `{"success":true,"data":{"admission_id":"a","open_time":0,"ac_routing":{"ac_id":"x","dest_host":"h","dest_port":443}}}`, wantErr: ErrAdmissionInvalidResponse},
		{name: "200 missing ac_routing -> invalid", status: http.StatusOK, body: `{"success":true,"data":{"admission_id":"a","open_time":30}}`, wantErr: ErrAdmissionInvalidResponse},
		{name: "200 empty dest_host -> invalid", status: http.StatusOK, body: `{"success":true,"data":{"admission_id":"a","open_time":30,"ac_routing":{"ac_id":"x","dest_port":443}}}`, wantErr: ErrAdmissionInvalidResponse},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newAdmissionTestResolver(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			})
			_, err := r.PrepareAdmission(context.Background(), &AdmissionPrepareRequest{QurlClaimsB64: "c", QurlIssuerSigB64: "s"})
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestCommitAdmission(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		var gotPath string
		r := newAdmissionTestResolver(t, func(w http.ResponseWriter, req *http.Request) {
			gotPath = req.URL.Path
			w.WriteHeader(http.StatusOK)
		})
		if err := r.CommitAdmission(context.Background(), "adm_xyz", "req-1"); err != nil {
			t.Fatalf("CommitAdmission: %v", err)
		}
		if gotPath != "/internal/v2/qurl/admissions/adm_xyz/commit" {
			t.Errorf("path = %s", gotPath)
		}
	})

	t.Run("non-2xx errors", func(t *testing.T) {
		r := newAdmissionTestResolver(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		})
		if err := r.CommitAdmission(context.Background(), "adm_xyz", ""); !errors.Is(err, ErrAdmissionService) {
			t.Fatalf("err = %v, want ErrAdmissionService", err)
		}
	})

	t.Run("empty admission id errors without HTTP", func(t *testing.T) {
		called := false
		r := newAdmissionTestResolver(t, func(w http.ResponseWriter, _ *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		})
		if err := r.CommitAdmission(context.Background(), "", ""); !errors.Is(err, ErrAdmissionService) {
			t.Fatalf("err = %v, want ErrAdmissionService", err)
		}
		if called {
			t.Error("must not make an HTTP call with an empty admission id")
		}
	})
}

func TestCancelAdmission(t *testing.T) {
	var gotPath string
	r := newAdmissionTestResolver(t, func(w http.ResponseWriter, req *http.Request) {
		gotPath = req.URL.Path
		w.WriteHeader(http.StatusOK)
	})
	if err := r.CancelAdmission(context.Background(), "adm_abc", "req-2"); err != nil {
		t.Fatalf("CancelAdmission: %v", err)
	}
	if gotPath != "/internal/v2/qurl/admissions/adm_abc/cancel" {
		t.Errorf("path = %s", gotPath)
	}
}

// TestAdmission_EmptyServiceToken proves the methods fail closed when the service
// token is unset (never a silent unauthenticated call).
func TestAdmission_EmptyServiceToken(t *testing.T) {
	r := &QurlResolver{httpClient: &http.Client{}, baseURL: "https://x", serviceToken: ""}
	if _, err := r.PrepareAdmission(context.Background(), &AdmissionPrepareRequest{}); !errors.Is(err, ErrAdmissionService) {
		t.Errorf("prepare err = %v", err)
	}
	if err := r.CommitAdmission(context.Background(), "a", ""); !errors.Is(err, ErrAdmissionService) {
		t.Errorf("commit err = %v", err)
	}
	if err := r.CancelAdmission(context.Background(), "a", ""); !errors.Is(err, ErrAdmissionService) {
		t.Errorf("cancel err = %v", err)
	}
}
