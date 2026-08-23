package ac

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/OpenNHP/opennhp/nhp/common"
)

func TestHttpACReadinessRequiresConnectedAssignedServer(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name     string
		ha       *HttpAC
		want     int
		wantBody string
	}{
		{
			name:     "nil udp ac is unavailable",
			ha:       &HttpAC{},
			want:     http.StatusServiceUnavailable,
			wantBody: "no healthy assigned server\n",
		},
		{
			name:     "missing registration is unavailable",
			ha:       &HttpAC{ua: &UdpAC{}},
			want:     http.StatusServiceUnavailable,
			wantBody: "no healthy assigned server\n",
		},
		{
			name: "empty assignment is unavailable",
			ha: &HttpAC{ua: &UdpAC{registration: &ACRegistration{
				assignedServers: nil,
			}}},
			want:     http.StatusServiceUnavailable,
			wantBody: "no healthy assigned server\n",
		},
		{
			name: "only disconnected assignments are unavailable",
			ha: &HttpAC{ua: &UdpAC{registration: &ACRegistration{
				assignedServers: []*AssignedServer{
					{Target: common.RedirectTarget{IP: "10.0.0.1", Port: testServerListenPort}},
				},
			}}},
			want:     http.StatusServiceUnavailable,
			wantBody: "no healthy assigned server\n",
		},
		{
			name: "stale connected assignment is unavailable",
			ha: &HttpAC{ua: &UdpAC{registration: &ACRegistration{
				assignedServers: []*AssignedServer{
					{
						Target:    common.RedirectTarget{IP: "10.0.0.1", Port: testServerListenPort},
						Connected: true,
						LastSeen:  time.Now().Add(-(KeepaliveInterval*KeepaliveMaxRetries + time.Second)),
					},
				},
			}}},
			want:     http.StatusServiceUnavailable,
			wantBody: "no healthy assigned server\n",
		},
		{
			name: "healthy assignment without boot flush is unavailable",
			ha: &HttpAC{ua: &UdpAC{registration: &ACRegistration{
				assignedServers: []*AssignedServer{
					{Target: common.RedirectTarget{IP: "10.0.0.1", Port: testServerListenPort}, Connected: true, LastSeen: time.Now()},
				},
			}}},
			want:     http.StatusServiceUnavailable,
			wantBody: "session admission not ready\n",
		},
		{
			name: "healthy assignment without authority lease is unavailable",
			ha: func() *HttpAC {
				ac := &UdpAC{registration: &ACRegistration{assignedServers: []*AssignedServer{
					{Target: common.RedirectTarget{IP: "10.0.0.1", Port: testServerListenPort}, Connected: true, LastSeen: time.Now()},
				}}}
				ac.sessionFlushComplete.Store(true)
				return &HttpAC{ua: ac}
			}(),
			want:     http.StatusServiceUnavailable,
			wantBody: "session admission not ready\n",
		},
		{
			name: "healthy assignment with session authority is ready",
			ha: func() *HttpAC {
				ac := &UdpAC{registration: &ACRegistration{assignedServers: []*AssignedServer{
					{Target: common.RedirectTarget{IP: "10.0.0.1", Port: testServerListenPort}, Connected: true, LastSeen: time.Now()},
				}}}
				ac.sessionFlushComplete.Store(true)
				ac.sessionControlLeaseHeld.Store(true)
				return &HttpAC{ua: ac}
			}(),
			want:     http.StatusOK,
			wantBody: "ready\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.ha.ginEngine = gin.New()
			tt.ha.initRouter()

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, acReadinessPath, nil)
			tt.ha.ginEngine.ServeHTTP(rec, req)

			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d", rec.Code, tt.want)
			}
			if rec.Body.String() != tt.wantBody {
				t.Fatalf("body = %q, want %q", rec.Body.String(), tt.wantBody)
			}
		})
	}
}

func TestHttpACReadinessRejectAAKDoesNotAcquireSessionAuthority(t *testing.T) {
	gin.SetMode(gin.TestMode)
	server := &AssignedServer{
		Target:    common.RedirectTarget{IP: "10.0.0.1", Port: testServerListenPort},
		Connected: true, LastSeen: time.Now(),
	}
	ac := &UdpAC{
		bootID: "00112233445566778899aabbccddeeff",
		config: &Config{ACId: "test-session-control-reject", ServerEndpoint: "server.nhp.test.internal"},
	}
	ac.sessionFlushGeneration.Store(7)
	ac.sessionFlushComplete.Store(true)
	registration := &ACRegistration{ac: ac, assignedServers: []*AssignedServer{server}}
	ac.registration = registration
	sendAddr := &net.UDPAddr{IP: net.ParseIP(server.Target.IP), Port: server.Target.Port}
	registration.handleRefreshResponse(newAAKPacket(t, ac, common.ServerACAckMsg{
		ErrCode: common.ErrACSessionControlNotReady.ErrorCode(),
		ErrMsg:  common.ErrACSessionControlNotReady.Error(),
	}), server, sendAddr)
	if ac.sessionControlLeaseHeld.Load() || ac.sessionAdmissionReady() {
		t.Fatal("strict session-control denial acquired the global admission lease")
	}

	httpAC := &HttpAC{ua: ac, ginEngine: gin.New()}
	httpAC.initRouter()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, acReadinessPath, nil)
	httpAC.ginEngine.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable || rec.Body.String() != "session admission not ready\n" {
		t.Fatalf("readiness after strict rejection = %d/%q", rec.Code, rec.Body.String())
	}
}
