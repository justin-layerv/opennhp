package ac

import (
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
					{Target: common.RedirectTarget{IP: "10.0.0.1", Port: DefaultServerPort}},
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
						Target:    common.RedirectTarget{IP: "10.0.0.1", Port: DefaultServerPort},
						Connected: true,
						LastSeen:  time.Now().Add(-(KeepaliveInterval*KeepaliveMaxRetries + time.Second)),
					},
				},
			}}},
			want:     http.StatusServiceUnavailable,
			wantBody: "no healthy assigned server\n",
		},
		{
			name: "healthy assignment is ready",
			ha: &HttpAC{ua: &UdpAC{registration: &ACRegistration{
				assignedServers: []*AssignedServer{
					{Target: common.RedirectTarget{IP: "10.0.0.1", Port: DefaultServerPort}, Connected: true, LastSeen: time.Now()},
				},
			}}},
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
