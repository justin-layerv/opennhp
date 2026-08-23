package server

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/nhp/common"
)

func TestResolveInternalKnockResourceUsesStoredRoutingData(t *testing.T) {
	stored := &common.ResourceData{
		ResourceGroup: common.ResourceGroup{
			AuthServiceId: "qurl",
			ResourceId:    "nhp-resource",
			OpenTime:      300,
			Resources: map[string]*common.ResourceInfo{
				"trusted": {
					ACId:     "trusted-ac",
					Hostname: "trusted.example",
					Addr:     &common.NetAddress{Ip: "10.0.0.10", Port: 443, Protocol: "tcp"},
				},
			},
		},
		SkipAuth: true,
		ExInfo: map[string]any{
			"source": "storage",
			"nested": map[string]any{
				"token": "stored",
			},
			"list": []any{
				"stored",
				map[string]any{"inner": "stored"},
			},
		},
	}
	hs := &HttpServer{udpServer: &UdpServer{
		authServiceMap: common.AuthSvcProviderMap{
			"qurl": {
				AuthSvcId: "qurl",
				ResourceGroups: common.ResourceGroupMap{
					"nhp-resource": stored,
				},
			},
		},
	}}

	caller := &common.ResourceData{
		ResourceGroup: common.ResourceGroup{
			AuthServiceId: "qurl",
			ResourceId:    "nhp-resource",
			OpenTime:      90,
			Resources: map[string]*common.ResourceInfo{
				"attacker": {
					ACId:     "attacker-ac",
					Hostname: "attacker.example",
					Addr:     &common.NetAddress{Ip: "10.66.66.66", Port: 22, Protocol: "tcp"},
				},
			},
		},
		ExInfo:             map[string]any{"JWTSecret": "caller-jwt-secret"},
		RedirectUrl:        "https://qurl.link/next",
		RedirectWithParams: true,
		CookieDomain:       ".qurl.link",
	}
	req := &common.HttpKnockRequest{
		AuthServiceId: "qurl",
		ResourceId:    "nhp-resource",
		SrcIp:         "203.0.113.25",
	}

	got, err := hs.resolveInternalKnockResource(context.Background(), req, caller)
	if err != nil {
		t.Fatalf("resolveInternalKnockResource returned error: %v", err)
	}
	if got == stored {
		t.Fatal("resolved resource aliases stored resource")
	}
	if len(got.Resources) != 1 || got.Resources["trusted"] == nil {
		t.Fatalf("resolved resources = %#v, want only stored routing data", got.Resources)
	}
	if got.Resources["attacker"] != nil {
		t.Fatalf("caller-supplied routing data was trusted: %#v", got.Resources["attacker"])
	}
	if got.Resources["trusted"].ACId != "trusted-ac" {
		t.Fatalf("resolved ACId = %q, want stored trusted-ac", got.Resources["trusted"].ACId)
	}
	if got.OpenTime != 90 {
		t.Fatalf("OpenTime = %d, want caller's shorter bounded override 90", got.OpenTime)
	}
	if got.ExInfo["source"] != "storage" {
		t.Fatalf("ExInfo source = %#v, want stored metadata preserved", got.ExInfo["source"])
	}
	if got.ExInfo["JWTSecret"] != nil {
		t.Fatalf("caller ExInfo was trusted: %#v", got.ExInfo["JWTSecret"])
	}
	if got.RedirectUrl != "" || got.RedirectWithParams || got.CookieDomain != "" {
		t.Fatalf("caller redirect/cookie metadata was trusted: redirect=%q withParams=%t cookieDomain=%q", got.RedirectUrl, got.RedirectWithParams, got.CookieDomain)
	}

	got.Resources["trusted"].Addr.Port = 8443
	got.ExInfo["source"] = "mutated"
	got.ExInfo["nested"].(map[string]any)["token"] = "mutated"
	got.ExInfo["list"].([]any)[1].(map[string]any)["inner"] = "mutated"
	if stored.Resources["trusted"].Addr.Port != 443 {
		t.Fatalf("mutating resolved resource changed stored Addr.Port to %d", stored.Resources["trusted"].Addr.Port)
	}
	if stored.ExInfo["source"] != "storage" {
		t.Fatalf("mutating resolved ExInfo changed stored ExInfo: %#v", stored.ExInfo)
	}
	if stored.ExInfo["nested"].(map[string]any)["token"] != "stored" {
		t.Fatalf("mutating nested resolved ExInfo changed stored ExInfo: %#v", stored.ExInfo)
	}
	if stored.ExInfo["list"].([]any)[1].(map[string]any)["inner"] != "stored" {
		t.Fatalf("mutating nested slice resolved ExInfo changed stored ExInfo: %#v", stored.ExInfo)
	}
}

func TestResolveInternalKnockResourcePlacesQURLTunnelServerFromPerAZRows(t *testing.T) {
	hs := &HttpServer{udpServer: &UdpServer{
		metrics: metrics.NewPublisherForTest(t),
		authServiceMap: common.AuthSvcProviderMap{
			"qurl": {
				AuthSvcId: "qurl",
				ResourceGroups: common.ResourceGroupMap{
					"qurl-tunnel-server-a": {
						ResourceGroup: common.ResourceGroup{
							AuthServiceId: "qurl",
							ResourceId:    "qurl-tunnel-server-a",
							OpenTime:      120,
							Resources: map[string]*common.ResourceInfo{
								"qurl-tunnel-server-a": {
									ACId:       "ac-a",
									Hostname:   "connect.example",
									PortSuffix: true,
									Addr:       &common.NetAddress{Port: 7000, Protocol: "tcp"},
								},
							},
						},
						SkipAuth: true,
					},
					"qurl-tunnel-server-b": {
						ResourceGroup: common.ResourceGroup{
							AuthServiceId: "qurl",
							ResourceId:    "qurl-tunnel-server-b",
							OpenTime:      120,
							Resources: map[string]*common.ResourceInfo{
								"qurl-tunnel-server-b": {
									ACId:       "ac-b",
									Hostname:   "connect.example",
									PortSuffix: true,
									Addr:       &common.NetAddress{Port: 7001, Protocol: "tcp"},
								},
							},
						},
						SkipAuth: true,
					},
				},
			},
		},
	}}
	req := &common.HttpKnockRequest{
		AuthServiceId: "qurl",
		ResourceId:    "qurl-tunnel-server",
		SrcIp:         " 203.0.113.25\n",
	}
	caller := &common.ResourceData{
		ResourceGroup: common.ResourceGroup{
			AuthServiceId: "qurl",
			ResourceId:    "qurl-tunnel-server",
			OpenTime:      90,
		},
	}

	got, err := hs.resolveInternalKnockResource(context.Background(), req, caller)
	if err != nil {
		t.Fatalf("resolveInternalKnockResource returned error: %v", err)
	}
	if got.ResourceId != "qurl-tunnel-server" {
		t.Fatalf("ResourceId = %q, want placement-neutral qurl-tunnel-server", got.ResourceId)
	}
	if got.OpenTime != 90 {
		t.Fatalf("OpenTime = %d, want caller's shorter bounded override 90", got.OpenTime)
	}
	if req.SrcIp != "203.0.113.25" {
		t.Fatalf("request SrcIp = %q, want canonical 203.0.113.25", req.SrcIp)
	}
	info := got.Resources["qurl-tunnel-server"]
	if info == nil {
		t.Fatalf("Resources missing placement-neutral qurl-tunnel-server entry: %#v", got.Resources)
	}
	wantPortForAC := map[string]int{"ac-a": 7000, "ac-b": 7001}
	wantPort, ok := wantPortForAC[info.ACId]
	if !ok {
		t.Fatalf("selected ACId = %q, want one of ac-a/ac-b", info.ACId)
	}
	if !info.PortSuffix {
		t.Fatal("selected resource must force PortSuffix so ACK includes the per-AZ public port")
	}
	if info.Hostname != "connect.example" {
		t.Fatalf("Hostname = %q, want connect.example", info.Hostname)
	}
	if info.Addr == nil || info.Addr.Port != wantPort {
		t.Fatalf("Addr = %#v, want per-AZ port %d for ACId %q", info.Addr, wantPort, info.ACId)
	}
	for _, perAZ := range []string{"qurl-tunnel-server-a", "qurl-tunnel-server-b"} {
		if _, leaked := got.Resources[perAZ]; leaked {
			t.Fatalf("alias leaked per-AZ resource %s: %#v", perAZ, got.Resources)
		}
	}

	again, err := hs.resolveInternalKnockResource(context.Background(), req, caller)
	if err != nil {
		t.Fatalf("second resolveInternalKnockResource returned error: %v", err)
	}
	againInfo := again.Resources["qurl-tunnel-server"]
	if againInfo == nil {
		t.Fatalf("second resolve missing placement-neutral qurl-tunnel-server entry: %#v", again.Resources)
	}
	if againInfo.ACId != info.ACId {
		t.Fatalf("same SrcIp selected ACId %q then %q; want stable placement", info.ACId, againInfo.ACId)
	}
}

func TestResolveInternalKnockResourceQURLDynamicResourceUsesDirectLookup(t *testing.T) {
	q := newFakeResourcesQuerier()
	q.put(nhpSystemCustomerID, "qurl-tunnel-server-stale", "qurl", "stale-ac", "stale.example", "stale.example", 7000, 120)
	lookup, err := NewResourceLookup(q, "test-table", nhpSystemCustomerID, nil)
	if err != nil {
		t.Fatalf("NewResourceLookup: %v", err)
	}
	if _, err := lookup.LookupAuthServiceProvider(context.Background(), "qurl"); err != nil {
		t.Fatalf("warm stale ASP cache: %v", err)
	}
	q.putDynamicQURLWithTTL("q_123456789ab", "qurl", "dynamic-ac", "dynamic.example", "dynamic.example", 8443, 300, time.Now().Add(time.Hour).Unix())

	hs := &HttpServer{udpServer: &UdpServer{
		metrics:        metrics.NewPublisherForTest(t),
		authServiceMap: common.AuthSvcProviderMap{},
		resourceLookup: lookup,
	}}
	req := &common.HttpKnockRequest{
		AuthServiceId: "qurl",
		ResourceId:    "q_123456789ab",
		SrcIp:         " 10.0.1.50 ",
	}
	caller := &common.ResourceData{
		ResourceGroup: common.ResourceGroup{
			AuthServiceId: "qurl",
			ResourceId:    "q_123456789ab",
			OpenTime:      60,
		},
	}

	got, err := hs.resolveInternalKnockResource(context.Background(), req, caller)
	if err != nil {
		t.Fatalf("resolveInternalKnockResource returned error: %v", err)
	}
	if got.ResourceId != "q_123456789ab" {
		t.Fatalf("ResourceId = %q, want q_123456789ab", got.ResourceId)
	}
	info := got.Resources["q_123456789ab"]
	if info == nil {
		t.Fatalf("Resources missing q_123456789ab: %#v", got.Resources)
	}
	if info.ACId != "dynamic-ac" {
		t.Fatalf("ACId = %q, want dynamic-ac", info.ACId)
	}
	if info.Addr == nil || info.Addr.Port != 8443 {
		t.Fatalf("Addr = %#v, want port 8443", info.Addr)
	}
	if got.OpenTime != 60 {
		t.Fatalf("OpenTime = %d, want caller cap 60", got.OpenTime)
	}
	if req.SrcIp != "10.0.1.50" {
		t.Fatalf("request SrcIp = %q, want canonical 10.0.1.50", req.SrcIp)
	}
}

func TestResolveInternalKnockResourceQURLDynamicResourceResolvesWithoutASPWarmThenRejectsDirectHTTPAdmission(t *testing.T) {
	const (
		acID         = "dynamic-ac-cold"
		resourceID   = "q_00000000022"
		knockerIP    = "10.0.1.50"
		wantOpen     = uint32(60)
		wantDestIP   = "dynamic.example"
		wantDestPort = 8443
	)

	q := newFakeResourcesQuerier()
	q.putDynamicQURLWithTTL(resourceID, "qurl", acID, wantDestIP, wantDestIP, wantDestPort, 300, time.Now().Add(time.Hour).Unix())
	lookup, err := NewResourceLookup(q, "test-table", nhpSystemCustomerID, nil)
	if err != nil {
		t.Fatalf("NewResourceLookup: %v", err)
	}
	us := &UdpServer{
		metrics:        metrics.NewPublisherForTest(t),
		authServiceMap: common.AuthSvcProviderMap{},
		resourceLookup: lookup,
	}
	hs := &HttpServer{udpServer: us}
	req := &common.HttpKnockRequest{
		UserId:        "u-dynamic",
		AuthServiceId: "qurl",
		ResourceId:    resourceID,
		SrcIp:         " " + knockerIP + " ",
		Ctx:           context.Background(),
	}
	caller := &common.ResourceData{ResourceGroup: common.ResourceGroup{
		AuthServiceId: "qurl",
		ResourceId:    resourceID,
		OpenTime:      wantOpen,
	}}

	resolved, err := hs.resolveInternalKnockResource(context.Background(), req, caller)
	if err != nil {
		t.Fatalf("resolveInternalKnockResource returned error: %v", err)
	}
	info := resolved.Resources[resourceID]
	if resolved.ResourceId != resourceID || resolved.OpenTime != wantOpen || info == nil || info.ACId != acID {
		t.Fatalf("resolved dynamic resource = %#v", resolved)
	}
	if req.SrcIp != knockerIP {
		t.Fatalf("canonical request source = %q, want %q", req.SrcIp, knockerIP)
	}
	if info.Addr == nil || info.Addr.Ip != "" || info.Addr.Port != wantDestPort || info.Addr.Protocol != "tcp" || info.DestHost() != wantDestIP {
		t.Fatalf("resolved dynamic destination = %#v, want host %q port %d/tcp", info, wantDestIP, wantDestPort)
	}
	ack, err := hs.handleHttpOpenResource(req, resolved)
	if !errors.Is(err, common.ErrHTTPAccessOperationUnsupported) {
		t.Fatalf("terminal direct HTTP admission error = %v, want unsupported", err)
	}
	if ack == nil || ack.ErrCode != common.ErrHTTPAccessOperationUnsupported.ErrorCode() {
		t.Fatalf("terminal direct HTTP admission ACK = %#v", ack)
	}
	if _, warmed := us.authServiceMap["qurl"]; warmed {
		t.Fatal("dynamic qURL resolution unexpectedly warmed or required the qurl ASP cache")
	}
}
func TestResolveInternalKnockResourceQURLDynamicResourceEmptySrcIPFailsClosed(t *testing.T) {
	q := newFakeResourcesQuerier()
	q.putDynamicQURLWithTTL("q_123456789ab", "qurl", "dynamic-ac", "dynamic.example", "dynamic.example", 8443, 300, time.Now().Add(time.Hour).Unix())
	lookup, err := NewResourceLookup(q, "test-table", nhpSystemCustomerID, nil)
	if err != nil {
		t.Fatalf("NewResourceLookup: %v", err)
	}
	hs := &HttpServer{udpServer: &UdpServer{
		metrics:        metrics.NewPublisherForTest(t),
		resourceLookup: lookup,
	}}
	req := &common.HttpKnockRequest{
		AuthServiceId: "qurl",
		ResourceId:    "q_123456789ab",
		SrcIp:         " \t ",
	}
	caller := &common.ResourceData{ResourceGroup: common.ResourceGroup{
		AuthServiceId: "qurl",
		ResourceId:    "q_123456789ab",
		OpenTime:      60,
	}}

	_, err = hs.resolveInternalKnockResource(context.Background(), req, caller)
	if !errors.Is(err, common.ErrResourceNotFound) {
		t.Fatalf("error = %v, want ErrResourceNotFound for empty SrcIp with dynamic qURL row", err)
	}
	if got := q.callCount(); got != 0 {
		t.Fatalf("resource lookup calls = %d, want 0 before source identity is present", got)
	}
	if req.SrcIp != " \t " {
		t.Fatalf("request SrcIp = %q, want original preserved on catalog miss", req.SrcIp)
	}
	counters, _ := hs.udpServer.metrics.CountersForTest(t)
	if got := counters[MetricInternalKnockResourceNotFound]; got != 1 {
		t.Fatalf("MetricInternalKnockResourceNotFound = %v, want 1", got)
	}
}

func TestResolveInternalKnockResourceQPrefixNonQURLASPUsesASPCache(t *testing.T) {
	q := newFakeResourcesQuerier()
	q.put(nhpSystemCustomerID, "q_123456789ab", "qurl", "wrong-asp-ac", "wrong.example", "wrong.example", 9443, 300)
	lookup, err := NewResourceLookup(q, "test-table", nhpSystemCustomerID, nil)
	if err != nil {
		t.Fatalf("NewResourceLookup: %v", err)
	}
	stored := &common.ResourceData{
		ResourceGroup: common.ResourceGroup{
			AuthServiceId: "agent",
			ResourceId:    "q_123456789ab",
			OpenTime:      120,
			Resources: map[string]*common.ResourceInfo{
				"q_123456789ab": {
					ACId: "agent-ac",
					Addr: &common.NetAddress{Ip: "10.0.0.10", Port: 443, Protocol: "tcp"},
				},
			},
		},
		SkipAuth: true,
	}
	hs := &HttpServer{udpServer: &UdpServer{
		metrics: metrics.NewPublisherForTest(t),
		authServiceMap: common.AuthSvcProviderMap{
			"agent": {
				AuthSvcId: "agent",
				ResourceGroups: common.ResourceGroupMap{
					"q_123456789ab": stored,
				},
			},
		},
		resourceLookup: lookup,
	}}
	req := &common.HttpKnockRequest{
		AuthServiceId: "agent",
		ResourceId:    "q_123456789ab",
		SrcIp:         "203.0.113.25",
	}
	caller := &common.ResourceData{ResourceGroup: common.ResourceGroup{
		AuthServiceId: "agent",
		ResourceId:    "q_123456789ab",
		OpenTime:      60,
	}}

	got, err := hs.resolveInternalKnockResource(context.Background(), req, caller)
	if err != nil {
		t.Fatalf("resolveInternalKnockResource returned error: %v", err)
	}
	info := got.Resources["q_123456789ab"]
	if info == nil {
		t.Fatalf("Resources missing q_123456789ab: %#v", got.Resources)
	}
	if info.ACId != "agent-ac" {
		t.Fatalf("ACId = %q, want agent-ac from cached agent ASP", info.ACId)
	}
	if got.OpenTime != 60 {
		t.Fatalf("OpenTime = %d, want caller cap 60", got.OpenTime)
	}
	if got := q.callCount(); got != 0 {
		t.Fatalf("DDB calls = %d, want 0; q_ prefix is dynamic only for the qurl ASP", got)
	}
}

func TestResolveInternalKnockResourceEmptySrcIPFailsClosedForPerAZRows(t *testing.T) {
	hs := &HttpServer{udpServer: &UdpServer{
		metrics: metrics.NewPublisherForTest(t),
		authServiceMap: common.AuthSvcProviderMap{
			"qurl": {
				AuthSvcId: "qurl",
				ResourceGroups: common.ResourceGroupMap{
					"qurl-tunnel-server-a": {
						ResourceGroup: common.ResourceGroup{
							AuthServiceId: "qurl",
							ResourceId:    "qurl-tunnel-server-a",
							OpenTime:      120,
							Resources: map[string]*common.ResourceInfo{
								"qurl-tunnel-server-a": {
									ACId:       "ac-a",
									Hostname:   "connect.example",
									PortSuffix: true,
									Addr:       &common.NetAddress{Port: 7000, Protocol: "tcp"},
								},
							},
						},
						SkipAuth: true,
					},
				},
			},
		},
	}}
	req := &common.HttpKnockRequest{AuthServiceId: "qurl", ResourceId: "qurl-tunnel-server"}
	caller := &common.ResourceData{ResourceGroup: common.ResourceGroup{
		AuthServiceId: "qurl",
		ResourceId:    "qurl-tunnel-server",
		OpenTime:      90,
	}}

	_, err := hs.resolveInternalKnockResource(context.Background(), req, caller)
	if !errors.Is(err, common.ErrResourceNotFound) {
		t.Fatalf("error = %v, want ErrResourceNotFound for empty SrcIp with per-AZ-only catalog", err)
	}
	counters, _ := hs.udpServer.metrics.CountersForTest(t)
	if got := counters[MetricInternalKnockResourceNotFound]; got != 1 {
		t.Fatalf("MetricInternalKnockResourceNotFound = %v, want 1", got)
	}
}

func TestResolveInternalKnockResourceEmptySrcIPUsesDirectRowDuringTransition(t *testing.T) {
	hs := &HttpServer{udpServer: &UdpServer{
		metrics: metrics.NewPublisherForTest(t),
		authServiceMap: common.AuthSvcProviderMap{
			"qurl": {
				AuthSvcId: "qurl",
				ResourceGroups: common.ResourceGroupMap{
					"qurl-tunnel-server": {
						ResourceGroup: common.ResourceGroup{
							AuthServiceId: "qurl",
							ResourceId:    "qurl-tunnel-server",
							OpenTime:      120,
							Resources: map[string]*common.ResourceInfo{
								"qurl-tunnel-server": {
									ACId:       "ac-direct",
									Hostname:   "connect.example",
									PortSuffix: false,
									Addr:       &common.NetAddress{Port: 7000, Protocol: "tcp"},
								},
							},
						},
						SkipAuth: true,
					},
				},
			},
		},
	}}
	req := &common.HttpKnockRequest{AuthServiceId: "qurl", ResourceId: "qurl-tunnel-server"}
	caller := &common.ResourceData{ResourceGroup: common.ResourceGroup{
		AuthServiceId: "qurl",
		ResourceId:    "qurl-tunnel-server",
		OpenTime:      90,
	}}

	got, err := hs.resolveInternalKnockResource(context.Background(), req, caller)
	if err != nil {
		t.Fatalf("resolveInternalKnockResource returned error: %v", err)
	}
	info := got.Resources["qurl-tunnel-server"]
	if info == nil {
		t.Fatalf("Resources missing direct qurl-tunnel-server entry: %#v", got.Resources)
	}
	if info.ACId != "ac-direct" {
		t.Fatalf("ACId = %q, want ac-direct", info.ACId)
	}
	if !info.PortSuffix {
		t.Fatal("PortSuffix=false, want transition direct row forced true")
	}
	if info.Addr == nil || info.Addr.Port != 7000 {
		t.Fatalf("Addr = %#v, want direct-row port 7000", info.Addr)
	}
	counters, _ := hs.udpServer.metrics.CountersForTest(t)
	if got := counters[MetricInternalKnockResourceNotFound]; got != 0 {
		t.Fatalf("MetricInternalKnockResourceNotFound = %v, want 0 with transition direct row", got)
	}
}

func TestResolveInternalKnockResourceStoredZeroUsesDefaultBeforeOverride(t *testing.T) {
	hs := &HttpServer{udpServer: &UdpServer{
		authServiceMap: common.AuthSvcProviderMap{
			"qurl": {
				AuthSvcId: "qurl",
				ResourceGroups: common.ResourceGroupMap{
					"nhp-resource": {
						ResourceGroup: common.ResourceGroup{
							AuthServiceId: "qurl",
							ResourceId:    "nhp-resource",
							Resources: map[string]*common.ResourceInfo{
								"trusted": {ACId: "trusted-ac", Addr: &common.NetAddress{Ip: "10.0.0.10", Port: 443, Protocol: "tcp"}},
							},
						},
					},
				},
			},
		},
	}}
	req := &common.HttpKnockRequest{AuthServiceId: "qurl", ResourceId: "nhp-resource"}

	t.Run("caller cannot widen past default", func(t *testing.T) {
		caller := &common.ResourceData{ResourceGroup: common.ResourceGroup{AuthServiceId: "qurl", ResourceId: "nhp-resource", OpenTime: DefaultIpOpenTime + 1}}

		got, err := hs.resolveInternalKnockResource(context.Background(), req, caller)
		if err != nil {
			t.Fatalf("resolveInternalKnockResource returned error: %v", err)
		}
		if got.OpenTime != DefaultIpOpenTime {
			t.Fatalf("OpenTime = %d, want DefaultIpOpenTime %d", got.OpenTime, DefaultIpOpenTime)
		}
	})

	t.Run("caller can still shorten default", func(t *testing.T) {
		caller := &common.ResourceData{ResourceGroup: common.ResourceGroup{AuthServiceId: "qurl", ResourceId: "nhp-resource", OpenTime: DefaultIpOpenTime - 1}}

		got, err := hs.resolveInternalKnockResource(context.Background(), req, caller)
		if err != nil {
			t.Fatalf("resolveInternalKnockResource returned error: %v", err)
		}
		if got.OpenTime != DefaultIpOpenTime-1 {
			t.Fatalf("OpenTime = %d, want caller's shorter override %d", got.OpenTime, DefaultIpOpenTime-1)
		}
	})
}

func TestResolveInternalKnockResourceDoesNotWidenOpenTime(t *testing.T) {
	hs := &HttpServer{udpServer: &UdpServer{
		authServiceMap: common.AuthSvcProviderMap{
			"qurl": {
				AuthSvcId: "qurl",
				ResourceGroups: common.ResourceGroupMap{
					"nhp-resource": {
						ResourceGroup: common.ResourceGroup{
							AuthServiceId: "qurl",
							ResourceId:    "nhp-resource",
							OpenTime:      300,
							Resources: map[string]*common.ResourceInfo{
								"trusted": {ACId: "trusted-ac", Addr: &common.NetAddress{Ip: "10.0.0.10", Port: 443, Protocol: "tcp"}},
							},
						},
					},
				},
			},
		},
	}}
	req := &common.HttpKnockRequest{AuthServiceId: "qurl", ResourceId: "nhp-resource"}
	caller := &common.ResourceData{ResourceGroup: common.ResourceGroup{AuthServiceId: "qurl", ResourceId: "nhp-resource", OpenTime: 999}}

	got, err := hs.resolveInternalKnockResource(context.Background(), req, caller)
	if err != nil {
		t.Fatalf("resolveInternalKnockResource returned error: %v", err)
	}
	if got.OpenTime != 300 {
		t.Fatalf("OpenTime = %d, want stored cap 300", got.OpenTime)
	}
}

func TestResolveInternalKnockResourceNormalizesTrimmedRequestIDs(t *testing.T) {
	hs := &HttpServer{udpServer: &UdpServer{
		authServiceMap: common.AuthSvcProviderMap{
			"qurl": {
				AuthSvcId: "qurl",
				ResourceGroups: common.ResourceGroupMap{
					"nhp-resource": {
						ResourceGroup: common.ResourceGroup{
							AuthServiceId: "qurl",
							ResourceId:    "nhp-resource",
							OpenTime:      300,
							Resources: map[string]*common.ResourceInfo{
								"trusted": {ACId: "trusted-ac", Addr: &common.NetAddress{Ip: "10.0.0.10", Port: 443, Protocol: "tcp"}},
							},
						},
					},
				},
			},
		},
	}}
	req := &common.HttpKnockRequest{AuthServiceId: " qurl ", ResourceId: "\tnhp-resource\n"}
	caller := &common.ResourceData{ResourceGroup: common.ResourceGroup{AuthServiceId: " qurl ", ResourceId: " nhp-resource ", OpenTime: 120}}

	got, err := hs.resolveInternalKnockResource(context.Background(), req, caller)
	if err != nil {
		t.Fatalf("resolveInternalKnockResource returned error: %v", err)
	}
	if req.AuthServiceId != "qurl" || req.ResourceId != "nhp-resource" {
		t.Fatalf("request IDs = (%q, %q), want canonical trimmed IDs", req.AuthServiceId, req.ResourceId)
	}
	if got.OpenTime != 120 {
		t.Fatalf("OpenTime = %d, want caller's shorter override 120", got.OpenTime)
	}
}

func TestResolveInternalKnockResourceMissingResource(t *testing.T) {
	hs := &HttpServer{udpServer: &UdpServer{
		metrics: metrics.NewPublisherForTest(t),
		authServiceMap: common.AuthSvcProviderMap{
			"qurl": {AuthSvcId: "qurl", ResourceGroups: common.ResourceGroupMap{}},
		},
	}}
	req := &common.HttpKnockRequest{AuthServiceId: " qurl ", ResourceId: "\tmissing\n"}

	_, err := hs.resolveInternalKnockResource(context.Background(), req, nil)
	if !errors.Is(err, common.ErrResourceNotFound) {
		t.Fatalf("error = %v, want ErrResourceNotFound", err)
	}
	if req.AuthServiceId != " qurl " || req.ResourceId != "\tmissing\n" {
		t.Fatalf("request IDs = (%q, %q), want original IDs preserved on catalog miss", req.AuthServiceId, req.ResourceId)
	}
	counters, _ := hs.udpServer.metrics.CountersForTest(t)
	if got := counters[MetricInternalKnockResourceNotFound]; got != 1 {
		t.Fatalf("MetricInternalKnockResourceNotFound = %v, want 1", got)
	}
}

func TestResolveInternalKnockResourceMissingASPUsesInternalMetric(t *testing.T) {
	lookup, err := NewResourceLookup(nil, "test-table", nhpSystemCustomerID, nil)
	if err != nil {
		t.Fatalf("NewResourceLookup: %v", err)
	}
	hs := &HttpServer{udpServer: &UdpServer{
		metrics:        metrics.NewPublisherForTest(t),
		authServiceMap: common.AuthSvcProviderMap{},
		resourceLookup: lookup,
	}}
	req := &common.HttpKnockRequest{AuthServiceId: "missing-asp", ResourceId: "nhp-resource"}

	_, err = hs.resolveInternalKnockResource(context.Background(), req, nil)
	if !errors.Is(err, common.ErrAuthServiceProviderNotFound) {
		t.Fatalf("error = %v, want ErrAuthServiceProviderNotFound", err)
	}
	counters, _ := hs.udpServer.metrics.CountersForTest(t)
	if got := counters[MetricInternalKnockASPNotFound]; got != 1 {
		t.Fatalf("MetricInternalKnockASPNotFound = %v, want 1", got)
	}
	if got := counters[MetricAuthFailure]; got != 0 {
		t.Fatalf("MetricAuthFailure = %v, want 0 for internal knock catalog miss", got)
	}
}

func TestHandleInternalKnockResourceLookupErrorReturns500(t *testing.T) {
	q := newFakeResourcesQuerier()
	q.err = errors.New("ddb throttled")
	lookup, err := NewResourceLookup(q, "test-table", nhpSystemCustomerID, nil)
	if err != nil {
		t.Fatalf("NewResourceLookup: %v", err)
	}
	hs := &HttpServer{udpServer: &UdpServer{
		metrics:        metrics.NewPublisherForTest(t),
		authServiceMap: common.AuthSvcProviderMap{},
		resourceLookup: lookup,
	}}
	fwdReq := HttpKnockForwardRequest{
		Request: &common.HttpKnockRequest{
			AuthServiceId: "qurl",
			ResourceId:    "nhp-resource",
			SrcIp:         "10.0.1.50",
		},
		Source: SourceAPI,
	}

	w := callHandleInternalKnock(t, hs, fwdReq)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500. body=%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "not found") {
		t.Fatalf("body = %q, DDB error must not masquerade as not found", w.Body.String())
	}
	counters, _ := hs.udpServer.metrics.CountersForTest(t)
	if got := counters[MetricResourceLookupDDBError]; got != 1 {
		t.Fatalf("MetricResourceLookupDDBError = %v, want 1", got)
	}
	if got := counters[MetricInternalKnockASPNotFound]; got != 0 {
		t.Fatalf("MetricInternalKnockASPNotFound = %v, want 0 for DDB error", got)
	}
}

func TestHandleInternalKnockQURLDynamicResourceLookupErrorReturns500(t *testing.T) {
	q := newFakeResourcesQuerier()
	q.err = errors.New("ddb throttled")
	lookup, err := NewResourceLookup(q, "test-table", nhpSystemCustomerID, nil)
	if err != nil {
		t.Fatalf("NewResourceLookup: %v", err)
	}
	hs := &HttpServer{udpServer: &UdpServer{
		metrics:        metrics.NewPublisherForTest(t),
		authServiceMap: common.AuthSvcProviderMap{},
		resourceLookup: lookup,
	}}
	fwdReq := HttpKnockForwardRequest{
		Request: &common.HttpKnockRequest{
			AuthServiceId: "qurl",
			ResourceId:    "q_123456789ab",
			SrcIp:         "10.0.1.50",
		},
		Source: SourceAPI,
	}

	w := callHandleInternalKnock(t, hs, fwdReq)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500. body=%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "not found") {
		t.Fatalf("body = %q, DDB error must not masquerade as not found", w.Body.String())
	}
	counters, _ := hs.udpServer.metrics.CountersForTest(t)
	if got := counters[MetricResourceLookupDDBError]; got != 1 {
		t.Fatalf("MetricResourceLookupDDBError = %v, want 1", got)
	}
	if got := counters[MetricInternalKnockResourceNotFound]; got != 0 {
		t.Fatalf("MetricInternalKnockResourceNotFound = %v, want 0 for DDB error", got)
	}
	if got := counters[MetricInternalKnockASPNotFound]; got != 0 {
		t.Fatalf("MetricInternalKnockASPNotFound = %v, want 0 for dynamic resource DDB error", got)
	}
}

func TestResolveInternalKnockResourceQURLDynamicDDBErrorUsesInfraMetric(t *testing.T) {
	ddbErr := errors.New("ddb throttled")
	q := newFakeResourcesQuerier()
	q.err = ddbErr
	lookup, err := NewResourceLookup(q, "test-table", nhpSystemCustomerID, nil)
	if err != nil {
		t.Fatalf("NewResourceLookup: %v", err)
	}
	us := &UdpServer{
		metrics:        metrics.NewPublisherForTest(t),
		resourceLookup: lookup,
	}

	_, err = us.ResolveInternalKnockResource(context.Background(), "qurl", "q_123456789ab", "test")
	if !errors.Is(err, ddbErr) {
		t.Fatalf("error = %v, want wrapped DDB error", err)
	}
	if errors.Is(err, common.ErrResourceNotFound) {
		t.Fatalf("error = %v, DDB error must not masquerade as ErrResourceNotFound", err)
	}
	counters, _ := us.metrics.CountersForTest(t)
	if got := counters[MetricResourceLookupDDBError]; got != 1 {
		t.Fatalf("MetricResourceLookupDDBError = %v, want 1", got)
	}
	if got := counters[MetricInternalKnockResourceNotFound]; got != 0 {
		t.Fatalf("MetricInternalKnockResourceNotFound = %v, want 0 for DDB error", got)
	}
}

func TestHandleInternalKnockResourceNotFoundResponseIsOpaque(t *testing.T) {
	hs := &HttpServer{udpServer: &UdpServer{
		metrics: metrics.NewPublisherForTest(t),
		authServiceMap: common.AuthSvcProviderMap{
			"qurl": {AuthSvcId: "qurl", ResourceGroups: common.ResourceGroupMap{}},
		},
	}}
	fwdReq := HttpKnockForwardRequest{
		Request: &common.HttpKnockRequest{
			AuthServiceId: "qurl",
			ResourceId:    "missing",
			SrcIp:         "10.0.1.50",
		},
		Source: SourceAPI,
	}

	w := callHandleInternalKnock(t, hs, fwdReq)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404. body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "not found") {
		t.Fatalf("body = %q, want opaque not found", w.Body.String())
	}
	if strings.Contains(w.Body.String(), common.ErrAuthServiceProviderNotFound.Error()) || strings.Contains(w.Body.String(), common.ErrResourceNotFound.Error()) {
		t.Fatalf("body leaked catalog detail: %s", w.Body.String())
	}
}

func TestHandleInternalKnockInvalidRequestResponseIsOpaque(t *testing.T) {
	hs := &HttpServer{udpServer: &UdpServer{}}
	fwdReq := HttpKnockForwardRequest{
		Request: &common.HttpKnockRequest{
			AuthServiceId: "qurl",
			ResourceId:    "nhp-resource",
			SrcIp:         "10.0.1.50",
		},
		Resource: &common.ResourceData{ResourceGroup: common.ResourceGroup{
			AuthServiceId: "qurl",
			ResourceId:    "attacker-resource",
		}},
		Source: SourceAPI,
	}

	w := callHandleInternalKnock(t, hs, fwdReq)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400. body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "invalid request") {
		t.Fatalf("body = %q, want generic invalid request", w.Body.String())
	}
	if strings.Contains(w.Body.String(), "attacker-resource") || strings.Contains(w.Body.String(), "does not match") {
		t.Fatalf("body leaked caller input or validation detail: %s", w.Body.String())
	}
}

func TestResolveInternalKnockResourceRejectsMismatchedCallerResource(t *testing.T) {
	hs := &HttpServer{}
	req := &common.HttpKnockRequest{AuthServiceId: "qurl", ResourceId: "nhp-resource"}
	caller := &common.ResourceData{ResourceGroup: common.ResourceGroup{AuthServiceId: "qurl", ResourceId: "attacker-resource"}}

	_, err := hs.resolveInternalKnockResource(context.Background(), req, caller)
	if !errors.Is(err, errInvalidInternalKnockRequest) {
		t.Fatalf("error = %v, want errInvalidInternalKnockRequest", err)
	}
}

func TestClampOpenTimeDownward(t *testing.T) {
	cases := []struct {
		name     string
		ceiling  uint32
		override uint32
		want     uint32
	}{
		{"override below ceiling lowers it", 300, 60, 60},
		{"override above ceiling capped to ceiling", 120, 300, 120},
		{"override equal to ceiling stays ceiling", 120, 120, 120},
		{"zero override falls back to ceiling", 300, 0, 300},
		{"one second override is allowed (no floor)", 300, 1, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClampOpenTimeDownward(tc.ceiling, tc.override); got != tc.want {
				t.Errorf("ClampOpenTimeDownward(%d, %d) = %d, want %d", tc.ceiling, tc.override, got, tc.want)
			}
		})
	}
}
