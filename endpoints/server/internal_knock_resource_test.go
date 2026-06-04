package server

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

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

func TestHandleInternalKnockResourceNotFoundResponseIsOpaque(t *testing.T) {
	hs := &HttpServer{udpServer: &UdpServer{
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
