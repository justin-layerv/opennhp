package qurlplacement

import (
	"fmt"
	"testing"

	"github.com/OpenNHP/opennhp/nhp/common"
)

func TestResolveResource_SelectsPerAZTunnelServer(t *testing.T) {
	asp := testTunnelASP()

	res := ResolveResource(TunnelServerResourceID, Identity{PublicKey: "client-instance-a"}, asp)
	if res == nil {
		t.Fatal("ResolveResource returned nil")
	}
	if res.ResourceId != TunnelServerResourceID {
		t.Fatalf("ResourceId=%q want %q", res.ResourceId, TunnelServerResourceID)
	}
	if len(res.Resources) != 1 {
		t.Fatalf("Resources=%v want one placement-neutral entry", res.Resources)
	}
	info := res.Resources[TunnelServerResourceID]
	if info == nil {
		t.Fatalf("Resources missing %q entry: %v", TunnelServerResourceID, res.Resources)
	}
	if got := info.DestHost(); got == "" || got == "connect.test" {
		t.Fatalf("DestHost()=%q want explicit public host:port from selected AZ row", got)
	}
	if !info.PortSuffix {
		t.Fatal("PortSuffix=false want true")
	}
}

func TestResolveResource_DistributesByStableIdentity(t *testing.T) {
	asp := testTunnelASP()
	counts := map[string]int{}

	// Bounds are calibrated to these deterministic identity strings. Recompute
	// the window if the fixture format changes.
	for i := 0; i < 600; i++ {
		res := ResolveResource(TunnelServerResourceID, Identity{PublicKey: fmt.Sprintf("client-instance-%03d", i)}, asp)
		if res == nil {
			t.Fatalf("ResolveResource(%d) returned nil", i)
		}
		info := res.Resources[TunnelServerResourceID]
		if info == nil {
			t.Fatalf("ResolveResource(%d) missing placement-neutral resource: %+v", i, res.Resources)
		}
		counts[info.DestHost()]++
	}

	if len(counts) != 3 {
		t.Fatalf("placement counts=%v want all three AZ ports represented", counts)
	}
	for host, count := range counts {
		if count < 150 || count > 250 {
			t.Fatalf("placement counts=%v; host %q got %d of 600, want rough even spread", counts, host, count)
		}
	}
}

func TestResolveResource_StableForSameIdentity(t *testing.T) {
	asp := testTunnelASP()
	first := ResolveResource(TunnelServerResourceID, Identity{PublicKey: "same-client"}, asp)
	if first == nil || first.Resources[TunnelServerResourceID] == nil {
		t.Fatalf("first ResolveResource returned %+v", first)
	}
	want := first.Resources[TunnelServerResourceID].DestHost()

	for i := 0; i < 100; i++ {
		next := ResolveResource(TunnelServerResourceID, Identity{PublicKey: "same-client"}, asp)
		if next == nil || next.Resources[TunnelServerResourceID] == nil {
			t.Fatalf("ResolveResource(%d) returned %+v", i, next)
		}
		if got := next.Resources[TunnelServerResourceID].DestHost(); got != want {
			t.Fatalf("ResolveResource(%d) DestHost()=%q want stable %q", i, got, want)
		}
	}
}

func TestResolveResource_PublicKeyPreferredOverUserID(t *testing.T) {
	asp := testTunnelASP()

	withPubKeyAndUserID := ResolveResource(TunnelServerResourceID, Identity{PublicKey: "pub-1", UserID: "different-user"}, asp)
	withPubKeyOnly := ResolveResource(TunnelServerResourceID, Identity{PublicKey: "pub-1"}, asp)
	if withPubKeyAndUserID == nil || withPubKeyAndUserID.Resources[TunnelServerResourceID] == nil {
		t.Fatalf("ResolveResource with public key + user id returned %+v", withPubKeyAndUserID)
	}
	if withPubKeyOnly == nil || withPubKeyOnly.Resources[TunnelServerResourceID] == nil {
		t.Fatalf("ResolveResource with public key only returned %+v", withPubKeyOnly)
	}

	pubKeyAndUserIDHost := withPubKeyAndUserID.Resources[TunnelServerResourceID].DestHost()
	pubKeyOnlyHost := withPubKeyOnly.Resources[TunnelServerResourceID].DestHost()
	if pubKeyAndUserIDHost != pubKeyOnlyHost {
		t.Fatalf("placement with public key + user id = %q, want public-key-only placement %q", pubKeyAndUserIDHost, pubKeyOnlyHost)
	}
}

func TestResolveResource_SingleAZCandidate(t *testing.T) {
	asp := &common.AuthServiceProviderData{
		AuthSvcId: "agent",
		ResourceGroups: common.ResourceGroupMap{
			"qurl-tunnel-server-c": testTunnelResource("qurl-tunnel-server-c", 7002),
		},
	}

	res := ResolveResource(TunnelServerResourceID, Identity{PublicKey: "client-instance"}, asp)
	if res == nil || res.Resources[TunnelServerResourceID] == nil {
		t.Fatalf("ResolveResource returned %+v", res)
	}
	if got := res.Resources[TunnelServerResourceID].DestHost(); got != "connect.test:7002" {
		t.Fatalf("DestHost()=%q want connect.test:7002", got)
	}
}

func TestResolveResource_ExcludesBarePrefixCandidate(t *testing.T) {
	asp := &common.AuthServiceProviderData{
		AuthSvcId: "agent",
		ResourceGroups: common.ResourceGroupMap{
			"qurl-tunnel-server-":  testTunnelResource("qurl-tunnel-server-", 7999),
			"qurl-tunnel-server-c": testTunnelResource("qurl-tunnel-server-c", 7002),
		},
	}

	res := ResolveResource(TunnelServerResourceID, Identity{PublicKey: "client-instance"}, asp)
	if res == nil || res.Resources[TunnelServerResourceID] == nil {
		t.Fatalf("ResolveResource returned %+v", res)
	}
	if got := res.Resources[TunnelServerResourceID].DestHost(); got != "connect.test:7002" {
		t.Fatalf("DestHost()=%q want connect.test:7002 from real AZ suffix row", got)
	}
}

func TestResolveResource_EmptyIdentityDoesNotHotspotPerAZRows(t *testing.T) {
	if got := ResolveResource(TunnelServerResourceID, Identity{}, testTunnelASP()); got != nil {
		t.Fatalf("ResolveResource with empty identity=%+v want nil", got)
	}
}

func TestResolveResource_DirectTunnelServerRowFallback(t *testing.T) {
	asp := &common.AuthServiceProviderData{
		AuthSvcId: "agent",
		ResourceGroups: common.ResourceGroupMap{
			TunnelServerResourceID: testTunnelResource(TunnelServerResourceID, 7000),
		},
	}

	res := ResolveResource(TunnelServerResourceID, Identity{}, asp)
	if res == nil || res.Resources[TunnelServerResourceID] == nil {
		t.Fatalf("ResolveResource returned %+v", res)
	}
	if got := res.Resources[TunnelServerResourceID].DestHost(); got != "connect.test:7000" {
		t.Fatalf("DestHost()=%q want connect.test:7000", got)
	}
}

func TestResolveResource_DirectTunnelServerRowFallbackMalformedPortFailsClosed(t *testing.T) {
	asp := &common.AuthServiceProviderData{
		AuthSvcId: "agent",
		ResourceGroups: common.ResourceGroupMap{
			TunnelServerResourceID: testTunnelResource(TunnelServerResourceID, 0),
		},
	}

	res := ResolveResource(TunnelServerResourceID, Identity{}, asp)
	if res == nil || res.Resources[TunnelServerResourceID] == nil {
		t.Fatalf("ResolveResource returned %+v", res)
	}
	if got := res.Resources[TunnelServerResourceID].DestHost(); got != "" {
		t.Fatalf("DestHost()=%q, want empty fail-closed host for direct row without explicit port", got)
	}
}

func TestResolveResource_EmptyIdentityFallsBackToDirectRowDuringTransition(t *testing.T) {
	asp := testTunnelASP()
	asp.ResourceGroups[TunnelServerResourceID] = testTunnelResource(TunnelServerResourceID, 7000)

	res := ResolveResource(TunnelServerResourceID, Identity{}, asp)
	if res == nil || res.Resources[TunnelServerResourceID] == nil {
		t.Fatalf("ResolveResource returned %+v", res)
	}
	if got := res.Resources[TunnelServerResourceID].DestHost(); got != "connect.test:7000" {
		t.Fatalf("DestHost()=%q want transition direct-row fallback", got)
	}
}

func TestResolveResource_PerAZPlacementWinsOverDirectRowWithIdentity(t *testing.T) {
	asp := testTunnelASP()
	asp.ResourceGroups[TunnelServerResourceID] = testTunnelResource(TunnelServerResourceID, 7999)

	res := ResolveResource(TunnelServerResourceID, Identity{PublicKey: "client-instance"}, asp)
	if res == nil || res.Resources[TunnelServerResourceID] == nil {
		t.Fatalf("ResolveResource returned %+v", res)
	}
	if got := res.Resources[TunnelServerResourceID].DestHost(); got == "connect.test:7999" {
		t.Fatalf("DestHost()=%q came from transition direct row; want identity-based per-AZ placement", got)
	}
}

func TestResolveResource_PerAZResourcePassesThroughUnaliased(t *testing.T) {
	asp := testTunnelASP()
	perAZ := asp.ResourceGroups["qurl-tunnel-server-a"]
	perAZ.Resources["qurl-tunnel-server-a"].PortSuffix = false

	res := ResolveResource("qurl-tunnel-server-a", Identity{}, asp)
	if res != perAZ {
		t.Fatalf("ResolveResource(per-AZ) returned %+v, want original row %+v", res, perAZ)
	}
	if res.Resources["qurl-tunnel-server-a"].PortSuffix {
		t.Fatal("per-AZ direct lookup must not force PortSuffix=true")
	}
}

func TestResolveResource_NonQURLResourceBypassesTunnelAlias(t *testing.T) {
	custom := testTunnelResource("custom-resource", 0)
	custom.Resources["custom-resource"].PortSuffix = false
	asp := &common.AuthServiceProviderData{
		AuthSvcId: "agent",
		ResourceGroups: common.ResourceGroupMap{
			TunnelServerResourceID: testTunnelResource(TunnelServerResourceID, 0),
			"custom-resource":      custom,
		},
	}

	res := ResolveResource("custom-resource", Identity{PublicKey: "client-instance"}, asp)
	if res != custom {
		t.Fatalf("ResolveResource(non-qURL) returned %+v, want original custom row %+v", res, custom)
	}
	if res.Resources["custom-resource"].PortSuffix {
		t.Fatal("non-qURL resource must not force PortSuffix=true through tunnel alias path")
	}
}

func TestResolveResource_PreservesResourceDataExtensions(t *testing.T) {
	asp := &common.AuthServiceProviderData{
		AuthSvcId: "agent",
		ResourceGroups: common.ResourceGroupMap{
			"qurl-tunnel-server-a": testTunnelResource("qurl-tunnel-server-a", 7000),
		},
	}
	selected := asp.ResourceGroups["qurl-tunnel-server-a"]
	selected.AppKey = "app-key"
	selected.AppSecret = "app-secret"
	selected.AccessKey = "access-key"
	selected.SecretKey = "secret-key"
	selected.RedirectUrl = "https://redirect.example"
	selected.RedirectWithParams = true
	selected.CookieDomain = ".example.com"
	selected.ExInfo = map[string]any{"region": "a"}

	res := ResolveResource(TunnelServerResourceID, Identity{PublicKey: "client-instance"}, asp)
	if res == nil {
		t.Fatal("ResolveResource returned nil")
	}
	if res.AppKey != selected.AppKey || res.AppSecret != selected.AppSecret ||
		res.AccessKey != selected.AccessKey || res.SecretKey != selected.SecretKey ||
		res.RedirectUrl != selected.RedirectUrl || res.CookieDomain != selected.CookieDomain ||
		!res.RedirectWithParams {
		t.Fatalf("ResourceData extensions not preserved: got %+v want based on %+v", res, selected)
	}
	if res.ExInfo["region"] != "a" {
		t.Fatalf("ExInfo=%v want copied region", res.ExInfo)
	}
	res.ExInfo["region"] = "mutated"
	if selected.ExInfo["region"] != "a" {
		t.Fatalf("ExInfo alias mutated selected row: %v", selected.ExInfo)
	}
	if !res.SkipAuth {
		t.Fatal("SkipAuth=false after alias; want true")
	}
	res.Resources[TunnelServerResourceID].Addr.Port = 9999
	if selected.Resources["qurl-tunnel-server-a"].Addr.Port != 7000 {
		t.Fatalf("Addr alias mutated selected row: %+v", selected.Resources["qurl-tunnel-server-a"].Addr)
	}
}

func TestResolveResource_PreservesMaskHostThroughAlias(t *testing.T) {
	asp := &common.AuthServiceProviderData{
		AuthSvcId: "agent",
		ResourceGroups: common.ResourceGroupMap{
			"qurl-tunnel-server-a": testTunnelResource("qurl-tunnel-server-a", 7000),
		},
	}
	asp.ResourceGroups["qurl-tunnel-server-a"].Resources["qurl-tunnel-server-a"].MaskHost = true

	res := ResolveResource(TunnelServerResourceID, Identity{PublicKey: "client-instance"}, asp)
	if res == nil || res.Resources[TunnelServerResourceID] == nil {
		t.Fatalf("ResolveResource returned %+v", res)
	}
	if !res.Resources[TunnelServerResourceID].MaskHost {
		t.Fatal("MaskHost=false after alias; want true")
	}
}

func TestAliasTunnelServerResource_MissingSelectedKeyReturnsNil(t *testing.T) {
	selected := testTunnelResource("qurl-tunnel-server-a", 7000)
	delete(selected.Resources, "qurl-tunnel-server-a")

	if got := aliasTunnelServerResource("qurl-tunnel-server-a", selected); got != nil {
		t.Fatalf("aliasTunnelServerResource returned %+v, want nil when selected row omits selected key", got)
	}
}

func TestOnlyResourceInfoRejectsMultiEntryMaps(t *testing.T) {
	res := testTunnelResource("custom-resource", 443)
	res.Resources["other-resource"] = &common.ResourceInfo{ACId: "other-ac"}

	if got := OnlyResourceInfo(res); got != nil {
		t.Fatalf("OnlyResourceInfo(multi-entry)=%+v want nil", got)
	}
}

func TestTunnelPlacementScoreGolden(t *testing.T) {
	cases := []struct {
		identity    string
		candidateID string
		want        uint64
	}{
		{"pub:client-instance-a", "qurl-tunnel-server-a", 14205387831173285549},
		{"pub:client-instance-a", "qurl-tunnel-server-b", 3176267060280025851},
		{"usr:customer-17", "qurl-tunnel-server-c", 857192021404568897},
		{"pub:same-client", "qurl-tunnel-server-b", 4130248969780633248},
	}
	for _, tc := range cases {
		t.Run(tc.identity+"/"+tc.candidateID, func(t *testing.T) {
			if got := tunnelPlacementScore(tc.identity, tc.candidateID); got != tc.want {
				t.Fatalf("tunnelPlacementScore(%q,%q)=%d want %d", tc.identity, tc.candidateID, got, tc.want)
			}
		})
	}
}

func testTunnelASP() *common.AuthServiceProviderData {
	return &common.AuthServiceProviderData{
		AuthSvcId: "agent",
		ResourceGroups: common.ResourceGroupMap{
			"qurl-tunnel-server-a": testTunnelResource("qurl-tunnel-server-a", 7000),
			"qurl-tunnel-server-b": testTunnelResource("qurl-tunnel-server-b", 7001),
			"qurl-tunnel-server-c": testTunnelResource("qurl-tunnel-server-c", 7002),
		},
	}
}

func testTunnelResource(resourceID string, port int) *common.ResourceData {
	return &common.ResourceData{
		ResourceGroup: common.ResourceGroup{
			AuthServiceId: "agent",
			ResourceId:    resourceID,
			OpenTime:      120,
			Resources: map[string]*common.ResourceInfo{
				resourceID: {
					ACId:       "layerv-ac-tf",
					Hostname:   "connect.test",
					PortSuffix: true,
					Addr: &common.NetAddress{
						Port:     port,
						Protocol: "tcp",
					},
				},
			},
		},
		SkipAuth: true,
	}
}
