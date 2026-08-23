package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/endpoints/server/internal/qurlv2"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

// forwardKnockOutcome captures a ForwardKnock return value so tests can run the
// call in a goroutine and select on its completion.
type forwardKnockOutcome struct {
	result *common.ServerForwardResultMsg
	err    error
}

func TestForwardedAgentPubKeyRejectsEmpty(t *testing.T) {
	if got, ok := forwardedAgentPubKey(&core.PacketParserData{}); ok || got != "" {
		t.Fatalf("forwardedAgentPubKey(empty)=(%q,%v), want empty,false", got, ok)
	}
	if got, ok := forwardedAgentPubKey(nil); ok || got != "" {
		t.Fatalf("forwardedAgentPubKey(nil)=(%q,%v), want empty,false", got, ok)
	}
	if got, ok := forwardedAgentPubKey(&core.PacketParserData{RemotePubKey: []byte{1, 2, 3, 4}}); ok || got != "" {
		t.Fatalf("forwardedAgentPubKey(short)=(%q,%v), want empty,false", got, ok)
	}
	if got, ok := forwardedAgentPubKey(&core.PacketParserData{RemotePubKey: make([]byte, 33)}); ok || got != "" {
		t.Fatalf("forwardedAgentPubKey(long)=(%q,%v), want empty,false", got, ok)
	}
}

func TestForwardedAgentPubKeyEncodesAuthenticatedKey(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	got, ok := forwardedAgentPubKey(&core.PacketParserData{RemotePubKey: raw})
	if !ok {
		t.Fatal("forwardedAgentPubKey returned ok=false, want true")
	}
	if want := base64.StdEncoding.EncodeToString(raw); got != want {
		t.Fatalf("forwardedAgentPubKey=%q want %q", got, want)
	}
}

func TestNativeForwardAdmissionRevocationData_MetadataOnly(t *testing.T) {
	src := &common.ResourceData{
		ResourceGroup: common.ResourceGroup{
			AuthServiceId: "qurl",
			ResourceId:    "res-from-catalog",
			OpenTime:      999,
			Resources: map[string]*common.ResourceInfo{
				"res-from-catalog": {
					ACId: "ac-origin",
					Addr: &common.NetAddress{Ip: "192.0.2.50", Port: 8443},
				},
			},
		},
		RedirectUrl:           "https://origin.example/should-not-forward",
		QurlUserPublicKeyHash: "qhash",
		ResourcePublicKeyHash: "verified-rhash",
		QurlSessionId:         "sess-live",
		AdmissionId:           "adm-123",
		Deadline:              1781910300,
		RedirectWithParams:    true,
		SkipAuth:              true,
		CookieDomain:          "origin.example",
		ResourcePublicKeyB64:  "catalog-carrier-only",
		AppKey:                "app-key",
		AppSecret:             "app-secret",
		AccessKey:             "access-key",
		SecretKey:             "secret-key",
		ExInfo:                map[string]any{"keep": "out"},
	}

	if got := nativeForwardAdmissionRevocationData(nil); got != nil {
		t.Fatalf("nil ResourceData should omit the sidecar, got %+v", got)
	}

	got := nativeForwardAdmissionRevocationData(src)
	if got == nil {
		t.Fatal("nativeForwardAdmissionRevocationData returned nil for populated metadata")
	}
	if got.QurlUserPublicKeyHash != "qhash" ||
		got.ResourcePublicKeyHash != "verified-rhash" ||
		got.QurlSessionId != "sess-live" ||
		got.AdmissionId != "adm-123" ||
		got.Deadline != 1781910300 {
		t.Fatalf("forward metadata = %+v, want only qURL v2 revocation fields", got)
	}
	wire, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal forward revocation data: %v", err)
	}
	for _, leaked := range []string{"app-secret", "access-key", "origin.example", "catalog-carrier-only"} {
		if strings.Contains(string(wire), leaked) {
			t.Fatalf("forward revocation sidecar leaked %q in wire JSON: %s", leaked, wire)
		}
	}

	if empty := nativeForwardAdmissionRevocationData(&common.ResourceData{
		ResourceGroup: common.ResourceGroup{ResourceId: "catalog-only"},
	}); empty != nil {
		t.Fatalf("catalog-only ResourceData should omit the sidecar, got %+v", empty)
	}
	if hashOnly := nativeForwardAdmissionRevocationData(&common.ResourceData{
		ResourcePublicKeyHash: "catalog-rhash",
	}); hashOnly != nil {
		t.Fatalf("resource-hash-only ResourceData should omit the sidecar, got %+v", hashOnly)
	}
}

func TestForwardAdmissionRevocationData_FieldSetMatchesStampedMetadata(t *testing.T) {
	sidecarType := reflect.TypeOf(common.ForwardAdmissionRevocationData{})
	gotFields := make([]string, 0, sidecarType.NumField())
	for i := 0; i < sidecarType.NumField(); i++ {
		gotFields = append(gotFields, sidecarType.Field(i).Name)
	}
	slices.Sort(gotFields)

	wantFields := stampedQurlV2AdmissionFieldNames(t)
	if !slices.Equal(gotFields, wantFields) {
		t.Fatalf("ForwardAdmissionRevocationData fields = %v, want stamped qURL v2 field set %v", gotFields, wantFields)
	}

	acOpsType := reflect.TypeOf(common.ServerACOpsMsg{})
	for _, fieldName := range wantFields {
		sidecarField, _ := sidecarType.FieldByName(fieldName)
		acOpsField, ok := acOpsType.FieldByName(fieldName)
		if !ok {
			t.Fatalf("ServerACOpsMsg missing qURL v2 field %s", fieldName)
		}
		if got, want := jsonTagName(sidecarField), jsonTagName(acOpsField); got != want {
			t.Fatalf("ForwardAdmissionRevocationData.%s json tag = %q, want ServerACOpsMsg tag %q", fieldName, got, want)
		}
		if got, want := sidecarField.Type, acOpsField.Type; got != want {
			t.Fatalf("ForwardAdmissionRevocationData.%s type = %s, want ServerACOpsMsg type %s", fieldName, got, want)
		}
	}

	overlay, resourceHashMismatch := forwardedACOperationResourceData(&common.ResourceData{}, &common.ForwardAdmissionRevocationData{
		QurlUserPublicKeyHash: "qhash",
		ResourcePublicKeyHash: "rhash",
		QurlSessionId:         "sess-live",
		AdmissionId:           "adm-123",
		Deadline:              1781910300,
	})
	if resourceHashMismatch.mismatch {
		t.Fatal("empty receiver catalog should not report a resource hash mismatch")
	}
	aop := &common.ServerACOpsMsg{}
	stampQurlV2RevocationMetadata(aop, overlay)

	if aop.QurlUserPublicKeyHash != "qhash" ||
		aop.ResourcePublicKeyHash != "rhash" ||
		aop.QurlSessionId != "sess-live" ||
		aop.AdmissionId != "adm-123" ||
		aop.Deadline != 1781910300 ||
		aop.RevocationEpoch != 0 {
		t.Fatalf("stamped AOP metadata = %+v, want sidecar field set only", aop)
	}
}

func TestForwardAdmissionRevocationData_RoundTripsStampedFields(t *testing.T) {
	fields := stampedQurlV2AdmissionFieldNames(t)
	src := &common.ResourceData{}
	srcValue := reflect.ValueOf(src).Elem()
	for i, fieldName := range fields {
		if !setSentinelField(t, srcValue.FieldByName(fieldName), fieldName, i) {
			t.Fatalf("could not set sentinel for ResourceData.%s", fieldName)
		}
	}

	sidecar := nativeForwardAdmissionRevocationData(src)
	if sidecar == nil {
		t.Fatal("nativeForwardAdmissionRevocationData omitted populated stamped fields")
	}
	assertFieldValuesMatch(t, sidecar, src, fields)

	overlay, resourceHashMismatch := forwardedACOperationResourceData(&common.ResourceData{}, sidecar)
	if resourceHashMismatch.mismatch {
		t.Fatal("empty receiver catalog should not report a resource hash mismatch")
	}
	assertFieldValuesMatch(t, overlay, sidecar, fields)
}

func stampedQurlV2AdmissionFieldNames(t *testing.T) []string {
	t.Helper()

	res := &common.ResourceData{}
	resValue := reflect.ValueOf(res).Elem()
	resType := resValue.Type()
	acOpsType := reflect.TypeOf(common.ServerACOpsMsg{})

	candidates := make([]string, 0)
	for i := 0; i < resType.NumField(); i++ {
		field := resType.Field(i)
		if _, ok := acOpsType.FieldByName(field.Name); !ok {
			continue
		}
		if setSentinelField(t, resValue.Field(i), field.Name, i) {
			candidates = append(candidates, field.Name)
		}
	}
	if len(candidates) == 0 {
		t.Fatal("no ResourceData/ServerACOpsMsg shared fields available for stamp drift test")
	}

	aop := &common.ServerACOpsMsg{}
	stampQurlV2RevocationMetadata(aop, res)
	aopValue := reflect.ValueOf(aop).Elem()

	fields := make([]string, 0, len(candidates))
	for _, fieldName := range candidates {
		resField := resValue.FieldByName(fieldName)
		aopField := aopValue.FieldByName(fieldName)
		if aopField.IsValid() && reflect.DeepEqual(aopField.Interface(), resField.Interface()) {
			fields = append(fields, fieldName)
		}
	}
	slices.Sort(fields)
	if len(fields) == 0 {
		t.Fatal("stampQurlV2RevocationMetadata stamped no ResourceData-derived qURL v2 fields")
	}
	return fields
}

func setSentinelField(t *testing.T, value reflect.Value, fieldName string, index int) bool {
	t.Helper()
	if !value.CanSet() {
		return false
	}
	setSentinelValue(t, value, fieldName, index)
	return true
}

func setSentinelValue(t *testing.T, value reflect.Value, fieldName string, index int) {
	t.Helper()
	switch value.Kind() {
	case reflect.String:
		value.SetString("sentinel-" + fieldName)
	case reflect.Bool:
		value.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		value.SetInt(int64(1000 + index))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		value.SetUint(uint64(1000 + index))
	case reflect.Float32, reflect.Float64:
		value.SetFloat(float64(1000 + index))
	case reflect.Pointer:
		elem := reflect.New(value.Type().Elem())
		setSentinelValue(t, elem.Elem(), fieldName, index)
		value.Set(elem)
	case reflect.Slice:
		slice := reflect.MakeSlice(value.Type(), 1, 1)
		setSentinelValue(t, slice.Index(0), fieldName, index)
		value.Set(slice)
	case reflect.Array:
		if value.Len() == 0 {
			t.Fatalf("cannot set sentinel for zero-length array ResourceData.%s", fieldName)
		}
		setSentinelValue(t, value.Index(0), fieldName, index)
	default:
		t.Fatalf("unsupported sentinel kind %s for ResourceData.%s; update drift guard before stamping this field", value.Kind(), fieldName)
	}
}

func assertFieldValuesMatch(t *testing.T, got any, want any, fields []string) {
	t.Helper()
	gotValue := reflect.ValueOf(got)
	if gotValue.Kind() == reflect.Pointer {
		if gotValue.IsNil() {
			t.Fatalf("got nil %T", got)
		}
		gotValue = gotValue.Elem()
	}
	wantValue := reflect.ValueOf(want)
	if wantValue.Kind() == reflect.Pointer {
		if wantValue.IsNil() {
			t.Fatalf("want nil %T", want)
		}
		wantValue = wantValue.Elem()
	}

	for _, fieldName := range fields {
		gotField := gotValue.FieldByName(fieldName)
		wantField := wantValue.FieldByName(fieldName)
		if !gotField.IsValid() {
			t.Fatalf("%T missing field %s", got, fieldName)
		}
		if !wantField.IsValid() {
			t.Fatalf("%T missing field %s", want, fieldName)
		}
		if !reflect.DeepEqual(gotField.Interface(), wantField.Interface()) {
			t.Fatalf("%T.%s = %v, want %T.%s = %v", got, fieldName, gotField.Interface(), want, fieldName, wantField.Interface())
		}
	}
}

func jsonTagName(field reflect.StructField) string {
	name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
	return name
}

func TestForwardedACOperationResourceData_OverlaysAdmissionMetadata(t *testing.T) {
	catalog := &common.ResourceData{
		ResourceGroup: common.ResourceGroup{
			AuthServiceId: "qurl",
			ResourceId:    "res-catalog",
			OpenTime:      30,
			Resources: map[string]*common.ResourceInfo{
				"res-catalog": {
					ACId: "ac-catalog",
					Addr: &common.NetAddress{Ip: "10.0.0.5", Port: 443},
				},
			},
		},
		ResourcePublicKeyHash: "catalog-rhash",
	}
	admission := &common.ForwardAdmissionRevocationData{
		ResourcePublicKeyHash: "verified-rhash",
		QurlUserPublicKeyHash: "qhash",
		QurlSessionId:         "sess-live",
		AdmissionId:           "adm-123",
		Deadline:              1781910300,
	}

	got, resourceHashMismatch := forwardedACOperationResourceData(catalog, nil)
	if got != catalog {
		t.Fatalf("nil admission sidecar should preserve legacy catalog pointer, got %p want %p", got, catalog)
	}
	if resourceHashMismatch.mismatch {
		t.Fatal("nil admission sidecar should not report a resource hash mismatch")
	}
	got, resourceHashMismatch = forwardedACOperationResourceData(catalog, &common.ForwardAdmissionRevocationData{})
	if got != catalog {
		t.Fatalf("empty admission sidecar should preserve legacy catalog pointer, got %p want %p", got, catalog)
	}
	if resourceHashMismatch.mismatch {
		t.Fatal("empty admission sidecar should not report a resource hash mismatch")
	}
	got, resourceHashMismatch = forwardedACOperationResourceData(catalog, &common.ForwardAdmissionRevocationData{
		ResourcePublicKeyHash: "crafted-rhash",
	})
	if got != catalog {
		t.Fatalf("hash-only admission sidecar should be ignored as legacy metadata, got %p want %p", got, catalog)
	}
	if resourceHashMismatch.mismatch {
		t.Fatal("hash-only admission sidecar should not report a resource hash mismatch")
	}

	got, resourceHashMismatch = forwardedACOperationResourceData(catalog, admission)
	if got == nil {
		t.Fatal("forwardedACOperationResourceData returned nil")
	}
	if !resourceHashMismatch.mismatch {
		t.Fatal("different populated catalog and admission resource hashes should report a mismatch")
	}
	if resourceHashMismatch.catalogHash != "catalog-rhash" || resourceHashMismatch.admissionHash != "verified-rhash" {
		t.Fatalf("resource hash mismatch decision = %+v, want catalog/admission hashes", resourceHashMismatch)
	}
	if got.OpenTime != 30 || got.AuthServiceId != "qurl" || got.ResourceId != "res-catalog" {
		t.Fatalf("catalog routing fields changed: %+v", got.ResourceGroup)
	}
	info := got.Resources["res-catalog"]
	if info == nil || info.ACId != "ac-catalog" || info.Addr == nil || info.Addr.Ip != "10.0.0.5" || info.Addr.Port != 443 {
		t.Fatalf("catalog resource info was not preserved: %+v", got.Resources)
	}
	if got.QurlUserPublicKeyHash != "qhash" ||
		got.ResourcePublicKeyHash != "catalog-rhash" ||
		got.QurlSessionId != "sess-live" ||
		got.AdmissionId != "adm-123" ||
		got.Deadline != 1781910300 {
		t.Fatalf("admission metadata was not overlaid: %+v", got)
	}

	catalogWithoutResourceHash := cloneResourceData(catalog)
	catalogWithoutResourceHash.ResourcePublicKeyHash = ""
	filled, resourceHashMismatch := forwardedACOperationResourceData(catalogWithoutResourceHash, admission)
	if resourceHashMismatch.mismatch {
		t.Fatal("missing receiver catalog hash should be filled, not reported as a mismatch")
	}
	if filled.ResourcePublicKeyHash != "verified-rhash" {
		t.Fatalf("missing catalog resource hash was not filled from admission sidecar: %+v", filled)
	}
}

func TestNativeForwardResolvedResourceData_RoutingAndProtectedSubjectOnly(t *testing.T) {
	src := &common.ResourceData{
		ResourceGroup: common.ResourceGroup{
			AuthServiceId:     "qurl",
			ResourceId:        "q_123456789ab",
			OpenTime:          300,
			AuthProviderToken: "must-not-cross",
			Resources: map[string]*common.ResourceInfo{
				"ac-a": {
					ACId:     "ac-a",
					Hostname: "resource.example",
					Addr: &common.NetAddress{
						Ip:       "",
						Port:     443,
						Protocol: "tcp",
					},
				},
			},
		},
		AppSecret:             "must-not-cross",
		SecretKey:             "must-not-cross",
		ExInfo:                map[string]any{"jwt_secret": "must-not-cross"},
		RedirectUrl:           "https://resource.example",
		ResourcePublicKeyB64:  testProtectedResourceID,
		ResourcePublicKeyHash: "rhash",
		QurlUserPublicKeyHash: "qhash",
		AdmissionId:           "adm-123",
	}

	got := nativeForwardResolvedResourceData(src)
	if got == nil {
		t.Fatal("nativeForwardResolvedResourceData returned nil")
	}
	if got.AuthServiceId != "qurl" || got.ResourceId != "q_123456789ab" || got.OpenTime != 300 || got.ResourcePublicKeyB64 != testProtectedResourceID || got.ResourcePublicKeyHash != "rhash" {
		t.Fatalf("resolved route = %+v, want routing scalars plus canonical public resource identity/hash", got)
	}
	if len(got.Resources) != 1 || got.Resources["ac-a"] == nil || got.Resources["ac-a"].Addr == nil {
		t.Fatalf("resolved route resources not copied: %+v", got.Resources)
	}
	src.Resources["ac-a"].Addr.Port = 8443
	if got.Resources["ac-a"].Addr.Port != 443 {
		t.Fatal("resolved route resources alias source ResourceData")
	}

	if got := nativeForwardResolvedResourceData(&common.ResourceData{
		ResourceGroup: common.ResourceGroup{AuthServiceId: "qurl", ResourceId: "q_123456789ab"},
	}); got != nil {
		t.Fatalf("catalog without Resources should omit resolved route, got %+v", got)
	}
}

func TestForwardedResolvedResourceData_BindsQurlV2ResourceIdentity(t *testing.T) {
	resourceKeyB64 := base64.RawURLEncoding.EncodeToString([]byte("resource-key-identity"))
	resourceHash, err := qurlv2.PublicKeyHashFromB64(resourceKeyB64)
	if err != nil {
		t.Fatalf("hash resource key: %v", err)
	}
	route := &common.ForwardResolvedResourceData{
		AuthServiceId:         "qurl",
		ResourceId:            "q_123456789ab",
		OpenTime:              300,
		ResourcePublicKeyHash: resourceHash,
		Resources: map[string]*common.ResourceInfo{
			"ac-a": {
				ACId: "ac-a",
				Addr: &common.NetAddress{Port: 443, Protocol: "tcp"},
			},
		},
	}
	knock := &common.AgentKnockMsg{AuthServiceId: "qurl", ResourceId: resourceKeyB64}

	got, err := forwardedResolvedResourceData(route, nil, knock)
	if err != nil {
		t.Fatalf("forwardedResolvedResourceData returned error: %v", err)
	}
	if got.ResourceId != "q_123456789ab" || got.ResourcePublicKeyHash != resourceHash || got.OpenTime != 300 {
		t.Fatalf("resolved fallback ResourceData = %+v", got)
	}

	badRoute := *route
	badRoute.ResourcePublicKeyHash = "not-the-knock-hash"
	if _, err := forwardedResolvedResourceData(&badRoute, nil, knock); err == nil {
		t.Fatal("expected resource-hash mismatch to reject forwarded route")
	}

	noHashRoute := *route
	noHashRoute.ResourcePublicKeyHash = ""
	if _, err := forwardedResolvedResourceData(&noHashRoute, nil, knock); err == nil {
		t.Fatal("expected differing resource ids without a hash to reject forwarded route")
	}
}

func TestHandleDecryptedForwardedKnock_CarriesAdmissionMetadata(t *testing.T) {
	baseDeps := NewMockForwarderDeps()
	baseDeps.SetAuthServiceProvider(&common.AuthServiceProviderData{
		AuthSvcId: "qurl",
		ResourceGroups: common.ResourceGroupMap{
			"res-catalog": {
				ResourceGroup: common.ResourceGroup{
					AuthServiceId: "qurl",
					ResourceId:    "res-catalog",
					OpenTime:      30,
					Resources: map[string]*common.ResourceInfo{
						"res-catalog": {
							ACId:     "ac-catalog",
							Hostname: "resource.example",
							Addr: &common.NetAddress{
								Ip:       "10.0.0.5",
								Port:     443,
								Protocol: "tcp",
							},
						},
					},
				},
				ResourcePublicKeyHash: "catalog-rhash",
			},
		},
	})
	baseDeps.SetACConnection(&ACConn{})
	deps := &captureBroadcastForwarderDeps{MockForwarderDeps: baseDeps}
	forwarder := NewServerForwarder(deps)

	knockMsg := &common.AgentKnockMsg{
		HeaderType:    core.NHP_KNK,
		UserId:        "user-1",
		DeviceId:      "device-1",
		AuthServiceId: "qurl",
		ResourceId:    "res-catalog",
	}
	body, err := json.Marshal(knockMsg)
	if err != nil {
		t.Fatalf("marshal knock: %v", err)
	}
	fwdMsg := &common.ServerForwardMsg{
		SessionId:            1,
		SessionIssuedAtNanos: time.Now().UnixNano(),
		SourceServer:         "srv-origin",
		UserAddr:             "203.0.113.10:54321",
		TransactionId:        77,
		Timestamp:            time.Now().Unix(),
		AdmissionRevocationData: &common.ForwardAdmissionRevocationData{
			QurlUserPublicKeyHash: "qhash",
			ResourcePublicKeyHash: "verified-rhash",
			QurlSessionId:         "sess-live",
			AdmissionId:           "adm-123",
			Deadline:              1781910300,
		},
	}
	userAddr, err := net.ResolveUDPAddr("udp", fwdMsg.UserAddr)
	if err != nil {
		t.Fatalf("resolve user addr: %v", err)
	}

	forwarder.handleDecryptedForwardedKnock(nil, fwdMsg, userAddr, &core.PacketParserData{
		BodyMessage:  body,
		RemotePubKey: make([]byte, 32),
	})

	got := deps.capturedResource
	if got == nil {
		t.Fatal("forward receiver did not call ProcessACOperationBroadcast")
	}
	if got.OpenTime != 30 || got.AuthServiceId != "qurl" || got.ResourceId != "res-catalog" {
		t.Fatalf("receiver must keep catalog routing/openTime fields, got %+v", got.ResourceGroup)
	}
	info := got.Resources["res-catalog"]
	if info == nil || info.ACId != "ac-catalog" || info.Addr == nil || info.Addr.Ip != "10.0.0.5" || info.Addr.Port != 443 {
		t.Fatalf("receiver catalog Resources were not preserved: %+v", got.Resources)
	}
	if got.QurlUserPublicKeyHash != "qhash" ||
		got.ResourcePublicKeyHash != "catalog-rhash" ||
		got.QurlSessionId != "sess-live" ||
		got.AdmissionId != "adm-123" ||
		got.Deadline != 1781910300 {
		t.Fatalf("forwarded admission metadata missing from AC operation ResourceData: %+v", got)
	}
	if deps.capturedOpenTime != 30 {
		t.Fatalf("openTime = %d, want receiver catalog openTime 30", deps.capturedOpenTime)
	}
	if got := baseDeps.MetricCount(MetricForwardAdmissionResourceHashMismatch); got != 1 {
		t.Fatalf("%s = %d, want 1 for sidecar/catalog resource-hash mismatch",
			MetricForwardAdmissionResourceHashMismatch, got)
	}

	select {
	case msg := <-baseDeps.GetSendChannel():
		var result common.ServerForwardResultMsg
		if err := json.Unmarshal(msg.Message, &result); err != nil {
			t.Fatalf("parse forward result: %v", err)
		}
		if !result.Success {
			t.Fatalf("forward result failed: %+v", result)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for forward result")
	}
}

func TestHandleDecryptedForwardedKnock_UsesResolvedResourceFallbackForQurlV2(t *testing.T) {
	resourceKeyB64 := base64.RawURLEncoding.EncodeToString([]byte("resource-key-identity"))
	resourceHash, err := qurlv2.PublicKeyHashFromB64(resourceKeyB64)
	if err != nil {
		t.Fatalf("hash resource key: %v", err)
	}

	baseDeps := NewMockForwarderDeps()
	baseDeps.SetAuthServiceProvider(&common.AuthServiceProviderData{
		AuthSvcId:      "qurl",
		ResourceGroups: common.ResourceGroupMap{},
	})
	baseDeps.SetACConnection(&ACConn{})
	deps := &captureBroadcastForwarderDeps{MockForwarderDeps: baseDeps}
	forwarder := NewServerForwarder(deps)

	knockMsg := &common.AgentKnockMsg{
		HeaderType:    core.NHP_KNK,
		UserId:        "user-1",
		DeviceId:      "device-1",
		AuthServiceId: "qurl",
		ResourceId:    resourceKeyB64,
	}
	body, err := json.Marshal(knockMsg)
	if err != nil {
		t.Fatalf("marshal knock: %v", err)
	}
	fwdMsg := &common.ServerForwardMsg{
		SessionId:            1,
		SessionIssuedAtNanos: time.Now().UnixNano(),
		SourceServer:         "srv-origin",
		UserAddr:             "203.0.113.10:54321",
		TransactionId:        77,
		Timestamp:            time.Now().Unix(),
		AdmissionRevocationData: &common.ForwardAdmissionRevocationData{
			QurlUserPublicKeyHash: "qhash",
			ResourcePublicKeyHash: resourceHash,
			AdmissionId:           "adm-123",
			Deadline:              1781910300,
		},
		ResolvedResourceData: &common.ForwardResolvedResourceData{
			AuthServiceId:         "qurl",
			ResourceId:            "q_123456789ab",
			OpenTime:              300,
			ResourcePublicKeyHash: resourceHash,
			Resources: map[string]*common.ResourceInfo{
				"ac-a": {
					ACId:     "ac-a",
					Hostname: "resource.example",
					Addr: &common.NetAddress{
						Port:     443,
						Protocol: "tcp",
					},
				},
			},
		},
	}
	userAddr, err := net.ResolveUDPAddr("udp", fwdMsg.UserAddr)
	if err != nil {
		t.Fatalf("resolve user addr: %v", err)
	}

	forwarder.handleDecryptedForwardedKnock(nil, fwdMsg, userAddr, &core.PacketParserData{
		BodyMessage:  body,
		RemotePubKey: make([]byte, 32),
	})

	got := deps.capturedResource
	if got == nil {
		t.Fatal("forward receiver did not call ProcessACOperationBroadcast")
	}
	if got.AuthServiceId != "qurl" || got.ResourceId != "q_123456789ab" || got.OpenTime != 300 {
		t.Fatalf("fallback ResourceData routing fields = %+v", got.ResourceGroup)
	}
	info := got.Resources["ac-a"]
	if info == nil || info.ACId != "ac-a" || info.Hostname != "resource.example" || info.Addr == nil || info.Addr.Port != 443 {
		t.Fatalf("fallback ResourceData resource info = %+v", got.Resources)
	}
	if got.ResourcePublicKeyHash != resourceHash ||
		got.QurlUserPublicKeyHash != "qhash" ||
		got.AdmissionId != "adm-123" ||
		got.Deadline != 1781910300 {
		t.Fatalf("fallback ResourceData admission metadata = %+v", got)
	}
	if deps.capturedOpenTime != 300 {
		t.Fatalf("openTime = %d, want forwarded resolved route openTime 300", deps.capturedOpenTime)
	}
	if got := baseDeps.MetricCount(MetricForwardResolvedResourceFallback); got != 1 {
		t.Fatalf("%s = %d, want 1", MetricForwardResolvedResourceFallback, got)
	}

	select {
	case msg := <-baseDeps.GetSendChannel():
		var result common.ServerForwardResultMsg
		if err := json.Unmarshal(msg.Message, &result); err != nil {
			t.Fatalf("parse forward result: %v", err)
		}
		if !result.Success {
			t.Fatalf("forward result failed: %+v", result)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for forward result")
	}
}

func TestHandleDecryptedForwardedKnock_ResourceHashMismatchMetricNegativeCases(t *testing.T) {
	knockMsg := &common.AgentKnockMsg{
		HeaderType:    core.NHP_KNK,
		UserId:        "user-1",
		DeviceId:      "device-1",
		AuthServiceId: "qurl",
		ResourceId:    "res-catalog",
	}
	body, err := json.Marshal(knockMsg)
	if err != nil {
		t.Fatalf("marshal knock: %v", err)
	}

	for _, tc := range []struct {
		name             string
		catalogHash      string
		admissionHash    string
		wantResourceHash string
	}{
		{
			name:             "matching catalog and admission hashes",
			catalogHash:      "verified-rhash",
			admissionHash:    "verified-rhash",
			wantResourceHash: "verified-rhash",
		},
		{
			name:             "missing catalog hash filled from admission",
			catalogHash:      "",
			admissionHash:    "verified-rhash",
			wantResourceHash: "verified-rhash",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			baseDeps := NewMockForwarderDeps()
			baseDeps.SetAuthServiceProvider(&common.AuthServiceProviderData{
				AuthSvcId: "qurl",
				ResourceGroups: common.ResourceGroupMap{
					"res-catalog": {
						ResourceGroup: common.ResourceGroup{
							AuthServiceId: "qurl",
							ResourceId:    "res-catalog",
							OpenTime:      30,
							Resources: map[string]*common.ResourceInfo{
								"res-catalog": {
									ACId: "ac-catalog",
									Addr: &common.NetAddress{
										Ip:       "10.0.0.5",
										Port:     443,
										Protocol: "tcp",
									},
								},
							},
						},
						ResourcePublicKeyHash: tc.catalogHash,
					},
				},
			})
			baseDeps.SetACConnection(&ACConn{})
			deps := &captureBroadcastForwarderDeps{MockForwarderDeps: baseDeps}
			forwarder := NewServerForwarder(deps)

			fwdMsg := &common.ServerForwardMsg{
				SessionId:            1,
				SessionIssuedAtNanos: time.Now().UnixNano(),
				SourceServer:         "srv-origin",
				UserAddr:             "203.0.113.10:54321",
				TransactionId:        77,
				Timestamp:            time.Now().Unix(),
				AdmissionRevocationData: &common.ForwardAdmissionRevocationData{
					QurlUserPublicKeyHash: "qhash",
					ResourcePublicKeyHash: tc.admissionHash,
					QurlSessionId:         "sess-live",
					AdmissionId:           "adm-123",
					Deadline:              1781910300,
				},
			}
			userAddr, err := net.ResolveUDPAddr("udp", fwdMsg.UserAddr)
			if err != nil {
				t.Fatalf("resolve user addr: %v", err)
			}

			forwarder.handleDecryptedForwardedKnock(nil, fwdMsg, userAddr, &core.PacketParserData{
				BodyMessage:  body,
				RemotePubKey: make([]byte, 32),
			})

			if got := baseDeps.MetricCount(MetricForwardAdmissionResourceHashMismatch); got != 0 {
				t.Fatalf("%s = %d, want 0", MetricForwardAdmissionResourceHashMismatch, got)
			}
			if deps.capturedResource == nil {
				t.Fatal("forward receiver did not call ProcessACOperationBroadcast")
			}
			if got := deps.capturedResource.ResourcePublicKeyHash; got != tc.wantResourceHash {
				t.Fatalf("ResourcePublicKeyHash = %q, want %q", got, tc.wantResourceHash)
			}
		})
	}
}

// ============================================================================
// ServerHealthTracker Tests
// ============================================================================

func TestServerHealthTracker_InitialState(t *testing.T) {
	tracker := NewServerHealthTracker()

	// All servers should be healthy initially
	if tracker.IsUnhealthy("srv-1") {
		t.Error("Expected server to be healthy initially")
	}
}

func TestServerHealthTracker_RecordFailure(t *testing.T) {
	tracker := NewServerHealthTracker()

	tracker.RecordFailure("srv-1")

	if !tracker.IsUnhealthy("srv-1") {
		t.Error("Expected server to be unhealthy after failure")
	}
}

func TestServerHealthTracker_RecordNoResponseThreshold(t *testing.T) {
	tracker := NewServerHealthTracker()

	if tracker.RecordNoResponse("srv-1") {
		t.Fatal("first no-response should not mark server unhealthy")
	}
	if tracker.IsUnhealthy("srv-1") {
		t.Fatal("server should stay healthy after one no-response")
	}
	if !tracker.RecordNoResponse("srv-1") {
		t.Fatal("second consecutive no-response should mark server unhealthy")
	}
	if !tracker.IsUnhealthy("srv-1") {
		t.Fatal("server should be unhealthy after no-response threshold")
	}

	tracker.RecordSuccess("srv-1")
	if tracker.IsUnhealthy("srv-1") {
		t.Fatal("success should clear no-response unhealthy state")
	}
	if tracker.RecordNoResponse("srv-1") {
		t.Fatal("success should reset no-response counter")
	}
}

func TestServerHealthTracker_ClearNoResponsePreservesFailure(t *testing.T) {
	tracker := NewServerHealthTracker()

	if tracker.RecordNoResponse("srv-1") {
		t.Fatal("first no-response should not mark server unhealthy")
	}
	tracker.ClearNoResponse("srv-1")
	if tracker.RecordNoResponse("srv-1") {
		t.Fatal("ClearNoResponse should reset no-response counter")
	}

	tracker.RecordFailure("srv-1")
	tracker.ClearNoResponse("srv-1")
	if !tracker.IsUnhealthy("srv-1") {
		t.Fatal("ClearNoResponse should not clear hard failure state")
	}
}

func TestServerHealthTracker_RecordSuccess(t *testing.T) {
	tracker := NewServerHealthTracker()

	// Record failure then success
	tracker.RecordFailure("srv-1")
	if !tracker.IsUnhealthy("srv-1") {
		t.Fatal("Expected server to be unhealthy after failure")
	}

	tracker.RecordSuccess("srv-1")
	if tracker.IsUnhealthy("srv-1") {
		t.Error("Expected server to be healthy after success")
	}
}

func TestServerHealthTracker_HealthDecay(t *testing.T) {
	// Create tracker and record failure
	tracker := NewServerHealthTracker()
	tracker.RecordFailure("srv-decay")

	if !tracker.IsUnhealthy("srv-decay") {
		t.Fatal("Expected server to be unhealthy immediately after failure")
	}

	// Manually set failure time to past (simulating decay)
	tracker.mu.Lock()
	tracker.failures["srv-decay"] = time.Now().Add(-HealthDecayDuration - time.Second)
	tracker.mu.Unlock()

	// Should be healthy now (decay expired)
	if tracker.IsUnhealthy("srv-decay") {
		t.Error("Expected server to be healthy after decay period")
	}
}

func TestServerHealthTracker_ConcurrentAccess(t *testing.T) {
	tracker := NewServerHealthTracker()

	var wg sync.WaitGroup
	goroutines := 10
	iterations := 100

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			serverID := "srv-concurrent-" + string(rune('A'+gid%5))

			for i := 0; i < iterations; i++ {
				switch i % 3 {
				case 0:
					tracker.RecordFailure(serverID)
				case 1:
					tracker.RecordSuccess(serverID)
				case 2:
					tracker.IsUnhealthy(serverID)
				}
			}
		}(g)
	}

	wg.Wait()
	// If we get here without panic/race, the test passes
}

// ============================================================================
// ServerForwarder Tests
// ============================================================================

func TestServerForwarder_NextTransactionID(t *testing.T) {
	// Test sequential ID generation (IDs should increment by 1)
	forwarder := &ServerForwarder{
		health:      NewServerHealthTracker(),
		pendingFwds: make(map[uint64]*PendingForward),
		serverPeers: make(map[string]*core.UdpPeer),
		nextTxID:    1000, // Start with known value
	}

	id1 := forwarder.nextTransactionID()
	id2 := forwarder.nextTransactionID()
	id3 := forwarder.nextTransactionID()

	if id1 != 1001 {
		t.Errorf("Expected first ID to be 1001, got %d", id1)
	}
	if id2 != 1002 {
		t.Errorf("Expected second ID to be 1002, got %d", id2)
	}
	if id3 != 1003 {
		t.Errorf("Expected third ID to be 1003, got %d", id3)
	}
}

func TestServerForwarder_EntropyInitialization(t *testing.T) {
	// Test that NewServerForwarder initializes with entropy (non-zero, unpredictable)
	forwarder1 := NewServerForwarder(nil)
	forwarder2 := NewServerForwarder(nil)

	// Both should have non-zero initial IDs
	if forwarder1.nextTxID == 0 {
		t.Error("Expected forwarder1 to have non-zero initial txID")
	}
	if forwarder2.nextTxID == 0 {
		t.Error("Expected forwarder2 to have non-zero initial txID")
	}

	// The two forwarders should have different initial IDs (extremely unlikely to collide)
	if forwarder1.nextTxID == forwarder2.nextTxID {
		t.Error("Expected forwarders to have different initial txIDs")
	}
}

func TestServerForwarder_CleanupPendingForwards(t *testing.T) {
	forwarder := &ServerForwarder{
		health:      NewServerHealthTracker(),
		pendingFwds: make(map[uint64]*PendingForward),
		serverPeers: make(map[string]*core.UdpPeer),
	}

	// Add some pending forwards
	now := time.Now()

	// Fresh pending - should be kept
	forwarder.pendingFwds[1] = &PendingForward{
		TransactionID: 1,
		CreatedAt:     now,
	}

	// Old pending - should be cleaned up
	forwarder.pendingFwds[2] = &PendingForward{
		TransactionID: 2,
		CreatedAt:     now.Add(-ForwardTimeout * 3), // Well past timeout
	}

	// Run cleanup
	forwarder.CleanupPendingForwards()

	// Check results
	if _, exists := forwarder.pendingFwds[1]; !exists {
		t.Error("Expected fresh pending forward to be kept")
	}
	if _, exists := forwarder.pendingFwds[2]; exists {
		t.Error("Expected old pending forward to be cleaned up")
	}
}

func TestServerForwarder_ConcurrentTransactionIDs(t *testing.T) {
	forwarder := &ServerForwarder{
		health:      NewServerHealthTracker(),
		pendingFwds: make(map[uint64]*PendingForward),
		serverPeers: make(map[string]*core.UdpPeer),
	}

	var wg sync.WaitGroup
	goroutines := 10
	idsPerGoroutine := 100

	allIDs := make(chan uint64, goroutines*idsPerGoroutine)

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < idsPerGoroutine; i++ {
				id := forwarder.nextTransactionID()
				allIDs <- id
			}
		}()
	}

	wg.Wait()
	close(allIDs)

	// Collect all IDs and check for uniqueness
	seen := make(map[uint64]bool)
	for id := range allIDs {
		if seen[id] {
			t.Errorf("Duplicate transaction ID generated: %d", id)
		}
		seen[id] = true
	}

	expectedCount := goroutines * idsPerGoroutine
	if len(seen) != expectedCount {
		t.Errorf("Expected %d unique IDs, got %d", expectedCount, len(seen))
	}
}

// ============================================================================
// PendingForward Tests
// ============================================================================

func TestPendingForward_Creation(t *testing.T) {
	pending := &PendingForward{
		TransactionID: 12345,
		ResponseCh:    make(chan *common.ServerForwardResultMsg, 1),
		CreatedAt:     time.Now(),
	}

	if pending.TransactionID != 12345 {
		t.Errorf("Expected TransactionID 12345, got %d", pending.TransactionID)
	}
	if pending.ResponseCh == nil {
		t.Error("Expected ResponseCh to be non-nil")
	}
}

// ============================================================================
// ForwardKnock Tests with MemoryStorage
// ============================================================================

func TestForwardKnock_NoAssignedServers(t *testing.T) {
	forwarder := &ServerForwarder{
		health:      NewServerHealthTracker(),
		pendingFwds: make(map[uint64]*PendingForward),
		serverPeers: make(map[string]*core.UdpPeer),
		nextTxID:    1000,
	}

	// Empty assignment
	assignment := &ACAssignment{
		ACID:            "ac-empty",
		AssignedServers: []ServerInfo{},
	}

	ctx := context.Background()
	_, err := forwarder.ForwardKnock(ctx, assignment, []byte("knock"), nil, nil)
	if err == nil {
		t.Fatal("Expected error for empty assigned servers")
	}
	if err.Error() != "no assigned servers for AC" {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestForwardKnock_SkipsUnhealthyServersWhenHealthyTargetsRemain(t *testing.T) {
	testPrivateKey := make([]byte, 32)
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_SERVER, testPrivateKey, nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}
	defer device.Stop()

	baseDeps := NewMockForwarderDeps()
	baseDeps.SetDevice(device)
	sent := make(chan *core.MsgData, 3)
	deps := &captureSendForwarderDeps{
		MockForwarderDeps: baseDeps,
		sent:              sent,
	}
	forwarder := NewServerForwarder(deps)
	forwarder.health.RecordFailure("srv-a")
	assignment := &ACAssignment{
		ACID: "ac-skip-unhealthy",
		AssignedServers: []ServerInfo{
			{ID: "srv-a", InternalIP: "10.0.0.71", Port: common.DefaultNHPPort, PubKey: device.PublicKeyBase64()},
			{ID: "srv-b", InternalIP: "10.0.0.72", Port: common.DefaultNHPPort, PubKey: device.PublicKeyBase64()},
			{ID: "srv-c", InternalIP: "10.0.0.73", Port: common.DefaultNHPPort, PubKey: device.PublicKeyBase64()},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := forwarder.ForwardKnock(
			ctx,
			assignment,
			[]byte("knock"),
			&net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 54321},
			nil,
		)
		done <- err
	}()

	forwarded := collectForwardedMsgData(t, sent, 2)
	assertForwardedRemoteIPs(t, forwarded, []string{"10.0.0.72", "10.0.0.73"})

	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("ForwardKnock error = %v, want context deadline exceeded", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for ForwardKnock skip-unhealthy attempt")
	}
}

func TestForwardKnock_AllUnhealthyServersStillAttempted(t *testing.T) {
	testPrivateKey := make([]byte, 32)
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_SERVER, testPrivateKey, nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}
	defer device.Stop()

	baseDeps := NewMockForwarderDeps()
	baseDeps.SetDevice(device)
	sent := make(chan *core.MsgData, 3)
	deps := &captureSendForwarderDeps{
		MockForwarderDeps: baseDeps,
		sent:              sent,
	}
	forwarder := NewServerForwarder(deps)
	assignment := &ACAssignment{
		ACID: "ac-all-unhealthy",
		AssignedServers: []ServerInfo{
			{ID: "srv-a", InternalIP: "10.0.0.74", Port: common.DefaultNHPPort, PubKey: device.PublicKeyBase64()},
			{ID: "srv-b", InternalIP: "10.0.0.75", Port: common.DefaultNHPPort, PubKey: device.PublicKeyBase64()},
			{ID: "srv-c", InternalIP: "10.0.0.76", Port: common.DefaultNHPPort, PubKey: device.PublicKeyBase64()},
		},
	}
	for _, target := range assignment.AssignedServers {
		forwarder.health.RecordFailure(target.ID)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := forwarder.ForwardKnock(
			ctx,
			assignment,
			[]byte("knock"),
			&net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 54321},
			nil,
		)
		done <- err
	}()

	forwarded := collectForwardedMsgData(t, sent, 3)
	assertForwardedRemoteIPs(t, forwarded, []string{"10.0.0.74", "10.0.0.75", "10.0.0.76"})

	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("ForwardKnock error = %v, want context deadline exceeded", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for ForwardKnock all-unhealthy fallback")
	}
}

func TestForwardKnock_SendFailureReturnsImmediately(t *testing.T) {
	testPrivateKey := make([]byte, 32)
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_SERVER, testPrivateKey, nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}
	defer device.Stop()

	baseDeps := NewMockForwarderDeps()
	baseDeps.SetDevice(device)
	deps := &captureSendForwarderDeps{
		MockForwarderDeps: baseDeps,
		err:               errors.New("prequeue drop"),
	}
	forwarder := NewServerForwarder(deps)
	assignment := &ACAssignment{
		ACID: "ac-send-fail",
		AssignedServers: []ServerInfo{
			{
				ID:         "srv-send-fail",
				InternalIP: "10.0.0.50",
				Port:       common.DefaultNHPPort,
				PubKey:     device.PublicKeyBase64(),
			},
		},
	}

	start := time.Now()
	_, err := forwarder.ForwardKnock(
		context.Background(),
		assignment,
		[]byte("knock"),
		&net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 54321},
		nil,
	)

	if err == nil {
		t.Fatal("ForwardKnock returned nil error, want send failure")
	}
	if !strings.Contains(err.Error(), "forward send failed: prequeue drop") {
		t.Fatalf("ForwardKnock error = %q, want prequeue send failure", err)
	}
	if elapsed := time.Since(start); elapsed >= ForwardTimeout/2 {
		t.Fatalf("ForwardKnock waited %v after immediate send failure, want less than %v", elapsed, ForwardTimeout/2)
	}
	if forwarder.health.IsUnhealthy("srv-send-fail") {
		t.Fatal("local send failure marked remote server unhealthy")
	}
}

func TestForwardKnock_PendingBackpressureDoesNotPoisonPeerHealth(t *testing.T) {
	testPrivateKey := make([]byte, 32)
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_SERVER, testPrivateKey, nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}
	defer device.Stop()

	baseDeps := NewMockForwarderDeps()
	baseDeps.SetDevice(device)
	forwarder := NewServerForwarder(baseDeps)
	for i := 0; i < MaxPendingForwards; i++ {
		forwarder.pendingFwds[uint64(i+1)] = &PendingForward{TransactionID: uint64(i + 1)}
	}

	assignment := &ACAssignment{
		ACID: "ac-backpressure",
		AssignedServers: []ServerInfo{
			{
				ID:         "srv-backpressure",
				InternalIP: "10.0.0.55",
				Port:       common.DefaultNHPPort,
				PubKey:     device.PublicKeyBase64(),
			},
		},
	}

	_, err := forwarder.ForwardKnock(
		context.Background(),
		assignment,
		[]byte("knock"),
		&net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 54321},
		nil,
	)
	if err == nil {
		t.Fatal("ForwardKnock returned nil error, want pending-forward backpressure")
	}
	if !strings.Contains(err.Error(), "too many pending forwards") {
		t.Fatalf("ForwardKnock error = %q, want pending-forward backpressure", err)
	}
	if forwarder.health.IsUnhealthy("srv-backpressure") {
		t.Fatal("local pending-forward backpressure marked remote server unhealthy")
	}
}

func TestForwardKnock_CarriesAdmissionRevocationData(t *testing.T) {
	testPrivateKey := make([]byte, 32)
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_SERVER, testPrivateKey, nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}
	defer device.Stop()

	baseDeps := NewMockForwarderDeps()
	baseDeps.SetDevice(device)
	sent := make(chan *core.MsgData, 1)
	deps := &captureSendForwarderDeps{
		MockForwarderDeps: baseDeps,
		sent:              sent,
	}
	forwarder := NewServerForwarder(deps)
	assignment := &ACAssignment{
		ACID: "ac-forward",
		AssignedServers: []ServerInfo{
			{
				ID:         "srv-forward-peer",
				InternalIP: "10.0.0.61",
				Port:       common.DefaultNHPPort,
				PubKey:     device.PublicKeyBase64(),
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan forwardKnockOutcome, 1)
	go func() {
		result, err := forwarder.ForwardKnock(
			ctx,
			assignment,
			[]byte("knock"),
			&net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 54321},
			&common.ResourceData{
				ResourceGroup: common.ResourceGroup{
					AuthServiceId: "qurl",
					ResourceId:    "q_123456789ab",
					OpenTime:      300,
					Resources: map[string]*common.ResourceInfo{
						"ac-a": {
							ACId: "ac-a",
							Addr: &common.NetAddress{Port: 443, Protocol: "tcp"},
						},
					},
				},
				QurlUserPublicKeyHash: "qhash",
				ResourcePublicKeyHash: "verified-rhash",
				QurlSessionId:         "sess-live",
				AdmissionId:           "adm-123",
				Deadline:              1781910300,
			},
		)
		done <- forwardKnockOutcome{result: result, err: err}
	}()

	var fwdMsg common.ServerForwardMsg
	select {
	case md := <-sent:
		if md.HeaderType != core.NHP_FWD {
			t.Fatalf("HeaderType=%s, want NHP_FWD", core.HeaderTypeToString(md.HeaderType))
		}
		if err := json.Unmarshal(md.Message, &fwdMsg); err != nil {
			t.Fatalf("unmarshal first-success forward message: %v", err)
		}
		got := fwdMsg.AdmissionRevocationData
		if got == nil {
			t.Fatal("ForwardKnock omitted admission revocation sidecar")
		}
		if got.QurlUserPublicKeyHash != "qhash" ||
			got.ResourcePublicKeyHash != "verified-rhash" ||
			got.QurlSessionId != "sess-live" ||
			got.AdmissionId != "adm-123" ||
			got.Deadline != 1781910300 {
			t.Fatalf("forward admission revocation data = %+v, want origin admission metadata", got)
		}
		route := fwdMsg.ResolvedResourceData
		if route == nil {
			t.Fatal("ForwardKnock omitted resolved resource route")
		}
		if route.AuthServiceId != "qurl" || route.ResourceId != "q_123456789ab" || route.OpenTime != 300 || route.ResourcePublicKeyHash != "verified-rhash" {
			t.Fatalf("forward resolved resource route = %+v, want origin routing snapshot", route)
		}
		if route.Resources["ac-a"] == nil || route.Resources["ac-a"].Addr == nil || route.Resources["ac-a"].Addr.Port != 443 {
			t.Fatalf("forward resolved resource route resources = %+v", route.Resources)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for ForwardKnock send")
	}

	forwarder.HandleForwardResult(nil, &common.ServerForwardResultMsg{
		TransactionId: fwdMsg.TransactionId,
		Success:       true,
		ACKData:       []byte("ack"),
	})

	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("ForwardKnock returned error: %v", got.err)
		}
		if got.result == nil || !got.result.Success || string(got.result.ACKData) != "ack" {
			t.Fatalf("ForwardKnock result = %+v, want successful ack", got.result)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for ForwardKnock result")
	}
}

func TestForwardKnock_FansOutAssignedServersAndReturnsFirstSuccess(t *testing.T) {
	testPrivateKey := make([]byte, 32)
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_SERVER, testPrivateKey, nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}
	defer device.Stop()

	baseDeps := NewMockForwarderDeps()
	baseDeps.SetDevice(device)
	sent := make(chan *core.MsgData, 3)
	deps := &captureSendForwarderDeps{
		MockForwarderDeps: baseDeps,
		sent:              sent,
	}
	forwarder := NewServerForwarder(deps)
	assignment := &ACAssignment{
		ACID: "ac-forward",
		AssignedServers: []ServerInfo{
			{ID: "srv-a", InternalIP: "10.0.0.61", Port: common.DefaultNHPPort, PubKey: device.PublicKeyBase64()},
			{ID: "srv-b", InternalIP: "10.0.0.62", Port: common.DefaultNHPPort, PubKey: device.PublicKeyBase64()},
			{ID: "srv-c", InternalIP: "10.0.0.63", Port: common.DefaultNHPPort, PubKey: device.PublicKeyBase64()},
		},
	}
	for _, target := range assignment.AssignedServers {
		if forwarder.health.RecordNoResponse(target.ID) {
			t.Fatalf("first no-response for %s should not mark server unhealthy", target.ID)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan forwardKnockOutcome, 1)
	go func() {
		result, err := forwarder.ForwardKnock(
			ctx,
			assignment,
			[]byte("knock"),
			&net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 54321},
			nil,
		)
		done <- forwardKnockOutcome{result: result, err: err}
	}()

	forwarded := collectForwardedMessages(t, sent, 3)
	if got := baseDeps.MetricCount(MetricKnockForwardPeerAttempt); got != 3 {
		t.Fatalf("%s metric = %d, want one per assigned peer", MetricKnockForwardPeerAttempt, got)
	}

	forwarder.HandleForwardResult(nil, &common.ServerForwardResultMsg{
		TransactionId: forwarded[0].TransactionId,
		Success:       false,
		ErrCode:       "AC_NOT_CONNECTED",
		ErrMsg:        "AC not connected to this server",
	})

	select {
	case got := <-done:
		t.Fatalf("ForwardKnock returned after an unsuccessful peer result: result=%+v err=%v", got.result, got.err)
	default:
	}

	forwarder.HandleForwardResult(nil, &common.ServerForwardResultMsg{
		TransactionId: forwarded[1].TransactionId,
		Success:       true,
		ACKData:       []byte("ack"),
	})

	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("ForwardKnock returned error despite a successful peer: %v", got.err)
		}
		if got.result == nil || !got.result.Success || string(got.result.ACKData) != "ack" {
			t.Fatalf("ForwardKnock result = %+v, want successful ack", got.result)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for ForwardKnock result")
	}

	for _, target := range assignment.AssignedServers {
		if forwarder.health.RecordNoResponse(target.ID) {
			t.Fatalf("first-success should clear stale no-response debt for %s", target.ID)
		}
	}

	waitForPendingForwardRemoval(t, forwarder, forwarded[2].TransactionId)
	forwarder.HandleForwardResult(nil, &common.ServerForwardResultMsg{
		TransactionId: forwarded[2].TransactionId,
		Success:       true,
		ACKData:       []byte("late-loser-ack"),
	})
	if got := baseDeps.MetricCount(MetricServerForwardUnknownResult); got != 1 {
		t.Fatalf("%s metric = %d, want late loser response counted once", MetricServerForwardUnknownResult, got)
	}
}

func TestForwardKnock_AllPeersRejectReturnsErrorAfterAllResults(t *testing.T) {
	testPrivateKey := make([]byte, 32)
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_SERVER, testPrivateKey, nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}
	defer device.Stop()

	baseDeps := NewMockForwarderDeps()
	baseDeps.SetDevice(device)
	sent := make(chan *core.MsgData, 2)
	deps := &captureSendForwarderDeps{
		MockForwarderDeps: baseDeps,
		sent:              sent,
	}
	forwarder := NewServerForwarder(deps)
	assignment := &ACAssignment{
		ACID: "ac-reject",
		AssignedServers: []ServerInfo{
			{ID: "srv-a", InternalIP: "10.0.0.71", Port: common.DefaultNHPPort, PubKey: device.PublicKeyBase64()},
			{ID: "srv-b", InternalIP: "10.0.0.72", Port: common.DefaultNHPPort, PubKey: device.PublicKeyBase64()},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan forwardKnockOutcome, 1)
	go func() {
		result, err := forwarder.ForwardKnock(
			ctx,
			assignment,
			[]byte("knock"),
			&net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 54321},
			nil,
		)
		done <- forwardKnockOutcome{result: result, err: err}
	}()

	forwarded := collectForwardedMessages(t, sent, 2)
	forwarder.HandleForwardResult(nil, &common.ServerForwardResultMsg{
		TransactionId: forwarded[0].TransactionId,
		Success:       false,
		ErrCode:       "AC_NOT_CONNECTED",
		ErrMsg:        "first peer had no AC",
	})

	select {
	case got := <-done:
		t.Fatalf("ForwardKnock returned before every assigned peer answered: result=%+v err=%v", got.result, got.err)
	case <-time.After(50 * time.Millisecond):
	}

	forwarder.HandleForwardResult(nil, &common.ServerForwardResultMsg{
		TransactionId: forwarded[1].TransactionId,
		Success:       false,
		ErrCode:       "AC_NOT_CONNECTED",
		ErrMsg:        "second peer had no AC",
	})

	select {
	case got := <-done:
		if got.result != nil {
			t.Fatalf("ForwardKnock result = %+v, want nil result after all peers reject", got.result)
		}
		if got.err == nil || !strings.Contains(got.err.Error(), "AC_NOT_CONNECTED") {
			t.Fatalf("ForwardKnock error = %v, want AC_NOT_CONNECTED rejection", got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for ForwardKnock rejection")
	}
}

func TestForwardKnock_BudgetTimeoutDoesNotPoisonAssignedServers(t *testing.T) {
	testPrivateKey := make([]byte, 32)
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_SERVER, testPrivateKey, nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}
	defer device.Stop()

	baseDeps := NewMockForwarderDeps()
	baseDeps.SetDevice(device)
	sent := make(chan *core.MsgData, 3)
	deps := &captureSendForwarderDeps{
		MockForwarderDeps: baseDeps,
		sent:              sent,
	}
	forwarder := NewServerForwarder(deps)
	assignment := &ACAssignment{
		ACID: "ac-budget-timeout",
		AssignedServers: []ServerInfo{
			{ID: "srv-a", InternalIP: "10.0.0.81", Port: common.DefaultNHPPort, PubKey: device.PublicKeyBase64()},
			{ID: "srv-b", InternalIP: "10.0.0.82", Port: common.DefaultNHPPort, PubKey: device.PublicKeyBase64()},
			{ID: "srv-c", InternalIP: "10.0.0.83", Port: common.DefaultNHPPort, PubKey: device.PublicKeyBase64()},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	done := make(chan forwardKnockOutcome, 1)
	go func() {
		result, err := forwarder.ForwardKnock(
			ctx,
			assignment,
			[]byte("knock"),
			&net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 54321},
			nil,
		)
		done <- forwardKnockOutcome{result: result, err: err}
	}()

	collectForwardedMessages(t, sent, 3)

	select {
	case got := <-done:
		if got.result != nil {
			t.Fatalf("ForwardKnock result = %+v, want nil result after budget timeout", got.result)
		}
		if !errors.Is(got.err, context.DeadlineExceeded) {
			t.Fatalf("ForwardKnock error = %v, want context deadline exceeded", got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for ForwardKnock budget timeout")
	}

	for _, target := range assignment.AssignedServers {
		if forwarder.health.IsUnhealthy(target.ID) {
			t.Fatalf("shared budget timeout marked %s unhealthy", target.ID)
		}
	}
}

func TestForwardKnock_RepeatedBudgetTimeoutMarksNoResponsePeersUnhealthy(t *testing.T) {
	testPrivateKey := make([]byte, 32)
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_SERVER, testPrivateKey, nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}
	defer device.Stop()

	baseDeps := NewMockForwarderDeps()
	baseDeps.SetDevice(device)
	sent := make(chan *core.MsgData, 6)
	deps := &captureSendForwarderDeps{
		MockForwarderDeps: baseDeps,
		sent:              sent,
	}
	forwarder := NewServerForwarder(deps)
	assignment := &ACAssignment{
		ACID: "ac-repeated-budget-timeout",
		AssignedServers: []ServerInfo{
			{ID: "srv-a", InternalIP: "10.0.0.91", Port: common.DefaultNHPPort, PubKey: device.PublicKeyBase64()},
			{ID: "srv-b", InternalIP: "10.0.0.92", Port: common.DefaultNHPPort, PubKey: device.PublicKeyBase64()},
			{ID: "srv-c", InternalIP: "10.0.0.93", Port: common.DefaultNHPPort, PubKey: device.PublicKeyBase64()},
		},
	}

	for attempt := 1; attempt <= ForwardNoResponseFailureThreshold; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		done := make(chan error, 1)
		go func() {
			_, err := forwarder.ForwardKnock(
				ctx,
				assignment,
				[]byte("knock"),
				&net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 54321},
				nil,
			)
			done <- err
		}()

		collectForwardedMessages(t, sent, len(assignment.AssignedServers))

		select {
		case err := <-done:
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("attempt %d error = %v, want context deadline exceeded", attempt, err)
			}
		case <-time.After(time.Second):
			t.Fatalf("timeout waiting for ForwardKnock attempt %d", attempt)
		}
		cancel()

		for _, target := range assignment.AssignedServers {
			gotUnhealthy := forwarder.health.IsUnhealthy(target.ID)
			wantUnhealthy := attempt == ForwardNoResponseFailureThreshold
			if gotUnhealthy != wantUnhealthy {
				t.Fatalf("attempt %d: IsUnhealthy(%s) = %v, want %v",
					attempt, target.ID, gotUnhealthy, wantUnhealthy)
			}
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := forwarder.ForwardKnock(
			ctx,
			assignment,
			[]byte("knock"),
			&net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 54321},
			nil,
		)
		done <- err
	}()

	collectForwardedMessages(t, sent, len(assignment.AssignedServers))

	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("all-unhealthy fallback error = %v, want context deadline exceeded", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for ForwardKnock all-unhealthy fallback")
	}
}

func TestForwardKnock_DeduplicatesAssignedServers(t *testing.T) {
	testPrivateKey := make([]byte, 32)
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_SERVER, testPrivateKey, nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}
	defer device.Stop()

	baseDeps := NewMockForwarderDeps()
	baseDeps.SetDevice(device)
	sent := make(chan *core.MsgData, 3)
	deps := &captureSendForwarderDeps{
		MockForwarderDeps: baseDeps,
		sent:              sent,
	}
	forwarder := NewServerForwarder(deps)
	assignment := &ACAssignment{
		ACID: "ac-duplicate-assignment",
		AssignedServers: []ServerInfo{
			{ID: "srv-a", InternalIP: "10.0.0.101", Port: common.DefaultNHPPort, PubKey: device.PublicKeyBase64()},
			{ID: "srv-a", InternalIP: "10.0.0.102", Port: common.DefaultNHPPort, PubKey: device.PublicKeyBase64()},
			{ID: "srv-b", InternalIP: "10.0.0.103", Port: common.DefaultNHPPort, PubKey: device.PublicKeyBase64()},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := forwarder.ForwardKnock(
			ctx,
			assignment,
			[]byte("knock"),
			&net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 54321},
			nil,
		)
		done <- err
	}()

	collectForwardedMessages(t, sent, 2)
	select {
	case md := <-sent:
		t.Fatalf("unexpected duplicate forward packet after dedupe: tx=%d", md.TransactionId)
	default:
	}

	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("ForwardKnock error = %v, want context deadline exceeded", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for ForwardKnock duplicate-assignment timeout")
	}
}

func TestFanoutKnock_CarriesAdmissionRevocationData(t *testing.T) {
	testPrivateKey := make([]byte, 32)
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_SERVER, testPrivateKey, nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}
	defer device.Stop()

	baseDeps := NewMockForwarderDeps()
	baseDeps.SetDevice(device)
	sent := make(chan *core.MsgData, 1)
	deps := &captureSendForwarderDeps{
		MockForwarderDeps: baseDeps,
		err:               errors.New("prequeue drop"),
		sent:              sent,
	}
	forwarder := NewServerForwarder(deps)
	assignment := &ACAssignment{
		ACID: "ac-fanout",
		AssignedServers: []ServerInfo{
			{
				ID:         "srv-fanout-peer",
				InternalIP: "10.0.0.60",
				Port:       common.DefaultNHPPort,
				PubKey:     device.PublicKeyBase64(),
			},
		},
	}

	accepted := forwarder.FanoutKnock(
		context.Background(),
		assignment,
		"10.0.0.1",
		[]byte("knock"),
		&net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 54321},
		&common.ResourceData{
			ResourceGroup: common.ResourceGroup{
				AuthServiceId: "qurl",
				ResourceId:    "q_123456789ab",
				OpenTime:      300,
				Resources: map[string]*common.ResourceInfo{
					"ac-a": {
						ACId: "ac-a",
						Addr: &common.NetAddress{Port: 443, Protocol: "tcp"},
					},
				},
			},
			QurlUserPublicKeyHash: "qhash",
			ResourcePublicKeyHash: "verified-rhash",
			QurlSessionId:         "sess-live",
			AdmissionId:           "adm-123",
			Deadline:              1781910300,
		},
	)
	if accepted != 0 {
		t.Fatalf("FanoutKnock accepted peers = %d, want 0 after local send failure", accepted)
	}

	select {
	case md := <-sent:
		if md.HeaderType != core.NHP_FWD {
			t.Fatalf("HeaderType=%s, want NHP_FWD", core.HeaderTypeToString(md.HeaderType))
		}
		var fwdMsg common.ServerForwardMsg
		if err := json.Unmarshal(md.Message, &fwdMsg); err != nil {
			t.Fatalf("unmarshal fanout forward message: %v", err)
		}
		got := fwdMsg.AdmissionRevocationData
		if got == nil {
			t.Fatal("FanoutKnock omitted admission revocation sidecar")
		}
		if got.QurlUserPublicKeyHash != "qhash" ||
			got.ResourcePublicKeyHash != "verified-rhash" ||
			got.QurlSessionId != "sess-live" ||
			got.AdmissionId != "adm-123" ||
			got.Deadline != 1781910300 {
			t.Fatalf("fanout admission revocation data = %+v, want origin admission metadata", got)
		}
		route := fwdMsg.ResolvedResourceData
		if route == nil {
			t.Fatal("FanoutKnock omitted resolved resource route")
		}
		if route.AuthServiceId != "qurl" || route.ResourceId != "q_123456789ab" || route.OpenTime != 300 || route.ResourcePublicKeyHash != "verified-rhash" {
			t.Fatalf("fanout resolved resource route = %+v, want origin routing snapshot", route)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for FanoutKnock send")
	}
}

func TestForwardKnock_ServerShuffling(t *testing.T) {
	// This test verifies that servers are shuffled for load distribution
	// Run multiple times and track which server is tried first
	firstServerCounts := make(map[string]int)

	for i := 0; i < 100; i++ {
		forwarder := &ServerForwarder{
			health:      NewServerHealthTracker(),
			pendingFwds: make(map[uint64]*PendingForward),
			serverPeers: make(map[string]*core.UdpPeer),
			nextTxID:    1000,
		}

		assignment := CreateTestACAssignment("ac-shuffle", "srv-a", "srv-b", "srv-c")

		// We can't easily test actual network calls, but we can verify
		// that health tracking affects ordering
		// Mark srv-a as unhealthy - it should always be skipped
		forwarder.health.RecordFailure("srv-a")

		// At this point, either srv-b or srv-c would be tried first
		// (randomly shuffled), but never srv-a
		if !forwarder.health.IsUnhealthy("srv-a") {
			t.Error("srv-a should be marked unhealthy")
		}
		if forwarder.health.IsUnhealthy("srv-b") || forwarder.health.IsUnhealthy("srv-c") {
			t.Error("srv-b and srv-c should be healthy")
		}

		// Track which servers are NOT skipped
		for _, s := range assignment.AssignedServers {
			if !forwarder.health.IsUnhealthy(s.ID) {
				firstServerCounts[s.ID]++
			}
		}
	}

	// srv-a should never be counted (always skipped)
	if firstServerCounts["srv-a"] > 0 {
		t.Error("srv-a should always be skipped (unhealthy)")
	}

	// srv-b and srv-c should each be counted ~100 times
	if firstServerCounts["srv-b"] != 100 || firstServerCounts["srv-c"] != 100 {
		t.Errorf("Expected srv-b and srv-c to be available 100 times each, got b=%d c=%d",
			firstServerCounts["srv-b"], firstServerCounts["srv-c"])
	}
}

// ============================================================================
// HandleForwardRequest Timestamp Validation Tests
// ============================================================================

func TestHandleForwardRequest_StaleTimestamp(t *testing.T) {
	mockDeps := NewMockForwarderDeps()
	forwarder := &ServerForwarder{
		deps:        mockDeps,
		health:      NewServerHealthTracker(),
		pendingFwds: make(map[uint64]*PendingForward),
		serverPeers: make(map[string]*core.UdpPeer),
	}

	// Create message with old timestamp
	fwdMsg := &common.ServerForwardMsg{
		SessionId:            1,
		SessionIssuedAtNanos: time.Now().UnixNano(),
		KnockData:            []byte("test-knock"),
		SourceServer:         "srv-source",
		UserAddr:             "1.2.3.4:12345",
		TransactionId:        1234,
		Timestamp:            time.Now().Add(-MaxTimestampAge - time.Minute).Unix(), // Very old
	}

	// Should reject with stale timestamp error
	// Note: HandleForwardRequest sends response via channel, so we check channel
	go forwarder.HandleForwardRequest(nil, fwdMsg)

	select {
	case msg := <-mockDeps.GetSendChannel():
		if msg.HeaderType != core.NHP_FRT {
			t.Errorf("Expected NHP_FRT, got %d", msg.HeaderType)
		}
		// Parse result message to verify error
		var result common.ServerForwardResultMsg
		if err := json.Unmarshal(msg.Message, &result); err != nil {
			t.Fatalf("Failed to parse result: %v", err)
		}
		if result.Success {
			t.Error("Expected failure for stale timestamp")
		}
		if result.ErrCode != "STALE_TIMESTAMP" {
			t.Errorf("Expected STALE_TIMESTAMP error, got %s", result.ErrCode)
		}
	case <-time.After(time.Second):
		t.Fatal("Timeout waiting for response")
	}
}

func TestHandleForwardRequest_FutureTimestamp(t *testing.T) {
	mockDeps := NewMockForwarderDeps()
	forwarder := &ServerForwarder{
		deps:        mockDeps,
		health:      NewServerHealthTracker(),
		pendingFwds: make(map[uint64]*PendingForward),
		serverPeers: make(map[string]*core.UdpPeer),
	}

	// Create message with future timestamp (beyond clock skew tolerance)
	fwdMsg := &common.ServerForwardMsg{
		SessionId:            1,
		SessionIssuedAtNanos: time.Now().UnixNano(),
		KnockData:            []byte("test-knock"),
		SourceServer:         "srv-source",
		UserAddr:             "1.2.3.4:12345",
		TransactionId:        1234,
		Timestamp:            time.Now().Add(10 * time.Second).Unix(), // Too far in future
	}

	go forwarder.HandleForwardRequest(nil, fwdMsg)

	select {
	case msg := <-mockDeps.GetSendChannel():
		var result common.ServerForwardResultMsg
		if err := json.Unmarshal(msg.Message, &result); err != nil {
			t.Fatalf("Failed to parse result: %v", err)
		}
		if result.Success {
			t.Error("Expected failure for future timestamp")
		}
		if result.ErrCode != "FUTURE_TIMESTAMP" {
			t.Errorf("Expected FUTURE_TIMESTAMP error, got %s", result.ErrCode)
		}
	case <-time.After(time.Second):
		t.Fatal("Timeout waiting for response")
	}
}

func TestHandleForwardRequest_ValidTimestamp_WithinSkew(t *testing.T) {
	mockDeps := NewMockForwarderDeps()
	forwarder := &ServerForwarder{
		deps:        mockDeps,
		health:      NewServerHealthTracker(),
		pendingFwds: make(map[uint64]*PendingForward),
		serverPeers: make(map[string]*core.UdpPeer),
	}

	// Create message with timestamp slightly in future (within 5s tolerance)
	fwdMsg := &common.ServerForwardMsg{
		SessionId:            1,
		SessionIssuedAtNanos: time.Now().UnixNano(),
		KnockData:            []byte("test-knock"),
		SourceServer:         "srv-source",
		UserAddr:             "1.2.3.4:12345",
		TransactionId:        1234,
		Timestamp:            time.Now().Add(3 * time.Second).Unix(), // Within tolerance
	}

	go forwarder.HandleForwardRequest(nil, fwdMsg)

	// Should NOT fail on timestamp, but will fail later due to missing device
	select {
	case msg := <-mockDeps.GetSendChannel():
		var result common.ServerForwardResultMsg
		if err := json.Unmarshal(msg.Message, &result); err != nil {
			t.Fatalf("Failed to parse result: %v", err)
		}
		// Should fail on decryption, NOT timestamp
		if result.ErrCode == "STALE_TIMESTAMP" || result.ErrCode == "FUTURE_TIMESTAMP" {
			t.Errorf("Should not fail on timestamp (within tolerance), got %s", result.ErrCode)
		}
	case <-time.After(time.Second):
		t.Fatal("Timeout waiting for response")
	}
}

func TestHandleForwardRequest_InvalidUserAddr(t *testing.T) {
	mockDeps := NewMockForwarderDeps()
	forwarder := &ServerForwarder{
		deps:        mockDeps,
		health:      NewServerHealthTracker(),
		pendingFwds: make(map[uint64]*PendingForward),
		serverPeers: make(map[string]*core.UdpPeer),
	}

	// Create message with invalid user address
	fwdMsg := &common.ServerForwardMsg{
		SessionId:            1,
		SessionIssuedAtNanos: time.Now().UnixNano(),
		KnockData:            []byte("test-knock"),
		SourceServer:         "srv-source",
		UserAddr:             "not-a-valid-address", // Invalid
		TransactionId:        1234,
		Timestamp:            time.Now().Unix(),
	}

	go forwarder.HandleForwardRequest(nil, fwdMsg)

	select {
	case msg := <-mockDeps.GetSendChannel():
		var result common.ServerForwardResultMsg
		if err := json.Unmarshal(msg.Message, &result); err != nil {
			t.Fatalf("Failed to parse result: %v", err)
		}
		if result.ErrCode != "INVALID_USER_ADDR" {
			t.Errorf("Expected INVALID_USER_ADDR error, got %s", result.ErrCode)
		}
	case <-time.After(time.Second):
		t.Fatal("Timeout waiting for response")
	}
}

func TestHandleDecryptedForwardedKnock_RejectsEmptyResourceHost(t *testing.T) {
	mockDeps := NewMockForwarderDeps()
	mockDeps.SetAuthServiceProvider(&common.AuthServiceProviderData{
		AuthSvcId: "agent",
		ResourceGroups: common.ResourceGroupMap{
			"qurl-tunnel-server": {
				ResourceGroup: common.ResourceGroup{
					AuthServiceId: "agent",
					ResourceId:    "qurl-tunnel-server",
					OpenTime:      30,
					Resources: map[string]*common.ResourceInfo{
						"qurl-tunnel-server": {
							ACId:       "ac-a",
							Hostname:   "connect.test",
							PortSuffix: true,
							Addr: &common.NetAddress{
								Port:     0,
								Protocol: "tcp",
							},
						},
					},
				},
			},
		},
	})
	forwarder := NewServerForwarder(mockDeps)

	knockMsg := &common.AgentKnockMsg{
		HeaderType:    core.NHP_KNK,
		UserId:        "test-user",
		DeviceId:      "test-device",
		AuthServiceId: "agent",
		ResourceId:    "qurl-tunnel-server",
		RunID:         "0123456789abcdef",
		RunAttempt:    1,
	}
	body, err := json.Marshal(knockMsg)
	if err != nil {
		t.Fatalf("marshal knock: %v", err)
	}
	fwdMsg := &common.ServerForwardMsg{
		SessionId:            1,
		SessionIssuedAtNanos: time.Now().UnixNano(),
		SourceServer:         "srv-source",
		UserAddr:             "1.2.3.4:12345",
		TransactionId:        1234,
		Timestamp:            time.Now().Unix(),
	}
	userAddr, err := net.ResolveUDPAddr("udp", fwdMsg.UserAddr)
	if err != nil {
		t.Fatalf("resolve user addr: %v", err)
	}

	forwarder.handleDecryptedForwardedKnock(nil, fwdMsg, userAddr, &core.PacketParserData{
		BodyMessage:  body,
		RemotePubKey: make([]byte, 32),
	})

	select {
	case msg := <-mockDeps.GetSendChannel():
		var result common.ServerForwardResultMsg
		if err := json.Unmarshal(msg.Message, &result); err != nil {
			t.Fatalf("parse result: %v", err)
		}
		if result.ErrCode != "RESOURCE_INFO_INCOMPLETE" {
			t.Fatalf("ErrCode=%s ErrMsg=%s, want RESOURCE_INFO_INCOMPLETE", result.ErrCode, result.ErrMsg)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for response")
	}
}

func TestHandleDecryptedForwardedKnock_RejectsMissingRegisteredAgentRunIDBeforeDependencies(t *testing.T) {
	mockDeps := NewMockForwarderDeps()
	forwarder := NewServerForwarder(mockDeps)
	body, err := json.Marshal(&common.AgentKnockMsg{
		HeaderType:    core.NHP_KNK,
		UserId:        "missing-run-id",
		DeviceId:      "device",
		AuthServiceId: common.RegisteredAgentAuthServiceID,
		ResourceId:    "connector",
	})
	if err != nil {
		t.Fatalf("marshal knock: %v", err)
	}
	fwdMsg := &common.ServerForwardMsg{SessionId: 1, SessionIssuedAtNanos: time.Now().UnixNano(), TransactionId: 9876}
	forwarder.handleDecryptedForwardedKnock(nil, fwdMsg, &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 40000}, &core.PacketParserData{
		BodyMessage:  body,
		RemotePubKey: make([]byte, 32),
	})

	select {
	case msg := <-mockDeps.GetSendChannel():
		var result common.ServerForwardResultMsg
		if err := json.Unmarshal(msg.Message, &result); err != nil {
			t.Fatalf("parse result: %v", err)
		}
		if result.ErrCode != "INVALID_RUN_ID" {
			t.Fatalf("ErrCode=%q ErrMsg=%q, want INVALID_RUN_ID", result.ErrCode, result.ErrMsg)
		}
		if result.ErrMsg != common.ErrKnockRunIDInvalid.Error() {
			t.Fatalf("ErrMsg=%q, want %q", result.ErrMsg, common.ErrKnockRunIDInvalid.Error())
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for missing-RunID rejection")
	}
	if got := mockDeps.LastResolveCtx(); got != nil {
		t.Fatalf("auth-provider resolver was called with context %v; missing RunID must reject before dependency work", got)
	}
}

func TestHandleDecryptedForwardedKnock_RejectsMalformedRegisteredAgentRunIDWithStableError(t *testing.T) {
	mockDeps := NewMockForwarderDeps()
	forwarder := NewServerForwarder(mockDeps)
	fwdMsg := &common.ServerForwardMsg{SessionId: 1, SessionIssuedAtNanos: time.Now().UnixNano(), TransactionId: 9877}
	forwarder.handleDecryptedForwardedKnock(nil, fwdMsg, &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 40000}, &core.PacketParserData{
		BodyMessage:  []byte(`{"headerType":1,"usrId":"malformed-run-id","devId":"device","aspId":"agent","resId":"connector","runId":"0123456789ABCDEF"}`),
		RemotePubKey: make([]byte, 32),
	})

	select {
	case msg := <-mockDeps.GetSendChannel():
		var result common.ServerForwardResultMsg
		if err := json.Unmarshal(msg.Message, &result); err != nil {
			t.Fatalf("parse result: %v", err)
		}
		if result.ErrCode != "INVALID_RUN_ID" {
			t.Fatalf("ErrCode=%q ErrMsg=%q, want INVALID_RUN_ID", result.ErrCode, result.ErrMsg)
		}
		if result.ErrMsg != common.ErrKnockRunIDInvalid.Error() {
			t.Fatalf("ErrMsg=%q, want %q", result.ErrMsg, common.ErrKnockRunIDInvalid.Error())
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for malformed-RunID rejection")
	}
	if got := mockDeps.LastResolveCtx(); got != nil {
		t.Fatalf("auth-provider resolver was called with context %v; malformed RunID must reject before dependency work", got)
	}
}

// ============================================================================
// HandleForwardResult Tests
// ============================================================================

func TestHandleForwardResult_MatchingTransaction(t *testing.T) {
	forwarder := &ServerForwarder{
		health:      NewServerHealthTracker(),
		pendingFwds: make(map[uint64]*PendingForward),
		serverPeers: make(map[string]*core.UdpPeer),
	}

	// Create pending forward
	responseCh := make(chan *common.ServerForwardResultMsg, 1)
	forwarder.pendingFwds[12345] = &PendingForward{
		TransactionID: 12345,
		ResponseCh:    responseCh,
		CreatedAt:     time.Now(),
	}

	// Handle result
	resultMsg := &common.ServerForwardResultMsg{
		TransactionId: 12345,
		Success:       true,
		ACKData:       []byte(`{"errCode":"0"}`),
	}

	forwarder.HandleForwardResult(nil, resultMsg)

	// Should receive on channel
	select {
	case received := <-responseCh:
		if received.TransactionId != 12345 {
			t.Errorf("Expected txID 12345, got %d", received.TransactionId)
		}
		if !received.Success {
			t.Error("Expected success")
		}
	case <-time.After(time.Second):
		t.Fatal("Timeout waiting for result on channel")
	}
}

func TestHandleForwardResult_UnknownTransaction(t *testing.T) {
	deps := NewMockForwarderDeps()
	forwarder := &ServerForwarder{
		deps:        deps,
		health:      NewServerHealthTracker(),
		pendingFwds: make(map[uint64]*PendingForward),
		serverPeers: make(map[string]*core.UdpPeer),
	}

	// Handle result for unknown transaction
	resultMsg := &common.ServerForwardResultMsg{
		TransactionId: 99999, // No pending forward with this ID
		Success:       true,
	}

	// Should not panic; unknown results are counted instead of warning-spamming.
	forwarder.HandleForwardResult(nil, resultMsg)
	if got := deps.MetricCount(MetricServerForwardUnknownResult); got != 1 {
		t.Fatalf("%s metric = %d, want 1", MetricServerForwardUnknownResult, got)
	}
}

// ============================================================================
// ServerForwarder Lifecycle Tests
// ============================================================================

func TestServerForwarder_StartStop(t *testing.T) {
	forwarder := NewServerForwarder(nil)

	// Add old pending forward BEFORE starting
	forwarder.pendingMutex.Lock()
	forwarder.pendingFwds[1] = &PendingForward{
		TransactionID: 1,
		CreatedAt:     time.Now().Add(-time.Hour), // Very old - will be cleaned
	}
	forwarder.pendingMutex.Unlock()

	forwarder.Start()

	// Let cleanup run at least once (every 4 seconds)
	time.Sleep(ForwardTimeout*2 + 500*time.Millisecond)

	// Verify old pending was cleaned up
	forwarder.pendingMutex.Lock()
	_, hasOld := forwarder.pendingFwds[1]
	forwarder.pendingMutex.Unlock()

	if hasOld {
		t.Error("Expected old pending forward to be cleaned up")
	}

	// Add fresh pending AFTER cleanup ran - this proves cleanup keeps fresh items
	forwarder.pendingMutex.Lock()
	forwarder.pendingFwds[2] = &PendingForward{
		TransactionID: 2,
		CreatedAt:     time.Now(), // Fresh - should be kept
	}
	forwarder.pendingMutex.Unlock()

	// Run cleanup manually to verify fresh entry is kept
	forwarder.CleanupPendingForwards()

	forwarder.pendingMutex.Lock()
	_, hasFresh := forwarder.pendingFwds[2]
	forwarder.pendingMutex.Unlock()

	if !hasFresh {
		t.Error("Expected fresh pending forward to be kept after cleanup")
	}

	// Stop should not hang
	done := make(chan struct{})
	go func() {
		forwarder.Stop()
		close(done)
	}()

	select {
	case <-done:
		// Good
	case <-time.After(5 * time.Second):
		t.Fatal("Stop() timed out")
	}
}

// ============================================================================
// Integration: Storage + Forwarder
// ============================================================================

func TestIntegration_StorageForwarderFlow(t *testing.T) {
	// This test simulates the flow when a knock arrives at a server
	// that doesn't have the AC connection

	storage := NewMemoryStorage()

	// Setup: AC is assigned to servers srv-1, srv-2, srv-3
	storage.PutACAssignment(CreateTestACAssignment("ac-target", "srv-1", "srv-2", "srv-3"))

	// Simulate: Server srv-7 (not assigned) receives knock
	ctx := context.Background()
	assignment, err := storage.GetACAssignment(ctx, "ac-target")
	if err != nil {
		t.Fatalf("Failed to get assignment: %v", err)
	}

	// Verify we got correct assignment
	if len(assignment.AssignedServers) != 3 {
		t.Fatalf("Expected 3 assigned servers, got %d", len(assignment.AssignedServers))
	}

	// Verify server IDs
	serverIDs := make(map[string]bool)
	for _, s := range assignment.AssignedServers {
		serverIDs[s.ID] = true
	}
	if !serverIDs["srv-1"] || !serverIDs["srv-2"] || !serverIDs["srv-3"] {
		t.Error("Expected servers srv-1, srv-2, srv-3 in assignment")
	}

	// The forwarder would now forward to one of these servers
	// (actual network forwarding tested in integration tests)
}

// ============================================================================
// Advanced Forwarding Scenarios
// ============================================================================

func TestForwardKnock_HealthTrackingDuringRetry(t *testing.T) {
	// Test that health tracking is updated correctly when servers fail/succeed
	tracker := NewServerHealthTracker()

	// Simulate forwarding retry scenario:
	// 1. Try srv-1 -> fails
	// 2. Try srv-2 -> fails
	// 3. Try srv-3 -> succeeds

	// Initially all healthy
	if tracker.IsUnhealthy("srv-1") || tracker.IsUnhealthy("srv-2") || tracker.IsUnhealthy("srv-3") {
		t.Fatal("All servers should be healthy initially")
	}

	// Simulate srv-1 failure
	tracker.RecordFailure("srv-1")
	if !tracker.IsUnhealthy("srv-1") {
		t.Error("srv-1 should be unhealthy after failure")
	}

	// Simulate srv-2 failure
	tracker.RecordFailure("srv-2")
	if !tracker.IsUnhealthy("srv-2") {
		t.Error("srv-2 should be unhealthy after failure")
	}

	// Simulate srv-3 success
	tracker.RecordSuccess("srv-3")
	if tracker.IsUnhealthy("srv-3") {
		t.Error("srv-3 should remain healthy after success")
	}

	// On next forwarding attempt, srv-1 and srv-2 should be skipped
	skipped := 0
	for _, serverID := range []string{"srv-1", "srv-2", "srv-3"} {
		if tracker.IsUnhealthy(serverID) {
			skipped++
		}
	}
	if skipped != 2 {
		t.Errorf("Expected 2 servers to be skipped, got %d", skipped)
	}
}

func TestForwardKnock_AllServersFailThenRecover(t *testing.T) {
	tracker := NewServerHealthTracker()

	servers := []string{"srv-1", "srv-2", "srv-3"}

	// Mark all as failed
	for _, s := range servers {
		tracker.RecordFailure(s)
	}

	// All should be unhealthy
	healthyCount := 0
	for _, s := range servers {
		if !tracker.IsUnhealthy(s) {
			healthyCount++
		}
	}
	if healthyCount != 0 {
		t.Error("All servers should be unhealthy")
	}

	// Simulate one server recovering
	tracker.RecordSuccess("srv-2")

	// Now srv-2 should be available
	if tracker.IsUnhealthy("srv-2") {
		t.Error("srv-2 should be healthy after success")
	}
	if !tracker.IsUnhealthy("srv-1") || !tracker.IsUnhealthy("srv-3") {
		t.Error("srv-1 and srv-3 should still be unhealthy")
	}
}

func TestPendingForwards_ConcurrentAddRemove(t *testing.T) {
	forwarder := &ServerForwarder{
		health:      NewServerHealthTracker(),
		pendingFwds: make(map[uint64]*PendingForward),
		serverPeers: make(map[string]*core.UdpPeer),
		nextTxID:    1000,
	}

	var wg sync.WaitGroup
	goroutines := 20
	iterations := 100

	// Concurrent add/remove of pending forwards
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				txID := forwarder.nextTransactionID()

				// Add pending
				forwarder.pendingMutex.Lock()
				forwarder.pendingFwds[txID] = &PendingForward{
					TransactionID: txID,
					ResponseCh:    make(chan *common.ServerForwardResultMsg, 1),
					CreatedAt:     time.Now(),
				}
				forwarder.pendingMutex.Unlock()

				// Simulate some work
				time.Sleep(time.Microsecond)

				// Remove pending
				forwarder.pendingMutex.Lock()
				delete(forwarder.pendingFwds, txID)
				forwarder.pendingMutex.Unlock()
			}
		}(g)
	}

	wg.Wait()

	// All pending forwards should be removed
	forwarder.pendingMutex.Lock()
	remaining := len(forwarder.pendingFwds)
	forwarder.pendingMutex.Unlock()

	if remaining != 0 {
		t.Errorf("Expected 0 pending forwards after cleanup, got %d", remaining)
	}
}

// ============================================================================
// decryptForwardedKnock Error Path Tests
// ============================================================================

func TestDecryptForwardedKnock_EmptyData(t *testing.T) {
	// Create a minimal mock deps
	testPrivateKey := make([]byte, 32)
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_SERVER, testPrivateKey, nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}
	defer device.Stop()

	deps := NewMockForwarderDeps()
	deps.SetDevice(device)

	forwarder := NewServerForwarder(deps)

	// Test with empty data
	_, err := forwarder.decryptForwardedKnock([]byte{}, nil)
	if err == nil {
		t.Error("Expected error for empty knock data")
	}
	if err.Error() != "empty knock data" {
		t.Errorf("Expected 'empty knock data' error, got: %v", err)
	}
}

func TestDecryptForwardedKnock_InvalidPacket(t *testing.T) {
	// Create a minimal mock deps
	testPrivateKey := make([]byte, 32)
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_SERVER, testPrivateKey, nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}
	defer device.Stop()

	deps := NewMockForwarderDeps()
	deps.SetDevice(device)

	forwarder := NewServerForwarder(deps)

	// Test with random invalid data (not a valid NHP packet)
	invalidData := []byte("this is not a valid NHP packet")
	_, err := forwarder.decryptForwardedKnock(invalidData, nil)
	if err == nil {
		t.Error("Expected error for invalid packet data")
	}
	// The error should be from the decryption process
	t.Logf("Got expected error: %v", err)
}

func TestDecryptForwardedKnock_TooShort(t *testing.T) {
	// Create a minimal mock deps
	testPrivateKey := make([]byte, 32)
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_SERVER, testPrivateKey, nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}
	defer device.Stop()

	deps := NewMockForwarderDeps()
	deps.SetDevice(device)

	forwarder := NewServerForwarder(deps)

	// Test with data too short to be a valid packet header
	tooShort := make([]byte, 10) // NHP packet header is much larger
	_, err := forwarder.decryptForwardedKnock(tooShort, nil)
	if err == nil {
		t.Error("Expected error for packet data too short")
	}
	t.Logf("Got expected error: %v", err)
}

// ============================================================================
// getOrCreateServerPeer Tests
// ============================================================================

func TestGetOrCreateServerPeer_CreatesNew(t *testing.T) {
	testPrivateKey := make([]byte, 32)
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_SERVER, testPrivateKey, nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}
	defer device.Stop()

	deps := NewMockForwarderDeps()
	deps.SetDevice(device)

	forwarder := NewServerForwarder(deps)

	// Create a server info
	serverInfo := ServerInfo{
		ID:         "test-server-1",
		InternalIP: "10.0.0.1",
		Port:       common.DefaultNHPPort,
		PubKey:     "dGVzdHB1YmtleWJhc2U2NA==", // "testpubkeybase64" in base64
	}

	// Get or create peer
	peer, err := forwarder.getOrCreateServerPeer(serverInfo)
	if err != nil {
		t.Fatalf("Failed to create peer: %v", err)
	}
	if peer == nil {
		t.Fatal("Expected non-nil peer")
	}

	// Verify peer is cached
	forwarder.peerMutex.RLock()
	cachedPeer, found := forwarder.serverPeers[serverInfo.ID]
	forwarder.peerMutex.RUnlock()

	if !found {
		t.Error("Expected peer to be cached")
	}
	if cachedPeer != peer {
		t.Error("Cached peer should be same as returned peer")
	}
}

func TestGetOrCreateServerPeer_ReturnsExisting(t *testing.T) {
	testPrivateKey := make([]byte, 32)
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_SERVER, testPrivateKey, nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}
	defer device.Stop()

	deps := NewMockForwarderDeps()
	deps.SetDevice(device)

	forwarder := NewServerForwarder(deps)

	serverInfo := ServerInfo{
		ID:         "test-server-2",
		InternalIP: "10.0.0.2",
		Port:       common.DefaultNHPPort,
		PubKey:     "dGVzdHB1YmtleTI=", // "testpubkey2" in base64
	}

	// Create peer first time
	peer1, err := forwarder.getOrCreateServerPeer(serverInfo)
	if err != nil {
		t.Fatalf("First call failed: %v", err)
	}

	// Get peer second time (should return same instance)
	peer2, err := forwarder.getOrCreateServerPeer(serverInfo)
	if err != nil {
		t.Fatalf("Second call failed: %v", err)
	}

	if peer1 != peer2 {
		t.Error("Expected same peer instance on second call")
	}
}

func TestGetOrCreateServerPeer_ConcurrentCreation(t *testing.T) {
	testPrivateKey := make([]byte, 32)
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_SERVER, testPrivateKey, nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}
	defer device.Stop()

	deps := NewMockForwarderDeps()
	deps.SetDevice(device)

	forwarder := NewServerForwarder(deps)

	serverInfo := ServerInfo{
		ID:         "test-server-concurrent",
		InternalIP: "10.0.0.3",
		Port:       common.DefaultNHPPort,
		PubKey:     "Y29uY3VycmVudHRlc3Q=", // "concurrenttest" in base64
	}

	// Launch multiple goroutines trying to create the same peer
	var wg sync.WaitGroup
	peers := make(chan *core.UdpPeer, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			peer, err := forwarder.getOrCreateServerPeer(serverInfo)
			if err != nil {
				t.Errorf("Failed to get peer: %v", err)
				return
			}
			peers <- peer
		}()
	}

	wg.Wait()
	close(peers)

	// All peers should be the same instance
	var firstPeer *core.UdpPeer
	for peer := range peers {
		if firstPeer == nil {
			firstPeer = peer
		} else if peer != firstPeer {
			t.Error("Expected all concurrent calls to return same peer instance")
		}
	}

	// Should only have one peer in the map
	forwarder.peerMutex.RLock()
	peerCount := len(forwarder.serverPeers)
	forwarder.peerMutex.RUnlock()

	if peerCount != 1 {
		t.Errorf("Expected 1 peer in map, got %d", peerCount)
	}
}

// ============================================================================
// Context Cancellation Tests
// ============================================================================

func TestForwardKnock_ContextCancellation(t *testing.T) {
	testPrivateKey := make([]byte, 32)
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_SERVER, testPrivateKey, nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}
	device.Start()
	defer device.Stop()

	deps := NewMockForwarderDeps()
	deps.SetDevice(device)

	forwarder := NewServerForwarder(deps)

	// Create an assignment with servers
	assignment := &ACAssignment{
		ACID: "test-ac-cancel",
		AssignedServers: []ServerInfo{
			{ID: "srv-1", InternalIP: "10.0.0.1", Port: common.DefaultNHPPort, PubKey: "c3J2MXB1YmtleQ=="},
			{ID: "srv-2", InternalIP: "10.0.0.2", Port: common.DefaultNHPPort, PubKey: "c3J2MnB1YmtleQ=="},
		},
	}

	// Create an already-canceled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Try to forward with canceled context
	_, err := forwarder.ForwardKnock(ctx, assignment, []byte("test-knock"), nil, nil)

	// Should return context error
	if err == nil {
		t.Fatal("Expected error from canceled context")
	}

	// The error might be context.Canceled or could be from connection timeout
	// depending on timing, but it should fail
	t.Logf("Got expected error on canceled context: %v", err)
}

// ============================================================================
// Storage Error Scenarios
// ============================================================================

func TestIntegration_StorageError_GracefulDegradation(t *testing.T) {
	storage := NewMemoryStorage()

	// Initially storage works
	storage.PutACAssignment(CreateTestACAssignment("ac-error-test", "srv-1"))

	ctx := context.Background()

	// First lookup succeeds
	assignment, err := storage.GetACAssignment(ctx, "ac-error-test")
	if err != nil {
		t.Fatalf("Initial lookup should succeed: %v", err)
	}
	if assignment.ACID != "ac-error-test" {
		t.Error("Wrong assignment returned")
	}

	// Simulate storage outage
	storage.SetServiceUnavailable("DynamoDB throttled")

	// Lookup during outage should fail with SERVICE_UNAVAILABLE
	_, err = storage.GetACAssignment(ctx, "ac-error-test")
	if err == nil {
		t.Fatal("Expected error during storage outage")
	}

	var se *StorageError
	if !errors.As(err, &se) {
		t.Fatalf("Expected StorageError, got %T", err)
	}
	if se.Code != ErrCodeServiceUnavail {
		t.Errorf("Expected SERVICE_UNAVAILABLE, got %s", se.Code)
	}

	// After outage clears, storage should work again
	assignment, err = storage.GetACAssignment(ctx, "ac-error-test")
	if err != nil {
		t.Fatalf("Lookup should succeed after outage: %v", err)
	}
	if assignment.ACID != "ac-error-test" {
		t.Error("Wrong assignment after recovery")
	}
}

// ============================================================================
// Version Conflict Tests
// ============================================================================

func TestIntegration_VersionConflict_Detection(t *testing.T) {
	storage := NewMemoryStorage()

	// Create assignment with version 1
	assignment := CreateTestACAssignment("ac-version", "srv-1")
	assignment.Version = 1
	storage.PutACAssignment(assignment)

	ctx := context.Background()

	// Read assignment
	retrieved, _ := storage.GetACAssignment(ctx, "ac-version")
	if retrieved.Version != 1 {
		t.Fatalf("Expected version 1, got %d", retrieved.Version)
	}

	// Simulate concurrent update (version bump)
	updated := CreateTestACAssignment("ac-version", "srv-new")
	updated.Version = 2
	storage.PutACAssignment(updated)

	// Re-read shows new version
	retrieved2, _ := storage.GetACAssignment(ctx, "ac-version")
	if retrieved2.Version != 2 {
		t.Errorf("Expected version 2, got %d", retrieved2.Version)
	}
	if retrieved2.AssignedServers[0].ID != "srv-new" {
		t.Error("Expected updated server assignment")
	}
}

// ============================================================================
// Health Tracker Advanced Tests
// ============================================================================

func TestHealthTracker_MultipleServers_IndependentTracking(t *testing.T) {
	tracker := NewServerHealthTracker()

	// Mark different servers as failed at different times
	tracker.RecordFailure("srv-1")
	time.Sleep(10 * time.Millisecond)
	tracker.RecordFailure("srv-2")

	// Both should be unhealthy
	if !tracker.IsUnhealthy("srv-1") {
		t.Error("srv-1 should be unhealthy")
	}
	if !tracker.IsUnhealthy("srv-2") {
		t.Error("srv-2 should be unhealthy")
	}

	// srv-3 was never marked failed
	if tracker.IsUnhealthy("srv-3") {
		t.Error("srv-3 should be healthy")
	}

	// Clear srv-1
	tracker.RecordSuccess("srv-1")
	if tracker.IsUnhealthy("srv-1") {
		t.Error("srv-1 should be healthy after success")
	}
	if !tracker.IsUnhealthy("srv-2") {
		t.Error("srv-2 should still be unhealthy")
	}
}

func TestHealthTracker_RapidFailureSuccess(t *testing.T) {
	tracker := NewServerHealthTracker()

	// Rapid alternation
	for i := 0; i < 100; i++ {
		tracker.RecordFailure("srv-flaky")
		if !tracker.IsUnhealthy("srv-flaky") {
			t.Errorf("Iteration %d: should be unhealthy after failure", i)
		}
		tracker.RecordSuccess("srv-flaky")
		if tracker.IsUnhealthy("srv-flaky") {
			t.Errorf("Iteration %d: should be healthy after success", i)
		}
	}
}

// TestIsSuccessErrCode validates common.IsSuccessErrCode helper function.
// Per nhp/common/errors.go, success is indicated by "" or "0".
func TestIsSuccessErrCode(t *testing.T) {
	tests := []struct {
		name      string
		errCode   string
		isSuccess bool
	}{
		{"empty string is success", "", true},
		{"0 is success", "0", true},
		{"SUCCESS string is not success", "SUCCESS", false},
		{"error code is not success", "LICENSE_EXPIRED", false},
		{"numeric error is not success", "50001", false},
		{"1 is not success", "1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isSuccess := common.IsSuccessErrCode(tt.errCode)
			if isSuccess != tt.isSuccess {
				t.Errorf("IsSuccessErrCode(%q): got %v, want %v", tt.errCode, isSuccess, tt.isSuccess)
			}
		})
	}
}

// ============================================================================
// getOrCreateServerPeer Regression Tests
// ============================================================================

// TestGetOrCreateServerPeer_UsesStaticIP verifies that server peers use the
// static InternalIP field for addressing, NOT DNS resolution of the server ID.
// Regression test: previously target.ID was set as Hostname, causing DNS
// resolution of identifiers like "server-b" to random IPs.
func TestGetOrCreateServerPeer_UsesStaticIP(t *testing.T) {
	device := core.NewDevice(core.NHP_SERVER, make([]byte, 32), nil)
	if device == nil {
		t.Fatal("failed to create device")
	}
	device.Start()
	defer device.Stop()

	forwarder := &ServerForwarder{
		health:      NewServerHealthTracker(),
		pendingFwds: make(map[uint64]*PendingForward),
		serverPeers: make(map[string]*core.UdpPeer),
		deps:        &testForwarderDepsWithDevice{device: device},
	}

	target := ServerInfo{
		ID:         "non-resolvable-server-id", // NOT a valid hostname
		InternalIP: "10.0.1.50",
		Port:       common.DefaultNHPPort,
		PubKey:     device.PublicKeyBase64(), // self-key for simplicity
	}

	peer, err := forwarder.getOrCreateServerPeer(target)
	if err != nil {
		t.Fatalf("getOrCreateServerPeer failed: %v", err)
	}

	addr := peer.SendAddr()
	if addr == nil {
		t.Fatal("SendAddr() returned nil — peer has no valid address")
	}

	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		t.Fatalf("expected *net.UDPAddr, got %T", addr)
	}

	if udpAddr.IP.String() != "10.0.1.50" {
		t.Errorf("expected IP 10.0.1.50, got %s (DNS resolution of server ID?)", udpAddr.IP)
	}
	if udpAddr.Port != common.DefaultNHPPort {
		t.Errorf("expected port %d, got %d", common.DefaultNHPPort, udpAddr.Port)
	}
}

type captureSendForwarderDeps struct {
	*MockForwarderDeps
	err  error
	sent chan *core.MsgData
}

func collectForwardedMessages(t *testing.T, sent <-chan *core.MsgData, want int) []common.ServerForwardMsg {
	t.Helper()

	msgs := collectForwardedMsgData(t, sent, want)
	forwarded := make([]common.ServerForwardMsg, 0, want)
	for _, md := range msgs {
		var fwdMsg common.ServerForwardMsg
		if err := json.Unmarshal(md.Message, &fwdMsg); err != nil {
			t.Fatalf("unmarshal forward message: %v", err)
		}
		forwarded = append(forwarded, fwdMsg)
	}
	return forwarded
}

func collectForwardedMsgData(t *testing.T, sent <-chan *core.MsgData, want int) []*core.MsgData {
	t.Helper()

	forwarded := make([]*core.MsgData, 0, want)
	for len(forwarded) < want {
		select {
		case md := <-sent:
			if md.HeaderType != core.NHP_FWD {
				t.Fatalf("HeaderType=%s, want NHP_FWD", core.HeaderTypeToString(md.HeaderType))
			}
			forwarded = append(forwarded, md)
		case <-time.After(time.Second):
			t.Fatalf("timeout waiting for parallel forwards; got %d, want %d", len(forwarded), want)
		}
	}
	return forwarded
}

func assertForwardedRemoteIPs(t *testing.T, forwarded []*core.MsgData, want []string) {
	t.Helper()

	got := make([]string, 0, len(forwarded))
	for _, md := range forwarded {
		if md.RemoteAddr == nil {
			t.Fatal("RemoteAddr is nil, want *net.UDPAddr")
		}
		got = append(got, md.RemoteAddr.IP.String())
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("forwarded remote IPs = %v, want %v", got, want)
	}
}

func waitForPendingForwardRemoval(t *testing.T, forwarder *ServerForwarder, txID uint64) {
	t.Helper()

	deadline := time.After(time.Second)
	for {
		forwarder.pendingMutex.RLock()
		_, exists := forwarder.pendingFwds[txID]
		forwarder.pendingMutex.RUnlock()
		if !exists {
			return
		}

		select {
		case <-deadline:
			t.Fatalf("timeout waiting for pending forward %d to be removed", txID)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func (d *captureSendForwarderDeps) SendMessage(md *core.MsgData) error {
	if d.sent != nil {
		d.sent <- md
	}
	return d.err
}

type captureBroadcastForwarderDeps struct {
	*MockForwarderDeps
	capturedResource *common.ResourceData
	capturedOpenTime uint32
}

func (d *captureBroadcastForwarderDeps) ProcessACOperationBroadcast(
	_ context.Context,
	_ *common.AgentKnockMsg,
	_ []*ACConn,
	_ *common.NetAddress,
	_ []*common.NetAddress,
	openTime uint32,
	res *common.ResourceData,
) (*common.ACOpsResultMsg, error) {
	d.capturedOpenTime = openTime
	d.capturedResource = cloneResourceData(res)
	return &common.ACOpsResultMsg{
		ErrCode:  common.ErrSuccess.ErrorCode(),
		ACToken:  "tok-forwarded",
		OpenTime: openTime,
	}, nil
}

// testForwarderDepsWithDevice is a minimal ForwarderDeps for unit tests that
// only need GetDevice().
type testForwarderDepsWithDevice struct {
	device *core.Device
}

func (d *testForwarderDepsWithDevice) GetHostname() string             { return "test-server" }
func (d *testForwarderDepsWithDevice) GetDevice() *core.Device         { return d.device }
func (d *testForwarderDepsWithDevice) SendMessage(*core.MsgData) error { return nil }
func (d *testForwarderDepsWithDevice) IncrForwarderMetric(string)      {}
func (d *testForwarderDepsWithDevice) FindACConnectionsForResource(*common.AgentKnockMsg, *common.ResourceData) []*ACConn {
	return nil
}
func (d *testForwarderDepsWithDevice) FindAuthSvcProvider(string) *common.AuthServiceProviderData {
	return nil
}
func (d *testForwarderDepsWithDevice) ResolveAuthSvcProvider(context.Context, string, string) *common.AuthServiceProviderData {
	return nil
}
func (d *testForwarderDepsWithDevice) LifecycleCtx() context.Context {
	return context.Background()
}
func (d *testForwarderDepsWithDevice) ProcessACOperation(*common.AgentKnockMsg, *ACConn, *common.NetAddress, []*common.NetAddress, uint32, *common.ResourceData) (*common.ACOpsResultMsg, error) {
	return nil, nil
}
func (d *testForwarderDepsWithDevice) ProcessACOperationBroadcast(context.Context, *common.AgentKnockMsg, []*ACConn, *common.NetAddress, []*common.NetAddress, uint32, *common.ResourceData) (*common.ACOpsResultMsg, error) {
	return nil, nil
}
func (d *testForwarderDepsWithDevice) PublishACKTokens(context.Context, *common.AgentKnockMsg, *common.ServerKnockAckMsg, string, int, string) error {
	return nil
}

func (d *testForwarderDepsWithDevice) ResolveOwnerIDByPubKey(context.Context, string) string {
	return ""
}
