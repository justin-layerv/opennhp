package acktoken

import (
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"

	"github.com/OpenNHP/opennhp/nhp/common"
)

func TestHashToken_DoesNotPersistRawToken(t *testing.T) {
	const rawToken = "raw-ac-token-secret"

	got := HashToken(rawToken)
	if got == rawToken {
		t.Fatal("HashToken returned the raw token")
	}
	if len(got) != 64 {
		t.Fatalf("HashToken length = %d, want 64 hex chars", len(got))
	}
	if strings.Contains(got, rawToken) {
		t.Fatalf("HashToken output contains raw token material: %q", got)
	}
	if got != HashToken(rawToken) {
		t.Fatal("HashToken is not deterministic")
	}
}

func TestItemRoundTrip(t *testing.T) {
	expire := time.Now().Add(60 * time.Second).UTC().Round(time.Nanosecond)
	entry := &ACTokenEntry{
		User: &common.AgentUser{
			UserId:         "user-1",
			DeviceId:       "device-1",
			OrganizationId: "org-1",
			AuthServiceId:  "asp-1",
			OwnerId:        "owner-1",
		},
		ResourceId: "resource-1",
		KnockSrcIP: "203.0.113.12",
		RunID:      "run-1",
		OpenTime:   60,
		ExpireTime: expire,
	}

	item := ItemFromEntry("raw-token", entry)
	if item.TokenHash == "" || item.TokenHash == "raw-token" {
		t.Fatalf("TokenHash = %q, want hashed token", item.TokenHash)
	}
	if item.TTL != expire.Unix()+ttlGraceSeconds {
		t.Fatalf("TTL = %d, want %d", item.TTL, expire.Unix()+ttlGraceSeconds)
	}
	if item.OpenTime != 60 {
		t.Fatalf("OpenTime = %d, want 60", item.OpenTime)
	}

	got := EntryFromItem(item)
	if got.User == nil {
		t.Fatal("round-tripped entry User is nil")
	}
	if got.User.UserId != "user-1" || got.User.OwnerId != "owner-1" {
		t.Fatalf("round-tripped user = %+v, want user_id and owner_id preserved", got.User)
	}
	if got.ResourceId != "resource-1" {
		t.Fatalf("ResourceId = %q, want resource-1", got.ResourceId)
	}
	if got.KnockSrcIP != "203.0.113.12" {
		t.Fatalf("KnockSrcIP = %q, want 203.0.113.12", got.KnockSrcIP)
	}
	if got.RunID != "run-1" {
		t.Fatalf("RunID = %q, want run-1", got.RunID)
	}
	if got.OpenTime != 60 {
		t.Fatalf("OpenTime = %d, want 60", got.OpenTime)
	}
	if !got.ExpireTime.Equal(expire) {
		t.Fatalf("ExpireTime = %v, want %v", got.ExpireTime, expire)
	}
}

func TestItemRoundTrip_NilUserPreserved(t *testing.T) {
	expire := time.Now().Add(60 * time.Second).UTC().Round(time.Nanosecond)
	entry := &ACTokenEntry{
		User:       nil,
		ResourceId: "resource-no-user",
		KnockSrcIP: "203.0.113.13",
		RunID:      "run-no-user",
		OpenTime:   30,
		ExpireTime: expire,
	}

	got := EntryFromItem(ItemFromEntry("raw-token-no-user", entry))
	if got.User != nil {
		t.Fatalf("round-tripped entry User = %+v, want nil", got.User)
	}
	if got.ResourceId != "resource-no-user" {
		t.Fatalf("ResourceId = %q, want resource-no-user", got.ResourceId)
	}
	if got.KnockSrcIP != "203.0.113.13" {
		t.Fatalf("KnockSrcIP = %q, want 203.0.113.13", got.KnockSrcIP)
	}
	if got.RunID != "run-no-user" {
		t.Fatalf("RunID = %q, want run-no-user", got.RunID)
	}
	if got.OpenTime != 30 {
		t.Fatalf("OpenTime = %d, want 30", got.OpenTime)
	}
	if !got.ExpireTime.Equal(expire) {
		t.Fatalf("ExpireTime = %v, want %v", got.ExpireTime, expire)
	}
	if got.ACTokens == nil || len(got.ACTokens) != 0 {
		t.Fatalf("ACTokens = %+v, want non-nil empty map", got.ACTokens)
	}
}

func TestItemRoundTrip_EmptyUserPreserved(t *testing.T) {
	expire := time.Now().Add(60 * time.Second).UTC().Round(time.Nanosecond)
	entry := &ACTokenEntry{
		User:       &common.AgentUser{},
		ResourceId: "resource-empty-user",
		KnockSrcIP: "203.0.113.14",
		RunID:      "run-empty-user",
		OpenTime:   30,
		ExpireTime: expire,
	}

	item := ItemFromEntry("raw-token-empty-user", entry)
	if !item.UserPresent {
		t.Fatal("UserPresent = false, want true for non-nil empty user")
	}
	got := EntryFromItem(item)
	if got.User == nil {
		t.Fatal("round-tripped entry User is nil, want non-nil empty user")
	}
	if got.User.UserId != "" || got.User.OwnerId != "" {
		t.Fatalf("round-tripped user = %+v, want empty identity fields", got.User)
	}
}

func TestItem_DynamoDBAttributeValueRoundTrip(t *testing.T) {
	expire := time.Now().Add(60 * time.Second).UTC().Round(time.Nanosecond)
	entry := &ACTokenEntry{
		User:       &common.AgentUser{},
		ResourceId: "resource-ddb-av",
		KnockSrcIP: "203.0.113.15",
		RunID:      "run-ddb-av",
		OpenTime:   45,
		ExpireTime: expire,
	}

	av, err := attributevalue.MarshalMap(ItemFromEntry("raw-token-ddb-av", entry))
	if err != nil {
		t.Fatalf("MarshalMap: %v", err)
	}
	if _, ok := av["user_present"]; !ok {
		t.Fatalf("MarshalMap did not include user_present for non-nil empty User: keys=%v", av)
	}
	var item PersistedItem
	if err := attributevalue.UnmarshalMap(av, &item); err != nil {
		t.Fatalf("UnmarshalMap: %v", err)
	}
	got := EntryFromItem(item)
	if got.User == nil {
		t.Fatal("DynamoDB attributevalue round-trip User is nil, want non-nil empty user")
	}
	if got.ResourceId != "resource-ddb-av" || got.OpenTime != 45 || !got.ExpireTime.Equal(expire) {
		t.Fatalf("round-tripped entry = %+v, want resource/open/expire preserved", got)
	}
}
