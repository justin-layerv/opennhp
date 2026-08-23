package server

import (
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

func testSessionControlReadyOwner(t *testing.T, seed byte) (sessionControlTargetAuthority, sessionControlOwnerAuthority) {
	t.Helper()
	candidate := testSessionControlTargetCandidate(seed, "00112233445566778899aabbccddeeff", 7)
	preparing := testSessionControlTargetAuthority(candidate, sessionControlTargetPreparing, 1)
	preparingOwner, err := sessionControlOwnerFromTarget(preparing, nil, sessionControlOwnerPreparing)
	if err != nil {
		t.Fatal(err)
	}
	active := preparing
	active.State = sessionControlTargetActive
	active.Version++
	active.AuthorityVersion++
	active.CountedActiveSlot = true
	active.ActivatedControlVersion = 4
	activeOwner, err := sessionControlOwnerFromTarget(active, &preparingOwner, sessionControlOwnerActiveUnready)
	if err != nil {
		t.Fatal(err)
	}
	ready := active
	ready.Version++
	ready.ReadyControlVersion = ready.ActivatedControlVersion
	ready.AAKEnqueuedAtMillis = ready.PreparedAtMillis + 1
	ready.AAKTransactionID = 99
	ready.UpdatedAtMillis = ready.AAKEnqueuedAtMillis
	readyOwner, err := sessionControlOwnerFromTarget(ready, &activeOwner, sessionControlOwnerReady)
	if err != nil {
		t.Fatal(err)
	}
	return ready, readyOwner
}

func TestSessionControlOwnerLifecycleWorkAndReconnect(t *testing.T) {
	ready, owner := testSessionControlReadyOwner(t, 0xc1)
	if owner.LifecycleVersion != 3 || owner.WorkVersion != 1 || owner.Phase != sessionControlOwnerReady ||
		owner.TaskCount != 0 || owner.PendingCount != 0 || !owner.exactTarget(ready, sessionControlOwnerReady) {
		t.Fatalf("ready owner = %#v", owner)
	}

	inserted, err := planSessionControlOwnerTaskInsert(owner, owner.UpdatedAtMillis+1)
	if err != nil || inserted.WorkVersion != 2 || inserted.TaskCount != 1 || inserted.PendingCount != 1 ||
		inserted.Phase != sessionControlOwnerActiveUnready || inserted.ReadyControlVersion != ready.ReadyControlVersion {
		t.Fatalf("task insertion = %#v, %v", inserted, err)
	}
	acked, err := planSessionControlOwnerTaskAck(inserted, inserted.UpdatedAtMillis+1)
	if err != nil || acked.WorkVersion != 3 || acked.TaskCount != 1 || acked.PendingCount != 0 ||
		acked.Phase != sessionControlOwnerReady {
		t.Fatalf("task ack = %#v, %v", acked, err)
	}
	cleaned, err := planSessionControlOwnerTaskCleanup(acked, acked.UpdatedAtMillis+1)
	if err != nil || cleaned.WorkVersion != 4 || cleaned.TaskCount != 0 || cleaned.PendingCount != 0 {
		t.Fatalf("task cleanup = %#v, %v", cleaned, err)
	}

	reconnect := ready
	reconnect.State = sessionControlTargetPreparing
	reconnect.Version++
	reconnect.BootID = "11112222333344445555666677778888"
	reconnect.FlushGeneration++
	reconnect.ActivatedControlVersion = 0
	reconnect.ReadyControlVersion = 0
	reconnect.AAKEnqueuedAtMillis = 0
	reconnect.AAKTransactionID = 0
	reconnect.PreparedAtMillis++
	reconnect.UpdatedAtMillis = reconnect.PreparedAtMillis
	reconnected, err := sessionControlOwnerFromTarget(reconnect, &cleaned, sessionControlOwnerPreparing)
	if err != nil || reconnected.LifecycleVersion != cleaned.LifecycleVersion+1 ||
		reconnected.WorkVersion != cleaned.WorkVersion || reconnected.TaskCount != 0 ||
		reconnected.PendingCount != 0 || reconnected.Phase != sessionControlOwnerPreparing ||
		reconnected.ReadyControlVersion != 0 || reconnected.AAKTransactionID != 0 {
		t.Fatalf("reconnected owner = %#v, %v", reconnected, err)
	}
	if sessionControlOwnerPK(owner.CellID, owner.ACID, owner.PublicKey) !=
		sessionControlOwnerPK(reconnected.CellID, reconnected.ACID, reconnected.PublicKey) {
		t.Fatal("stable owner key changed across reconnect")
	}
}

func TestSessionControlOwnerPhysicalTaskCapAndRetirement(t *testing.T) {
	_, owner := testSessionControlReadyOwner(t, 0xc2)
	impossible := owner
	impossible.Phase = sessionControlOwnerActiveUnready
	if err := validateSessionControlOwnerAuthority(impossible); !errors.Is(err, errSessionControlOwnerCorrupt) {
		t.Fatalf("ready-cursor active-unready owner without pending work error = %v, want corrupt", err)
	}
	owner.TaskCount = sessionControlFenceActiveLimit
	atReservedSlot, err := planSessionControlOwnerTaskInsert(owner, owner.UpdatedAtMillis)
	if err != nil || atReservedSlot.TaskCount != sessionControlOwnerTaskLimit || atReservedSlot.PendingCount != 1 {
		t.Fatalf("1025th owner task = %#v, %v", atReservedSlot, err)
	}
	if _, err := planSessionControlOwnerTaskInsert(atReservedSlot, owner.UpdatedAtMillis); !errors.Is(err, errSessionControlOwnerCapacity) {
		t.Fatalf("1026th owner task error = %v, want capacity", err)
	}

	retired := owner
	retired.Phase = sessionControlOwnerRetired
	retired.TargetCountedActiveSlot = false
	retired.RetiredAtMillis = retired.UpdatedAtMillis
	if err := validateSessionControlOwnerAuthority(retired); !errors.Is(err, errSessionControlOwnerCorrupt) {
		t.Fatalf("retired owner with residual tasks error = %v, want corrupt", err)
	}
	retired.TaskCount = 0
	if err := validateSessionControlOwnerAuthority(retired); err != nil {
		t.Fatalf("empty retired owner error = %v", err)
	}
}

func TestSessionControlOwnerRequiredPresenceAndTTL(t *testing.T) {
	_, owner := testSessionControlReadyOwner(t, 0xc3)
	row, err := sessionControlOwnerToRow(owner)
	if err != nil {
		t.Fatal(err)
	}
	item := marshalSessionControlSessionTestRow(t, row)
	for _, field := range []string{"lifecycle_version", "work_version", "task_count", "pending_count", "ready_control_version"} {
		t.Run(field, func(t *testing.T) {
			copy := make(map[string]types.AttributeValue, len(item))
			for key, value := range item {
				copy[key] = value
			}
			delete(copy, field)
			if _, err := sessionControlOwnerFromItem(copy, owner.CellID, owner.ACID, owner.PublicKey); !errors.Is(err, errSessionControlOwnerCorrupt) {
				t.Fatalf("missing %s error = %v", field, err)
			}
		})
	}
	item["ttl"] = &types.AttributeValueMemberN{Value: "1"}
	if _, err := sessionControlOwnerFromItem(item, owner.CellID, owner.ACID, owner.PublicKey); !errors.Is(err, errSessionControlOwnerCorrupt) {
		t.Fatalf("TTL-bearing owner error = %v", err)
	}
}

func TestSessionControlOwnerTransitionTokenBindsFullAuthority(t *testing.T) {
	_, current := testSessionControlReadyOwner(t, 0xc4)
	next, err := planSessionControlOwnerTaskInsert(current, current.UpdatedAtMillis+1)
	if err != nil {
		t.Fatal(err)
	}
	base := aws.ToString(sessionControlOwnerTransitionToken("ready", &current, next))
	if base == "" || len(base) > 36 || base != aws.ToString(sessionControlOwnerTransitionToken("ready", &current, next)) {
		t.Fatalf("unstable owner token = %q", base)
	}
	mutations := map[string]func(*sessionControlOwnerAuthority){
		"cell":             func(value *sessionControlOwnerAuthority) { value.CellID += "x" },
		"ac":               func(value *sessionControlOwnerAuthority) { value.ACID += "x" },
		"key":              func(value *sessionControlOwnerAuthority) { value.PublicKey += "x" },
		"lifecycle":        func(value *sessionControlOwnerAuthority) { value.LifecycleVersion++ },
		"work":             func(value *sessionControlOwnerAuthority) { value.WorkVersion++ },
		"tasks":            func(value *sessionControlOwnerAuthority) { value.TaskCount++ },
		"pending":          func(value *sessionControlOwnerAuthority) { value.PendingCount++ },
		"phase":            func(value *sessionControlOwnerAuthority) { value.Phase += "x" },
		"boot":             func(value *sessionControlOwnerAuthority) { value.BootID += "x" },
		"flush":            func(value *sessionControlOwnerAuthority) { value.FlushGeneration++ },
		"target version":   func(value *sessionControlOwnerAuthority) { value.TargetVersion++ },
		"target authority": func(value *sessionControlOwnerAuthority) { value.TargetAuthorityVersion++ },
		"target counted": func(value *sessionControlOwnerAuthority) {
			value.TargetCountedActiveSlot = !value.TargetCountedActiveSlot
		},
		"activated cursor": func(value *sessionControlOwnerAuthority) { value.ActivatedControlVersion++ },
		"ready cursor":     func(value *sessionControlOwnerAuthority) { value.ReadyControlVersion++ },
		"target created":   func(value *sessionControlOwnerAuthority) { value.TargetCreatedAtMillis++ },
		"target prepared":  func(value *sessionControlOwnerAuthority) { value.TargetPreparedAtMillis++ },
		"target updated":   func(value *sessionControlOwnerAuthority) { value.TargetUpdatedAtMillis++ },
		"aak at":           func(value *sessionControlOwnerAuthority) { value.AAKEnqueuedAtMillis++ },
		"aak id":           func(value *sessionControlOwnerAuthority) { value.AAKTransactionID++ },
		"created":          func(value *sessionControlOwnerAuthority) { value.CreatedAtMillis++ },
		"updated":          func(value *sessionControlOwnerAuthority) { value.UpdatedAtMillis++ },
		"retired":          func(value *sessionControlOwnerAuthority) { value.RetiredAtMillis++ },
	}
	for name, mutate := range mutations {
		t.Run("current "+name, func(t *testing.T) {
			changed := current
			mutate(&changed)
			if got := aws.ToString(sessionControlOwnerTransitionToken("ready", &changed, next)); got == base || len(got) > 36 {
				t.Fatalf("current mutation reused token %q", got)
			}
		})
		t.Run("next "+name, func(t *testing.T) {
			changed := next
			mutate(&changed)
			if got := aws.ToString(sessionControlOwnerTransitionToken("ready", &current, changed)); got == base || len(got) > 36 {
				t.Fatalf("next mutation reused token %q", got)
			}
		})
	}
	if got := aws.ToString(sessionControlOwnerTransitionToken("activate", &current, next)); got == base {
		t.Fatalf("action reused token %q", got)
	}
	if got := aws.ToString(sessionControlOwnerTransitionToken("ready", nil, next)); got == base {
		t.Fatalf("absent current reused token %q", got)
	}
}
