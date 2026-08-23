package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

func testReadyTargetAttachment(t *testing.T) (sessionControlTargetAttachment, sessionControlOwnerAuthority) {
	t.Helper()
	store := newMemorySessionControlStore(time.Unix(1_800_020_000, 0).UTC())
	candidate := testSessionControlTargetCandidate(0xb1, "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1", 9)
	prepared, err := store.PrepareTarget(context.Background(), candidate)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.SnapshotActiveFences(context.Background(), candidate.ControlCellID)
	if err != nil {
		t.Fatal(err)
	}
	active, err := store.ActivateTarget(context.Background(), prepared.Target.fence().activation(snapshot.DirectoryVersion))
	if err != nil {
		t.Fatal(err)
	}
	ready, err := store.FinalizeTargetReady(context.Background(),
		active.fence().readiness(*snapshot, active.PreparedAtMillis+1, 91))
	if err != nil {
		t.Fatal(err)
	}
	owner := store.owners[ready.key()]
	attachment := sessionControlTargetAttachment{Candidate: candidate, Target: *ready, Snapshot: *snapshot}
	if !validSessionControlTargetAttachment(attachment) ||
		!sessionControlReadyAttachmentExact(*ready, owner, attachment) {
		t.Fatalf("invalid ready attachment fixture: %#v / %#v", attachment, owner)
	}
	return attachment, owner
}

func seedReadyTargetAttachment(t *testing.T, fake *sessionControlSessionDynamoFake,
	attachment sessionControlTargetAttachment, owner sessionControlOwnerAuthority,
) {
	t.Helper()
	targetRow, err := sessionControlTargetToRow(attachment.Target)
	if err != nil {
		t.Fatal(err)
	}
	ownerRow, err := sessionControlOwnerToRow(owner)
	if err != nil {
		t.Fatal(err)
	}
	targetItem, err := attributevalue.MarshalMap(targetRow)
	if err != nil {
		t.Fatal(err)
	}
	ownerItem, err := attributevalue.MarshalMap(ownerRow)
	if err != nil {
		t.Fatal(err)
	}
	fake.setItem(targetItem)
	fake.setItem(ownerItem)
	seedSessionControlDirectory(t, fake, attachment.Snapshot)
}

func TestDynamoSessionControlVerifyReadyTargetAttachmentExactConditionTransaction(t *testing.T) {
	attachment, owner := testReadyTargetAttachment(t)
	fake := newSessionControlSessionDynamoFake()
	seedReadyTargetAttachment(t, fake, attachment, owner)
	store := newSessionControlSessionDynamoStore(fake, time.Second)
	got, err := store.VerifyReadyTargetAttachment(context.Background(), attachment)
	if err != nil || got == nil || *got != attachment.Target {
		t.Fatalf("VerifyReadyTargetAttachment() = %#v, %v", got, err)
	}
	if len(fake.transactions) != 1 {
		t.Fatalf("transactions = %d, want 1", len(fake.transactions))
	}
	txn := fake.transactions[0]
	if txn.ClientRequestToken == nil || len(*txn.ClientRequestToken) > 36 {
		t.Fatalf("client token = %#v", txn.ClientRequestToken)
	}
	if len(txn.TransactItems) != 3 {
		t.Fatalf("transaction members = %d, want 3", len(txn.TransactItems))
	}
	wantKeys := []string{
		sessionControlSessionDynamoMapKey(sessionControlTargetDynamoKey(attachment.Target.key())),
		sessionControlSessionDynamoMapKey(sessionControlOwnerKey(owner.CellID, owner.ACID, owner.PublicKey)),
		sessionControlSessionDynamoMapKey(sessionControlFenceDirectoryKey(attachment.Snapshot.CellID)),
	}
	for i, member := range txn.TransactItems {
		if member.ConditionCheck == nil || member.Put != nil || member.Update != nil || member.Delete != nil {
			t.Fatalf("member %d = %#v, want ConditionCheck only", i, member)
		}
		if gotKey := sessionControlSessionDynamoMapKey(member.ConditionCheck.Key); gotKey != wantKeys[i] {
			t.Fatalf("member %d key = %q, want %q", i, gotKey, wantKeys[i])
		}
	}
	for i, read := range fake.gets {
		if read.ConsistentRead == nil || !*read.ConsistentRead {
			t.Fatalf("GetItem %d was not strongly consistent", i)
		}
	}

	mutatedOwner := owner
	mutatedOwner.WorkVersion++
	if *sessionControlAttachmentToken(attachment, owner) == *sessionControlAttachmentToken(attachment, mutatedOwner) {
		t.Fatal("attachment token ignored owner work-version mutation")
	}
}

func TestDynamoSessionControlVerifyReadyTargetAttachmentConditionalCancellationNeverSucceeds(t *testing.T) {
	for _, mutation := range []struct {
		name  string
		apply func(*testing.T, *sessionControlSessionDynamoFake, sessionControlTargetAttachment, sessionControlOwnerAuthority)
	}{
		{name: "exact state still fails", apply: func(*testing.T, *sessionControlSessionDynamoFake, sessionControlTargetAttachment, sessionControlOwnerAuthority) {
		}},
		{name: "target generation", apply: func(t *testing.T, fake *sessionControlSessionDynamoFake, attachment sessionControlTargetAttachment, _ sessionControlOwnerAuthority) {
			target := attachment.Target
			target.BootID = "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"
			row, err := sessionControlTargetToRow(target)
			if err != nil {
				t.Fatal(err)
			}
			item, err := attributevalue.MarshalMap(row)
			if err != nil {
				t.Fatal(err)
			}
			fake.setItem(item)
		}},
		{name: "owner task inserted", apply: func(t *testing.T, fake *sessionControlSessionDynamoFake, _ sessionControlTargetAttachment, owner sessionControlOwnerAuthority) {
			owner.WorkVersion++
			owner.TaskCount++
			owner.PendingCount++
			owner.Phase = sessionControlOwnerActiveUnready
			row, err := sessionControlOwnerToRow(owner)
			if err != nil {
				t.Fatal(err)
			}
			item, err := attributevalue.MarshalMap(row)
			if err != nil {
				t.Fatal(err)
			}
			fake.setItem(item)
		}},
		{name: "directory advanced", apply: func(t *testing.T, fake *sessionControlSessionDynamoFake, attachment sessionControlTargetAttachment, _ sessionControlOwnerAuthority) {
			snapshot := attachment.Snapshot
			snapshot.DirectoryVersion++
			seedSessionControlDirectory(t, fake, snapshot)
		}},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			attachment, owner := testReadyTargetAttachment(t)
			fake := newSessionControlSessionDynamoFake()
			seedReadyTargetAttachment(t, fake, attachment, owner)
			fake.transactHook = func(context.Context, *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
				mutation.apply(t, fake, attachment, owner)
				return nil, &types.TransactionCanceledException{}
			}
			store := newSessionControlSessionDynamoStore(fake, time.Second)
			if got, err := store.VerifyReadyTargetAttachment(context.Background(), attachment); err == nil || got != nil {
				t.Fatalf("VerifyReadyTargetAttachment() = %#v, %v; conditional cancellation must fail", got, err)
			}
		})
	}
}

func TestDynamoSessionControlVerifyReadyTargetAttachmentLostResponseClassification(t *testing.T) {
	t.Run("exact authority remains publishable", func(t *testing.T) {
		attachment, owner := testReadyTargetAttachment(t)
		fake := newSessionControlSessionDynamoFake()
		seedReadyTargetAttachment(t, fake, attachment, owner)
		fake.transactHook = func(context.Context, *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
			return nil, errors.New("lost response")
		}
		store := newSessionControlSessionDynamoStore(fake, time.Second)
		got, err := store.VerifyReadyTargetAttachment(context.Background(), attachment)
		if err != nil || got == nil || *got != attachment.Target {
			t.Fatalf("lost-response classification = %#v, %v", got, err)
		}
	})
	t.Run("drift after ambiguous send fails closed", func(t *testing.T) {
		attachment, owner := testReadyTargetAttachment(t)
		fake := newSessionControlSessionDynamoFake()
		seedReadyTargetAttachment(t, fake, attachment, owner)
		fake.transactHook = func(context.Context, *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
			owner.WorkVersion++
			owner.TaskCount++
			owner.PendingCount++
			owner.Phase = sessionControlOwnerActiveUnready
			row, err := sessionControlOwnerToRow(owner)
			if err != nil {
				return nil, err
			}
			item, err := attributevalue.MarshalMap(row)
			if err != nil {
				return nil, err
			}
			fake.setItem(item)
			return nil, errors.New("lost response")
		}
		store := newSessionControlSessionDynamoStore(fake, time.Second)
		if got, err := store.VerifyReadyTargetAttachment(context.Background(), attachment); err == nil || got != nil {
			t.Fatalf("drifted lost-response classification = %#v, %v", got, err)
		}
	})
}
