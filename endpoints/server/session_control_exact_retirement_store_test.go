package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

func TestDynamoSessionControlResolveExactSessionForCloseBindsFullCandidateAndMembership(t *testing.T) {
	directory := sessionControlCloseTestDirectory(testSessionControlSessionSnapshot(7), 1_800_000_000_000)
	fake, store, reserved := newSessionControlExactCloseFixture(t, directory)
	selector := sessionControlExactRetirementSelectorForCandidate(reserved.Candidate)
	got, err := store.ResolveExactSessionForClose(context.Background(), selector)
	if err != nil {
		t.Fatalf("ResolveExactSessionForClose: %v", err)
	}
	if got == nil || *got != reserved {
		t.Fatalf("resolved authority = %#v, want %#v", got, reserved)
	}
	if len(fake.gets) != 2 || fake.gets[0].ConsistentRead == nil || !*fake.gets[0].ConsistentRead ||
		fake.gets[1].ConsistentRead == nil || !*fake.gets[1].ConsistentRead {
		t.Fatalf("strong exact close reads = %#v", fake.gets)
	}

	for name, mutate := range map[string]func(*sessionControlExactRetirementSelector){
		"cell": func(candidate *sessionControlExactRetirementSelector) { candidate.CellID = "cell-02" },
		"agent": func(candidate *sessionControlExactRetirementSelector) {
			candidate.AgentPublicKey = testACSessionControlPublicKey(0x92)
		},
		"session": func(candidate *sessionControlExactRetirementSelector) { candidate.SessionID++ },
		"issuance": func(candidate *sessionControlExactRetirementSelector) {
			candidate.IssuedAtMillis++
		},
		"run":         func(candidate *sessionControlExactRetirementSelector) { candidate.RunID = "fedcba9876543210" },
		"run attempt": func(candidate *sessionControlExactRetirementSelector) { candidate.RunAttempt++ },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := selector
			mutate(&candidate)
			if _, err := store.ResolveExactSessionForClose(context.Background(), candidate); err == nil {
				t.Fatalf("mutated candidate resolved: %#v", candidate)
			}
		})
	}

	delete(fake.items, sessionControlSessionDynamoMapKey(sessionControlAgentSessionDynamoKey(reserved.Candidate)))
	if _, err := store.ResolveExactSessionForClose(context.Background(), selector); !errors.Is(err, errSessionControlSessionCorrupt) {
		t.Fatalf("missing membership error = %v, want corrupt", err)
	}
}

func TestDynamoSessionControlResolveExactSessionForClosePreservesOperationalErrors(t *testing.T) {
	directory := sessionControlCloseTestDirectory(testSessionControlSessionSnapshot(7), 1_800_000_000_000)
	fake, store, reserved := newSessionControlExactCloseFixture(t, directory)
	selector := sessionControlExactRetirementSelectorForCandidate(reserved.Candidate)
	sentinel := errors.New("membership transport")
	fake.getHook = func(_ context.Context, input *dynamodb.GetItemInput, call int) (*dynamodb.GetItemOutput, error) {
		if call == 1 {
			return nil, sentinel
		}
		fake.mu.Lock()
		defer fake.mu.Unlock()
		return &dynamodb.GetItemOutput{Item: fake.items[sessionControlSessionDynamoMapKey(input.Key)]}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := store.ResolveExactSessionForClose(ctx, selector)
	if !errors.Is(err, sentinel) || errors.Is(err, errSessionControlSessionCorrupt) {
		t.Fatalf("operational error = %v, want preserved sentinel", err)
	}
}

func TestDynamoSessionControlResolveExactSessionForCloseRequiresImmutableClosedAudit(t *testing.T) {
	fixture := newSessionControlTerminalFixture(t, 0)
	closed, err := fixture.store.FinalizeTerminalExactClose(context.Background(), fixture.candidate, fixture.close.EventID)
	if err != nil {
		t.Fatal(err)
	}
	selector := sessionControlExactRetirementSelectorForCandidate(fixture.candidate)
	resolved, err := fixture.store.ResolveExactSessionForClose(context.Background(), selector)
	if err != nil {
		t.Fatalf("resolve terminal session: %v", err)
	}
	if resolved == nil || *resolved != closed.SessionAfter || resolved.CloseEventID != sessionControlExactCloseEventID(fixture.candidate) {
		t.Fatalf("resolved terminal authority = %#v, want %#v", resolved, closed.SessionAfter)
	}

	delete(fixture.fake.items, sessionControlSessionDynamoMapKey(sessionControlCloseClosedKey(fixture.close.EventID)))
	if _, err := fixture.store.ResolveExactSessionForClose(context.Background(), selector); !errors.Is(err, errSessionControlSessionCorrupt) {
		t.Fatalf("missing immutable CLOSED audit error = %v, want corrupt", err)
	}
}
