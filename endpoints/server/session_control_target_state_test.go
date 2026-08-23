package server

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

const testSessionControlCellID = "cell-01"

func testSessionControlTargetCandidate(seed byte, bootID string, generation uint64) sessionControlTargetCandidate {
	return sessionControlTargetCandidate{
		ACID:            "ac-session-authority",
		PublicKey:       testACSessionControlPublicKey(seed),
		BootID:          bootID,
		FlushGeneration: generation,
		ControlCellID:   testSessionControlCellID,
	}
}

func requireRequiredTargetCount(t *testing.T, store sessionControlStore, acID string, want int) []sessionControlTargetAuthority {
	t.Helper()
	targets, err := store.ListRequiredTargets(context.Background(), acID, testSessionControlCellID)
	if err != nil {
		t.Fatalf("ListRequiredTargets() error = %v", err)
	}
	if len(targets) != want {
		t.Fatalf("required target count = %d, want %d: %#v", len(targets), want, targets)
	}
	return targets
}

func TestSessionControlTargetLifecycleFailsClosed(t *testing.T) {
	const bootID = "00112233445566778899aabbccddeeff"
	store := newMemorySessionControlStore(time.Unix(1_800_000_000, 0))
	candidate := testSessionControlTargetCandidate(0x31, bootID, 7)

	prepared, err := store.PrepareTarget(context.Background(), candidate)
	if err != nil {
		t.Fatalf("PrepareTarget() error = %v", err)
	}
	if prepared.Target.State != sessionControlTargetPreparing || prepared.Target.Version != 1 || !prepared.RequiresActivation {
		t.Fatalf("preparation = %#v", prepared)
	}
	requireRequiredTargetCount(t, store, candidate.ACID, 0)

	active, err := store.ActivateTarget(context.Background(), prepared.Target.fence().activation(1))
	if err != nil {
		t.Fatalf("ActivateTarget() error = %v", err)
	}
	if active.State != sessionControlTargetActive || active.Version != 2 ||
		active.ControlCellID != candidate.ControlCellID || active.ActivatedControlVersion != 1 || active.ready() {
		t.Fatalf("active target = %#v", active)
	}
	if authority := store.authorities[candidate.ACID]; authority.ControlCellID != candidate.ControlCellID {
		t.Fatalf("authority cell binding = %#v, want %q", authority, candidate.ControlCellID)
	}
	// An activation response can be lost. Repeating the exact fenced transition
	// is idempotent and must not rotate the durable version again.
	replayed, err := store.ActivateTarget(context.Background(), prepared.Target.fence().activation(1))
	if err != nil || *replayed != *active {
		t.Fatalf("activation replay = %#v, %v; want %#v", replayed, err, active)
	}

	snapshot := sessionControlFenceSnapshot{
		CellID: candidate.ControlCellID, DirectoryVersion: 1,
	}
	ready, err := store.FinalizeTargetReady(context.Background(),
		active.fence().readiness(snapshot, active.PreparedAtMillis+1, 41))
	if err != nil {
		t.Fatalf("FinalizeTargetReady() error = %v", err)
	}
	if !ready.ready() || ready.Version != 3 || ready.ReadyControlVersion != ready.ActivatedControlVersion ||
		ready.AAKTransactionID != 41 {
		t.Fatalf("ready target = %#v", ready)
	}
	required := requireRequiredTargetCount(t, store, candidate.ACID, 1)
	if required[0] != *ready {
		t.Fatalf("required target = %#v, want %#v", required[0], *ready)
	}

	if _, err := store.CancelTargetPreparation(context.Background(), prepared.Target.fence()); !errors.Is(err, errSessionControlTargetConflict) {
		t.Fatalf("delayed cancellation error = %v, want conflict", err)
	}
	requireRequiredTargetCount(t, store, candidate.ACID, 1)

	retired, err := store.retireTarget(context.Background(), ready.fence())
	if err != nil {
		t.Fatalf("RetireTarget() error = %v", err)
	}
	if retired.State != sessionControlTargetRetired || retired.Version != 4 || retired.RetiredAtMillis == 0 {
		t.Fatalf("retired target = %#v", retired)
	}
	requireRequiredTargetCount(t, store, candidate.ACID, 0)

	newBoot := candidate
	newBoot.BootID = "ffeeddccbbaa99887766554433221100"
	newBoot.FlushGeneration++
	if _, err := store.PrepareTarget(context.Background(), newBoot); !errors.Is(err, errSessionControlTargetRetired) {
		t.Fatalf("retired key preparation error = %v, want permanently retired", err)
	}
}

func TestSessionControlTargetReadinessOrdersEventsAndReconnects(t *testing.T) {
	const bootID = "00112233445566778899aabbccddeeff"
	now := time.Unix(1_800_000_000, 0)
	store := newMemorySessionControlStore(now)
	candidate := testSessionControlTargetCandidate(0x5a, bootID, 9)
	prepared, err := store.PrepareTarget(context.Background(), candidate)
	if err != nil {
		t.Fatal(err)
	}
	active, err := store.ActivateTarget(context.Background(), prepared.Target.fence().activation(1))
	if err != nil {
		t.Fatal(err)
	}
	oldSnapshot := sessionControlFenceSnapshot{CellID: candidate.ControlCellID, DirectoryVersion: 1}
	oldReadiness := active.fence().readiness(oldSnapshot, active.PreparedAtMillis+1, 51)

	// Event preparation wins before readiness finalization. Its directory bump
	// fences the old catch-up cursor, leaving the counted target required but
	// ineligible for AOP until a reconnect catches up again.
	store.controlDirectories[candidate.ControlCellID] = sessionControlFenceDirectory{
		CellID: candidate.ControlCellID, Version: 2, ActiveFenceCount: 1,
		CreatedAtMillis: now.UnixMilli(), UpdatedAtMillis: now.UnixMilli() + 1,
	}
	if _, err := store.FinalizeTargetReady(context.Background(), oldReadiness); !errors.Is(err, errSessionControlTargetControlStale) {
		t.Fatalf("event-first finalize error = %v, want stale control", err)
	}
	current, err := store.GetTarget(context.Background(), active.key())
	if err != nil || current.ready() || current.Version != active.Version {
		t.Fatalf("event-first target = %#v, %v; want unchanged unready", current, err)
	}

	reconnect, err := store.PrepareTarget(context.Background(), candidate)
	if err != nil {
		t.Fatal(err)
	}
	if !reconnect.Target.CountedActiveSlot || reconnect.Target.ReadyControlVersion != 0 ||
		reconnect.Target.AAKEnqueuedAtMillis != 0 || reconnect.Target.AAKTransactionID != 0 {
		t.Fatalf("counted reconnect preparation = %#v", reconnect.Target)
	}
	recaught, err := store.ActivateTarget(context.Background(), reconnect.Target.fence().activation(2))
	if err != nil {
		t.Fatal(err)
	}
	newSnapshot := sessionControlFenceSnapshot{CellID: candidate.ControlCellID, DirectoryVersion: 2, ActiveFenceCount: 1}
	ready, err := store.FinalizeTargetReady(context.Background(),
		recaught.fence().readiness(newSnapshot, recaught.PreparedAtMillis+2, 52))
	if err != nil || !ready.ready() {
		t.Fatalf("recaught readiness = %#v, %v", ready, err)
	}

	// Readiness can instead linearize before a later event. A lost finalize
	// response remains exactly idempotent after that event advances CONTROL.
	store.controlDirectories[candidate.ControlCellID] = sessionControlFenceDirectory{
		CellID: candidate.ControlCellID, Version: 3, ActiveFenceCount: 2,
		CreatedAtMillis: now.UnixMilli(), UpdatedAtMillis: now.UnixMilli() + 2,
	}
	replayed, err := store.FinalizeTargetReady(context.Background(),
		recaught.fence().readiness(newSnapshot, recaught.PreparedAtMillis+2, 52))
	if err != nil || *replayed != *ready {
		t.Fatalf("post-directory-bump readiness replay = %#v, %v; want %#v", replayed, err, ready)
	}
}

func TestSessionControlTargetReadinessTokenBindsEveryFence(t *testing.T) {
	target := testSessionControlTargetAuthority(
		testSessionControlTargetCandidate(0x5b, "00112233445566778899aabbccddeeff", 3),
		sessionControlTargetActive, 2)
	readiness := target.fence().readiness(sessionControlFenceSnapshot{
		CellID: target.ControlCellID, DirectoryVersion: target.ActivatedControlVersion,
	}, target.PreparedAtMillis+1, 61)
	base := *sessionControlReadinessToken(readiness)
	if len(base) > 36 {
		t.Fatalf("readiness token length = %d, want <=36: %q", len(base), base)
	}
	tests := map[string]func(*sessionControlTargetReadiness){
		"AC id":             func(value *sessionControlTargetReadiness) { value.Fence.ACID += "-next" },
		"target version":    func(value *sessionControlTargetReadiness) { value.Fence.Version++ },
		"authority version": func(value *sessionControlTargetReadiness) { value.Fence.AuthorityVersion++ },
		"activated cursor":  func(value *sessionControlTargetReadiness) { value.Fence.ActivatedControlVersion++ },
		"current ready cursor": func(value *sessionControlTargetReadiness) {
			value.Fence.ReadyControlVersion++
		},
		"current AAK time":   func(value *sessionControlTargetReadiness) { value.Fence.AAKEnqueuedAtMillis++ },
		"current AAK id":     func(value *sessionControlTargetReadiness) { value.Fence.AAKTransactionID++ },
		"created timestamp":  func(value *sessionControlTargetReadiness) { value.Fence.CreatedAtMillis++ },
		"prepared timestamp": func(value *sessionControlTargetReadiness) { value.Fence.PreparedAtMillis++ },
		"boot id": func(value *sessionControlTargetReadiness) {
			value.Fence.BootID = "ffeeddccbbaa99887766554433221100"
		},
		"flush generation":   func(value *sessionControlTargetReadiness) { value.Fence.FlushGeneration++ },
		"target cell":        func(value *sessionControlTargetReadiness) { value.Fence.ControlCellID = "cell-02" },
		"directory cell":     func(value *sessionControlTargetReadiness) { value.ControlDirectory.CellID = "cell-02" },
		"directory version":  func(value *sessionControlTargetReadiness) { value.ControlDirectory.DirectoryVersion++ },
		"directory count":    func(value *sessionControlTargetReadiness) { value.ControlDirectory.ActiveFenceCount++ },
		"directory latch":    func(value *sessionControlTargetReadiness) { value.ControlDirectory.AdmissionBlocked = true },
		"overflow count":     func(value *sessionControlTargetReadiness) { value.ControlDirectory.OverflowCloseCount++ },
		"AAK timestamp":      func(value *sessionControlTargetReadiness) { value.AAKEnqueuedAtMillis++ },
		"AAK transaction id": func(value *sessionControlTargetReadiness) { value.AAKTransactionID++ },
		"target public key": func(value *sessionControlTargetReadiness) {
			value.Fence.PublicKey = testACSessionControlPublicKey(0x5c)
		},
		"target counted state": func(value *sessionControlTargetReadiness) { value.Fence.CountedActiveSlot = false },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			changed := readiness
			mutate(&changed)
			if token := *sessionControlReadinessToken(changed); token == base || len(token) > 36 {
				t.Fatalf("changed token = %q, base = %q", token, base)
			}
		})
	}
}

func TestSessionControlTargetReadinessRejectsCeilings(t *testing.T) {
	target := testSessionControlTargetAuthority(
		testSessionControlTargetCandidate(0x5d, "00112233445566778899aabbccddeeff", 3),
		sessionControlTargetActive, ^uint64(0)-1)
	readiness := target.fence().readiness(sessionControlFenceSnapshot{
		CellID: target.ControlCellID, DirectoryVersion: target.ActivatedControlVersion,
	}, target.PreparedAtMillis+1, 71)
	if validSessionControlTargetReadiness(readiness) {
		t.Fatal("readiness at target version ceiling accepted")
	}
	target.Version = 2
	readiness = target.fence().readiness(sessionControlFenceSnapshot{
		CellID: target.ControlCellID, DirectoryVersion: target.ActivatedControlVersion,
		ActiveFenceCount: sessionControlFenceActiveLimit + 1,
	}, target.PreparedAtMillis+1, 71)
	if validSessionControlTargetReadiness(readiness) {
		t.Fatal("readiness above active-fence capacity accepted")
	}
}

func TestSessionControlTargetLateGateCancellationFencesDelayedActivation(t *testing.T) {
	const bootID = "11111111111111111111111111111111"
	store := newMemorySessionControlStore(time.Unix(1_800_000_100, 0))
	candidate := testSessionControlTargetCandidate(0x32, bootID, 8)

	first, err := store.PrepareTarget(context.Background(), candidate)
	if err != nil {
		t.Fatal(err)
	}
	canceled, err := store.CancelTargetPreparation(context.Background(), first.Target.fence())
	if err != nil {
		t.Fatalf("CancelTargetPreparation() error = %v", err)
	}
	if canceled.State != sessionControlTargetCanceled || canceled.Version != 2 {
		t.Fatalf("canceled target = %#v", canceled)
	}
	requireRequiredTargetCount(t, store, candidate.ACID, 0)
	if _, err := store.ActivateTarget(context.Background(), first.Target.fence().activation(1)); !errors.Is(err, errSessionControlTargetConflict) {
		t.Fatalf("delayed activation error = %v, want conflict", err)
	}

	retry, err := store.PrepareTarget(context.Background(), candidate)
	if err != nil {
		t.Fatalf("retry PrepareTarget() error = %v", err)
	}
	if retry.Target.State != sessionControlTargetPreparing || retry.Target.Version != 3 || !retry.RequiresActivation {
		t.Fatalf("retry preparation = %#v", retry)
	}
	active, err := store.ActivateTarget(context.Background(), retry.Target.fence().activation(1))
	if err != nil {
		t.Fatalf("retry ActivateTarget() error = %v", err)
	}
	if active.Version != 4 || active.State != sessionControlTargetActive {
		t.Fatalf("retried active target = %#v", active)
	}
	if _, err := store.CancelTargetPreparation(context.Background(), first.Target.fence()); !errors.Is(err, errSessionControlTargetConflict) {
		t.Fatalf("old cancellation after replacement error = %v, want conflict", err)
	}
	requireRequiredTargetCount(t, store, candidate.ACID, 1)
}

func TestSessionControlTargetReplacementIsPreparingUntilFinalCAS(t *testing.T) {
	store := newMemorySessionControlStore(time.Unix(1_800_000_200, 0))
	oldCandidate := testSessionControlTargetCandidate(0x33, "22222222222222222222222222222222", 9)
	oldPreparation, err := store.PrepareTarget(context.Background(), oldCandidate)
	if err != nil {
		t.Fatal(err)
	}
	oldActive, err := store.ActivateTarget(context.Background(), oldPreparation.Target.fence().activation(1))
	if err != nil {
		t.Fatal(err)
	}

	newCandidate := oldCandidate
	newCandidate.BootID = "33333333333333333333333333333333"
	newCandidate.FlushGeneration = 10
	replacement, err := store.PrepareTarget(context.Background(), newCandidate)
	if err != nil {
		t.Fatalf("replacement PrepareTarget() error = %v", err)
	}
	if replacement.Target.State != sessionControlTargetPreparing || replacement.Target.Version != oldActive.Version+1 {
		t.Fatalf("replacement = %#v", replacement)
	}
	requireRequiredTargetCount(t, store, oldCandidate.ACID, 1)
	if _, err := store.ActivateTarget(context.Background(), oldPreparation.Target.fence().activation(1)); !errors.Is(err, errSessionControlTargetConflict) {
		t.Fatalf("old boot activation error = %v, want conflict", err)
	}
	if _, err := store.PrepareTarget(context.Background(), oldCandidate); !errors.Is(err, errSessionControlTargetStale) {
		t.Fatalf("old boot preparation error = %v, want stale", err)
	}
	if _, err := store.ActivateTarget(context.Background(), replacement.Target.fence().activation(1)); err != nil {
		t.Fatalf("replacement ActivateTarget() error = %v", err)
	}
	requireRequiredTargetCount(t, store, oldCandidate.ACID, 1)
}

func TestSessionControlTargetConcurrentSameCandidateIsIdempotent(t *testing.T) {
	store := newMemorySessionControlStore(time.Unix(1_800_000_300, 0))
	candidate := testSessionControlTargetCandidate(0x34, "44444444444444444444444444444444", 11)

	const workers = 32
	preparations := make(chan *sessionControlTargetPreparation, workers)
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			prepared, err := store.PrepareTarget(context.Background(), candidate)
			if err != nil {
				errs <- err
				return
			}
			preparations <- prepared
		}()
	}
	wg.Wait()
	close(preparations)
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent preparation error = %v", err)
	}
	var fence sessionControlTargetFence
	for preparation := range preparations {
		if preparation.Target.State != sessionControlTargetPreparing || preparation.Target.Version != 1 || !preparation.RequiresActivation {
			t.Fatalf("concurrent preparation = %#v", preparation)
		}
		fence = preparation.Target.fence()
	}

	results := make(chan *sessionControlTargetAuthority, workers)
	errs = make(chan error, workers)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			active, err := store.ActivateTarget(context.Background(), fence.activation(1))
			if err != nil {
				errs <- err
				return
			}
			results <- active
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent activation error = %v", err)
	}
	for active := range results {
		if active.State != sessionControlTargetActive || active.Version != 2 {
			t.Fatalf("concurrent activation = %#v", active)
		}
	}
	requireRequiredTargetCount(t, store, candidate.ACID, 1)
}

func TestSessionControlTargetSameTupleReconnectRequiresFreshCatchup(t *testing.T) {
	store := newMemorySessionControlStore(time.Unix(1_800_000_400, 0))
	candidate := testSessionControlTargetCandidate(0x35, "55555555555555555555555555555555", 12)
	first, err := store.PrepareTarget(context.Background(), candidate)
	if err != nil {
		t.Fatal(err)
	}
	active, err := store.ActivateTarget(context.Background(), first.Target.fence().activation(1))
	if err != nil {
		t.Fatal(err)
	}
	authorityBefore := store.authorities[candidate.ACID]

	reconnect, err := store.PrepareTarget(context.Background(), candidate)
	if err != nil {
		t.Fatalf("same-tuple reconnect PrepareTarget() error = %v", err)
	}
	if !reconnect.RequiresActivation || reconnect.Target.State != sessionControlTargetPreparing ||
		reconnect.Target.Version != active.Version+1 || !reconnect.Target.CountedActiveSlot ||
		reconnect.Target.AuthorityVersion != authorityBefore.Version || reconnect.Target.ActivatedControlVersion != 0 {
		t.Fatalf("same-tuple reconnect = %#v", reconnect)
	}
	// A counted reconnect remains required while catch-up runs so an AOL
	// failure cannot silently drop authority for rules owned by the old control.
	requireRequiredTargetCount(t, store, candidate.ACID, 1)
	if _, err := store.ActivateTarget(context.Background(), first.Target.fence().activation(1)); !errors.Is(err, errSessionControlTargetConflict) {
		t.Fatalf("delayed first activation error = %v, want conflict", err)
	}
	directory := store.controlDirectories[candidate.ControlCellID]
	directory.Version = 2
	directory.UpdatedAtMillis++
	store.controlDirectories[candidate.ControlCellID] = directory
	reactivated, err := store.ActivateTarget(context.Background(), reconnect.Target.fence().activation(2))
	if err != nil {
		t.Fatalf("same-tuple reactivation error = %v", err)
	}
	if reactivated.State != sessionControlTargetActive || reactivated.Version != reconnect.Target.Version+1 ||
		reactivated.AuthorityVersion != authorityBefore.Version || !reactivated.CountedActiveSlot ||
		reactivated.ActivatedControlVersion != 2 {
		t.Fatalf("same-tuple reactivated target = %#v", reactivated)
	}
	authorityAfter := store.authorities[candidate.ACID]
	if authorityAfter != authorityBefore || authorityAfter.ActiveTargetCount != 1 {
		t.Fatalf("same-key reconnect changed authority count/version: before=%#v after=%#v", authorityBefore, authorityAfter)
	}
	requireRequiredTargetCount(t, store, candidate.ACID, 1)
}

func TestSessionControlTargetActivationRejectsStaleControlCursorWithoutMutation(t *testing.T) {
	store := newMemorySessionControlStore(time.Unix(1_800_000_450, 0))
	candidate := testSessionControlTargetCandidate(0x75, "ababcdcdababcdcdababcdcdababcdcd", 21)
	prepared, err := store.PrepareTarget(context.Background(), candidate)
	if err != nil {
		t.Fatal(err)
	}
	directory := store.controlDirectories[candidate.ControlCellID]
	directory.Version++
	directory.UpdatedAtMillis++
	store.controlDirectories[candidate.ControlCellID] = directory
	if err := store.advanceAuthorityVersionForTest(candidate.ACID); err != nil {
		t.Fatal(err)
	}

	if _, err := store.ActivateTarget(context.Background(), prepared.Target.fence().activation(1)); !errors.Is(err, errSessionControlTargetControlStale) {
		t.Fatalf("stale control activation error = %v, want stale catch-up", err)
	}
	if current := store.targets[prepared.Target.key()]; current != prepared.Target {
		t.Fatalf("stale control activation mutated target: got %#v want %#v", current, prepared.Target)
	}
	if authority := store.authorities[candidate.ACID]; authority.ActiveTargetCount != 0 || authority.ControlCellID != "" {
		t.Fatalf("stale control activation mutated authority: %#v", authority)
	}
}

func TestSessionControlTargetActivationRejectsNonzeroPreparedCursor(t *testing.T) {
	store := newMemorySessionControlStore(time.Unix(1_800_000_460, 0))
	candidate := testSessionControlTargetCandidate(0x78, "56565656565656565656565656565656", 24)
	prepared, err := store.PrepareTarget(context.Background(), candidate)
	if err != nil {
		t.Fatal(err)
	}
	activation := prepared.Target.fence().activation(1)
	activation.Fence.ActivatedControlVersion = 1
	if _, err := store.ActivateTarget(context.Background(), activation); err == nil {
		t.Fatal("activation accepted nonzero cursor on preparing fence")
	}
	if current := store.targets[prepared.Target.key()]; current != prepared.Target {
		t.Fatalf("invalid activation mutated target: got %#v want %#v", current, prepared.Target)
	}
}

func TestSessionControlTargetAuthorityAdvanceFencesFinalActivation(t *testing.T) {
	store := newMemorySessionControlStore(time.Unix(1_800_000_500, 0))
	candidate := testSessionControlTargetCandidate(0x36, "66666666666666666666666666666666", 13)
	first, err := store.PrepareTarget(context.Background(), candidate)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.advanceAuthorityVersionForTest(candidate.ACID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ActivateTarget(context.Background(), first.Target.fence().activation(1)); !errors.Is(err, errSessionControlTargetConflict) {
		t.Fatalf("activation across authority event error = %v, want conflict", err)
	}
	current, err := store.GetTarget(context.Background(), first.Target.key())
	if err != nil || current.State != sessionControlTargetPreparing || current.Version != first.Target.Version {
		t.Fatalf("fenced target = %#v, %v; want original preparing row", current, err)
	}

	refreshed, err := store.PrepareTarget(context.Background(), candidate)
	if err != nil {
		t.Fatalf("refreshed PrepareTarget() error = %v", err)
	}
	if refreshed.Target.Version != first.Target.Version+1 || refreshed.Target.AuthorityVersion != first.Target.AuthorityVersion+1 {
		t.Fatalf("refreshed preparation = %#v", refreshed)
	}
	active, err := store.ActivateTarget(context.Background(), refreshed.Target.fence().activation(1))
	if err != nil {
		t.Fatalf("refreshed ActivateTarget() error = %v", err)
	}
	if active.State != sessionControlTargetActive || active.AuthorityVersion != refreshed.Target.AuthorityVersion+1 {
		t.Fatalf("active after authority refresh = %#v", active)
	}
	if _, err := store.ActivateTarget(context.Background(), first.Target.fence().activation(1)); !errors.Is(err, errSessionControlTargetConflict) {
		t.Fatalf("old activation after newer success error = %v, want conflict", err)
	}
}

func TestSessionControlTargetGlobalCapacityIsAtomicAndSameKeyDoesNotIncrement(t *testing.T) {
	store := newMemorySessionControlStore(time.Unix(1_800_000_600, 0))
	var first sessionControlTargetCandidate
	for i := 0; i < MaxACConnsPerID; i++ {
		candidate := testSessionControlTargetCandidate(byte(0x50+i), fmt.Sprintf("%032x", i+1), uint64(i+1))
		if i == 0 {
			first = candidate
		}
		prepared, err := store.PrepareTarget(context.Background(), candidate)
		if err != nil {
			t.Fatalf("PrepareTarget(%d) error = %v", i, err)
		}
		if _, err := store.ActivateTarget(context.Background(), prepared.Target.fence().activation(1)); err != nil {
			t.Fatalf("ActivateTarget(%d) error = %v", i, err)
		}
	}
	authorityAtCap := store.authorities[first.ACID]
	if authorityAtCap.ActiveTargetCount != uint64(MaxACConnsPerID) {
		t.Fatalf("active target count = %d, want %d", authorityAtCap.ActiveTargetCount, MaxACConnsPerID)
	}

	overflow := testSessionControlTargetCandidate(0x70, "77777777777777777777777777777777", 99)
	overflowPrepared, err := store.PrepareTarget(context.Background(), overflow)
	if err != nil {
		t.Fatalf("overflow PrepareTarget() error = %v", err)
	}
	if _, err := store.ActivateTarget(context.Background(), overflowPrepared.Target.fence().activation(1)); !errors.Is(err, errSessionControlTargetCapacity) {
		t.Fatalf("overflow activation error = %v, want capacity", err)
	}
	requireRequiredTargetCount(t, store, first.ACID, MaxACConnsPerID)

	reconnect, err := store.PrepareTarget(context.Background(), first)
	if err != nil {
		t.Fatalf("counted reconnect preparation error = %v", err)
	}
	if _, err := store.ActivateTarget(context.Background(), reconnect.Target.fence().activation(1)); err != nil {
		t.Fatalf("counted reconnect activation at cap error = %v", err)
	}
	if got := store.authorities[first.ACID]; got != authorityAtCap {
		t.Fatalf("counted reconnect changed header at cap: got %#v want %#v", got, authorityAtCap)
	}

	cancelPreparation, err := store.PrepareTarget(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CancelTargetPreparation(context.Background(), cancelPreparation.Target.fence()); !errors.Is(err, errSessionControlTargetConflict) {
		t.Fatalf("counted reconnect cancellation error = %v, want conflict", err)
	}
	if got := store.authorities[first.ACID]; got != authorityAtCap {
		t.Fatalf("cancellation changed counted authority slot: got %#v want %#v", got, authorityAtCap)
	}
	requireRequiredTargetCount(t, store, first.ACID, MaxACConnsPerID)
}

func TestSessionControlTargetRequiredListFailsClosedOnAuthorityCountDrift(t *testing.T) {
	store := newMemorySessionControlStore(time.Unix(1_800_000_700, 0))
	candidate := testSessionControlTargetCandidate(0x37, "88888888888888888888888888888888", 14)
	prepared, err := store.PrepareTarget(context.Background(), candidate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ActivateTarget(context.Background(), prepared.Target.fence().activation(1)); err != nil {
		t.Fatal(err)
	}
	authority := store.authorities[candidate.ACID]
	authority.ActiveTargetCount = 0
	store.authorities[candidate.ACID] = authority
	if _, err := store.ListRequiredTargets(context.Background(), candidate.ACID, candidate.ControlCellID); !errors.Is(err, errSessionControlTargetCorrupt) {
		t.Fatalf("ListRequiredTargets() drift error = %v, want corrupt", err)
	}
	delete(store.authorities, candidate.ACID)
	if _, err := store.ListRequiredTargets(context.Background(), candidate.ACID, candidate.ControlCellID); !errors.Is(err, errSessionControlTargetNotFound) {
		t.Fatalf("ListRequiredTargets() missing header error = %v, want not found", err)
	}
}

func TestSessionControlTargetRequiredListAllowsUnboundEmptyAuthority(t *testing.T) {
	store := newMemorySessionControlStore(time.Unix(1_800_000_750, 0))
	const acID = "ac-unbound-empty"
	store.authorities[acID] = sessionControlAuthority{
		ACID: acID, Version: 1, CreatedAtMillis: 1_800_000_750_000, UpdatedAtMillis: 1_800_000_750_000,
	}
	targets, err := store.ListRequiredTargets(context.Background(), acID, testSessionControlCellID)
	if err != nil || len(targets) != 0 {
		t.Fatalf("unbound empty required list = %#v, %v; want empty", targets, err)
	}
}

func TestSessionControlTargetVersionCeilingFailsBeforeMutation(t *testing.T) {
	store := newMemorySessionControlStore(time.Unix(1_800_000_800, 0))
	candidate := testSessionControlTargetCandidate(0x38, "99999999999999999999999999999999", 15)
	ceiling := testSessionControlTargetAuthority(candidate, sessionControlTargetPreparing, ^uint64(0)-1)
	store.targets[ceiling.key()] = ceiling
	store.authorities[candidate.ACID] = sessionControlAuthority{
		ACID:            candidate.ACID,
		Version:         1,
		CreatedAtMillis: 1_800_000_800_000,
		UpdatedAtMillis: 1_800_000_800_000,
	}
	for name, transition := range map[string]func() error{
		"activate": func() error {
			_, err := store.ActivateTarget(context.Background(), ceiling.fence().activation(1))
			return err
		},
		"cancel": func() error {
			_, err := store.CancelTargetPreparation(context.Background(), ceiling.fence())
			return err
		},
		"retire": func() error {
			_, err := store.retireTarget(context.Background(), ceiling.fence())
			return err
		},
	} {
		if err := transition(); !errors.Is(err, errSessionControlTargetCorrupt) {
			t.Fatalf("%s ceiling error = %v, want corrupt", name, err)
		}
	}
	if got := store.targets[ceiling.key()]; got != ceiling {
		t.Fatalf("version-ceiling transition mutated target: got %#v want %#v", got, ceiling)
	}

	plannerCurrent := ceiling
	plannerCurrent.Version = ^uint64(0) - 2
	plannerCurrent.State = sessionControlTargetCanceled
	authority := sessionControlAuthority{ACID: candidate.ACID, Version: 1, CreatedAtMillis: 1_800_000_800_000, UpdatedAtMillis: 1_800_000_800_000}
	if _, _, err := planSessionControlTargetPreparation(&plannerCurrent, candidate, authority, time.Unix(1_800_000_800, 0)); !errors.Is(err, errSessionControlTargetCorrupt) {
		t.Fatalf("planner ceiling error = %v, want corrupt", err)
	}
}

func TestSessionControlTargetChronologyAndAuditRowsFailClosed(t *testing.T) {
	candidate := testSessionControlTargetCandidate(0x79, "78787878787878787878787878787878", 25)
	active := testSessionControlTargetAuthority(candidate, sessionControlTargetActive, 2)
	baseRow, err := sessionControlTargetToRow(active)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*sessionControlTargetRow){
		"prepared before created": func(row *sessionControlTargetRow) { row.PreparedAtMillis = row.CreatedAtMillis - 1 },
		"updated before prepared": func(row *sessionControlTargetRow) { row.UpdatedAtMillis = row.PreparedAtMillis - 1 },
		"active cursor missing":   func(row *sessionControlTargetRow) { row.ActivatedControlVersion = 0 },
		"ready cursor mismatch": func(row *sessionControlTargetRow) {
			row.ReadyControlVersion = row.ActivatedControlVersion + 1
			row.AAKEnqueuedAtMillis = row.PreparedAtMillis
			row.AAKTransactionID = 1
		},
		"ready missing AAK timestamp": func(row *sessionControlTargetRow) {
			row.ReadyControlVersion = row.ActivatedControlVersion
			row.AAKTransactionID = 1
		},
		"unready retained AAK transaction": func(row *sessionControlTargetRow) {
			row.AAKTransactionID = 1
		},
		"preparing cursor retained": func(row *sessionControlTargetRow) {
			row.State = sessionControlTargetPreparing
			row.ActivatedControlVersion = 1
		},
		"retired audit mismatch": func(row *sessionControlTargetRow) {
			row.State = sessionControlTargetRetired
			row.CountedActiveSlot = false
			row.RetiredAtMillis = row.UpdatedAtMillis + 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			row := baseRow
			mutate(&row)
			if _, err := sessionControlTargetFromRow(row, candidate.ACID); !errors.Is(err, errSessionControlTargetCorrupt) {
				t.Fatalf("target row error = %v, want corrupt", err)
			}
		})
	}
	authority := sessionControlAuthority{
		ACID: candidate.ACID, ControlCellID: candidate.ControlCellID, Version: 2, ActiveTargetCount: 1,
		CreatedAtMillis: 1_800_000_000_000, UpdatedAtMillis: 1_799_999_999_999,
	}
	if err := validateSessionControlAuthority(authority); !errors.Is(err, errSessionControlTargetCorrupt) {
		t.Fatalf("authority chronology error = %v, want corrupt", err)
	}
	fence := active.fence()
	fence.PreparedAtMillis = fence.CreatedAtMillis - 1
	if validSessionControlTargetFence(fence) {
		t.Fatal("target fence accepted prepared_at before created_at")
	}
}
