package server

import (
	"context"
	"errors"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/log"
)

// reknockRetryTransactionTimeout is one server→AC AOP transaction timeout as a
// Duration: both the worst-case cost of the single reknock retry and the deadline
// margin below which broadcastACOpenWithReknock skips that retry (it could not
// finish before the caller's HttpKnockProcessingBudget deadline). It tracks the
// AC-open-specific ServerACOpenTransactionResponseTimeoutMs (1.5s) — NOT the shared
// ServerLocalTransactionResponseTimeoutMs, which the DB/forward paths keep at 4.7s.
const reknockRetryTransactionTimeout = time.Duration(core.ServerACOpenTransactionResponseTimeoutMs) * time.Millisecond

// broadcastACOpenWithReknock runs the NHP-AOP "open" broadcast for one resource
// and, when the broadcast's aggregate result is the transaction-timeout signature
// (ErrTransactionFailedByTimeout), re-snapshots the connection map and retries the
// broadcast ONCE against the fresh set.
//
// Why this exists: a blue/green AC reassignment — or any keepalive-window
// connection teardown — can leave a connection that is "live" at snapshot time
// but whose server-side transaction path is torn down before the AC's NHP-ART
// ACK returns. The AOP still reaches the AC and the ipset/eBPF pinhole IS
// written, but processACOperation times out (~1.5s, ServerACOpenTransactionResponseTimeoutMs)
// waiting for an ACK that never arrives and closes the connection
// (endpoints/server/udpserver.go, the ErrTransactionFailedByTimeout branch). A
// single knock then hard-fails (ErrServerACOpsFailed / 52005) even though the
// firewall was actually opened — the intermittent qURL knock failure root-caused
// empirically to a sandbox fleet migration whose AC↔server assignment thrash broke
// ACK return paths (qurl-service#976). It is the knock-path twin of the
// registration-path timeout that recordResponseError already classifies as the
// "dominant blue/green-flip transient" (endpoints/ac/registration.go).
//
// Retry predicate — the aggregate error, and the timeout it keys on:
//   - The predicate keys on the broadcast's AGGREGATE return, which when every AC
//     failed is the LAST-arriving AC error (processACOperationBroadcast returns
//     lastErr). In the dominant single-conn qURL case that IS that conn's error.
//     With multiple conns, a genuine AC error (ipset failure, replay drop)
//     co-occurring with a timeout can win or lose the aggregate by arrival order —
//     acceptable either way: the AC open is idempotent, so a resend triggered by a
//     timeout that masked a genuine error is a no-op, and a genuine error that wins
//     the aggregate is authoritative and is NOT retried.
//   - "Transaction-timeout signature" means the ~1.5s core-transaction timeout
//     surfaces as the bare ErrTransactionFailedByTimeout sentinel. This relies on
//     that timeout firing BEFORE the 3s broadcast-context deadline
//     (DefaultBroadcastTimeout): if the broadcast context wins instead,
//     processACOperation returns context.DeadlineExceeded, which this predicate
//     does NOT match and the retry silently never fires. Keep
//     DefaultBroadcastTimeout > ServerACOpenTransactionResponseTimeoutMs (fenced by
//     TestBroadcastTimeoutExceedsTransactionTimeout). Do NOT "fix" an inverted
//     ordering by merely broadening this predicate to also match
//     context.DeadlineExceeded: processACOperation's ctx-cancel arm does NOT
//     Close() the timed-out conn (only its ErrTransactionFailedByTimeout branch
//     does), so a resend would go to the same un-pruned dead conns — the ordering,
//     not the match set, is what keeps the retry sound.
//
// The retry is sound and bounded:
//   - processACOperation closed the timed-out conns, so the re-snapshot prunes
//     them (ConnData.IsClosed) and returns only conns that (re-)registered since
//     — a fresh ACK path. If none exist, freshConns is empty and the original
//     timeout stands (no pointless resend to the same dead conns). NOTE the
//     caller's pre-broadcast forward path only covers a conn that was ALREADY
//     absent when the forward decision ran; it does NOT re-forward a conn that
//     died mid-broadcast. So if the surviving (green) AC re-registered to a
//     DIFFERENT server, this local re-snapshot finds nothing and the knock returns
//     the timeout rather than forwarding in-flight — an accepted scope boundary:
//     the client re-knocks and the AC's pinhole write was idempotent.
//   - The AC open is idempotent (ipset add -exist / eBPF upsert), so a resend
//     reaching an AC that already applied the rule is a no-op.
//   - Exactly one retry after a short backoff bounds the added latency
//     (defaultReknockRetryBackoff + one transaction timeout ≈ 1.3s; whole AC-open ≈
//     3.3s worst case) and keeps the whole knock well within the knock-client budget
//     (see defaultReknockRetryBackoff for the arithmetic). The single retry is a HARD
//     ceiling, not a starting point: a SECOND retry would risk blowing that budget —
//     do not turn this into a loop.
//
// Operational notes (bounded, not bugs):
//   - "Timeout" here is ANY transaction timeout, not necessarily a reassignment.
//     An alive-but-overloaded AC that is re-registering can also trip this and get
//     a second broadcast — adding load exactly when it is already saturated. The
//     single-retry ceiling + idempotency bound the blast radius; watch the
//     KnockReknockRetry vs KnockReknockRetrySuccess ratio: a degrading ratio driven
//     by AC overload rather than a migration is the signal to act on.
//   - On the HTTP path the retry is ALSO gated by the caller's deadline
//     (HttpKnockProcessingBudget): if less than one transaction timeout of budget
//     remains it is skipped (KnockReknockDeadlineSkipped) instead of held, so a
//     broad flip does not pile up per-resource goroutines each waiting ~one
//     transaction timeout for a caller that has already given up. The UDP path
//     carries no deadline, so there the single-retry ceiling is the only bound.
//   - The two forward RECEIVER paths differ deliberately. The HTTP internal-knock
//     receiver (handleHttpOpenResource) DOES wrap its AC-open in this retry, because
//     qurl-service is still waiting its 7s knock timeout there. The UDP
//     server-to-server receiver (HandleForwardRequest) does NOT — see the rationale at
//     its call site (forward.go): its caller is a forwarding server bounded by the 2s
//     ForwardTimeout (forward.go:40 — NOT msghandler's unrelated 10s
//     DefaultForwardTimeout), which has already given up before a ~3.3s reknock could
//     return, so there is no in-flight forwarded
//     transaction left to rescue and wrapping would only burn a held goroutine per
//     forwarded timeout during the broad-flip window. Both forward paths recover a
//     genuinely lost open via the client's next re-knock against the settled topology
//     (the first AOP was idempotent).
//
// Used by BOTH knock paths: the UDP handleNhpOpenResource (the qURL v1/v2 browser
// and SDK knock path, which passes the server lifecycle context so a pending retry
// abandons on shutdown) and the HTTP handleHttpOpenResource (qurl-service's
// internal knock, which passes the request context so it abandons on client
// disconnect). It funnels through resolveProcessACOperationBroadcast so
// handler-site integration tests can inject a fake AC response.
func (s *UdpServer) broadcastACOpenWithReknock(
	ctx context.Context,
	knkMsg *common.AgentKnockMsg,
	acId string,
	conns []*ACConn,
	srcAddr *common.NetAddress,
	dstAddrs []*common.NetAddress,
	openTime uint32,
	res *common.ResourceData,
	logCtx string,
) (*common.ACOpsResultMsg, error) {
	artMsg, err := s.resolveProcessACOperationBroadcast()(ctx, knkMsg, conns, srcAddr, dstAddrs, openTime, res)
	if err == nil || !errors.Is(err, common.ErrTransactionFailedByTimeout) {
		return artMsg, err
	}

	// The retry backoff: the zero value (the production default) resolves to
	// defaultReknockRetryBackoff; timeout-path tests set a tiny per-instance value
	// via shortenReknockBackoff. Read once so the budget check and the pause agree.
	backoff := s.reknockRetryBackoff
	if backoff <= 0 {
		backoff = defaultReknockRetryBackoff
	}

	// The broadcast aggregated to the timeout signature — the reassignment-window
	// case. BEFORE pausing to re-snapshot, check the budget: if the caller's
	// deadline can't cover the backoff PLUS another transaction timeout, skip the
	// retry now rather than burning the backoff on a knock that cannot finish before
	// the caller (qurl-service) gives up — shedding load exactly during a broad flip.
	// The client's next re-knock retries against then-fresh conns. HTTP knocks carry
	// the HttpKnockProcessingBudget deadline (set by withKnockProcessingBudget on
	// both HTTP entry points, so its clock already includes admission time); the UDP
	// path passes the lifecycle context (no deadline) so this no-ops there.
	//
	// The threshold is backoff + one transaction timeout — the wall time the retry
	// path needs (pause for conns to re-register, then one transaction for the
	// resend). A retry, once issued, runs under the broadcast's own transaction
	// timeout, NOT this parent deadline (processACOperationBroadcast WithoutCancels
	// the parent), so the deadline gates only the decision to START the retry path,
	// not its duration; this check is what keeps a proceeding retry from overrunning
	// the caller (it rests on DefaultBroadcastTimeout > the transaction timeout,
	// fenced by TestBroadcastTimeoutExceedsTransactionTimeout).
	if dl, ok := ctx.Deadline(); ok && time.Until(dl) < reknockRetryTransactionTimeout+backoff {
		s.metrics.IncrCounter(MetricKnockReknockDeadlineSkipped)
		log.Warning("%s-ac(%s)[broadcastACOpenWithReknock] skipping reknock retry: < backoff + one transaction timeout (%v) of the knock budget remains; client re-knock will retry",
			logCtx, acId, reknockRetryTransactionTimeout+backoff)
		return artMsg, err
	}

	// Give the just-closed conns a beat to be pruned and a fresh registration a beat
	// to land, then re-snapshot. Abort the wait if the caller's context is done
	// (server shutdown on the UDP path via the lifecycle ctx; client disconnect on
	// the HTTP path via the request ctx).
	select {
	case <-time.After(backoff):
	case <-ctx.Done():
		return artMsg, err
	}

	// Re-snapshot the live conns for this acId. snapshotLiveACConns re-emits
	// MetricACConnStaleFiltered for the conns pruned here; that is intentional and
	// bounded — it fires only on this rare all-timeout retry path, and the pruned
	// conns are the ones the timed-out transactions just closed, so the extra count
	// is real reassignment-window signal, not a spurious re-count of the caller's
	// first snapshot (which saw those conns still live).
	freshConns, droppedStale := s.snapshotLiveACConns(acId)
	if len(freshConns) == 0 {
		// Nothing re-registered within the backoff — a stuck migration, or the
		// surviving AC re-registered to a DIFFERENT server (which this local path
		// does not forward in-flight). Distinct counter so this "escalate to the
		// ops/forward fix, not this retry" mode is directly observable rather than
		// invisible in the two retry counters below.
		s.metrics.IncrCounter(MetricKnockReknockNoFreshConns)
		return artMsg, err
	}

	s.metrics.IncrCounter(MetricKnockReknockRetry)
	log.Warning("%s-ac(%s)[broadcastACOpenWithReknock] AC broadcast hit the transaction-timeout signature (%d conn(s)); retrying open on %d fresh conn(s) (pruned %d stale)",
		logCtx, acId, len(conns), len(freshConns), droppedStale)

	// res is reused verbatim, so the resend's AOP carries the SAME qURL v2 P4a
	// revocation metadata (QurlUserPublicKeyHash / ResourcePublicKeyHash /
	// AdmissionId / SessionId / Deadline) as the first attempt — the retry path is
	// fully covered by revocation, not just the first broadcast.
	retryArtMsg, retryErr := s.resolveProcessACOperationBroadcast()(ctx, knkMsg, freshConns, srcAddr, dstAddrs, openTime, res)
	if retryErr == nil {
		s.metrics.IncrCounter(MetricKnockReknockRetrySuccess)
	}
	return retryArtMsg, retryErr
}
