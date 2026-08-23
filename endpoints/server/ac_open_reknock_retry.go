package server

import (
	"context"
	"errors"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/log"
)

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
//   - Exactly one retry after a short backoff bounds the added latency. The
//     single retry is a HARD ceiling, not a starting point; do not turn this
//     into a loop.
//
// Operational notes (bounded, not bugs):
//   - "Timeout" here is ANY transaction timeout, not necessarily a reassignment.
//     An alive-but-overloaded AC that is re-registering can also trip this and get
//     a second broadcast — adding load exactly when it is already saturated. The
//     single-retry ceiling + idempotency bound the blast radius; watch the
//     KnockReknockRetry vs KnockReknockRetrySuccess ratio: a degrading ratio driven
//     by AC overload rather than a migration is the signal to act on.
//
// Used by the native UDP handleNhpOpenResource path, which passes the server
// lifecycle context so a pending retry abandons on shutdown. The retired direct
// HTTP admission seam never reaches this helper. It funnels through
// resolveProcessACOperationBroadcast so handler-site integration tests can inject
// a fake AC response.
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
	// via shortenReknockBackoff.
	backoff := s.reknockRetryBackoff
	if backoff <= 0 {
		backoff = defaultReknockRetryBackoff
	}

	// Give the just-closed conns a beat to be pruned and a fresh registration a beat
	// to land, then re-snapshot. Abort the wait if the caller's context is done
	// (server shutdown on the native UDP path via the lifecycle context).
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
