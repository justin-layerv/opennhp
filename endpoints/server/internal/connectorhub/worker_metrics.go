package connectorhub

import "time"

// WorkerOutcome is the closed, low-cardinality packet outcome vocabulary for
// the dedicated public Hub worker. Values never contain source addresses,
// public keys, credentials, request bodies, or other attacker-controlled data.
type WorkerOutcome string

const (
	WorkerOutcomeChallengeSent          WorkerOutcome = "challenge_sent"
	WorkerOutcomeChallengeSizeRejected  WorkerOutcome = "challenge_size_rejected"
	WorkerOutcomeResponseSent           WorkerOutcome = "response_sent"
	WorkerOutcomeEnvelopeRejected       WorkerOutcome = "envelope_rejected"
	WorkerOutcomeAggregateRateRejected  WorkerOutcome = "aggregate_rate_rejected"
	WorkerOutcomeAggregateLimitRejected WorkerOutcome = "aggregate_limit_rejected"
	WorkerOutcomeDeadlineRejected       WorkerOutcome = "deadline_rejected"
	WorkerOutcomeCryptoRejected         WorkerOutcome = "crypto_rejected"
	WorkerOutcomeReplayRejected         WorkerOutcome = "replay_rejected"
	// Sustained replay_capacity_rejected means authenticated public traffic
	// exhausted fail-closed replay state: production wiring must alert on it as
	// either a flood or an admission/capacity configuration error.
	WorkerOutcomeReplayCapacityRejected  WorkerOutcome = "replay_capacity_rejected"
	WorkerOutcomePeerLimitRejected       WorkerOutcome = "peer_limit_rejected"
	WorkerOutcomeHandlerDropped          WorkerOutcome = "handler_dropped"
	WorkerOutcomeResponseInvalidRejected WorkerOutcome = "response_invalid_rejected"
	WorkerOutcomeResponseQueueRejected   WorkerOutcome = "response_queue_rejected"
	WorkerOutcomeResponseEncodeRejected  WorkerOutcome = "response_encode_rejected"
	WorkerOutcomeWriteFailed             WorkerOutcome = "write_failed"
	// WorkerOutcomeResponseOversize marks a sealed reply larger than one
	// unfragmented UDP datagram. The write still happens and still succeeds --
	// the kernel fragments it -- so write_failed stays zero and response_sent
	// still increments. Anything that drops IP fragments between here and the
	// agent, which includes every AWS Network Load Balancer, discards it in the
	// middle and the enrollment dies with no signal on either side.
	//
	// Sandbox, 2026-08-08: a client sent 14 datagrams and received all four
	// 340-342 byte challenges and none of the five ~1682-byte assignment
	// replies, while this worker recorded response_sent 5 and write_failed 0.
	// Alert on this: it is the only local evidence that a reply cannot arrive.
	//
	// SEMANTICS, for whoever writes that alert. This counts replies the worker
	// SEALED at an undeliverable size, not replies it sent, because it is
	// recorded before the response is queued. So it is NOT a subset of
	// response_sent: it also fires when the reply is subsequently dropped by a
	// full queue, an expired receipt budget, or a failed write. Conversely an
	// oversize reply that IS written increments both, so any dashboard reading
	// "delivered = response_sent" over-counts by exactly this metric.
	WorkerOutcomeResponseOversize WorkerOutcome = "response_oversize"
)

// unfragmentedUDPResponseCeiling is the largest reply that crosses a 1500-byte
// IPv4 path as one datagram: 1500 - 20 IP - 8 UDP. qurl-go pins the stricter
// IPv6-minimum form of the same bound as nativeudp.maxUnfragmentedPayload
// (1280 - 40 - 8 = 1232); this is the looser of the two on purpose, so the
// metric fires only when delivery is impossible rather than merely unsafe.
//
// The trade-off that buys: a reply between 1233 and 1472 bytes stays silently
// undeliverable across any genuinely IPv6-minimum segment without tripping
// this counter.
const unfragmentedUDPResponseCeiling = 1472

// responseIsOversize is the exact predicate handlePacket applies. A payload of
// exactly the ceiling still fits (1472 + 8 UDP + 20 IP = 1500), so the
// comparison is strictly greater-than, and it lives here so the boundary is
// testable without driving a production-sized reply through the fixture.
func responseIsOversize(n int) bool { return n > unfragmentedUDPResponseCeiling }

// WorkerObserver receives aggregate, secret-free observations. Implementations
// must be safe for concurrent, nonblocking calls and keep the enum values as
// closed metric labels; the worker never logs packet-specific failures on its
// public UDP path.
type WorkerObserver interface {
	ObserveWorkerOutcome(WorkerOutcome)
	ObserveHandlerResult(Classification, RequestRejection)
	// ObserveAuthorityDuration records the complete private Authority invocation
	// for one strictly decoded operation, including failures and timeouts.
	ObserveAuthorityDuration(Mode, time.Duration)
	// ObservePostAuthorityDuration records response mapping, Noise sealing,
	// queueing, and the successful UDP write after Authority returned.
	ObservePostAuthorityDuration(Mode, time.Duration)
	// ObserveChallengeDatagramBytes records histogram values, never labels.
	// The worker calls it only after a strictly smaller COK is written.
	ObserveChallengeDatagramBytes(requestBytes, responseBytes int)
}

type noopWorkerObserver struct{}

func (noopWorkerObserver) ObserveWorkerOutcome(WorkerOutcome)                    {}
func (noopWorkerObserver) ObserveHandlerResult(Classification, RequestRejection) {}
func (noopWorkerObserver) ObserveAuthorityDuration(Mode, time.Duration)          {}
func (noopWorkerObserver) ObservePostAuthorityDuration(Mode, time.Duration)      {}
func (noopWorkerObserver) ObserveChallengeDatagramBytes(int, int)                {}
