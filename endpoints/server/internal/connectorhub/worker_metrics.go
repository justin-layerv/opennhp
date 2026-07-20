package connectorhub

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
)

// WorkerObserver receives aggregate, secret-free observations. Implementations
// must be safe for concurrent, nonblocking calls and keep the enum values as
// closed metric labels; the worker never logs packet-specific failures on its
// public UDP path.
type WorkerObserver interface {
	ObserveWorkerOutcome(WorkerOutcome)
	ObserveHandlerResult(Classification, RequestRejection)
	// ObserveChallengeDatagramBytes records histogram values, never labels.
	// The worker calls it only after a strictly smaller COK is written.
	ObserveChallengeDatagramBytes(requestBytes, responseBytes int)
}

type noopWorkerObserver struct{}

func (noopWorkerObserver) ObserveWorkerOutcome(WorkerOutcome)                    {}
func (noopWorkerObserver) ObserveHandlerResult(Classification, RequestRejection) {}
func (noopWorkerObserver) ObserveChallengeDatagramBytes(int, int)                {}
