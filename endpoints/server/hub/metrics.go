package hub

import (
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	cloudwatchtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/endpoints/server/internal/connectorhub"
)

const (
	hubMetricsDrainInterval = 5 * time.Second

	metricHubWorkerOutcome          = "HubWorkerOutcome"
	metricHubHandlerClassification  = "HubHandlerClassification"
	metricHubRequestRejection       = "HubRequestRejection"
	metricHubUnknownLabel           = "HubUnknownLabel"
	metricHubChallengeObservation   = "HubChallengeObservation"
	metricHubChallengeRequestBytes  = "HubChallengeRequestBytes"
	metricHubChallengeResponseBytes = "HubChallengeResponseBytes"
	metricHubHealthAcceptRetry      = "HubHealthAcceptRetry"
)

// workerMetrics is the process's concrete connectorhub.WorkerObserver. Without
// it the worker falls back to the noop observer and emits nothing.
//
// Security properties this composition depends on:
//
//   - Nonblocking. Every method performs only atomic adds against counters
//     allocated once at construction. There are no locks, channels, syscalls,
//     or allocations on the call path, so a flood on the public UDP edge can
//     never stall a worker goroutine inside metric emission. The label maps are
//     written only by newWorkerMetrics and are read-only thereafter, so the
//     per-packet map reads are safe without synchronization.
//   - Closed label set. The only labels recorded are this composition's own
//     fixed enum constants; no source address, public key, credential, request
//     body, or other attacker-controlled value is ever incorporated. A value
//     outside the known vocabulary (which the current worker never emits) is
//     folded into a single "unknown" counter rather than allocating a new key,
//     so metric cardinality stays bounded regardless of packet contents.
type workerMetrics struct {
	outcomes        map[connectorhub.WorkerOutcome]*atomic.Uint64
	classifications map[connectorhub.Classification]*atomic.Uint64
	rejections      map[connectorhub.RequestRejection]*atomic.Uint64

	// unknown counts any label outside the closed vocabularies above. It is a
	// drift guard: the worker only emits the enumerated constants today, so a
	// nonzero value means a new outcome/classification/rejection was added
	// upstream without being registered here.
	unknown atomic.Uint64

	challengeObservations  atomic.Uint64
	challengeRequestBytes  atomic.Uint64
	challengeResponseBytes atomic.Uint64
}

// newWorkerMetrics registers a dedicated counter for every closed label the
// worker can emit. Constants are referenced by name so a rename upstream fails
// to compile here instead of silently dropping a metric.
func newWorkerMetrics() *workerMetrics {
	return &workerMetrics{
		outcomes: newCounterSet([]connectorhub.WorkerOutcome{
			connectorhub.WorkerOutcomeChallengeSent,
			connectorhub.WorkerOutcomeChallengeSizeRejected,
			connectorhub.WorkerOutcomeResponseSent,
			connectorhub.WorkerOutcomeEnvelopeRejected,
			connectorhub.WorkerOutcomeAggregateRateRejected,
			connectorhub.WorkerOutcomeAggregateLimitRejected,
			connectorhub.WorkerOutcomeDeadlineRejected,
			connectorhub.WorkerOutcomeCryptoRejected,
			connectorhub.WorkerOutcomeReplayRejected,
			connectorhub.WorkerOutcomeReplayCapacityRejected,
			connectorhub.WorkerOutcomePeerLimitRejected,
			connectorhub.WorkerOutcomeHandlerDropped,
			connectorhub.WorkerOutcomeResponseInvalidRejected,
			connectorhub.WorkerOutcomeResponseQueueRejected,
			connectorhub.WorkerOutcomeResponseEncodeRejected,
			connectorhub.WorkerOutcomeWriteFailed,
		}),
		classifications: newCounterSet([]connectorhub.Classification{
			connectorhub.ClassificationSuccess,
			connectorhub.ClassificationRequestRejected,
			connectorhub.ClassificationDeadlineRejected,
			connectorhub.ClassificationRegistrationDisabled,
			connectorhub.ClassificationRateLimited,
			connectorhub.ClassificationAdmissionUnavailable,
			connectorhub.ClassificationAuthorityInvocationFailed,
			connectorhub.ClassificationAuthorityResponseRejected,
			connectorhub.ClassificationAuthoritySemanticError,
			connectorhub.ClassificationInternalFailure,
		}),
		rejections: newCounterSet([]connectorhub.RequestRejection{
			connectorhub.RequestRejectionBodyParse,
			connectorhub.RequestRejectionUnknownField,
			connectorhub.RequestRejectionMissingField,
			connectorhub.RequestRejectionWrongType,
			connectorhub.RequestRejectionSemantic,
			connectorhub.RequestRejectionPeer,
			connectorhub.RequestRejectionBodySize,
			connectorhub.RequestRejectionEnvironment,
		}),
	}
}

// newHubMetricsPublisher uses the process's already-loaded AWS configuration,
// so the Hub's authority client and monitoring path share one region and
// credential identity. The Hub is environment-global rather than cell-local,
// so its base dimension is Environment only.
func newHubMetricsPublisher(environment string, awsConfig aws.Config) *metrics.Publisher {
	// No checkpoint directory is configured intentionally. Hub metrics are
	// best-effort operational counters, the runtime image has no persistent
	// writable state, and absence-of-metric alarms cover a dead publication
	// path. Graceful shutdown still drains the observer and flushes the
	// publisher; SIGKILL can lose the current in-memory interval.
	return metrics.NewPublisherWithAWSConfig(metrics.Config{
		Namespace: "LayerV/NHP",
		Dimensions: []cloudwatchtypes.Dimension{{
			Name:  aws.String("Environment"),
			Value: aws.String(environment),
		}},
	}, awsConfig)
}

// exportLoop periodically transfers the lock-free packet-path counters into the
// shared CloudWatch publisher. The stop path performs one final drain after the
// UDP worker has exited, so observations made between the last tick and process
// shutdown are not stranded in the atomics.
func (m *workerMetrics) exportLoop(stop <-chan struct{}, publisher *metrics.Publisher) {
	ticker := time.NewTicker(hubMetricsDrainInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			m.drainTo(publisher)
		case <-stop:
			m.drainTo(publisher)
			return
		}
	}
}

// drainTo swaps only the fixed counters allocated by newWorkerMetrics. It runs
// off the public packet path, so the Publisher's mutex and small dimension
// allocations can never delay UDP workers. A nil publisher leaves the atomics
// intact instead of silently consuming observations with nowhere to send them.
func (m *workerMetrics) drainTo(publisher *metrics.Publisher) {
	if publisher == nil {
		return
	}
	for outcome, counter := range m.outcomes {
		addClosedCounter(publisher, metricHubWorkerOutcome, "Outcome", string(outcome), counter)
	}
	for classification, counter := range m.classifications {
		addClosedCounter(publisher, metricHubHandlerClassification, "Classification", string(classification), counter)
	}
	for rejection, counter := range m.rejections {
		addClosedCounter(publisher, metricHubRequestRejection, "Rejection", string(rejection), counter)
	}
	addAtomicCounter(publisher, metricHubUnknownLabel, m.unknown.Swap(0))
	// These three swaps intentionally remain independent to keep the public
	// observer lock-free. A concurrent challenge can straddle adjacent drain
	// windows, but every observation and byte is conserved; dashboards must use
	// sums over publisher intervals rather than infer an exact per-drain average.
	addAtomicCounter(publisher, metricHubChallengeObservation, m.challengeObservations.Swap(0))
	addAtomicCounter(publisher, metricHubChallengeRequestBytes, m.challengeRequestBytes.Swap(0))
	addAtomicCounter(publisher, metricHubChallengeResponseBytes, m.challengeResponseBytes.Swap(0))
}

func addClosedCounter(
	publisher *metrics.Publisher,
	metricName string,
	dimensionName string,
	dimensionValue string,
	counter *atomic.Uint64,
) {
	value := counter.Swap(0)
	if value == 0 {
		return
	}
	publisher.AddCounterWithDims(metricName, float64(value), []cloudwatchtypes.Dimension{{
		Name:  aws.String(dimensionName),
		Value: aws.String(dimensionValue),
	}})
}

func addAtomicCounter(publisher *metrics.Publisher, metricName string, value uint64) {
	if value != 0 {
		publisher.AddCounterWithDims(metricName, float64(value), nil)
	}
}

func newCounterSet[K comparable](keys []K) map[K]*atomic.Uint64 {
	set := make(map[K]*atomic.Uint64, len(keys))
	for _, key := range keys {
		set[key] = new(atomic.Uint64)
	}
	return set
}

// ObserveWorkerOutcome records one closed packet-outcome label. Nonblocking.
func (m *workerMetrics) ObserveWorkerOutcome(outcome connectorhub.WorkerOutcome) {
	if counter := m.outcomes[outcome]; counter != nil {
		counter.Add(1)
		return
	}
	m.unknown.Add(1)
}

// ObserveHandlerResult records the handler's closed classification and, for a
// rejected request, its closed rejection label. Nonblocking. The empty
// rejection is the expected "not a rejection" sentinel and is not counted.
func (m *workerMetrics) ObserveHandlerResult(classification connectorhub.Classification, rejection connectorhub.RequestRejection) {
	if counter := m.classifications[classification]; counter != nil {
		counter.Add(1)
	} else {
		m.unknown.Add(1)
	}
	if rejection == "" {
		return
	}
	if counter := m.rejections[rejection]; counter != nil {
		counter.Add(1)
		return
	}
	m.unknown.Add(1)
}

// ObserveChallengeDatagramBytes records aggregate request/response datagram
// sizes for issued challenges. Nonblocking, and it records only byte magnitudes
// the worker already computed, never packet contents.
func (m *workerMetrics) ObserveChallengeDatagramBytes(requestBytes, responseBytes int) {
	m.challengeObservations.Add(1)
	if requestBytes > 0 {
		m.challengeRequestBytes.Add(uint64(requestBytes))
	}
	if responseBytes > 0 {
		m.challengeResponseBytes.Add(uint64(responseBytes))
	}
}

// outcomeCount returns the accumulated count for one outcome label.
func (m *workerMetrics) outcomeCount(outcome connectorhub.WorkerOutcome) uint64 {
	if counter := m.outcomes[outcome]; counter != nil {
		return counter.Load()
	}
	return 0
}

// classificationCount returns the accumulated count for one classification.
func (m *workerMetrics) classificationCount(classification connectorhub.Classification) uint64 {
	if counter := m.classifications[classification]; counter != nil {
		return counter.Load()
	}
	return 0
}

// rejectionCount returns the accumulated count for one rejection label.
func (m *workerMetrics) rejectionCount(rejection connectorhub.RequestRejection) uint64 {
	if counter := m.rejections[rejection]; counter != nil {
		return counter.Load()
	}
	return 0
}

// unknownCount returns the number of out-of-vocabulary observations.
func (m *workerMetrics) unknownCount() uint64 {
	return m.unknown.Load()
}

// challengeStats returns the aggregate challenge datagram observations and the
// summed request/response byte magnitudes.
func (m *workerMetrics) challengeStats() (observations, requestBytes, responseBytes uint64) {
	return m.challengeObservations.Load(), m.challengeRequestBytes.Load(), m.challengeResponseBytes.Load()
}

// Compile-time guard: the process observer satisfies the worker contract.
var _ connectorhub.WorkerObserver = (*workerMetrics)(nil)
