package hub

import (
	"sync"
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

	metricHubIssueAssignmentInvokeDuration                = "HubIssueAssignmentInvokeDuration"
	metricHubIssueAssignmentPostAuthorityDuration         = "HubIssueAssignmentPostAuthorityDuration"
	metricHubRefreshAssignmentInvokeDuration              = "HubRefreshAssignmentInvokeDuration"
	metricHubRefreshAssignmentPostAuthorityDuration       = "HubRefreshAssignmentPostAuthorityDuration"
	metricHubIssueCredentialRecoveryInvokeDuration        = "HubIssueCredentialRecoveryInvokeDuration"
	metricHubIssueCredentialRecoveryPostAuthorityDuration = "HubIssueCredentialRecoveryPostAuthorityDuration"
)

const durationDroppedSuffix = "Dropped"

type durationSeries struct {
	mu      sync.Mutex
	samples []float64
	dropped atomic.Uint64
}

type operationDurationSeries struct {
	invoke        durationSeries
	postAuthority durationSeries
}

// workerMetrics is the process's concrete connectorhub.WorkerObserver. Without
// it the worker falls back to the noop observer and emits nothing.
//
// Security properties this composition depends on:
//
//   - Nonblocking. Counter methods perform atomic adds. Duration observations
//     use TryLock against fixed-capacity, preallocated slices and drop rather
//     than wait when collection is contended or full. There are no blocking
//     locks, channels, syscalls, or allocations on the call path, so a flood on
//     the public UDP edge cannot stall a worker goroutine inside metric
//     emission. The maps are immutable after construction.
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
	durations       map[connectorhub.Mode]*operationDurationSeries

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
		durations: map[connectorhub.Mode]*operationDurationSeries{
			connectorhub.ModeEnroll:  newOperationDurationSeries(),
			connectorhub.ModeRefresh: newOperationDurationSeries(),
			connectorhub.ModeRecover: newOperationDurationSeries(),
		},
	}
}

func newOperationDurationSeries() *operationDurationSeries {
	return &operationDurationSeries{
		invoke:        durationSeries{samples: make([]float64, 0, metrics.MaxHistogramSamples)},
		postAuthority: durationSeries{samples: make([]float64, 0, metrics.MaxHistogramSamples)},
	}
}

func (m *workerMetrics) registerHistograms(publisher *metrics.Publisher) {
	if m == nil || publisher == nil {
		return
	}
	registrations := []struct {
		mode              connectorhub.Mode
		invokeName        string
		postAuthorityName string
	}{
		{connectorhub.ModeEnroll, metricHubIssueAssignmentInvokeDuration, metricHubIssueAssignmentPostAuthorityDuration},
		{connectorhub.ModeRefresh, metricHubRefreshAssignmentInvokeDuration, metricHubRefreshAssignmentPostAuthorityDuration},
		{connectorhub.ModeRecover, metricHubIssueCredentialRecoveryInvokeDuration, metricHubIssueCredentialRecoveryPostAuthorityDuration},
	}
	for _, registration := range registrations {
		series := m.durations[registration.mode]
		registerDurationSeries(publisher, registration.invokeName, &series.invoke)
		registerDurationSeries(publisher, registration.postAuthorityName, &series.postAuthority)
	}
}

func registerDurationSeries(publisher *metrics.Publisher, name string, series *durationSeries) {
	droppedName := name + durationDroppedSuffix
	publisher.RegisterHistogramFunc(name, cloudwatchtypes.StandardUnitMilliseconds, func() []float64 {
		values, dropped := series.drain()
		addAtomicCounter(publisher, droppedName, dropped)
		return values
	})
}

func (s *durationSeries) record(duration time.Duration) {
	// The Hub supplies monotonic time pairs, so negative means internal timing
	// drift rather than a real latency sample. Fold it into the validity guard.
	if duration < 0 || !s.mu.TryLock() {
		s.dropped.Add(1)
		return
	}
	defer s.mu.Unlock()
	if len(s.samples) == cap(s.samples) {
		s.dropped.Add(1)
		return
	}
	// Millisecond floats preserve microsecond resolution while keeping each
	// observation in the CloudWatch unit registered above. Clamp a real but
	// sub-microsecond invocation to one microsecond instead of publishing zero.
	rounded := duration.Round(time.Microsecond)
	if rounded == 0 {
		rounded = time.Microsecond
	}
	s.samples = append(s.samples, float64(rounded)/float64(time.Millisecond))
}

func (s *durationSeries) drain() ([]float64, uint64) {
	// Avoid replacing six empty 10k-capacity buffers on every idle collection.
	// Keep the active-path replacement allocation outside the mutex: record uses
	// TryLock and must not lose a load-correlated run of samples to an allocation
	// performed while the drain owns the lock.
	s.mu.Lock()
	empty := len(s.samples) == 0
	s.mu.Unlock()
	if empty {
		return nil, s.dropped.Swap(0)
	}
	replacement := make([]float64, 0, metrics.MaxHistogramSamples)
	s.mu.Lock()
	// Production has one publisher collector. Retain safe exactly-once behavior
	// if tests or a future caller invoke two drains concurrently.
	if len(s.samples) == 0 {
		s.mu.Unlock()
		return nil, s.dropped.Swap(0)
	}
	values := s.samples
	s.samples = replacement
	s.mu.Unlock()
	return values, s.dropped.Swap(0)
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

// ObserveAuthorityDuration records one complete synchronous Authority call.
// Unknown modes fold into the existing drift counter instead of creating a
// dynamic metric name.
func (m *workerMetrics) ObserveAuthorityDuration(mode connectorhub.Mode, duration time.Duration) {
	if series := m.durations[mode]; series != nil {
		series.invoke.record(duration)
		return
	}
	m.unknown.Add(1)
}

// ObservePostAuthorityDuration records only successfully written LRTs, from
// Authority completion through mapping, Noise sealing, queueing, and UDP I/O.
func (m *workerMetrics) ObservePostAuthorityDuration(mode connectorhub.Mode, duration time.Duration) {
	if series := m.durations[mode]; series != nil {
		series.postAuthority.record(duration)
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
