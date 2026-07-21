package hub

import (
	"runtime"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/endpoints/server/internal/connectorhub"
)

func TestHubMetricsPublisherUsesEnvironmentOnly(t *testing.T) {
	publisher := newHubMetricsPublisher("sandbox", aws.Config{Region: "us-east-2"})
	defer publisher.Stop()

	dimensions := publisher.DimensionsForTest(t)
	if len(dimensions) != 1 || dimensions[0].Name == nil || dimensions[0].Value == nil ||
		*dimensions[0].Name != "Environment" || *dimensions[0].Value != "sandbox" {
		t.Fatalf("Hub publisher dimensions = %#v, want Environment=sandbox only", dimensions)
	}
}

func TestWorkerMetricsCountsClosedLabels(t *testing.T) {
	m := newWorkerMetrics()

	m.ObserveWorkerOutcome(connectorhub.WorkerOutcomeChallengeSent)
	m.ObserveWorkerOutcome(connectorhub.WorkerOutcomeChallengeSent)
	m.ObserveWorkerOutcome(connectorhub.WorkerOutcomeResponseSent)
	if got := m.outcomeCount(connectorhub.WorkerOutcomeChallengeSent); got != 2 {
		t.Fatalf("challenge_sent = %d, want 2", got)
	}
	if got := m.outcomeCount(connectorhub.WorkerOutcomeResponseSent); got != 1 {
		t.Fatalf("response_sent = %d, want 1", got)
	}
	if got := m.outcomeCount(connectorhub.WorkerOutcomeWriteFailed); got != 0 {
		t.Fatalf("write_failed = %d, want 0", got)
	}

	// A rejected classification carries a rejection label; both are counted.
	m.ObserveHandlerResult(connectorhub.ClassificationRequestRejected, connectorhub.RequestRejectionMissingField)
	// A success classification carries the empty rejection sentinel, which must
	// not be counted as a rejection.
	m.ObserveHandlerResult(connectorhub.ClassificationSuccess, "")
	if got := m.classificationCount(connectorhub.ClassificationRequestRejected); got != 1 {
		t.Fatalf("request_rejected = %d, want 1", got)
	}
	if got := m.classificationCount(connectorhub.ClassificationSuccess); got != 1 {
		t.Fatalf("success = %d, want 1", got)
	}
	if got := m.rejectionCount(connectorhub.RequestRejectionMissingField); got != 1 {
		t.Fatalf("missing_field = %d, want 1", got)
	}
	if got := m.unknownCount(); got != 0 {
		t.Fatalf("unknown = %d, want 0 after only closed labels", got)
	}
}

func TestWorkerMetricsFoldsUnknownLabels(t *testing.T) {
	m := newWorkerMetrics()

	// Values outside the closed vocabularies (the worker never emits these) must
	// fold into the single bounded "unknown" counter, never a fresh key.
	m.ObserveWorkerOutcome(connectorhub.WorkerOutcome("not_a_real_outcome"))
	m.ObserveHandlerResult(connectorhub.Classification("not_a_real_classification"), connectorhub.RequestRejection("not_a_real_rejection"))
	if got := m.unknownCount(); got != 3 {
		t.Fatalf("unknown = %d, want 3 (one outcome, one classification, one rejection)", got)
	}
}

func TestWorkerMetricsChallengeStatsAccumulate(t *testing.T) {
	m := newWorkerMetrics()
	m.ObserveChallengeDatagramBytes(300, 120)
	m.ObserveChallengeDatagramBytes(200, 80)
	observations, requestBytes, responseBytes := m.challengeStats()
	if observations != 2 || requestBytes != 500 || responseBytes != 200 {
		t.Fatalf("challenge stats = %d obs, %d req, %d resp; want 2/500/200", observations, requestBytes, responseBytes)
	}
}

func TestWorkerMetricsDrainExportsClosedCountersExactlyOnce(t *testing.T) {
	publisher := metrics.NewPublisherForTest(t)
	m := newWorkerMetrics()
	m.ObserveWorkerOutcome(connectorhub.WorkerOutcomeChallengeSent)
	m.ObserveWorkerOutcome(connectorhub.WorkerOutcomeChallengeSent)
	m.ObserveHandlerResult(connectorhub.ClassificationRequestRejected, connectorhub.RequestRejectionMissingField)
	m.ObserveWorkerOutcome(connectorhub.WorkerOutcome("future_value"))
	m.ObserveChallengeDatagramBytes(300, 120)

	m.drainTo(publisher)
	_, dimensioned := publisher.CountersForTest(t)
	want := map[string]float64{
		metricHubWorkerOutcome + "\x00Outcome=challenge_sent":                  2,
		metricHubHandlerClassification + "\x00Classification=request_rejected": 1,
		metricHubRequestRejection + "\x00Rejection=missing_field":              1,
		metricHubUnknownLabel:           1,
		metricHubChallengeObservation:   1,
		metricHubChallengeRequestBytes:  300,
		metricHubChallengeResponseBytes: 120,
	}
	if len(dimensioned) != len(want) {
		t.Fatalf("exported metric count = %d, want %d: %#v", len(dimensioned), len(want), dimensioned)
	}
	for key, value := range want {
		if got := dimensioned[key]; got != value {
			t.Errorf("metric %q = %v, want %v", key, got, value)
		}
	}

	// A second drain has no delta to publish and must not double-count the first.
	m.drainTo(publisher)
	_, afterSecondDrain := publisher.CountersForTest(t)
	if len(afterSecondDrain) != len(want) {
		t.Fatalf("second drain changed metric count: %#v", afterSecondDrain)
	}
	for key, value := range want {
		if got := afterSecondDrain[key]; got != value {
			t.Errorf("metric %q after second drain = %v, want %v", key, got, value)
		}
	}
	if got := m.outcomeCount(connectorhub.WorkerOutcomeChallengeSent); got != 0 {
		t.Fatalf("drained challenge_sent atomic = %d, want 0", got)
	}
	if got := m.unknownCount(); got != 0 {
		t.Fatalf("drained unknown atomic = %d, want 0", got)
	}
}

// TestWorkerMetricsNonblockingUnderConcurrency exercises the emission path from
// many goroutines at once. It documents and (under -race) enforces that the
// observer is safe for the concurrent, nonblocking calls the worker makes; a
// lock-free atomic implementation also cannot deadlock or stall a caller here.
func TestWorkerMetricsNonblockingUnderConcurrency(t *testing.T) {
	m := newWorkerMetrics()
	const goroutines = 32
	const perGoroutine = 1000

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				m.ObserveWorkerOutcome(connectorhub.WorkerOutcomeResponseSent)
				m.ObserveHandlerResult(connectorhub.ClassificationSuccess, "")
				m.ObserveChallengeDatagramBytes(10, 5)
			}
		}()
	}
	wg.Wait()

	want := uint64(goroutines * perGoroutine)
	if got := m.outcomeCount(connectorhub.WorkerOutcomeResponseSent); got != want {
		t.Fatalf("response_sent = %d, want %d", got, want)
	}
	if got := m.classificationCount(connectorhub.ClassificationSuccess); got != want {
		t.Fatalf("success = %d, want %d", got, want)
	}
	observations, requestBytes, responseBytes := m.challengeStats()
	if observations != want || requestBytes != want*10 || responseBytes != want*5 {
		t.Fatalf("challenge stats = %d/%d/%d, want %d/%d/%d", observations, requestBytes, responseBytes, want, want*10, want*5)
	}
	if got := m.unknownCount(); got != 0 {
		t.Fatalf("unknown = %d, want 0", got)
	}
}

func TestWorkerMetricsConcurrentDrainConservesCounts(t *testing.T) {
	publisher := metrics.NewPublisherForTest(t)
	m := newWorkerMetrics()
	const goroutines = 16
	const perGoroutine = 1000

	var observers sync.WaitGroup
	observers.Add(goroutines)
	for range goroutines {
		go func() {
			defer observers.Done()
			for range perGoroutine {
				m.ObserveWorkerOutcome(connectorhub.WorkerOutcomeResponseSent)
			}
		}()
	}
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for range 100 {
			m.drainTo(publisher)
			runtime.Gosched()
		}
	}()

	observers.Wait()
	<-drained
	m.drainTo(publisher)
	_, dimensioned := publisher.CountersForTest(t)
	key := metricHubWorkerOutcome + "\x00Outcome=response_sent"
	if got, want := dimensioned[key], float64(goroutines*perGoroutine); got != want {
		t.Fatalf("concurrent exported response_sent = %v, want %v", got, want)
	}
}
