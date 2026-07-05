package metrics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"

	"github.com/OpenNHP/opennhp/nhp/log"
	"github.com/OpenNHP/opennhp/nhp/utils"
)

// loadAWSConfig is the function used to load AWS configuration.
// Extracted as a variable so tests can simulate AWS unavailability.
var loadAWSConfig = awsconfig.LoadDefaultConfig

// cloudWatchClient is the subset of CloudWatch client behavior needed by Publisher.
type cloudWatchClient interface {
	PutMetricData(ctx context.Context, params *cloudwatch.PutMetricDataInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.PutMetricDataOutput, error)
}

const (
	flushInterval = 60 * time.Second
	apiTimeout    = 5 * time.Second

	// batchSize is the number of metric datums per PutMetricData API call.
	// CloudWatch allows up to 1000 per call, but we use a smaller batch to keep
	// individual request payloads small and reduce the blast radius of failures.
	// Histogram datums can carry 150 Values and 150 Counts each; a 20-datum
	// histogram batch remains comfortably within the CloudWatch request-size
	// limit while preserving the same failure-containment boundary.
	batchSize = 20

	// maxLatencySamples caps the number of latency observations held between flushes.
	// Under sustained high load (~170 knocks/sec), the slice would grow to ~10k entries
	// per 60s flush interval. Beyond this cap, new samples are dropped to bound memory.
	maxLatencySamples = 10000

	// MaxHistogramSamples caps histogram observations collected between flushes.
	// Histogram functions are expected to drain process-local buffers, so this
	// mirrors maxLatencySamples to keep one flush window bounded even if a
	// producer emits faster than CloudWatch can accept. When this generic
	// publisher-side cap or finite-value filter drops samples, it reports
	// <metric>PublisherDropped; producers with their own upstream buffers may
	// also expose more specific drop metrics.
	// The AC conntrack-dump producer derives its local cap from this constant
	// (maxNetlinkDumpLatencySamples); re-check that producer's drop-signal docs
	// if this value moves.
	MaxHistogramSamples = 10000

	// maxHistogramValuesPerDatum is CloudWatch's per-MetricDatum Values limit.
	// Histogram observations are compacted to unique value/count pairs, then
	// split into chunks at this boundary. A full 10k-unique flush window becomes
	// 67 datums, or four PutMetricData batches at the publisher's batchSize.
	maxHistogramValuesPerDatum = 150

	// defaultCheckpointInterval is how often metrics state is saved to disk.
	// 15s is a quarter of flushInterval (60s): a crash loses at most 15s of
	// accumulated metrics, while the per-tick cost (one snapshot + one
	// fsynced rename of a small JSON file) stays well under a millisecond
	// on SSD. Shorter intervals reduce loss further but burn more disk;
	// longer intervals risk losing more between checkpoints.
	defaultCheckpointInterval = 15 * time.Second

	// checkpointFileName is the file name within the checkpoint directory.
	checkpointFileName = "nhp-metrics-checkpoint.json"

	// checkpointTempFileName is the staging file name used by saveCheckpoint
	// before atomically renaming over checkpointFileName. A fixed name keeps
	// the on-disk path statically derivable from the validated parent dir
	// (no random suffix from os.CreateTemp), which lets the rename target be
	// trivially provable as residing inside the checkpoint directory.
	checkpointTempFileName = "nhp-metrics-checkpoint.json.tmp"

	// checkpointSchemaVersion identifies the on-disk checkpoint schema.
	// Bump this any time the checkpoint struct is extended or changed
	// in a way that would silently misinterpret older files.
	checkpointSchemaVersion = 1

	// MetricCheckpointWriteFailure is incremented every time the periodic
	// checkpoint writer fails to persist a snapshot to disk (e.g. disk full,
	// permission revoked, parent directory unmounted). It is published as a
	// regular CloudWatch counter on the next flush so operators can alarm on
	// "checkpointing has been silently broken for N intervals".
	MetricCheckpointWriteFailure = "CheckpointWriteFailure"

	// MetricPublisherFailure counts PutMetricData batches that returned an
	// error during flush. It is incremented into the live counter map (same
	// path as MetricCheckpointWriteFailure) so the count rides the NEXT
	// successful flush, letting operators alarm on a publisher that is
	// partially or intermittently failing to publish.
	//
	// Coverage boundary (intentional): this counter only surfaces a PARTIALLY
	// failing publisher — one where enough flushes still succeed to carry the
	// accumulated count to CloudWatch (throttling, a transient IAM/STS hiccup,
	// one bad batch). It CANNOT surface a TOTALLY failing publisher, in either
	// form: (a) a nil publisher — NewPublisher returned nil because
	// loadAWSConfig failed (missing AWS_REGION/creds, IMDS unreachable; the
	// #1659 incident) — whose metric methods are nil-safe no-ops; or (b) a
	// non-nil publisher whose every PutMetricData persistently fails, which can
	// never publish this self-reported counter either. Both ride the same dead
	// channel. Total failure is instead caught by the absence-of-metric alarms
	// (treat_missing_data="breaching"), which fire precisely because the
	// success metrics they watch share that same broken publish path:
	// ac-registration-stale on the AC and
	// server-cloudmap-register-refresh-heartbeat on the server. See #1707.
	MetricPublisherFailure = "PublisherFailures"
)

// HealthProbe is a function that returns true if the storage backend is healthy.
type HealthProbe func(ctx context.Context) bool

// GaugeFunc is a function that returns the current value for a gauge metric.
// Registered via RegisterGaugeFunc, called each flush interval.
type GaugeFunc func() float64

// HistogramFunc drains pending observations for a histogram metric.
// The returned values are published in the unit supplied to
// RegisterHistogramFunc via CloudWatch MetricDatum Values/Counts so percentile
// statistics remain available. After the call returns, the publisher owns the
// returned slice and may retain or truncate it; return a copy if the producer
// reuses its live buffer. Implementations may emit companion counters before
// returning; histogram functions run outside the publisher lock so those
// counters join the same flush without lock re-entry.
type HistogramFunc func() []float64

type histogramFuncEntry struct {
	unit types.StandardUnit
	fn   HistogramFunc
}

type histogramEntry struct {
	unit   types.StandardUnit
	values []float64
}

// histogramPublisherDroppedMetricName reserves the PublisherDropped suffix for
// the generic histogram guardrail counter. It covers publisher-side cap drops
// and invalid finite-value-filter drops. Do not register a first-class metric
// that would intentionally collide with this synthesized name.
func histogramPublisherDroppedMetricName(name string) string {
	return name + "PublisherDropped"
}

// Config configures a metrics Publisher.
type Config struct {
	Namespace  string            // CloudWatch namespace (e.g. "NHP/AC", "LayerV/NHP")
	Dimensions []types.Dimension // Shared dimensions attached to all metrics

	// CheckpointDir is the directory for metric checkpoint files.
	// If empty, checkpointing is disabled.
	CheckpointDir string

	// CheckpointInterval controls how often metrics state is saved to disk.
	// Defaults to 15 seconds if CheckpointDir is set and this is zero.
	CheckpointInterval time.Duration
}

// dimCounterEntry holds a counter with custom dimensions.
type dimCounterEntry struct {
	metricName string
	dims       []types.Dimension // pre-merged: shared + extra
	value      float64
}

// Publisher batches and publishes metrics to CloudWatch.
// Metrics are accumulated in-memory and flushed periodically to minimize
// API calls and stay within CloudWatch PutMetricData limits.
type Publisher struct {
	client         cloudWatchClient
	namespace      string
	mu             sync.RWMutex
	counters       map[string]float64          // metric name → accumulated count (skipped when 0)
	dimCounters    map[string]*dimCounterEntry // composite key → counter with extra dims
	gauges         map[string]float64          // metric name → current value (always published)
	latencies      map[string][]float64        // metric name → recorded latencies
	histograms     map[string]*histogramEntry  // metric name → pending histogram observations
	dims           []types.Dimension
	stop           chan struct{}
	wg             sync.WaitGroup                // tracks flushLoop goroutine for graceful shutdown
	once           sync.Once                     // ensures Stop is idempotent
	healthProbe    HealthProbe                   // optional: emits StorageHealthy gauge each flush
	gaugeFuncs     map[string]GaugeFunc          // metric name → func called each flush
	histogramFuncs map[string]histogramFuncEntry // metric name → drain func called each flush
	emfWriter      io.Writer                     // destination for EMF JSON lines (defaults to os.Stdout)

	// Checkpoint fields (empty checkpointDir means checkpointing disabled)
	checkpointDir      string
	checkpointInterval time.Duration
}

// checkpointEnabled reports whether the publisher persists periodic
// checkpoints to disk. Centralizes the empty-string check used at every
// checkpoint call site so the invariant lives in one place.
func (mp *Publisher) checkpointEnabled() bool {
	return mp.checkpointDir != ""
}

// recoverFromCheckpoint loads any existing checkpoint and merges it into the
// publisher's in-memory state. Stale checkpoints (older than 2*flushInterval)
// are dropped without merging. No-op when checkpointing is disabled.
//
// Safe to call without holding mp.mu: NewPublisher invokes this before the
// flushLoop goroutine starts, so there are no other readers or writers yet.
//
// The on-disk file is removed only AFTER mergeCheckpoint completes, so a
// crash between load and merge leaves the file in place for the next start
// to retry instead of silently dropping the metrics it contained.
func (mp *Publisher) recoverFromCheckpoint() {
	if !mp.checkpointEnabled() {
		return
	}
	cp, loadErr := loadCheckpoint(mp.checkpointDir)
	if loadErr != nil {
		log.Warning("failed to load metrics checkpoint: %v", loadErr)
		return
	}
	if cp == nil {
		return
	}
	cpAge := time.Since(cp.Timestamp)
	stalenessThreshold := 2 * flushInterval
	if cpAge > stalenessThreshold {
		log.Warning("discarding stale metrics checkpoint (age=%s, threshold=%s)",
			cpAge.Truncate(time.Second), stalenessThreshold)
		// Stale data can never be replayed safely. Remove it so the
		// next start does not log the same warning forever.
		removeCheckpoint(mp.checkpointDir)
		return
	}
	mp.mergeCheckpoint(cp)
	// Merge succeeded; the on-disk copy has been absorbed into in-memory
	// state and any subsequent flush will publish (or re-checkpoint) it.
	//
	// Replay-stamping caveat: recovered metrics are re-stamped at the next
	// flush()'s flushStart, not their original event time, so the
	// "within one flushInterval of true event time" property does not hold for
	// them. The staleness drop above bounds the error — a checkpoint older than
	// 2*flushInterval is discarded, so replayed events are at most ~staleness +
	// one flush interval (~3 min) stale and can never approach CloudWatch's
	// ~2-week past-validity window. Seeding the stamp from cp.Timestamp would
	// close the gap; tracked in #2602.
	removeCheckpoint(mp.checkpointDir)
	log.Info("recovered metrics checkpoint from %s (age=%s)",
		mp.checkpointDir, cpAge.Truncate(time.Second))
}

// NewPublisher creates a CloudWatch metrics publisher.
// Returns nil if AWS config cannot be loaded (e.g., running locally without IAM).
// If CheckpointDir is set, the publisher loads any existing checkpoint from a
// previous crash and periodically saves metric state to disk.
func NewPublisher(cfg Config) *Publisher {
	ctx, cancel := context.WithTimeout(context.Background(), apiTimeout)
	defer cancel()

	awsCfg, err := loadAWSConfig(ctx)
	if err != nil {
		log.Warning("CloudWatch metrics disabled: %v", err)
		return nil
	}

	cpInterval := cfg.CheckpointInterval
	cpDir := cfg.CheckpointDir
	if cpDir != "" {
		if cpInterval == 0 {
			cpInterval = defaultCheckpointInterval
		}
		// Validate the checkpoint directory at construction so a misconfig
		// (path doesn't exist, isn't writable, fails the path-traversal
		// guard) surfaces as a startup warning instead of a silent
		// MetricCheckpointWriteFailure increment 15s into the process. We
		// disable checkpointing for this publisher on failure rather than
		// failing the whole metrics pipeline — losing checkpointing is much
		// better than losing all metrics.
		if _, _, _, resolveErr := resolveCheckpointTarget(cpDir); resolveErr != nil {
			log.Warning("CloudWatch metrics: CheckpointDir %q rejected (%v) — checkpointing disabled for this publisher",
				cpDir, resolveErr)
			cpDir = ""
			cpInterval = 0
		}
	}

	mp := &Publisher{
		client:             cloudwatch.NewFromConfig(awsCfg),
		namespace:          cfg.Namespace,
		counters:           make(map[string]float64),
		dimCounters:        make(map[string]*dimCounterEntry),
		gauges:             make(map[string]float64),
		latencies:          make(map[string][]float64),
		histograms:         make(map[string]*histogramEntry),
		dims:               cfg.Dimensions,
		stop:               make(chan struct{}),
		gaugeFuncs:         make(map[string]GaugeFunc),
		histogramFuncs:     make(map[string]histogramFuncEntry),
		emfWriter:          os.Stdout,
		checkpointDir:      cpDir,
		checkpointInterval: cpInterval,
	}

	mp.recoverFromCheckpoint()

	mp.wg.Add(1)
	go mp.flushLoop()

	dimDesc := make([]string, len(cfg.Dimensions))
	for i, d := range cfg.Dimensions {
		dimDesc[i] = *d.Name + "=" + *d.Value
	}

	cpStatus := "disabled"
	if mp.checkpointEnabled() {
		cpStatus = mp.checkpointDir + " every " + mp.checkpointInterval.String()
	}
	log.Info("CloudWatch metrics publisher started (namespace=%s, dims=[%s], emf=enabled, checkpoint=%s)",
		cfg.Namespace, strings.Join(dimDesc, ", "), cpStatus)
	return mp
}

// IncrCounter increments a counter metric by 1.
func (mp *Publisher) IncrCounter(name string) {
	if mp == nil {
		return
	}
	mp.mu.Lock()
	mp.counters[name]++
	mp.mu.Unlock()
}

// IncrCounterWithDims increments a counter metric by 1 with extra dimensions
// appended to the shared dimensions.
func (mp *Publisher) IncrCounterWithDims(name string, extraDims []types.Dimension) {
	mp.AddCounterWithDims(name, 1, extraDims)
}

// AddCounterWithDims adds a value to a counter metric with extra dimensions
// appended to the shared dimensions. Metrics with the same name and dimension
// set are batched together.
func (mp *Publisher) AddCounterWithDims(name string, value float64, extraDims []types.Dimension) {
	if mp == nil {
		return
	}

	allDims := make([]types.Dimension, 0, len(mp.dims)+len(extraDims))
	allDims = append(allDims, mp.dims...)
	allDims = append(allDims, extraDims...)

	key := buildDimCounterKey(name, allDims)

	mp.mu.Lock()
	entry, exists := mp.dimCounters[key]
	if !exists {
		entry = &dimCounterEntry{
			metricName: name,
			dims:       allDims,
		}
		mp.dimCounters[key] = entry
	}
	entry.value += value
	mp.mu.Unlock()
}

// SetGauge sets a gauge metric to the given value.
// Gauges are always published (even when 0), making them suitable for
// state indicators like peer counts or health status.
func (mp *Publisher) SetGauge(name string, value float64) {
	if mp == nil {
		return
	}
	mp.mu.Lock()
	mp.gauges[name] = value
	mp.mu.Unlock()
}

// RegisterGaugeFunc registers a function that is called each flush interval
// to update the named gauge metric. The function should return the current value.
func (mp *Publisher) RegisterGaugeFunc(name string, fn GaugeFunc) {
	if mp == nil {
		return
	}
	mp.mu.Lock()
	mp.gaugeFuncs[name] = fn
	mp.mu.Unlock()
}

// RegisterHistogramFunc registers a function that drains pending histogram
// observations each flush interval. The returned observations are buffered in
// the publisher for the immediately following flush and emitted with
// CloudWatch Values/Counts, preserving percentile statistics. Re-registering
// an existing name is last-unit-wins for any observations already buffered in
// the current flush window; production callers register once during startup.
func (mp *Publisher) RegisterHistogramFunc(name string, unit types.StandardUnit, fn HistogramFunc) {
	if mp == nil {
		return
	}
	mp.mu.Lock()
	if mp.histogramFuncs == nil {
		mp.histogramFuncs = make(map[string]histogramFuncEntry)
	}
	if mp.histograms == nil {
		mp.histograms = make(map[string]*histogramEntry)
	}
	if mp.counters == nil {
		mp.counters = make(map[string]float64)
	}
	mp.histogramFuncs[name] = histogramFuncEntry{unit: unit, fn: fn}
	mp.mu.Unlock()
}

// SetHealthProbe registers a function that is called each flush interval.
// The result is published as StorageHealthy (1.0 = healthy, 0.0 = unhealthy).
func (mp *Publisher) SetHealthProbe(probe HealthProbe) {
	if mp == nil {
		return
	}
	mp.mu.Lock()
	mp.healthProbe = probe
	mp.mu.Unlock()
}

// RecordLatency records a latency observation in milliseconds.
// Samples are dropped if the buffer exceeds maxLatencySamples to bound memory.
func (mp *Publisher) RecordLatency(name string, ms float64) {
	if mp == nil {
		return
	}
	mp.mu.Lock()
	if s := mp.latencies[name]; len(s) < maxLatencySamples {
		if s == nil {
			s = make([]float64, 0, 1000)
		}
		mp.latencies[name] = append(s, ms)
	} else {
		mp.counters[name+"_Dropped"]++
	}
	mp.mu.Unlock()
}

// Stop gracefully shuts down the publisher, flushing remaining metrics.
// It waits for the flushLoop goroutine to exit before performing the final flush
// to prevent concurrent flush operations. Safe to call multiple times.
// On graceful shutdown the checkpoint file is removed since the final flush
// captures all pending metrics.
func (mp *Publisher) Stop() {
	if mp == nil {
		return
	}
	mp.once.Do(func() {
		close(mp.stop)
		mp.wg.Wait() // wait for flushLoop to exit before final flush
		// Histogram funcs drain event-like samples from process-local buffers.
		// Collect once more before the final flush so shutdown does not strand
		// observations that arrived after the last periodic tick.
		mp.collectHistograms()
		mp.flush()
	})
}

func (mp *Publisher) flushLoop() {
	defer mp.wg.Done()
	flushTicker := time.NewTicker(flushInterval)
	defer flushTicker.Stop()

	// Checkpoint ticker: only active when checkpointing is enabled.
	var cpTickerC <-chan time.Time
	if mp.checkpointEnabled() {
		cpTicker := time.NewTicker(mp.checkpointInterval)
		defer cpTicker.Stop()
		cpTickerC = cpTicker.C
	}

	// flush and writeCheckpoint share this single goroutine via the select
	// below, so they cannot run concurrently during normal operation. That
	// property is what lets flush() drop the checkpoint file outside its
	// write lock without any inter-goroutine synchronization.
	//
	// Stop() also calls flush() once after wg.Wait() returns; that call is
	// safe because the flushLoop goroutine has already exited by then, so
	// no concurrent writeCheckpoint can be in flight.
	for {
		select {
		case <-flushTicker.C:
			mp.collectGauges()
			// Keep histogram collection adjacent to flush: histogram samples are
			// not checkpointed, while companion counters emitted by histogram
			// funcs use the normal counter maps. No checkpoint tick may interleave
			// between a drain and its PutMetricData attempt. If the process dies
			// after the drain, or PutMetricData fails, samples from that drain and
			// same-drain companion counters are best-effort and are not replayed.
			mp.collectHistograms()
			mp.probeHealth()
			mp.flush()
		case <-cpTickerC:
			mp.writeCheckpoint()
		case <-mp.stop:
			return
		}
	}
}

// writeCheckpoint snapshots current in-memory metrics to disk. Persistent
// failures (disk full, perms revoked, etc.) are surfaced via the
// MetricCheckpointWriteFailure counter so operators can alarm on a
// checkpointing outage in addition to seeing the warning logs.
func (mp *Publisher) writeCheckpoint() {
	mp.mu.RLock()
	cp := mp.snapshotToCheckpoint()
	mp.mu.RUnlock()

	if err := saveCheckpoint(mp.checkpointDir, cp); err != nil {
		log.Warning("failed to write metrics checkpoint: %v", err)
		mp.IncrCounter(MetricCheckpointWriteFailure)
	}
}

// collectGauges calls all registered gauge functions and updates their values.
// Gauge funcs are called outside the lock to avoid holding it during potentially
// slow operations (e.g., ACPeerCount acquires its own read lock).
func (mp *Publisher) collectGauges() {
	mp.mu.RLock()
	funcs := make(map[string]GaugeFunc, len(mp.gaugeFuncs))
	for name, fn := range mp.gaugeFuncs {
		funcs[name] = fn
	}
	mp.mu.RUnlock()

	values := make(map[string]float64, len(funcs))
	for name, fn := range funcs {
		values[name] = fn()
	}

	mp.mu.Lock()
	for name, val := range values {
		mp.gauges[name] = val
	}
	mp.mu.Unlock()
}

// collectHistograms calls registered histogram functions outside the publisher
// lock, then appends the drained observations to the pending histogram buffers.
func (mp *Publisher) collectHistograms() {
	mp.mu.RLock()
	funcs := make(map[string]histogramFuncEntry, len(mp.histogramFuncs))
	for name, entry := range mp.histogramFuncs {
		funcs[name] = entry
	}
	mp.mu.RUnlock()

	type sampleBatch struct {
		name   string
		unit   types.StandardUnit
		values []float64
	}
	batches := make([]sampleBatch, 0, len(funcs))
	for name, entry := range funcs {
		if entry.fn == nil {
			continue
		}
		values := entry.fn()
		if len(values) == 0 {
			continue
		}
		batches = append(batches, sampleBatch{
			name:   name,
			unit:   entry.unit,
			values: values,
		})
	}

	mp.mu.Lock()
	defer mp.mu.Unlock()
	for _, batch := range batches {
		values, invalidDropped := filterInvalidHistogramValues(batch.values)
		if invalidDropped > 0 {
			mp.counters[histogramPublisherDroppedMetricName(batch.name)] += float64(invalidDropped)
		}
		if len(values) == 0 {
			continue
		}
		entry := mp.histograms[batch.name]
		if entry == nil {
			entry = &histogramEntry{unit: batch.unit}
			mp.histograms[batch.name] = entry
		}
		if entry.unit != batch.unit {
			// Re-registration is last-unit-wins for any unflushed values.
			entry.unit = batch.unit
		}
		remaining := MaxHistogramSamples - len(entry.values)
		if remaining <= 0 {
			mp.counters[histogramPublisherDroppedMetricName(batch.name)] += float64(len(values))
			continue
		}
		if len(values) > remaining {
			mp.counters[histogramPublisherDroppedMetricName(batch.name)] += float64(len(values) - remaining)
			// The generic cap keeps the earliest collected observations and
			// reports the tail drop. The current AC producer cannot hit this
			// branch because its local cap matches MaxHistogramSamples.
			values = values[:remaining]
		}
		entry.values = append(entry.values, values...)
	}
}

func filterInvalidHistogramValues(values []float64) ([]float64, int) {
	var filtered []float64
	for i, value := range values {
		if math.IsNaN(value) || math.IsInf(value, 0) {
			if filtered == nil {
				filtered = make([]float64, 0, len(values)-1)
				filtered = append(filtered, values[:i]...)
			}
			continue
		}
		if filtered != nil {
			filtered = append(filtered, value)
		}
	}
	if filtered == nil {
		return values, 0
	}
	return filtered, len(values) - len(filtered)
}

// probeHealth runs the health probe (if set) and records the result as a gauge.
// The probe receives a context with apiTimeout (5s). If the probe's underlying
// ping has its own timeout, the shorter of the two wins.
func (mp *Publisher) probeHealth() {
	mp.mu.RLock()
	probe := mp.healthProbe
	mp.mu.RUnlock()

	if probe == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), apiTimeout)
	defer cancel()

	healthy := probe(ctx)
	val := 0.0
	if healthy {
		val = 1.0
	}

	mp.mu.Lock()
	mp.gauges["StorageHealthy"] = val
	mp.mu.Unlock()
}

// flush swaps out the in-memory metric maps and publishes them to CloudWatch.
// If PutMetricData fails, the swapped metrics are lost. This is intentional:
// observability data is best-effort, and merging failed metrics back into the
// live maps would add complexity and risk double-counting.
func (mp *Publisher) flush() {
	// Stamp every datapoint in this batch with one wall-clock instant,
	// captured here just before the lock. The map swap a few microseconds later
	// is the precise close of the accumulation window, so an event arriving in
	// that sliver is included in this batch yet stamped marginally (sub-ms)
	// before it occurred — negligible negative skew against the ~60s tolerance.
	// Without an explicit MetricDatum.Timestamp,
	// CloudWatch stamps each datapoint at PutMetricData *receive* time, which
	// is not event time and — with sparse traffic plus get-metric-data period
	// alignment — makes forensic correlation unreliable (#1257). Events in this
	// batch occurred roughly one flushInterval (60s) before this instant — a
	// little more if a preceding flush ran long, since flush() is synchronous
	// on the ticker goroutine and PutMetricData can block up to apiTimeout per
	// batch while the ticker coalesces — but batches are tiny in practice, so
	// the window stays close to 60s.
	//
	// This is host-clock-derived (time.Now), so datapoint time now tracks EC2
	// NTP health rather than the CloudWatch ingest clock — an intentional
	// trade, since receive time was never event time. Sharper consequence: an
	// explicit timestamp is subject to CloudWatch's validity window
	// (PutMetricData rejects datums more than ~2h in the future or ~2 weeks in
	// the past), which receive-time stamping could never trip — so a host clock
	// skewed past that window gets its whole batch rejected. We deliberately do
	// NOT clamp to the window: the only reference available here is this same
	// (skewed) clock, so a clamp would be tautological. The rejection is not
	// silent — the PutMetricData error path below logs it and bumps
	// MetricPublisherFailure, and a persistently skewed clock degrades to the
	// absence-of-metric alarms (treat_missing_data="breaching") that already
	// backstop total publish failure.
	flushStart := time.Now()

	mp.mu.Lock()
	counters := mp.counters
	dimCounters := mp.dimCounters
	gauges := mp.gauges
	latencies := mp.latencies
	histograms := mp.histograms
	mp.counters = make(map[string]float64)
	mp.dimCounters = make(map[string]*dimCounterEntry)
	mp.gauges = make(map[string]float64)
	mp.latencies = make(map[string][]float64)
	mp.histograms = make(map[string]*histogramEntry)
	mp.mu.Unlock()

	// Drop the checkpoint after the swap so a crash *between this point and
	// the next writeCheckpoint* cannot replay metrics that have just been
	// flushed: on recovery there is no checkpoint file, so we start from a
	// clean in-memory state. We deliberately remove BEFORE attempting the
	// CloudWatch publish below to bias toward "lose a few datapoints on a
	// publish-failure-then-crash" instead of "double-count on every crash
	// after a successful publish". Metric over-counting can fire alarms
	// spuriously, which is operationally worse than the small loss window.
	//
	// Runs outside the write lock because writeCheckpoint and flush share
	// the flushLoop goroutine (or, during shutdown, the flushLoop has
	// already exited before Stop() invokes flush()), so they cannot race.
	// Holding the write lock here would only block recorders (IncrCounter
	// etc.) for the duration of an unrelated unlink syscall.
	if mp.checkpointEnabled() {
		removeCheckpoint(mp.checkpointDir)
	}

	mp.emitEMF(flushStart, latencies)
	// Histograms publish percentile-compatible Values/Counts through
	// PutMetricData. Do not mirror them into EMF, or CloudWatch would extract
	// a second copy of each sample and skew percentile reads.

	metricData := mp.buildMetricData(flushStart, counters, dimCounters, gauges, latencies, histograms)

	if len(metricData) == 0 {
		return
	}
	if mp.client == nil {
		log.Warning("CloudWatch metrics skipped: client is nil (%d datums)", len(metricData))
		return
	}

	for i := 0; i < len(metricData); i += batchSize {
		end := i + batchSize
		if end > len(metricData) {
			end = len(metricData)
		}

		ctx, cancel := context.WithTimeout(context.Background(), apiTimeout)
		_, err := mp.client.PutMetricData(ctx, &cloudwatch.PutMetricDataInput{
			Namespace:  aws.String(mp.namespace),
			MetricData: metricData[i:end],
		})
		cancel()

		if err != nil {
			log.Warning("Failed to publish CloudWatch metrics (batch %d/%d, %d datums): %v",
				i/batchSize+1, (len(metricData)+batchSize-1)/batchSize,
				end-i, err)
			// Self-report the batch failure so a partially/intermittently
			// failing publisher is observable. IncrCounter writes into the
			// fresh counter map this flush already swapped in (above), so the
			// count rides the next successful flush. Under sustained failure
			// the running total is best-effort and may undercount (it is lost
			// if the carrying flush also fails) — fine for a presence alarm.
			// See MetricPublisherFailure for the total-death coverage boundary.
			mp.IncrCounter(MetricPublisherFailure)
		}
	}
}

type emfMetricDefinition struct {
	Name string `json:"Name"`
	Unit string `json:"Unit"`
}

type emfMetricDirective struct {
	Namespace  string                `json:"Namespace"`
	Dimensions [][]string            `json:"Dimensions"`
	Metrics    []emfMetricDefinition `json:"Metrics"`
}

type emfAWSBlock struct {
	Timestamp         int64                `json:"Timestamp"`
	CloudWatchMetrics []emfMetricDirective `json:"CloudWatchMetrics"`
}

const emfMaxValues = 150

// CloudWatch unit strings for EMF emissions.
const (
	emfUnitMilliseconds = "Milliseconds"
	emfUnitCount        = "Count"
)

// packDims splits a Dimension slice into the parallel (names slice, name→value map)
// shapes that buildEMFEvent expects. Shared between emitEMF and EmitEMFMetricNow.
func packDims(dims []types.Dimension) (names []string, values map[string]string) {
	names = make([]string, len(dims))
	values = make(map[string]string, len(dims))
	for i, d := range dims {
		names[i] = *d.Name
		values[*d.Name] = *d.Value
	}
	return names, values
}

// writeEMFEvent marshals one EMF event and writes it plus a newline to the
// publisher's emfWriter. Logs a warning on marshal or write errors tagged
// with `warnContext` so the flush-loop and one-shot paths produce
// distinguishable log lines. Shared inner helper for emitEMF and
// EmitEMFMetricNow.
func (mp *Publisher) writeEMFEvent(event map[string]any, warnContext string) {
	data, err := json.Marshal(event)
	if err != nil {
		log.Warning("Failed to marshal %s: %v", warnContext, err)
		return
	}
	data = append(data, '\n')
	if _, err := mp.emfWriter.Write(data); err != nil {
		log.Warning("Failed to write %s: %v", warnContext, err)
	}
}

// emitEMF writes accumulated latency observations as EMF events. ts is the
// flush instant captured once by flush() and shared with buildMetricData, so
// the EMF latency events and the PutMetricData statistic set for the same
// latencies in the same flush carry an identical timestamp (one flush → one
// event time). The one-shot EmitEMFMetricNow path keeps its own time.Now()
// because it emits immediately rather than at flush.
func (mp *Publisher) emitEMF(ts time.Time, latencies map[string][]float64) {
	if mp.emfWriter == nil {
		return
	}
	tsMs := ts.UnixMilli()
	dimNames, dimValues := packDims(mp.dims)
	for name, values := range latencies {
		if len(values) == 0 {
			continue
		}
		for i := 0; i < len(values); i += emfMaxValues {
			end := i + emfMaxValues
			if end > len(values) {
				end = len(values)
			}
			event := buildEMFEvent(mp.namespace, name, emfUnitMilliseconds, dimNames, dimValues, values[i:end], tsMs)
			mp.writeEMFEvent(event, "EMF latency event for "+name)
		}
	}
}

// EmitEMFMetricNow writes one EMF metric event immediately, bypassing the
// flush loop. Namespace and base dimensions come from the Publisher;
// extraDims are appended for this event only. Use for one-shot signals
// (e.g., startup events) where the next flush window would be too late
// and where CloudWatch EMF auto-extraction keeps the pipeline decoupled
// from SDK credential / network state at the emission site.
//
// Concurrency: one marshaled JSON line per call. os.Stdout writes under
// PIPE_BUF are atomic; callers routing emfWriter elsewhere must ensure
// the destination's Write is concurrent-safe with the flush loop's
// own emitEMF writes.
//
// No-op on a nil Publisher or nil emfWriter.
func (mp *Publisher) EmitEMFMetricNow(name, unit string, value float64, extraDims []types.Dimension) {
	if mp == nil || mp.emfWriter == nil {
		return
	}
	allDims := make([]types.Dimension, 0, len(mp.dims)+len(extraDims))
	allDims = append(allDims, mp.dims...)
	allDims = append(allDims, extraDims...)
	dimNames, dimValues := packDims(allDims)
	event := buildEMFEvent(mp.namespace, name, unit, dimNames, dimValues, []float64{value}, time.Now().UnixMilli())
	mp.writeEMFEvent(event, "EMF "+unit+" event for "+name)
}

// EmitEMFCounterNow is a convenience wrapper around EmitEMFMetricNow for
// the common "increment once, Unit=Count" case. Retained for call-site
// readability at startup/shutdown signals; more general callers should
// use EmitEMFMetricNow directly.
func (mp *Publisher) EmitEMFCounterNow(name string, extraDims []types.Dimension) {
	mp.EmitEMFMetricNow(name, emfUnitCount, 1, extraDims)
}

func buildEMFEvent(namespace, metricName, unit string, dimNames []string, dimValues map[string]string, values []float64, timestampMs int64) map[string]any {
	event := map[string]any{
		"_aws": emfAWSBlock{
			Timestamp: timestampMs,
			CloudWatchMetrics: []emfMetricDirective{
				{
					Namespace:  namespace,
					Dimensions: [][]string{dimNames},
					Metrics:    []emfMetricDefinition{{Name: metricName, Unit: unit}},
				},
			},
		},
	}
	for k, v := range dimValues {
		event[k] = v
	}
	if len(values) == 1 {
		event[metricName] = values[0]
	} else {
		event[metricName] = values
	}
	return event
}

// buildMetricData converts accumulated metrics into CloudWatch MetricDatum slices.
// Extracted from flush() to enable testing the metric data pipeline without an API call.
// Every datum is stamped with ts — the single wall-clock instant flush() captures at the
// start of the flush — so all datums in a batch share one (approximately) event time
// instead of PutMetricData receive time.
func (mp *Publisher) buildMetricData(
	ts time.Time,
	counters map[string]float64,
	dimCounters map[string]*dimCounterEntry,
	gauges map[string]float64,
	latencies map[string][]float64,
	histograms map[string]*histogramEntry,
) []types.MetricDatum {
	var metricData []types.MetricDatum

	// Every datum in this flush shares the one captured instant, so build the
	// pointer once and reuse it across all kinds below. Safe because the SDK
	// treats MetricDatum.Timestamp as read-only request input — it is never
	// mutated after construction.
	tsPtr := aws.Time(ts)

	// Flush counters (skip 0 — means the counter wasn't incremented this interval)
	for name, value := range counters {
		if value == 0 {
			continue
		}
		metricData = append(metricData, types.MetricDatum{
			MetricName: aws.String(name),
			Dimensions: mp.dims,
			Value:      aws.Float64(value),
			Unit:       types.StandardUnitCount,
			Timestamp:  tsPtr,
		})
	}

	// Flush dimCounters (counters with extra dimensions)
	for _, entry := range dimCounters {
		if entry.value == 0 {
			continue
		}
		metricData = append(metricData, types.MetricDatum{
			MetricName: aws.String(entry.metricName),
			Dimensions: entry.dims,
			Value:      aws.Float64(entry.value),
			Unit:       types.StandardUnitCount,
			Timestamp:  tsPtr,
		})
	}

	// Flush gauges (always published — 0 is a meaningful value, e.g. StorageHealthy=0 means unhealthy)
	for name, value := range gauges {
		metricData = append(metricData, types.MetricDatum{
			MetricName: aws.String(name),
			Dimensions: mp.dims,
			Value:      aws.Float64(value),
			Unit:       types.StandardUnitNone,
			Timestamp:  tsPtr,
		})
	}

	// Flush latencies as CloudWatch statistic sets.
	// A statistic set aggregates multiple observations into min/max/sum/count,
	// which is more efficient than publishing individual data points.
	for name, values := range latencies {
		if len(values) == 0 {
			continue
		}
		min, max, sum := values[0], values[0], 0.0
		for _, v := range values {
			sum += v
			if v < min {
				min = v
			}
			if v > max {
				max = v
			}
		}
		metricData = append(metricData, types.MetricDatum{
			MetricName: aws.String(name),
			Dimensions: mp.dims,
			StatisticValues: &types.StatisticSet{
				Minimum:     aws.Float64(min),
				Maximum:     aws.Float64(max),
				Sum:         aws.Float64(sum),
				SampleCount: aws.Float64(float64(len(values))),
			},
			Unit:      types.StandardUnitMilliseconds,
			Timestamp: tsPtr,
		})
	}

	// Flush histograms using CloudWatch Values/Counts instead of StatisticSet
	// so percentile statistics remain queryable. collectHistograms accounts
	// invalid NaN/+/-Inf samples as PublisherDropped; appendHistogramDatums
	// keeps a final defensive filter because CloudWatch rejects them. Do not
	// account drops again here, or invalid samples would double-count.
	for name, entry := range histograms {
		if entry == nil || len(entry.values) == 0 {
			continue
		}
		metricData = appendHistogramDatums(metricData, tsPtr, name, entry, mp.dims)
	}

	return metricData
}

func appendHistogramDatums(metricData []types.MetricDatum, tsPtr *time.Time, name string, entry *histogramEntry, dims []types.Dimension) []types.MetricDatum {
	countsByValue := make(map[float64]float64, len(entry.values))
	for _, value := range entry.values {
		// collectHistograms/filterInvalidHistogramValues owns PublisherDropped
		// accounting; this final guard only prevents a rejected CloudWatch datum.
		if math.IsNaN(value) || math.IsInf(value, 0) {
			continue
		}
		countsByValue[value]++
	}
	if len(countsByValue) == 0 {
		return metricData
	}

	values := make([]float64, 0, len(countsByValue))
	for value := range countsByValue {
		values = append(values, value)
	}
	slices.Sort(values)

	for i := 0; i < len(values); i += maxHistogramValuesPerDatum {
		end := i + maxHistogramValuesPerDatum
		if end > len(values) {
			end = len(values)
		}
		chunkValues := values[i:end]
		chunkCounts := make([]float64, len(chunkValues))
		for j, value := range chunkValues {
			chunkCounts[j] = countsByValue[value]
		}
		metricData = append(metricData, types.MetricDatum{
			MetricName: aws.String(name),
			Dimensions: dims,
			Values:     chunkValues,
			Counts:     chunkCounts,
			Unit:       entry.unit,
			Timestamp:  tsPtr,
		})
	}
	return metricData
}

// buildDimCounterKey builds a deterministic map key from a metric name and its dimensions.
// Null bytes (\x00) are used as internal separators. This is safe because CloudWatch
// dimension names and values are restricted to printable UTF-8 and cannot contain null bytes.
//
// Key format is part of the CountersForTest contract. Test helpers
// (e.g., countDimCountersWithPrefix in endpoints/ac) anchor on the
// metric_name + "\x00" prefix to count entries by exact metric name
// without colliding on a future metric whose name shares the prefix.
// If the separator changes, those test helpers must change in lockstep.
func buildDimCounterKey(name string, dims []types.Dimension) string {
	// Sort by dimension name for deterministic key, but skip the sort
	// if dimensions are already in order (common case: shared dims are
	// pre-sorted and extras are appended in consistent order).
	sorted := dims
	if !dimsSorted(dims) {
		sorted = slices.Clone(dims)
		sort.Slice(sorted, func(i, j int) bool {
			return *sorted[i].Name < *sorted[j].Name
		})
	}

	var b strings.Builder
	b.WriteString(name)
	for _, d := range sorted {
		b.WriteByte(0)
		b.WriteString(*d.Name)
		b.WriteByte('=')
		b.WriteString(*d.Value)
	}
	return b.String()
}

// dimsSorted returns true if dimensions are already sorted by name.
func dimsSorted(dims []types.Dimension) bool {
	for i := 1; i < len(dims); i++ {
		if *dims[i].Name < *dims[i-1].Name {
			return false
		}
	}
	return true
}

// ============================================================================
// Crash-Resilient Metric Checkpointing
// ============================================================================

// checkpointDimension is a JSON-friendly representation of types.Dimension.
type checkpointDimension struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// checkpointDimCounter is a JSON-friendly representation of dimCounterEntry.
type checkpointDimCounter struct {
	MetricName string                `json:"metric_name"`
	Dims       []checkpointDimension `json:"dims"`
	Value      float64               `json:"value"`
}

// checkpoint is the on-disk representation of accumulated metrics state.
// Bump checkpointSchemaVersion any time a field is added, removed, or
// reinterpreted so older files are discarded on load instead of being
// silently merged with missing fields.
type checkpoint struct {
	Version     int                             `json:"version"`
	Timestamp   time.Time                       `json:"timestamp"`
	Counters    map[string]float64              `json:"counters,omitempty"`
	DimCounters map[string]checkpointDimCounter `json:"dim_counters,omitempty"`
	Gauges      map[string]float64              `json:"gauges,omitempty"`
	Latencies   map[string][]float64            `json:"latencies,omitempty"`
}

// resolveCheckpointTarget validates the checkpoint directory and returns the
// resolved absolute final and temp paths. Callers only pass the trusted
// service-owned CheckpointDir today, but this guard keeps any future caller
// from inducing a traversal via the directory argument by funneling every
// checkpoint path through the same nhp/utils traversal helpers used in
// httpstorage.go and kbs/resource.go.
func resolveCheckpointTarget(dir string) (absDir, target, tmpTarget string, err error) {
	absDir, err = filepath.Abs(dir)
	if err != nil {
		return "", "", "", fmt.Errorf("resolve checkpoint dir: %w", err)
	}
	absDir = filepath.Clean(absDir)

	target, err = checkpointChildPath(absDir, checkpointFileName)
	if err != nil {
		return "", "", "", err
	}
	tmpTarget, err = checkpointChildPath(absDir, checkpointTempFileName)
	if err != nil {
		return "", "", "", err
	}
	return absDir, target, tmpTarget, nil
}

// checkpointChildPath joins parent and name, asserting that name is a plain
// basename and that the resulting absolute path stays inside parent.
func checkpointChildPath(parent, name string) (string, error) {
	if !utils.IsValidPathComponent(name) {
		return "", fmt.Errorf("invalid checkpoint file name %q", name)
	}
	p := filepath.Join(parent, name)
	if !utils.IsPathWithinDir(p, parent) {
		return "", fmt.Errorf("checkpoint path %q escapes parent %q", p, parent)
	}
	return p, nil
}

func saveCheckpoint(dir string, cp *checkpoint) error {
	data, err := json.Marshal(cp)
	if err != nil {
		return fmt.Errorf("marshal checkpoint: %w", err)
	}

	absDir, target, tmpName, err := resolveCheckpointTarget(dir)
	if err != nil {
		return err
	}

	// Clear any temp leftover from a previous run that crashed between
	// open and rename. Once cleared, the O_EXCL on the open below means a
	// pre-existing symlink at tmpName cannot be followed: the open will
	// fail rather than write through the symlink to an attacker-chosen
	// path.
	if removeErr := os.Remove(tmpName); removeErr != nil && !os.IsNotExist(removeErr) {
		return fmt.Errorf("clear stale temp checkpoint file %q: %w", tmpName, removeErr)
	}

	// Unconditional cleanup: harmless after a successful rename (os.Remove
	// returns ENOENT, which we ignore) and prevents temp-file leaks on any
	// error path between here and the rename.
	defer func() {
		if removeErr := os.Remove(tmpName); removeErr != nil && !os.IsNotExist(removeErr) {
			log.Warning("failed to remove temp checkpoint file %q: %v", tmpName, removeErr)
		}
	}()

	// O_EXCL closes the symlink-following hole: if anything pre-creates a
	// symlink at tmpName between the os.Remove above and this open, the
	// open will fail with EEXIST instead of writing through the symlink.
	tmp, err := os.OpenFile(tmpName, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create temp checkpoint file: %w", err)
	}

	// On Write/Sync failure we still need to close the handle to release
	// the fd, but the close itself can also fail (e.g. on a networked
	// filesystem when the underlying connection drops). errors.Join
	// surfaces both errors when close fails and degrades cleanly to just
	// the original error when close succeeds — errors.Join with a nil
	// argument returns the non-nil one. CodeQL would otherwise flag the
	// dropped close error as a potential data-loss path on these branches.
	if _, werr := tmp.Write(data); werr != nil {
		return errors.Join(fmt.Errorf("write checkpoint data: %w", werr), tmp.Close())
	}
	if syncErr := tmp.Sync(); syncErr != nil {
		return errors.Join(fmt.Errorf("sync checkpoint data to disk: %w", syncErr), tmp.Close())
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp checkpoint file: %w", err)
	}

	if err := os.Rename(tmpName, target); err != nil {
		return fmt.Errorf("rename checkpoint file: %w", err)
	}

	// Fsync the parent directory so the rename's metadata is durable on a
	// hard crash. Without this the file's contents are on disk (we synced
	// earlier) but the directory entry pointing at them may not survive a
	// power loss, leaving the checkpoint as a phantom file the next start
	// cannot find. Best-effort: directory fsync is widely supported on
	// POSIX filesystems but not all platforms (e.g. Windows) implement it,
	// so we log and continue rather than failing the save.
	if dirF, dirErr := os.Open(absDir); dirErr == nil {
		if syncErr := dirF.Sync(); syncErr != nil && !errors.Is(syncErr, syscall.EINVAL) {
			log.Warning("failed to fsync checkpoint dir %q: %v", absDir, syncErr)
		}
		dirF.Close()
	} else {
		log.Warning("failed to open checkpoint dir %q for fsync: %v", absDir, dirErr)
	}

	return nil
}

// loadCheckpoint reads and removes the checkpoint file at dir, returning the
// parsed contents. Returns (nil, nil) when there is nothing safe to merge —
// either the file does not exist or it carries an incompatible schema
// version (in which case the file is also deleted and a warning is logged).
// A non-nil error indicates a real I/O or unmarshal failure that the caller
// should surface.
//
// NOTE: the file is removed inside this function only on the *incompatible
// schema* path. On the happy path the caller (recoverFromCheckpoint) is
// responsible for removing the file via removeCheckpoint after the merge
// succeeds, so a panic between load and merge does not silently lose data.
func loadCheckpoint(dir string) (*checkpoint, error) {
	// Funnel the read through the same path validator that saveCheckpoint
	// uses so a future caller passing a hostile dir cannot induce a read
	// outside the trusted directory.
	_, target, _, err := resolveCheckpointTarget(dir)
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(target)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read checkpoint file: %w", err)
	}

	var cp checkpoint
	if err := json.Unmarshal(data, &cp); err != nil {
		return nil, fmt.Errorf("unmarshal checkpoint: %w", err)
	}

	// Schema version guard: any value other than checkpointSchemaVersion
	// (including zero from an untagged file) means the on-disk layout is
	// from an incompatible schema and must not be merged into live state.
	// Remove the file here because we know it can never be useful — leaving
	// it on disk would just trip the same warning on every restart.
	if cp.Version != checkpointSchemaVersion {
		log.Warning("discarding metrics checkpoint with unsupported version (got=%d, want=%d)",
			cp.Version, checkpointSchemaVersion)
		if removeErr := os.Remove(target); removeErr != nil && !os.IsNotExist(removeErr) {
			log.Warning("failed to remove incompatible checkpoint file: %v", removeErr)
		}
		return nil, nil
	}

	return &cp, nil
}

func removeCheckpoint(dir string) {
	// Funnel the unlink through the same path validator that
	// saveCheckpoint and loadCheckpoint use, so all three checkpoint
	// I/O paths share one trust boundary.
	_, target, _, err := resolveCheckpointTarget(dir)
	if err != nil {
		log.Warning("failed to resolve checkpoint dir for removal: %v", err)
		return
	}
	if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
		log.Warning("failed to remove checkpoint file: %v", err)
	}
}

// snapshotToCheckpoint copies the in-memory metric state into a serialisable
// checkpoint. The caller must be holding mp.mu so the maps cannot mutate
// underneath us.
//
// gaugeFuncs and histogramFuncs are intentionally NOT included: they are
// process-local closures that may read, maintain, or drain live process/kernel
// state on every flush, so they cannot meaningfully survive a process crash.
// Whatever functions exist after restart are re-registered by the same setup
// code that registered them the first time, and the next flush will pick up
// their current values.
func (mp *Publisher) snapshotToCheckpoint() *checkpoint {
	cp := &checkpoint{
		Version:   checkpointSchemaVersion,
		Timestamp: time.Now(),
		// Counters and gauges are scalar maps, so maps.Clone is a correct
		// deep copy. dimCounters and latencies hold pointers/slices and
		// must be cloned by hand below.
		Counters: maps.Clone(mp.counters),
		Gauges:   maps.Clone(mp.gauges),
	}

	if len(mp.dimCounters) > 0 {
		cp.DimCounters = make(map[string]checkpointDimCounter, len(mp.dimCounters))
		for k, entry := range mp.dimCounters {
			dims := make([]checkpointDimension, len(entry.dims))
			for i, dd := range entry.dims {
				dims[i] = checkpointDimension{
					Name:  aws.ToString(dd.Name),
					Value: aws.ToString(dd.Value),
				}
			}
			cp.DimCounters[k] = checkpointDimCounter{
				MetricName: entry.metricName,
				Dims:       dims,
				Value:      entry.value,
			}
		}
	}

	if len(mp.latencies) > 0 {
		cp.Latencies = make(map[string][]float64, len(mp.latencies))
		for k, v := range mp.latencies {
			cp.Latencies[k] = slices.Clone(v)
		}
	}

	return cp
}

func (mp *Publisher) mergeCheckpoint(cp *checkpoint) {
	if cp == nil {
		return
	}

	for k, v := range cp.Counters {
		mp.counters[k] += v
	}

	for k, cpEntry := range cp.DimCounters {
		existing, exists := mp.dimCounters[k]
		if exists {
			existing.value += cpEntry.Value
		} else {
			dims := make([]types.Dimension, len(cpEntry.Dims))
			for i, dd := range cpEntry.Dims {
				dims[i] = types.Dimension{
					Name:  aws.String(dd.Name),
					Value: aws.String(dd.Value),
				}
			}
			mp.dimCounters[k] = &dimCounterEntry{
				metricName: cpEntry.MetricName,
				dims:       dims,
				value:      cpEntry.Value,
			}
		}
	}

	for k, v := range cp.Gauges {
		if _, exists := mp.gauges[k]; !exists {
			mp.gauges[k] = v
		}
	}

	for k, v := range cp.Latencies {
		existing := mp.latencies[k]
		remaining := maxLatencySamples - len(existing)
		if remaining <= 0 {
			continue
		}
		if len(v) > remaining {
			v = v[:remaining]
		}
		mp.latencies[k] = append(existing, v...)
	}
}
