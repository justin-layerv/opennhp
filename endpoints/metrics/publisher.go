package metrics

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"

	"github.com/OpenNHP/opennhp/nhp/log"
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
	batchSize = 20

	// maxLatencySamples caps the number of latency observations held between flushes.
	// Under sustained high load (~170 knocks/sec), the slice would grow to ~10k entries
	// per 60s flush interval. Beyond this cap, new samples are dropped to bound memory.
	maxLatencySamples = 10000
)

// HealthProbe is a function that returns true if the storage backend is healthy.
type HealthProbe func(ctx context.Context) bool

// GaugeFunc is a function that returns the current value for a gauge metric.
// Registered via RegisterGaugeFunc, called each flush interval.
type GaugeFunc func() float64

// Config configures a metrics Publisher.
type Config struct {
	Namespace  string            // CloudWatch namespace (e.g. "NHP/AC", "LayerV/NHP")
	Dimensions []types.Dimension // Shared dimensions attached to all metrics
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
	client      cloudWatchClient
	namespace   string
	mu          sync.RWMutex
	counters    map[string]float64          // metric name → accumulated count (skipped when 0)
	dimCounters map[string]*dimCounterEntry // composite key → counter with extra dims
	gauges      map[string]float64          // metric name → current value (always published)
	latencies   map[string][]float64        // metric name → recorded latencies
	dims        []types.Dimension
	stop        chan struct{}
	wg          sync.WaitGroup       // tracks flushLoop goroutine for graceful shutdown
	once        sync.Once            // ensures Stop is idempotent
	healthProbe HealthProbe          // optional: emits StorageHealthy gauge each flush
	gaugeFuncs  map[string]GaugeFunc // metric name → func called each flush
	emfWriter   io.Writer            // destination for EMF JSON lines (defaults to os.Stdout)
}

// NewPublisher creates a CloudWatch metrics publisher.
// Returns nil if AWS config cannot be loaded (e.g., running locally without IAM).
func NewPublisher(cfg Config) *Publisher {
	ctx, cancel := context.WithTimeout(context.Background(), apiTimeout)
	defer cancel()

	awsCfg, err := loadAWSConfig(ctx)
	if err != nil {
		log.Warning("CloudWatch metrics disabled: %v", err)
		return nil
	}

	mp := &Publisher{
		client:      cloudwatch.NewFromConfig(awsCfg),
		namespace:   cfg.Namespace,
		counters:    make(map[string]float64),
		dimCounters: make(map[string]*dimCounterEntry),
		gauges:      make(map[string]float64),
		latencies:   make(map[string][]float64),
		dims:        cfg.Dimensions,
		stop:        make(chan struct{}),
		gaugeFuncs:  make(map[string]GaugeFunc),
		emfWriter:   os.Stdout,
	}

	mp.wg.Add(1)
	go mp.flushLoop()

	dimDesc := make([]string, len(cfg.Dimensions))
	for i, d := range cfg.Dimensions {
		dimDesc[i] = *d.Name + "=" + *d.Value
	}
	log.Info("CloudWatch metrics publisher started (namespace=%s, dims=[%s], emf=enabled)",
		cfg.Namespace, strings.Join(dimDesc, ", "))
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
func (mp *Publisher) Stop() {
	if mp == nil {
		return
	}
	mp.once.Do(func() {
		close(mp.stop)
		mp.wg.Wait() // wait for flushLoop to exit before final flush
		mp.flush()
	})
}

func (mp *Publisher) flushLoop() {
	defer mp.wg.Done()
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			mp.collectGauges()
			mp.probeHealth()
			mp.flush()
		case <-mp.stop:
			return
		}
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
	mp.mu.Lock()
	counters := mp.counters
	dimCounters := mp.dimCounters
	gauges := mp.gauges
	latencies := mp.latencies
	mp.counters = make(map[string]float64)
	mp.dimCounters = make(map[string]*dimCounterEntry)
	mp.gauges = make(map[string]float64)
	mp.latencies = make(map[string][]float64)
	mp.mu.Unlock()

	mp.emitEMF(latencies)

	metricData := mp.buildMetricData(counters, dimCounters, gauges, latencies)

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

// emfUnitMilliseconds is the CloudWatch unit string for latency metrics emitted via EMF.
const emfUnitMilliseconds = "Milliseconds"

func (mp *Publisher) emitEMF(latencies map[string][]float64) {
	if mp.emfWriter == nil {
		return
	}
	ts := time.Now().UnixMilli()
	dimNames := make([]string, len(mp.dims))
	dimValues := make(map[string]string, len(mp.dims))
	for i, d := range mp.dims {
		dimNames[i] = *d.Name
		dimValues[*d.Name] = *d.Value
	}
	for name, values := range latencies {
		if len(values) == 0 {
			continue
		}
		for i := 0; i < len(values); i += emfMaxValues {
			end := i + emfMaxValues
			if end > len(values) {
				end = len(values)
			}
			chunk := values[i:end]
			event := buildEMFEvent(mp.namespace, name, dimNames, dimValues, chunk, ts)
			data, err := json.Marshal(event)
			if err != nil {
				log.Warning("Failed to marshal EMF event for %s: %v", name, err)
				continue
			}
			data = append(data, 10)
			if _, err := mp.emfWriter.Write(data); err != nil {
				log.Warning("Failed to write EMF event for %s: %v", name, err)
			}
		}
	}
}

func buildEMFEvent(namespace, metricName string, dimNames []string, dimValues map[string]string, values []float64, timestampMs int64) map[string]any {
	event := map[string]any{
		"_aws": emfAWSBlock{
			Timestamp: timestampMs,
			CloudWatchMetrics: []emfMetricDirective{
				{
					Namespace:  namespace,
					Dimensions: [][]string{dimNames},
					Metrics:    []emfMetricDefinition{{Name: metricName, Unit: emfUnitMilliseconds}},
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
func (mp *Publisher) buildMetricData(
	counters map[string]float64,
	dimCounters map[string]*dimCounterEntry,
	gauges map[string]float64,
	latencies map[string][]float64,
) []types.MetricDatum {
	var metricData []types.MetricDatum

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
		})
	}

	// Flush gauges (always published — 0 is a meaningful value, e.g. StorageHealthy=0 means unhealthy)
	for name, value := range gauges {
		metricData = append(metricData, types.MetricDatum{
			MetricName: aws.String(name),
			Dimensions: mp.dims,
			Value:      aws.Float64(value),
			Unit:       types.StandardUnitNone,
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
			Unit: types.StandardUnitMilliseconds,
		})
	}

	return metricData
}

// buildDimCounterKey builds a deterministic map key from a metric name and its dimensions.
// Null bytes (\x00) are used as internal separators. This is safe because CloudWatch
// dimension names and values are restricted to printable UTF-8 and cannot contain null bytes.
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
