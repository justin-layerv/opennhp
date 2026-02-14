package server

import (
	"context"
	"os"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"

	"github.com/OpenNHP/opennhp/nhp/log"
)

const (
	metricsNamespace     = "LayerV/NHP"
	metricsFlushInterval = 60 * time.Second
	metricsTimeout       = 5 * time.Second

	// metricsBatchSize is the number of metric datums per PutMetricData API call.
	// CloudWatch allows up to 1000 per call, but we use a smaller batch to keep
	// individual request payloads small and reduce the blast radius of failures.
	metricsBatchSize = 20

	// maxLatencySamples caps the number of latency observations held between flushes.
	// Under sustained high load (~170 knocks/sec), the slice would grow to ~10k entries
	// per 60s flush interval. Beyond this cap, new samples are dropped to bound memory.
	maxLatencySamples = 10000
)

// HealthProbe is a function that returns true if the storage backend is healthy.
type HealthProbe func(ctx context.Context) bool

// MetricsPublisher batches and publishes NHP metrics to CloudWatch.
// Metrics are accumulated in-memory and flushed periodically to minimize
// API calls and stay within CloudWatch PutMetricData limits.
type MetricsPublisher struct {
	client      *cloudwatch.Client
	mu          sync.Mutex
	counters    map[string]float64   // metric name → accumulated count (skipped when 0)
	gauges      map[string]float64   // metric name → current value (always published)
	latencies   map[string][]float64 // metric name → recorded latencies
	dims        []types.Dimension
	stop        chan struct{}
	wg          sync.WaitGroup // tracks flushLoop goroutine for graceful shutdown
	once        sync.Once      // ensures Stop is idempotent
	healthProbe HealthProbe    // optional: emits StorageHealthy gauge each flush
}

// NewMetricsPublisher creates a CloudWatch metrics publisher.
// Returns nil if AWS config cannot be loaded (e.g., running locally without IAM).
func NewMetricsPublisher() *MetricsPublisher {
	ctx, cancel := context.WithTimeout(context.Background(), metricsTimeout)
	defer cancel()

	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		log.Warning("CloudWatch metrics disabled: %v", err)
		return nil
	}

	// Build dimensions from environment
	environment := os.Getenv("NHP_ENVIRONMENT")
	if environment == "" {
		environment = "unknown"
	}

	// Only use Environment dimension — CloudWatch alarms and dashboard widgets
	// match on exact dimension set. Adding extra dimensions (e.g., Component)
	// creates a separate metric time series that existing alarms won't find.
	dims := []types.Dimension{
		{Name: aws.String("Environment"), Value: aws.String(environment)},
	}

	mp := &MetricsPublisher{
		client:    cloudwatch.NewFromConfig(cfg),
		counters:  make(map[string]float64),
		gauges:    make(map[string]float64),
		latencies: make(map[string][]float64),
		dims:      dims,
		stop:      make(chan struct{}),
	}

	mp.wg.Add(1)
	go mp.flushLoop()
	log.Info("CloudWatch metrics publisher started (namespace=%s, env=%s)", metricsNamespace, environment)
	return mp
}

// IncrCounter increments a counter metric by 1.
func (mp *MetricsPublisher) IncrCounter(name string) {
	if mp == nil {
		return
	}
	mp.mu.Lock()
	mp.counters[name]++
	mp.mu.Unlock()
}

// SetHealthProbe registers a function that is called each flush interval.
// The result is published as StorageHealthy (1.0 = healthy, 0.0 = unhealthy).
func (mp *MetricsPublisher) SetHealthProbe(probe HealthProbe) {
	if mp == nil {
		return
	}
	mp.mu.Lock()
	mp.healthProbe = probe
	mp.mu.Unlock()
}

// RecordLatency records a latency observation in milliseconds.
// Samples are dropped if the buffer exceeds maxLatencySamples to bound memory.
func (mp *MetricsPublisher) RecordLatency(name string, ms float64) {
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
func (mp *MetricsPublisher) Stop() {
	if mp == nil {
		return
	}
	mp.once.Do(func() {
		close(mp.stop)
		mp.wg.Wait() // wait for flushLoop to exit before final flush
		mp.flush()
	})
}

func (mp *MetricsPublisher) flushLoop() {
	defer mp.wg.Done()
	ticker := time.NewTicker(metricsFlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			mp.probeHealth()
			mp.flush()
		case <-mp.stop:
			return
		}
	}
}

// probeHealth runs the health probe (if set) and records the result as a gauge.
// The probe receives a context with metricsTimeout (5s). If the probe's underlying
// ping has its own timeout, the shorter of the two wins.
func (mp *MetricsPublisher) probeHealth() {
	mp.mu.Lock()
	probe := mp.healthProbe
	mp.mu.Unlock()

	if probe == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), metricsTimeout)
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
func (mp *MetricsPublisher) flush() {
	mp.mu.Lock()
	counters := mp.counters
	gauges := mp.gauges
	latencies := mp.latencies
	mp.counters = make(map[string]float64)
	mp.gauges = make(map[string]float64)
	mp.latencies = make(map[string][]float64)
	mp.mu.Unlock()

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

	if len(metricData) == 0 {
		return
	}

	for i := 0; i < len(metricData); i += metricsBatchSize {
		end := i + metricsBatchSize
		if end > len(metricData) {
			end = len(metricData)
		}

		ctx, cancel := context.WithTimeout(context.Background(), metricsTimeout)
		_, err := mp.client.PutMetricData(ctx, &cloudwatch.PutMetricDataInput{
			Namespace:  aws.String(metricsNamespace),
			MetricData: metricData[i:end],
		})
		cancel()

		if err != nil {
			log.Warning("Failed to publish CloudWatch metrics (batch %d/%d, %d datums): %v",
				i/metricsBatchSize+1, (len(metricData)+metricsBatchSize-1)/metricsBatchSize,
				end-i, err)
		}
	}
}
