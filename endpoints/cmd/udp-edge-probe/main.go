// Command udp-edge-probe runs repeated real NHP SDK knocks against the public
// assigned-cell endpoint and enforces a success-ratio plus p99 latency SLO.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"github.com/OpenNHP/opennhp/endpoints/agent/sdk"
	"github.com/OpenNHP/opennhp/nhp/common"
)

type config struct {
	AgentPrivateKey string
	ServerPublicKey string
	ServerHost      string
	ASP             string
	Resource        string
	User            string
	Duration        time.Duration
	Interval        time.Duration
	MinimumSuccess  float64
	MaximumP99      time.Duration
	StartAt         time.Time
}

type ack struct {
	ErrCode string `json:"errCode"`
	ErrMsg  string `json:"errMsg"`
}

type result struct {
	Attempts     int     `json:"attempts"`
	Successes    int     `json:"successes"`
	SuccessRatio float64 `json:"success_ratio"`
	StartedEpoch int64   `json:"started_epoch"`
	EndedEpoch   int64   `json:"ended_epoch"`
	// Latency fields summarize successful ACKs only. Failed attempts remain
	// visible through SuccessRatio and LastError instead of an invented latency.
	P99MS     int64  `json:"p99_ms"`
	MaxMS     int64  `json:"max_ms"`
	LastError string `json:"last_error,omitempty"`
}

type knockWithRunIDFunc func(aspID, resourceID, runID, serverIP, serverHostname string, serverPort int) string

func generateProbeRunID(random io.Reader) (string, error) {
	var raw [8]byte
	if _, err := io.ReadFull(random, raw[:]); err != nil {
		return "", fmt.Errorf("read cryptographic randomness: %w", err)
	}
	return hex.EncodeToString(raw[:]), nil
}

func knockWithFreshRunID(
	cfg config,
	generate func() (string, error),
	knock knockWithRunIDFunc,
) (string, error) {
	runID, err := generate()
	if err != nil {
		return "", err
	}
	if err := common.ValidateAgentKnockRunID(runID); err != nil {
		return "", fmt.Errorf("generator returned noncanonical RunID: %w", err)
	}
	return knock(cfg.ASP, cfg.Resource, runID, "", cfg.ServerHost, 62206), nil
}

func required(name string) string {
	value := os.Getenv(name)
	if value == "" {
		fmt.Fprintf(os.Stderr, "%s is required\n", name)
		os.Exit(2)
	}
	return value
}

func envInt(name string, fallback int) int {
	if value := os.Getenv(name); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed <= 0 {
			fmt.Fprintf(os.Stderr, "%s must be a positive integer\n", name)
			os.Exit(2)
		}
		return parsed
	}
	return fallback
}

func envFloat(name string, fallback float64) float64 {
	if value := os.Getenv(name); value != "" {
		parsed, err := strconv.ParseFloat(value, 64)
		if err != nil || parsed <= 0 || parsed > 1 {
			fmt.Fprintf(os.Stderr, "%s must be in (0,1]\n", name)
			os.Exit(2)
		}
		return parsed
	}
	return fallback
}

func loadConfig() config {
	privateKey := required("NHP_UDP_PROBE_AGENT_PRIVATE_KEY_B64")
	decoded, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil || len(decoded) != 32 {
		fmt.Fprintln(os.Stderr, "NHP_UDP_PROBE_AGENT_PRIVATE_KEY_B64 must be a 32-byte base64 Curve25519 private key")
		os.Exit(2)
	}
	startAt := time.Now()
	if value := os.Getenv("NHP_UDP_READINESS_START_EPOCH"); value != "" {
		epoch, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			fmt.Fprintln(os.Stderr, "NHP_UDP_READINESS_START_EPOCH must be epoch seconds")
			os.Exit(2)
		}
		startAt = time.Unix(epoch, 0)
	}
	return config{
		AgentPrivateKey: privateKey,
		ServerPublicKey: required("NHP_UDP_PROBE_SERVER_PUBLIC_KEY_B64"),
		ServerHost:      required("NHP_UDP_PROBE_SERVER_HOST"),
		ASP:             required("NHP_UDP_PROBE_ASP_ID"),
		Resource:        required("NHP_UDP_PROBE_RESOURCE_ID"),
		User:            required("NHP_UDP_PROBE_USER_ID"),
		Duration:        time.Duration(envInt("NHP_UDP_PROBE_DURATION_SECONDS", 300)) * time.Second,
		Interval:        time.Duration(envInt("NHP_UDP_PROBE_INTERVAL_MS", 1000)) * time.Millisecond,
		MinimumSuccess:  envFloat("NHP_UDP_PROBE_MIN_SUCCESS_RATIO", 0.99),
		MaximumP99:      time.Duration(envInt("NHP_UDP_PROBE_MAX_P99_MS", 2000)) * time.Millisecond,
		StartAt:         startAt,
	}
}

func percentile99(values []time.Duration) time.Duration {
	if len(values) == 0 {
		return 0
	}
	// Sorting in place is intentional: callers do not retain sample order and
	// track maximum latency independently, so no hidden ordering contract remains.
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	index := int(math.Ceil(float64(len(values))*0.99)) - 1
	return values[index]
}

func run(cfg config) (result, error) {
	if delay := time.Until(cfg.StartAt); delay > 0 {
		time.Sleep(delay)
	}
	tmp, err := os.MkdirTemp("", "nhp-udp-edge-probe-")
	if err != nil {
		return result{}, fmt.Errorf("create temporary SDK root: %w", err)
	}
	defer os.RemoveAll(tmp)
	if err := os.MkdirAll(filepath.Join(tmp, "etc"), 0o700); err != nil {
		return result{}, fmt.Errorf("create SDK configuration directory: %w", err)
	}
	baseConfig := fmt.Sprintf("PrivateKeyBase64 = %q\nDefaultCipherScheme = 0\nUserId = %q\nOrganizationId = %q\nLogLevel = 1\n", cfg.AgentPrivateKey, cfg.User, "udp-readiness")
	if err := os.WriteFile(filepath.Join(tmp, "etc", "config.toml"), []byte(baseConfig), 0o600); err != nil {
		return result{}, fmt.Errorf("write SDK configuration: %w", err)
	}
	if !sdk.Init(tmp, 1) {
		return result{}, fmt.Errorf("initialize NHP SDK")
	}
	defer sdk.Close()
	if !sdk.AddServer(cfg.ServerPublicKey, "", cfg.ServerHost, 62206, 0) {
		return result{}, fmt.Errorf("add NHP server %s:62206", cfg.ServerHost)
	}
	if !sdk.SetKnockUser(cfg.User, "udp-readiness", "", `{}`) {
		return result{}, fmt.Errorf("set NHP probe user %q", cfg.User)
	}

	startedAt := time.Now()
	deadline := startedAt.Add(cfg.Duration)
	latencies := make([]time.Duration, 0, int(cfg.Duration/cfg.Interval)+1)
	var maximumLatency time.Duration
	summary := result{StartedEpoch: startedAt.Unix()}
	for time.Now().Before(deadline) {
		// Each liveness-probe attempt is its own logical outer cycle, so a fresh
		// RunID per iteration is intentional. qURL Connector retries instead
		// reuse one RunID within an outer cycle and must not copy this loop model.
		started := time.Now()
		raw, knockErr := knockWithFreshRunID(cfg, func() (string, error) {
			return generateProbeRunID(rand.Reader)
		}, sdk.KnockResourceWithRunID)
		if knockErr != nil {
			return summary, fmt.Errorf("generate RunID for probe attempt %d: %w", summary.Attempts+1, knockErr)
		}
		latency := time.Since(started)
		summary.Attempts++
		var response ack
		if err := json.Unmarshal([]byte(raw), &response); err != nil {
			summary.LastError = fmt.Sprintf("invalid ack JSON: %v", err)
		} else if response.ErrCode != "0" {
			summary.LastError = fmt.Sprintf("ack errCode=%s errMsg=%s", response.ErrCode, response.ErrMsg)
		} else {
			summary.Successes++
			latencies = append(latencies, latency)
			if latency > maximumLatency {
				maximumLatency = latency
			}
		}
		if sleep := cfg.Interval - time.Since(started); sleep > 0 {
			time.Sleep(sleep)
		}
		// A knock slower than Interval starts the next attempt immediately, but
		// never replays missed ticks. This deliberately keeps degraded-window
		// sampling strict instead of reducing attempts after a slow response.
	}
	if summary.Attempts > 0 {
		summary.SuccessRatio = float64(summary.Successes) / float64(summary.Attempts)
	}
	p99 := percentile99(latencies)
	summary.P99MS = p99.Milliseconds()
	summary.MaxMS = maximumLatency.Milliseconds()
	summary.EndedEpoch = time.Now().Unix()
	return summary, nil
}

func main() {
	cfg := loadConfig()
	summary, err := run(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "udp edge probe setup failed: %v\n", err)
		os.Exit(1)
	}
	encoded, err := json.Marshal(summary)
	if err != nil {
		fmt.Fprintf(os.Stderr, "encode udp edge probe summary: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(encoded))
	if summary.SuccessRatio < cfg.MinimumSuccess || time.Duration(summary.P99MS)*time.Millisecond > cfg.MaximumP99 {
		os.Exit(1)
	}
}
