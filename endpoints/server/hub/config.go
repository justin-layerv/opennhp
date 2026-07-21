// Package hub composes the dedicated Connector Hub UDP worker into a process.
// It intentionally owns no cell storage, generic NHP server, plugin, or HTTP
// surface.
package hub

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"time"

	conformance "github.com/layervai/qurl-conformance"
	"github.com/pelletier/go-toml/v2"

	"github.com/OpenNHP/opennhp/endpoints/server/internal/connectorauthority"
	"github.com/OpenNHP/opennhp/endpoints/server/internal/connectorhub"
)

const maxConfigBytes = 64 << 10

var ErrInvalidConfig = errors.New("connector hub: invalid process configuration")

// Config is the complete process configuration. Every field is explicit and
// strict TOML decoding rejects misspellings rather than silently selecting a
// zero value at the public assignment boundary.
type Config struct {
	Environment string `toml:"environment"`

	UDPListenAddr    string `toml:"udp_listen_addr"`
	HealthListenAddr string `toml:"health_listen_addr"`

	PrivateKeyBase64        string `toml:"private_key"`
	ActiveCookieKeyBase64   string `toml:"active_cookie_key"`
	PreviousCookieKeyBase64 string `toml:"previous_cookie_key"`

	AWSRegion                       string `toml:"aws_region"`
	AWSAccountID                    string `toml:"aws_account_id"`
	IssueAssignmentAliasARN         string `toml:"issue_assignment_alias_arn"`
	RefreshAssignmentAliasARN       string `toml:"refresh_assignment_alias_arn"`
	IssueCredentialRecoveryAliasARN string `toml:"issue_credential_recovery_alias_arn"`

	// Timing values use explicit Go duration strings. The Lambda value must still
	// resolve to integral seconds so Terraform can derive it from the same integer
	// that configures the three Authority functions.
	AuthorityLambdaTimeout string `toml:"authority_lambda_timeout"`
	HandlerBudget          string `toml:"handler_budget"`
	PacketBudget           string `toml:"packet_budget"`
	ResponseReserve        string `toml:"response_reserve"`
	WriteBudget            string `toml:"write_budget"`

	MaxConcurrentPackets  int `toml:"max_concurrent_packets"`
	PacketsPerSecond      int `toml:"packets_per_second"`
	PacketBurst           int `toml:"packet_burst"`
	MaxConcurrentPerPeer  int `toml:"max_concurrent_per_peer"`
	ResponseQueueCapacity int `toml:"response_queue_capacity"`
}

// LoadConfig reads one bounded, strict TOML document. Key material is never
// included in returned errors.
func LoadConfig(path string) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("connector hub: read config: %w", err)
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
	defer clear(data)
	if err != nil {
		return Config{}, fmt.Errorf("connector hub: read config: %w", err)
	}
	if len(data) == 0 || len(data) > maxConfigBytes {
		return Config{}, ErrInvalidConfig
	}

	decoder := toml.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var config Config
	if err := decoder.Decode(&config); err != nil {
		// Parser diagnostics can include the offending line. Keep secret-bearing
		// key values out of startup logs by returning only the closed error.
		return Config{}, ErrInvalidConfig
	}
	if _, _, _, err := config.validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

// validate parses the two listen addresses and timing ladder and enforces every
// field bound, returning the parsed UDP/health AddrPorts and worker timing. It is
// intentionally idempotent and cheap, and each process entrypoint re-runs it:
// LoadConfig validates freshly parsed TOML, Run guards its public API against a
// hand-built Config that never went through LoadConfig, and runWithAWSConfig
// re-validates at the directly testable seam while reusing the returned values.
// None of the three calls is
// therefore dead code. Every failure path returns the closed ErrInvalidConfig
// sentinel so no parse diagnostic or field value can reach a startup log.
func (c Config) validate() (netip.AddrPort, netip.AddrPort, connectorhub.WorkerTiming, error) {
	udpAddr, err := parseListenAddr(c.UDPListenAddr)
	if err != nil {
		return netip.AddrPort{}, netip.AddrPort{}, connectorhub.WorkerTiming{}, ErrInvalidConfig
	}
	healthAddr, err := parseListenAddr(c.HealthListenAddr)
	if err != nil {
		return netip.AddrPort{}, netip.AddrPort{}, connectorhub.WorkerTiming{}, ErrInvalidConfig
	}
	if !validEnvironment(c.Environment) || !cleanNonempty(c.AWSRegion) ||
		c.MaxConcurrentPackets <= 0 || c.PacketsPerSecond <= 0 || c.PacketBurst <= 0 ||
		c.MaxConcurrentPerPeer <= 0 || c.ResponseQueueCapacity <= 0 {
		return netip.AddrPort{}, netip.AddrPort{}, connectorhub.WorkerTiming{}, ErrInvalidConfig
	}
	timing, err := c.workerTiming()
	if err != nil {
		return netip.AddrPort{}, netip.AddrPort{}, connectorhub.WorkerTiming{}, ErrInvalidConfig
	}
	if err := connectorhub.ValidateWorkerKeyMaterial(
		c.PrivateKeyBase64,
		c.ActiveCookieKeyBase64,
		c.PreviousCookieKeyBase64,
	); err != nil {
		return netip.AddrPort{}, netip.AddrPort{}, connectorhub.WorkerTiming{}, ErrInvalidConfig
	}
	if err := connectorauthority.ValidateHubTargets(
		connectorauthority.Boundary{AccountID: c.AWSAccountID, Region: c.AWSRegion},
		connectorauthority.HubTargets{
			IssueAssignmentAliasARN:         c.IssueAssignmentAliasARN,
			RefreshAssignmentAliasARN:       c.RefreshAssignmentAliasARN,
			IssueCredentialRecoveryAliasARN: c.IssueCredentialRecoveryAliasARN,
		},
	); err != nil {
		return netip.AddrPort{}, netip.AddrPort{}, connectorhub.WorkerTiming{}, ErrInvalidConfig
	}
	return udpAddr, healthAddr, timing, nil
}

func (c Config) workerTiming() (connectorhub.WorkerTiming, error) {
	parse := func(value string) (time.Duration, error) {
		if !cleanNonempty(value) {
			return 0, ErrInvalidConfig
		}
		duration, err := time.ParseDuration(value)
		if err != nil {
			return 0, ErrInvalidConfig
		}
		return duration, nil
	}

	lambdaTimeout, err := parse(c.AuthorityLambdaTimeout)
	if err != nil {
		return connectorhub.WorkerTiming{}, err
	}
	handlerBudget, err := parse(c.HandlerBudget)
	if err != nil {
		return connectorhub.WorkerTiming{}, err
	}
	packetBudget, err := parse(c.PacketBudget)
	if err != nil {
		return connectorhub.WorkerTiming{}, err
	}
	responseReserve, err := parse(c.ResponseReserve)
	if err != nil {
		return connectorhub.WorkerTiming{}, err
	}
	writeBudget, err := parse(c.WriteBudget)
	if err != nil {
		return connectorhub.WorkerTiming{}, err
	}

	timing := connectorhub.WorkerTiming{
		AuthorityLambdaTimeout: lambdaTimeout,
		HandlerBudget:          handlerBudget,
		PacketBudget:           packetBudget,
		ResponseReserve:        responseReserve,
		WriteBudget:            writeBudget,
	}
	if err := connectorhub.ValidateWorkerTiming(timing); err != nil {
		return connectorhub.WorkerTiming{}, ErrInvalidConfig
	}
	return timing, nil
}

func validEnvironment(value string) bool {
	// Reuse the public protocol's accepted-environment contract instead of
	// maintaining a second list that can drift from request validation.
	peer := make([]byte, conformance.ConnectorHubRequestIDPeerBytes)
	nonce := make([]byte, conformance.ConnectorHubRequestIDNonceBytes)
	_, err := conformance.DeriveConnectorHubRequestID(
		value, conformance.ConnectorHubRequestIDOperationIssue, peer, nonce,
	)
	return err == nil
}

func parseListenAddr(value string) (netip.AddrPort, error) {
	if value == "" || strings.TrimSpace(value) != value {
		return netip.AddrPort{}, ErrInvalidConfig
	}
	addr, err := netip.ParseAddrPort(value)
	if err != nil || addr.Port() == 0 || addr.Addr().IsMulticast() {
		return netip.AddrPort{}, ErrInvalidConfig
	}
	return addr, nil
}

func cleanNonempty(value string) bool {
	return value != "" && strings.TrimSpace(value) == value
}
