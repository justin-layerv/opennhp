package hub

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"

	"github.com/OpenNHP/opennhp/endpoints/server/internal/connectorauthority"
	"github.com/OpenNHP/opennhp/endpoints/server/internal/connectorhub"
)

type componentResult struct {
	name string
	err  error
}

// Run loads the ambient AWS identity, constructs only the two Hub authority
// capabilities, and serves until ctx is canceled or either listener fails.
// The same cancellation reaches in-flight synchronous Lambda invocations via
// the worker's receipt-anchored Handler context.
func Run(ctx context.Context, config Config) error {
	if ctx == nil {
		return ErrInvalidConfig
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// Re-validate: Run is a public entrypoint, so a caller may hand-build a
	// Config that never passed through LoadConfig. See Config.validate.
	if _, _, err := config.validate(); err != nil {
		return err
	}
	awsConfig, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(config.AWSRegion))
	if err != nil {
		return fmt.Errorf("connector hub: load AWS configuration: %w", err)
	}
	return runWithAWSConfig(ctx, config, awsConfig)
}

func runWithAWSConfig(ctx context.Context, config Config, awsConfig aws.Config) error {
	if ctx == nil {
		return ErrInvalidConfig
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// Re-validate and capture the parsed listen addresses: runWithAWSConfig is a
	// directly testable seam callers may invoke without Run. See Config.validate.
	udpAddr, healthAddr, err := config.validate()
	if err != nil {
		return err
	}

	authority, err := connectorauthority.NewHubClient(awsConfig, connectorauthority.Boundary{
		AccountID: config.AWSAccountID,
		Region:    config.AWSRegion,
	}, connectorauthority.HubTargets{
		IssueAssignmentAliasARN:         config.IssueAssignmentAliasARN,
		RefreshAssignmentAliasARN:       config.RefreshAssignmentAliasARN,
		IssueCredentialRecoveryAliasARN: config.IssueCredentialRecoveryAliasARN,
	})
	if err != nil {
		return fmt.Errorf("connector hub: construct authority client: %w", err)
	}
	handler, err := connectorhub.NewHandler(config.Environment, authority, authorityAdmissionGate{})
	if err != nil {
		return fmt.Errorf("connector hub: construct handler: %w", err)
	}

	healthListener, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(healthAddr))
	if err != nil {
		return fmt.Errorf("connector hub: listen for private health checks: %w", err)
	}
	udpConn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(udpAddr))
	if err != nil {
		_ = healthListener.Close()
		return fmt.Errorf("connector hub: listen for UDP assignments: %w", err)
	}
	worker, err := connectorhub.NewWorker(udpConn, connectorhub.WorkerConfig{
		PrivateKeyBase64:        config.PrivateKeyBase64,
		ActiveCookieKeyBase64:   config.ActiveCookieKeyBase64,
		PreviousCookieKeyBase64: config.PreviousCookieKeyBase64,
		Handler:                 handler,
		Observer:                newWorkerMetrics(),
		MaxConcurrentPackets:    config.MaxConcurrentPackets,
		PacketsPerSecond:        config.PacketsPerSecond,
		PacketBurst:             config.PacketBurst,
		MaxConcurrentPerPeer:    config.MaxConcurrentPerPeer,
		ResponseQueueCapacity:   config.ResponseQueueCapacity,
	})
	if err != nil {
		_ = udpConn.Close()
		_ = healthListener.Close()
		return fmt.Errorf("connector hub: construct UDP worker: %w", err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	// Closing the TCP listener is the cancellation interrupt for Accept. The UDP
	// worker independently advances its read deadline when runCtx is canceled.
	closeHealth := make(chan struct{})
	go func() {
		select {
		case <-runCtx.Done():
			_ = healthListener.Close()
		case <-closeHealth:
		}
	}()

	results := make(chan componentResult, 2)
	go func() { results <- componentResult{name: "udp worker", err: worker.Serve(runCtx)} }()
	go func() { results <- componentResult{name: "health listener", err: serveHealth(runCtx, healthListener)} }()

	first := <-results
	cancel()
	_ = healthListener.Close()
	second := <-results
	close(closeHealth)

	return joinComponentErrors(first, second)
}

// authorityAdmissionGate is deliberately policy-free. The worker has already
// applied public-edge aggregate and authenticated-peer bounds; the private
// qurl-service authority adapter owns registration enablement and account-level
// admission so a Hub replica cannot acquire divergent policy state.
type authorityAdmissionGate struct{}

func (authorityAdmissionGate) AdmitAssignment(ctx context.Context, request connectorhub.AdmissionRequest) connectorhub.AdmissionResult {
	if ctx == nil || ctx.Err() != nil || !admissibleMode(request.Mode) {
		return connectorhub.AdmissionResult{Decision: connectorhub.AdmissionUnavailable}
	}
	return connectorhub.AdmissionResult{Decision: connectorhub.AdmissionAllow}
}

// admissibleMode is the closed allowlist of assignment operations this Hub
// admits. Credential recovery (ModeRecover) is admitted here and ONLY here:
// configuring the recovery alias grants the capability, but every request —
// recovery included — must pass this gate before the handler may reach the
// Authority. The switch fails closed by construction, so any mode outside the
// allowlist (including the zero value from an undecoded request) is rejected.
func admissibleMode(mode connectorhub.Mode) bool {
	switch mode {
	case connectorhub.ModeEnroll, connectorhub.ModeRefresh, connectorhub.ModeRecover:
		return true
	default:
		return false
	}
}

// serveHealth accepts and immediately closes TCP connections. It parses no
// bytes and exposes no application protocol. The later infrastructure slice
// must restrict this separately configured listener to the NLB health-check
// path; customers reach only the UDP listener.
//
// While the Hub is dark this loop treats only ctx cancellation and net.ErrClosed
// as clean shutdown and returns any other Accept error, which tears the process
// down. That is acceptable pre-activation, but the slice that makes this a
// load-bearing liveness listener must back off and continue on transient
// net.Error conditions (e.g. EMFILE under fd pressure) so temporary resource
// pressure cannot become a restart loop.
func serveHealth(ctx context.Context, listener *net.TCPListener) error {
	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		_ = conn.Close()
	}
}

func joinComponentErrors(results ...componentResult) error {
	var joined error
	for _, result := range results {
		if result.err != nil {
			joined = errors.Join(joined, fmt.Errorf("connector hub: %s: %w", result.name, result.err))
		}
	}
	return joined
}

// Compile-time guard: the gate is intentionally the only Handler dependency
// added by process composition.
var _ connectorhub.AdmissionGate = authorityAdmissionGate{}
