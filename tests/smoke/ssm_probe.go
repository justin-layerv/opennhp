//go:build smoke

package smoke

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

// ssm_probe.go is the single place in the smoke suite that sends SSM
// RunShellScript commands. It rests on one hard invariant plus one
// best-effort safety net:
//
//  1. Tests cannot express an arbitrary command. Every probe is a
//     named Go function with the command baked in as a string constant.
//     There is no exported API that accepts a command string as a
//     parameter. Adding a probe means adding a new named function
//     reviewed under CODEOWNERS.
//
//  2. Defense in depth — a best-effort tripwire, NOT a sandbox: the
//     private sendShellScript function regex-checks every command string
//     against the rejectPatterns list (below) before sending it to SSM.
//     The list catches the common mutation verbs (rm, mv, systemctl
//     restart, ...) and the common shell metacharacters — command
//     chaining (; and &&), substitution ($(...) and backticks), piping
//     (|), and I/O redirection (> and >>) — so a probe that slips past
//     invariant 1 during a refactor may be caught, but that is NOT
//     guaranteed. The list is deliberately non-exhaustive and makes no
//     completeness claim: bare process/network mutation (kill, ip route),
//     interpreter one-liners (python3 -c), and commands separated by a
//     newline or a bare & all pass it. Treat it as a
//     catch-the-obvious-mistake tripwire; invariant 1 — the
//     named-helper-only API — is the actual fence. See #1012 for the
//     full rationale.
//
// Probes are read-only. None of them install packages, modify files,
// start/stop services, or change iptables/ipset. If you need a new
// capability that involves writing state, it is almost certainly not a
// smoke test — it is an integration test, and it belongs in
// tests/integration with an ephemeral harness.

// Baked-in command strings. Every probe is a constant. No dynamic
// construction of command text is allowed.
//
// IMPORTANT: nhp-server runs in a Docker container with --net=host
// and the container image intentionally has NO curl, NO wget, and no
// other health-probe binaries (MEMORY gotcha "nhp-server container
// has no curl or wget"). Every health probe runs on the INSTANCE
// (the host), which reaches the container at 127.0.0.1:8888 thanks
// to --net=host.
//
// PR #1005's regression class was: the deploy gate tried
// `docker exec nhp-server wget ...`, the image had no wget, every
// standby instance was declared unhealthy, and the blue/green flip
// never happened. The correct fence is to run the deploy gate's
// actual post-#1005 shell command — host-side curl — against real
// instances and assert exit 0.
const (
	// cmdHealthLiveFromHost is the exact shape the post-#1005 deploy
	// gate uses: curl the nhp-server container's /health/live from
	// the host via --net=host loopback. If this returns non-zero,
	// either curl is missing from the AMI (which would be a new
	// regression class) or the server isn't responding — either way,
	// the blue/green deploy would not flip.
	cmdHealthLiveFromHost = "curl -sf -m 5 http://127.0.0.1:8888/health/live"

	// cmdHealthKnockReadyFromHost is the per-instance knock-readiness
	// probe. Used by Tier 2 tests to verify every server instance
	// reports ≥ 1 AC peer — the single-endpoint Tier 1 test hits
	// whichever instance the NLB picks, which is not enough to catch
	// "one instance stuck at zero peers" fleet drift.
	cmdHealthKnockReadyFromHost = "curl -sf -m 5 http://127.0.0.1:8888/health/knock-ready"

	cmdDockerNhpServerRunning = "docker ps --filter name=nhp-server --format '{{.Status}}'"
	cmdDockerImageTag         = "docker inspect --format '{{.Config.Image}}' nhp-server"

	// cmdDigInternalQurlAPI resolves the qurl-service internal ALB
	// hostname from the NHP server's view. Successful resolution to an
	// RFC1918 address proves: (a) the workload-account private hosted
	// zone exists, (b) the zone is associated with the VPC, (c) the
	// A-alias to the internal ALB is wired correctly. The result is
	// parsed by probeDigInternalQurlAPI, which validates the answer is
	// non-empty and starts with a private-IP byte. `+short` returns
	// only the answer-section A records, one per line.
	//
	// `dig` is preinstalled on Amazon Linux 2023 (bind-utils package).
	// Do NOT switch to nslookup or getent — both have quieter failure
	// modes that hide NXDOMAIN-vs-empty-answer drift, exactly the
	// regression class this probe exists to catch.
	//
	// Hostname is interpolated at probe-call time (see
	// probeDigInternalQurlAPI) since it varies per environment. The
	// reject-list is checked on the FINAL command string, so the
	// interpolated form must still pass — keeping the format string
	// here as a constant lets the reject-list catch tampering.
	//
	// +time=3 +tries=1 keeps a misconfigured PHZ from hanging the
	// probe through dig's default 5-second-per-try, three-try retry
	// budget. A clean-fail diagnostic in 3s beats a flaky-looking
	// timeout at 15s.
	cmdDigInternalQurlAPIFmt = "dig +short +time=3 +tries=1 %s"

	// cmdCurlInternalQurlAPIFmt curls the qurl-service internal ALB
	// /internal/v1/resource/<id>/target endpoint without an auth token.
	// We expect 401 from the auth middleware. Reaching 401 is stronger
	// than reaching 200 because it proves: (a) DNS resolves, (b) TLS
	// handshakes correctly with the new cert, (c) ALB SG accepts the
	// connection, (d) HostValidation passes (otherwise 400), (e) the
	// auth middleware actually runs (otherwise the handler 404s the
	// missing resource and we miss the auth gate).
	//
	// The resource ID is a structurally-valid `r_` + 11 base64url
	// chars literal so a future refactor that moves resource-ID format
	// validation into middleware (above auth) doesn't flip this probe
	// from 401 to 400 and silently break the diagnosis. Today the
	// format check lives inside the handler (resolve.go:225), AFTER
	// InternalServiceAuth in the middleware chain, so an unauthenticated
	// caller hits the 401 first regardless of ID shape — but pinning a
	// valid shape is cheap belt-and-suspenders.
	//
	// `-sS` is silent on success, errors on failure. `-o /dev/null`
	// discards body. `-w '%%{http_code}'` prints just the status code
	// to stdout, which the probe parses as int. `--max-time 10` is a
	// generous request timeout — the internal ALB lives on the same
	// VPC ENI subnet as the caller, so anything above 1s is a problem.
	// `--insecure` is NOT used; a cert-validation failure is a real
	// regression we want to catch.
	//
	// Hostname interpolation: the only %s slot is the qurl-service
	// internal hostname, sourced from var.qurl_internal_service_domain
	// in tfvars (validated by a regex precondition on that var). It is
	// operator-controlled config, NOT user input. The reject-list in
	// sendShellScript is defense-in-depth; the primary gate against
	// hostile hostnames is the variable validation.
	cmdCurlInternalQurlAPIFmt = "curl -sS -o /dev/null -w '%%{http_code}' --max-time 10 https://%s/internal/v1/resource/r_smokeprobe1/target"

	// cmdCurlInternalQurlResolveFmt is the parallel probe to
	// cmdCurlInternalQurlAPIFmt but hits POST /internal/v1/resolve
	// directly — the actual endpoint that issue qurl-service#335
	// names. If a future refactor changes middleware order on /resolve
	// specifically (e.g., parses the body before InternalServiceAuth),
	// the /resource/.../target probe alone wouldn't catch it. Today
	// both endpoints share the InternalServiceAuth middleware, so
	// POST with an empty body and no token returns 401 from auth
	// before any body parsing happens.
	//
	// `-d '{}'` triggers POST automatically and sends a structurally
	// valid (but semantically empty) JSON body, so a regression that
	// makes the body-parse step run before auth fails differently
	// (400 invalid_request_body) than a HostValidation-rejected one
	// (400 invalid_host) — the test's existing 400 diagnostic
	// mentions both possibilities.
	cmdCurlInternalQurlResolveFmt = "curl -sS -o /dev/null -w '%%{http_code}' --max-time 10 -H 'Content-Type: application/json' -d '{}' https://%s/internal/v1/resolve"

	// cmdSystemdNRestartsNhpServer reads systemd's NRestarts counter
	// for the nhp-server unit. systemd increments NRestarts only when
	// the unit exits unexpectedly and is re-executed by Restart=; a
	// user-driven `systemctl restart` does not bump it. Reading the
	// counter is therefore a crisp signal for "did the server process
	// crash during its current lifetime?" Zero is the only healthy
	// value.
	cmdSystemdNRestartsNhpServer = "systemctl show nhp-server --property=NRestarts --value"

	// nhpServerEnvFilePath is the systemd EnvironmentFile that
	// user_data.sh.tpl renders into for the nhp-server unit. Centralized
	// so probes, error wrappers, and tests share one source of truth.
	nhpServerEnvFilePath = "/opt/layerv/nhp-server/etc/env"

	// cmdGrepQurlAPIURL reads the QURL_API_URL line from the nhp-server
	// systemd EnvironmentFile. The line is written by
	// terraform/modules/compute/user_data.sh.tpl ('QURL_API_URL=' line)
	// from var.qurl_config.api_url. A regression here means a tfvars
	// revert pointed the plugin back at the public ALB — defeating the
	// network-isolation guarantee from qurl-service #335.
	//
	// `-m1` returns the FIRST match. systemd EnvironmentFile semantics
	// take the LAST occurrence when a key is duplicated, so the
	// invariant load-bearing for probe correctness is "user_data
	// renders exactly one QURL_API_URL= line." If a future template
	// ever writes a placeholder followed by an override, this probe
	// silently asserts on the wrong value. (`tail -1` would match
	// systemd's resolution rule, but `|` is in the reject-list.)
	cmdGrepQurlAPIURL = "grep -m1 '^QURL_API_URL=' " + nhpServerEnvFilePath

	// acConfigFilePath is the infrastructure-rendered config file read
	// by nhp-acd from its systemd WorkingDirectory. The deployed host
	// path is the thing #2812 needs to fence, not the in-image path.
	acConfigFilePath = "/opt/layerv/nhp-ac/etc/config.toml"

	acEBPFXDPObjectPath  = "/opt/layerv/nhp-ac/etc/nhp_ebpf_xdp.o"
	acTCEgressObjectPath = "/opt/layerv/nhp-ac/etc/tc_egress.o"

	// cmdGrepACFilterMode reads the AC FilterMode line from the deployed
	// host config. The eBPF object-layout smoke skips while this remains
	// iptables mode and turns into a hard gate as soon as a deployed AC
	// is actually running FilterMode=EBPFXDP. `-i` matches go-toml/v2's
	// case-insensitive key binding, while parseACFilterModeValue still
	// rejects the wrong key and non-numeric values. user_data renders
	// config.toml with 0600 permissions; this follows the existing
	// smoke-suite SSM convention that AWS-RunShellScript runs as root.
	cmdGrepACFilterMode = "grep -im1 '^FilterMode[[:space:]]*=' " + acConfigFilePath

	// These object checks probe the host-extracted AC tree, closing the
	// docker-cp gap from #2812. `-s` matches the Dockerfile image guard:
	// zero-byte objects are as load-breaking as absent objects. Keeping
	// one named probe per object makes a hard-gate failure identify the
	// exact missing or truncated file without shell chaining.
	cmdACEBPFXDPObjectPresent  = "test -s " + acEBPFXDPObjectPath
	cmdACTCEgressObjectPresent = "test -s " + acTCEgressObjectPath
)

const (
	// Mirrors endpoints/ac/config.go FilterMode_IPTABLES/FilterMode_EBPFXDP.
	// The smoke module intentionally does not import endpoints/, so unknown
	// future mode values fail loud until this gate is revisited.
	acFilterModeIPTables = 0
	acFilterModeEBPFXDP  = 1
)

// rejectPatterns are the command substrings that must never appear in
// any probe even if someone bypasses the named-helper API — the
// best-effort safety net described in invariant 2 above, which lists
// what it does and does not catch.
//
// The patterns err deliberately toward false-positives: the cost of
// rejecting a harmless probe is that someone rewrites it, which is a
// good conversation to have.
var rejectPatterns = []*regexp.Regexp{
	// State mutation (> and >> redirect output to files)
	regexp.MustCompile(`\brm\b`),
	regexp.MustCompile(`\bmv\b`),
	regexp.MustCompile(`\bcp\b`),
	regexp.MustCompile(`\bdd\b`),
	regexp.MustCompile(`\btee\b`),
	regexp.MustCompile(`\bchmod\b`),
	regexp.MustCompile(`\bchown\b`),
	regexp.MustCompile(`>`),
	regexp.MustCompile(`>>`),

	// Firewall/routing mutation (reads are allowed via explicit commands)
	regexp.MustCompile(`\biptables\b`),
	regexp.MustCompile(`\bipset\s+-(A|D|F|X|N)\b`),
	regexp.MustCompile(`\bsysctl\s+-w\b`),

	// Service mutation
	regexp.MustCompile(`\bsystemctl\s+(start|stop|restart|reload|enable|disable|mask|unmask)\b`),
	regexp.MustCompile(`\bservice\s+\S+\s+(start|stop|restart|reload)\b`),

	// Docker mutation
	regexp.MustCompile(`\bdocker\s+(start|stop|restart|kill|rm|rmi|run|pull|push|build|commit|tag)\b`),

	// Package install
	regexp.MustCompile(`\bapt(-get)?\s+(install|remove|purge|upgrade)\b`),
	regexp.MustCompile(`\byum\s+(install|remove|update)\b`),
	regexp.MustCompile(`\bdpkg\s+-i\b`),

	// Shell control chars: chaining, substitution, and piping. Reject
	// any probe containing these — every legitimate probe today is a
	// single command with none of them. If a future probe needs
	// piping or chaining, write it as a multi-line script invoked via
	// the named-helper API and audit it explicitly. The regex on
	// operator-controlled inputs (e.g., qurl_internal_service_domain)
	// already prevents these chars from being interpolated, so this is
	// pure defense-in-depth: it catches probes typed by future
	// contributors before the named-helper review can.
	//
	// Stricter than just shell metachars: this also rejects `;`/`|`/etc.
	// inside quoted args and JSON bodies. A future probe that needs to
	// carry one of these in a payload (e.g. a header `Cookie: a;b`,
	// or a JSON literal containing a backtick) cannot use the named
	// curl/dig helpers above — it must use a different transport
	// (separate Go HTTP/DNS client routed through the SSM session, or
	// base64-encode the payload and decode in a server-side script).
	regexp.MustCompile(`;`),
	regexp.MustCompile(`\|`),
	regexp.MustCompile(`&&`),
	regexp.MustCompile(`\$\(`),
	regexp.MustCompile("`"),
}

// errCommandRejected is returned by sendShellScript when a probe string
// trips the reject-list. Tests surface this as a clear failure: either
// the reject-list is overreaching, or a new probe was added that should
// not exist.
var errCommandRejected = errors.New("ssm_probe: command rejected by reject-list")

// errCurlNoResponse is returned when curl writes "000" — its sentinel
// for "no HTTP response observed" (TCP timeout, --max-time exceeded,
// connection refused before any response bytes). Callers should render
// this as "transport reachability failure" rather than HTTP status 0.
var errCurlNoResponse = errors.New("ssm_probe: curl received no HTTP response (TCP timeout or unreachable)")

// ssmFailedErrorFmt is the format sendShellScript uses for terminal
// non-success SSM states (Failed, Canceled, TimedOut). Pulled out as
// a constant so classifyQurlAPIURLError's substring match is coupled
// to exactly one place — a refactor that changes this format trips
// TestSSMFailedErrorFmtLockMatchesClassifier in the same package, so
// the silent-regression class the cr called out (#1597) is fenced
// even before the typed-error refactor lands.
const ssmFailedErrorFmt = "ssm command %s status=%s stderr=%q"

// sendShellScript is the ONLY function in this package that actually
// calls SSM. It is unexported; callers are the named probe functions
// below. Tests must not call it directly.
//
// Behavior:
//   - Returns errCommandRejected if cmd matches any rejectPatterns regex.
//     The rejected command is logged for diagnosis.
//   - Sends AWS-RunShellScript with --timeout-seconds 30 (API minimum).
//   - Polls get-command-invocation until a terminal status; max wait ~45s.
//   - Returns stdout on Success, an error containing stderr otherwise.
//
// ssmCommandFailed carries the invocation's exit code so callers can
// distinguish a command's meaningful non-zero exit (journalctl --grep with no
// matching entries exits 1) from a real probe failure. Error() preserves the
// exact wording sendShellScript always produced.
type ssmCommandFailed struct {
	CommandID    string
	Status       string
	ResponseCode int32
	Stderr       string
}

func (e *ssmCommandFailed) Error() string {
	return fmt.Sprintf(ssmFailedErrorFmt, e.CommandID, e.Status, e.Stderr)
}

func sendShellScript(ctx context.Context, instanceID, cmd string) (string, error) {
	for _, pat := range rejectPatterns {
		if pat.MatchString(cmd) {
			return "", fmt.Errorf("%w: pattern %q matched in %q", errCommandRejected, pat.String(), cmd)
		}
	}

	if testConfig.SSMClient == nil {
		return "", errors.New("ssm client not configured")
	}

	sendResp, err := testConfig.SSMClient.SendCommand(ctx, &ssm.SendCommandInput{
		InstanceIds:    []string{instanceID},
		DocumentName:   aws.String("AWS-RunShellScript"),
		TimeoutSeconds: aws.Int32(30),
		Parameters: map[string][]string{
			"commands": {cmd},
		},
	})
	if err != nil {
		return "", fmt.Errorf("ssm send-command %s: %w", instanceID, err)
	}
	if sendResp.Command == nil || sendResp.Command.CommandId == nil {
		return "", errors.New("ssm send-command returned nil command id")
	}
	cmdID := *sendResp.Command.CommandId

	// Poll GetCommandInvocation with exponential backoff. Most probes
	// complete in well under a second once the command is scheduled,
	// so starting with 250ms saves ~2s per probe vs. a fixed 2s
	// pre-poll sleep. Cap backoff at 2s so worst-case eventual
	// consistency is still handled without runaway latency.
	deadline := time.Now().Add(45 * time.Second)
	wait := 250 * time.Millisecond
	const maxWait = 2 * time.Second

	for {
		time.Sleep(wait)

		getResp, err := testConfig.SSMClient.GetCommandInvocation(ctx, &ssm.GetCommandInvocationInput{
			CommandId:  aws.String(cmdID),
			InstanceId: aws.String(instanceID),
		})
		if err != nil {
			// Eventual consistency: the invocation may not be visible
			// immediately after send-command. Retry until deadline.
			if time.Now().After(deadline) {
				return "", fmt.Errorf("ssm get-command-invocation %s: %w", cmdID, err)
			}
			if wait < maxWait {
				wait *= 2
			}
			continue
		}

		switch getResp.Status {
		case ssmtypes.CommandInvocationStatusSuccess:
			return strings.TrimSpace(aws.ToString(getResp.StandardOutputContent)), nil
		case ssmtypes.CommandInvocationStatusFailed,
			ssmtypes.CommandInvocationStatusCancelled,
			ssmtypes.CommandInvocationStatusTimedOut:
			return "", &ssmCommandFailed{
				CommandID:    cmdID,
				Status:       string(getResp.Status),
				ResponseCode: getResp.ResponseCode,
				Stderr:       aws.ToString(getResp.StandardErrorContent),
			}
		}

		if time.Now().After(deadline) {
			return "", fmt.Errorf("ssm command %s timed out in status=%s", cmdID, getResp.Status)
		}
		if wait < maxWait {
			wait *= 2
		}
	}
}

// probeHealthLiveFromHost runs the post-#1005 deploy gate shell
// command on the host and returns nil on exit 0. This is the exact
// shape verify-asg-instances-healthy.sh uses when called by the
// blue/green deploy, so passing this probe means the deploy gate
// would also pass against the same instance.
//
// Fences PR #1005 (deploy gate shell command must actually work
// against the deployed image).
func probeHealthLiveFromHost(ctx context.Context, instanceID string) error {
	_, err := sendShellScript(ctx, instanceID, cmdHealthLiveFromHost)
	return err
}

// probeHealthKnockReadyFromHost fetches /health/knock-ready from
// the host loopback and returns the JSON body on success. An error
// is returned when curl exits non-zero (4xx/5xx), which callers
// should surface per-instance rather than fatal the test — the
// caller iterates every instance and wants to accumulate errors.
func probeHealthKnockReadyFromHost(ctx context.Context, instanceID string) (string, error) {
	return sendShellScript(ctx, instanceID, cmdHealthKnockReadyFromHost)
}

// probeDockerNhpServerRunning returns the nhp-server container's
// `docker ps --format '{{.Status}}'` line (e.g. "Up 3 hours"). Empty
// string + nil error means no such container, which is itself a bug
// class worth fencing.
func probeDockerNhpServerRunning(ctx context.Context, instanceID string) (string, error) {
	return sendShellScript(ctx, instanceID, cmdDockerNhpServerRunning)
}

// probeDockerImageTag returns the image reference the nhp-server
// container was launched from (e.g. "layerv/nhp-server:abc123...").
func probeDockerImageTag(ctx context.Context, instanceID string) (string, error) {
	return sendShellScript(ctx, instanceID, cmdDockerImageTag)
}

// probeDigInternalQurlAPI runs `dig +short <hostname>` on the NHP
// server EC2 (in private subnets) and returns the raw output (one IP
// per line, possibly empty). Callers parse and validate that the
// returned addresses are RFC1918.
//
// Hostname is interpolated by the caller; we re-check the assembled
// command against the reject-list inside sendShellScript so a typo or
// hostile injection still fails closed. The hostname format itself is
// constrained by terraform's qurl_internal_service_domain validation
// (see terraform/variables.tf), so reaching here with a malformed
// hostname is impossible under normal operation.
//
// Regression fence for qurl-service #335 rollout: PR1 introduces the
// internal ALB + private hosted zone; this probe pins that DNS works
// from inside the VPC. A regression here fires when the PHZ
// VPC-association is dropped, the A-alias is broken, or the workload
// account loses its Route 53 Resolver wiring.
func probeDigInternalQurlAPI(ctx context.Context, instanceID, hostname string) (string, error) {
	cmd := fmt.Sprintf(cmdDigInternalQurlAPIFmt, hostname)
	return sendShellScript(ctx, instanceID, cmd)
}

// internalQurlEndpoint identifies which internal API endpoint a probe
// targets. Used by probeCurlInternalQurlEndpointStatus to pick the
// command format — keeps two parallel probe functions from drifting.
type internalQurlEndpoint int

const (
	// internalQurlEndpointResourceTarget hits GET
	// /internal/v1/resource/r_smokeprobe1/target. Fences general stack
	// reachability (DNS/TLS/SG/HostValidation/auth).
	internalQurlEndpointResourceTarget internalQurlEndpoint = iota
	// internalQurlEndpointResolve hits POST /internal/v1/resolve with
	// an empty JSON body. Fences the actual endpoint named by issue
	// qurl-service#335 — auth-middleware-runs-before-body-parse.
	internalQurlEndpointResolve
)

// path returns the request path each enum value corresponds to. Test
// error messages read this rather than maintaining a parallel literal —
// keeps the enum, the format-string constant, and the diagnostic
// description from drifting silently.
func (e internalQurlEndpoint) path() string {
	switch e {
	case internalQurlEndpointResourceTarget:
		return "/internal/v1/resource/r_smokeprobe1/target"
	case internalQurlEndpointResolve:
		return "/internal/v1/resolve"
	default:
		return fmt.Sprintf("<unknown endpoint %d>", e)
	}
}

// probeCurlInternalQurlEndpointStatus curls a qurl-service internal
// API endpoint from the host loopback (via the internal ALB) without
// auth and returns the HTTP status code. 401 is the expected healthy
// value (proves auth middleware reached); 400 means HostValidation
// rejected (or, on /resolve, that the body parser ran before auth —
// itself a regression worth catching); 502/504 mean SG/ALB path is
// broken; anything else is a new regression class.
//
// Regression fence for qurl-service #335 rollout: PR1 stands up the
// internal ALB and PR1's sub-step 1B closes the in-VPC ECS-SG bypass.
// Whichever stage we're in, both endpoints should return 401 from
// inside the VPC.
func probeCurlInternalQurlEndpointStatus(ctx context.Context, instanceID, hostname string, endpoint internalQurlEndpoint) (int, error) {
	var cmd string
	switch endpoint {
	case internalQurlEndpointResourceTarget:
		cmd = fmt.Sprintf(cmdCurlInternalQurlAPIFmt, hostname)
	case internalQurlEndpointResolve:
		cmd = fmt.Sprintf(cmdCurlInternalQurlResolveFmt, hostname)
	default:
		return 0, fmt.Errorf("unknown internal qurl endpoint: %d", endpoint)
	}
	out, err := sendShellScript(ctx, instanceID, cmd)
	if err != nil {
		return 0, err
	}
	out = strings.TrimSpace(out)
	// curl writes "000" when --max-time is exceeded or the connection
	// fails before any HTTP response. Surface this as errCurlNoResponse
	// so the caller can render a clear "ALB unreachable / TCP timeout"
	// diagnostic instead of treating it as an unexpected status 0.
	if out == "000" {
		return 0, errCurlNoResponse
	}
	code, err := strconv.Atoi(out)
	if err != nil {
		return 0, fmt.Errorf("parse http status %q: %w", out, err)
	}
	return code, nil
}

// probeQurlAPIURL reads the QURL_API_URL value from the nhp-server
// systemd EnvironmentFile on the host. Returns the URL on success,
// or an error if the file is missing, the line is missing, or the
// SSM call fails.
//
// Regression fence for qurl-service #335 PR2 — the value should be
// the workload-account internal-ALB hostname, not the public
// api.layerv.* hostname. A revert here means either tfvars regressed
// to the public URL or the user_data templating broke.
func probeQurlAPIURL(ctx context.Context, instanceID string) (string, error) {
	out, err := sendShellScript(ctx, instanceID, cmdGrepQurlAPIURL)
	if err != nil {
		return "", classifyQurlAPIURLError(err)
	}
	return parseQurlAPIURLValue(out)
}

// probeACFilterMode reads the deployed AC config's FilterMode from
// /opt/layerv/nhp-ac/etc/config.toml. user_data always renders this
// line; if it ever disappears, that is config drift and the probe fails
// loud rather than silently treating the host as iptables mode. It is
// intentionally separate from the object-existence probe so the smoke
// test can skip before E5 without masking missing-object failures once
// EBPFXDP is live.
func probeACFilterMode(ctx context.Context, instanceID string) (int, error) {
	out, err := sendShellScript(ctx, instanceID, cmdGrepACFilterMode)
	if err != nil {
		return 0, fmt.Errorf("read AC FilterMode from %s: %w", acConfigFilePath, err)
	}
	return parseACFilterModeValue(out)
}

// probeACEBPFObjectsPresent asserts that the eBPF object files the AC
// loads relative to its WorkingDirectory survived docker-cp extraction
// into the deployed host layout.
func probeACEBPFObjectsPresent(ctx context.Context, instanceID string) error {
	if _, err := sendShellScript(ctx, instanceID, cmdACEBPFXDPObjectPresent); err != nil {
		return fmt.Errorf("AC eBPF object presence check failed for deployed layout %s (missing, empty, unreadable, or SSM probe failure): %w", acEBPFXDPObjectPath, err)
	}
	if _, err := sendShellScript(ctx, instanceID, cmdACTCEgressObjectPresent); err != nil {
		return fmt.Errorf("AC eBPF object presence check failed for deployed layout %s (missing, empty, unreadable, or SSM probe failure): %w", acTCEgressObjectPath, err)
	}
	return nil
}

func parseACFilterModeValue(line string) (int, error) {
	line = strings.TrimSpace(line)
	const filterModeKey = "FilterMode"
	key, value, ok := strings.Cut(line, "=")
	if !ok || !strings.EqualFold(strings.TrimSpace(key), filterModeKey) {
		return 0, fmt.Errorf("unexpected AC config FilterMode line shape: %q", line)
	}
	value = strings.TrimSpace(value)
	if beforeComment, _, hasComment := strings.Cut(value, "#"); hasComment {
		value = strings.TrimSpace(beforeComment)
	}
	mode, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("parse AC FilterMode from %q: %w", line, err)
	}
	switch mode {
	case acFilterModeIPTables, acFilterModeEBPFXDP:
		return mode, nil
	default:
		return 0, fmt.Errorf("AC FilterMode = %d, want %d (iptables) or %d (EBPFXDP)", mode, acFilterModeIPTables, acFilterModeEBPFXDP)
	}
}

// parseQurlAPIURLValue extracts the RHS of a "QURL_API_URL=..." env
// file line. The unexpected-shape branch is unreachable from the
// production probe path because cmdGrepQurlAPIURL anchors on
// `^QURL_API_URL=` — but a transient SSM agent bug or a future probe
// that bypasses the anchor would surface here as a clear shape error
// rather than a silent empty-value drift hint at the classifier layer.
// Pulled out as a pure function so the malformed-line branch can be
// pinned by TestParseQurlAPIURLValue without an SSM round-trip.
func parseQurlAPIURLValue(line string) (string, error) {
	line = strings.TrimSpace(line)
	const prefix = "QURL_API_URL="
	if !strings.HasPrefix(line, prefix) {
		return "", fmt.Errorf("unexpected env file line shape: %q", line)
	}
	return strings.TrimPrefix(line, prefix), nil
}

// classifyQurlAPIURLError turns sendShellScript's generic error into a
// triage-ready diagnostic for the two grep failure modes the
// QURL_API_URL probe cares about:
//
//   - exit 2 (env file missing): stderr carries "No such file or
//     directory". Render as "nhp-server env file missing".
//   - exit 1 (line missing): SSM's shell wrapper reports a silent exit 1
//     as stderr="failed to run commands: exit status 1" (measured live on
//     i-0209b63d922e839b0; it APPENDS to a command's own stderr, so a real
//     error keeps its message and falls through). The empty-stderr match is
//     kept for older agent behaviour. Render as "QURL_API_URL line missing".
//
// All other shapes pass through untouched. Pulled out as a pure
// function so the dispatch contract is unit-testable in
// ssm_probe_test.go without an SSM round-trip.
//
// Note: sendShellScript uses the same `status=%s stderr=%q` format
// for the canceled and timed-out command paths. Those could match
// `stderr=""` if their stderr is empty, but they explicitly do NOT
// match this branch because we anchor on `status=Failed`. SSM-side
// cancel/timeout falls through to the pass-through path — the right
// outcome.
//
// String-matching on sendShellScript's own format string is brittle
// by construction; #1597 tracks moving sendShellScript to typed
// errors so this dispatcher can switch on category instead.
//
// Branch order is informational priority, not correctness. The two
// matching substrings are mutually exclusive in practice — empty
// stderr cannot also contain "No such file or directory" — so they
// can never both match. If a future grep variant ever did emit both,
// the file-missing branch wins because it is the more informative
// diagnostic. Do not reorder expecting different semantics.
func classifyQurlAPIURLError(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "No such file or directory"):
		return fmt.Errorf("nhp-server env file missing at %s — qurl-plugin not provisioned or user_data dropped the env-file write: %w", nhpServerEnvFilePath, err)
	case strings.Contains(msg, `status=Failed stderr=""`),
		strings.Contains(msg, `status=Failed stderr="failed to run commands: exit status 1"`):
		return fmt.Errorf("QURL_API_URL line missing in %s — qurl_config.enabled=false in tfvars, or user_data template regressed the qurl block: %w", nhpServerEnvFilePath, err)
	}
	return err
}

// probeServerNRestarts returns systemd's NRestarts counter for the
// nhp-server unit. Zero is the only healthy value; any non-zero means
// the process panicked or exited non-zero during this instance's
// lifetime and systemd re-executed it. Under normal operation the
// server does not self-restart, so a non-zero counter is a direct
// regression signal — most prominently for the class fixed in PR #1096
// (panic: send on closed channel in RemoteTransaction.Run cleanup).
func probeServerNRestarts(ctx context.Context, instanceID string) (int, error) {
	out, err := sendShellScript(ctx, instanceID, cmdSystemdNRestartsNhpServer)
	if err != nil {
		return 0, err
	}
	out = strings.TrimSpace(out)
	n, err := strconv.Atoi(out)
	if err != nil {
		return 0, fmt.Errorf("parse NRestarts %q: %w", out, err)
	}
	return n, nil
}

// sendShellScriptRaw is an UNEXPORTED test-only helper that lets
// ssm_probe_test.go exercise the reject-list directly without needing
// an actual SSM client. It short-circuits: returns errCommandRejected
// for rejected commands, nil otherwise. Production code paths (tests in
// other files) must not call this.
func sendShellScriptRaw(cmd string) error {
	for _, pat := range rejectPatterns {
		if pat.MatchString(cmd) {
			return fmt.Errorf("%w: pattern %q matched in %q", errCommandRejected, pat.String(), cmd)
		}
	}
	return nil
}
