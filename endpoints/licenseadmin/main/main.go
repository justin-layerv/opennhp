// Command nhp-license-admin provisions security-critical license and
// AC-assignment pubkey lists that server-side gates enforce.
//
// Background: the console repo that historically wrote nhp-licenses rows was
// archived, so the BoundPubKeys provisioning workflow (#1262) now lives here.
// The validation/canonicalization kernel and the DynamoDB write path live in
// package licenseadmin (deliberately decoupled from package server, which
// carries KBS init side-effects) so the write-side encoding contract can't
// drift from the gate's read side.
//
// Strict-flip runbook + key-rotation workflow:
// docs/runbooks/license-pubkey-strict-flip.md
package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/urfave/cli/v2"

	"github.com/OpenNHP/opennhp/endpoints/licenseadmin"
	"github.com/OpenNHP/opennhp/nhp/version"
)

const (
	acAssignmentDefaultCacheTTL      = "60s"
	acAssignmentReassignmentCacheTTL = "5s"
	maxOperatorLabelBytes            = 256
)

func main() {
	app := &cli.App{
		Name:    "nhp-license-admin",
		Usage:   "manage NHP license pubkey allowlists and AC revoked-pubkey denylists",
		Version: version.Version,
		Description: strings.TrimSpace(`
Binds AC static public keys to NHP license records so the server-side
license_pubkey_gate (#1155) can be flipped from permit to strict.

Also manages ACAssignment.RevokedPubKeys for the F5 runtime-revocation gate
(#1507): revoke adds a compromised AC pubkey to one acId's denylist, unrevoke
removes it, and list-revoked inspects the current set.

Writes the bound_pubkeys allowlist on the nhp-licenses DynamoDB table. Every
pubkey is validated as padded standard base64 (RFC 4648 §4) of a 32-byte
curve25519 key and stored in canonical form, so a provisioned key can never
silently mismatch a legitimate AC registration (which would look exactly like
a #1155 attack).

Run with AWS credentials for a role holding dynamodb:GetItem plus
dynamodb:UpdateItem on the target table: nhp-licenses for license mutations and
nhp-ac-assignments for revoke/unrevoke. Flags go AFTER the subcommand (e.g.
"bind --operator x --license-sha256 ..."). The mutation audit record is the JSON
line on stderr (and --audit-file, if set) — capture it. CloudTrail does NOT carry
the before/after license allowlist values or the resulting revoked-pubkey set,
and DynamoDB data-plane events (the IAM-principal who/when) are off by default on
the table. --operator is a self-asserted, advisory label capped at 256 bytes.

Strict-flip runbook: docs/runbooks/license-pubkey-strict-flip.md`),
		Commands: []*cli.Command{
			showCommand(),
			bindCommand(),
			unbindCommand(),
			resetCommand(),
			listRevokedCommand(),
			revokeCommand(),
			unrevokeCommand(),
		},
	}

	// Cancel in-flight DynamoDB calls on Ctrl-C / SIGTERM; the signal context
	// flows to the Client via c.Context. (Each UpdateItem is atomic+conditional,
	// so an interrupt can't leave a half-written row regardless.)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := app.RunContext(ctx, os.Args); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// Flags live at the subcommand level (not app level) so they can be supplied in
// the natural "bind --operator x --license-sha256 ..." order; cli/v2 app-level
// flags must precede the subcommand, which is an easy operator foot-gun.

// selectorFlags identify the target license. An operator typically only has the
// partition key (the plaintext key is shown once at issuance), so
// --license-sha256 is the primary selector; --license-key is a convenience that
// hashes locally.
func selectorFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{Name: "license-sha256", Usage: "license partition key (hex SHA256 of the license key); preferred selector"},
		&cli.StringFlag{Name: "license-key", Usage: "plaintext license key, hashed locally — leaks via process args; prefer --license-sha256, or supply the key via the NHP_LICENSE_KEY env var (used only when no selector flag is given)"},
	}
}

// connectionFlags configure which table the command talks to.
func connectionFlags() []cli.Flag {
	return dynamoConnectionFlags(
		"AWS region of the licenses table",
		&cli.StringFlag{Name: "licenses-table", Value: "nhp-licenses", Usage: "DynamoDB licenses table name"},
	)
}

func operatorFlag() cli.Flag {
	// NHP_ADMIN_* is the preferred cross-admin namespace. The older
	// NHP_LICENSE_ADMIN_* names remain as fallback-only compatibility aliases,
	// so a shell exporting both intentionally gets the generic value.
	return &cli.StringFlag{Name: "operator", EnvVars: []string{"NHP_ADMIN_OPERATOR", "NHP_LICENSE_ADMIN_OPERATOR"}, Usage: "identity of the admin running the command (recorded in the audit log; max 256 bytes)"}
}

func auditFileFlag() cli.Flag {
	return &cli.StringFlag{Name: "audit-file", EnvVars: []string{"NHP_ADMIN_AUDIT_FILE", "NHP_LICENSE_ADMIN_AUDIT_FILE"}, Usage: "append the JSON audit line to this file for a durable record (stderr always gets it too)"}
}

// commandFlags composes the selector + connection flags shared by every command
// with any command-specific extras.
func commandFlags(extra ...cli.Flag) []cli.Flag {
	flags := append(selectorFlags(), connectionFlags()...)
	return append(flags, extra...)
}

func assignmentConnectionFlags() []cli.Flag {
	return dynamoConnectionFlags(
		"AWS region of the AC assignments table (set --region or AWS_REGION if the incident profile points elsewhere)",
		&cli.StringFlag{Name: "ac-assignments-table", Value: "nhp-ac-assignments", Usage: "DynamoDB AC assignments table name"},
	)
}

func dynamoConnectionFlags(regionUsage string, tableFlag cli.Flag) []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{Name: "region", Value: "us-east-2", EnvVars: []string{"AWS_REGION"}, Usage: regionUsage},
		tableFlag,
		&cli.StringFlag{Name: "endpoint", Usage: "custom DynamoDB endpoint (local development only)"},
	}
}

func assignmentCommandFlags(extra ...cli.Flag) []cli.Flag {
	flags := append(assignmentConnectionFlags(),
		&cli.StringFlag{Name: "ac-id", Required: true, Usage: "AC assignment id (ac_id partition key)"},
	)
	return append(flags, extra...)
}

func showCommand() *cli.Command {
	return &cli.Command{
		Name:  "show",
		Usage: "print the bound_pubkeys allowlist for a license",
		Flags: commandFlags(),
		Action: func(c *cli.Context) error {
			sha, err := resolveSHA256(c)
			if err != nil {
				return cli.Exit(err, 1)
			}
			client, err := openClient(c)
			if err != nil {
				return cli.Exit(err, 1)
			}
			lic, err := client.GetLicense(c.Context, sha)
			if err != nil {
				return cli.Exit(err, 1)
			}
			fmt.Printf("license %s  (customer=%s tier=%s active=%t)\n", sha, lic.CustomerID, lic.Tier, lic.Active)
			printList(os.Stdout, "bound_pubkeys", lic.BoundPubKeys)
			return nil
		},
	}
}

func bindCommand() *cli.Command {
	return &cli.Command{
		Name:  "bind",
		Usage: "append one or more AC pubkeys to a license's allowlist",
		Flags: commandFlags(operatorFlag(), auditFileFlag(),
			&cli.StringSliceFlag{Name: "pubkey", Aliases: []string{"k"}, Usage: "AC static pubkey, padded standard base64 (repeatable)"},
			&cli.StringFlag{Name: "pubkeys-file", Usage: "file with one pubkey per line (# comments and blank lines ignored)"},
		),
		Action: func(c *cli.Context) error {
			// Merge + canonicalize first so a malformed key fails fast — before
			// AWS config load / client construction — and isn't re-validated on
			// each retry (symmetric with unbind).
			canonPubkeys, err := gatherCanonicalPubkeys(c.StringSlice("pubkey"), c.String("pubkeys-file"))
			if err != nil {
				return cli.Exit(err, 1)
			}
			operator, sha, client, err := mutationSetup(c)
			if err != nil {
				return cli.Exit(err, 1)
			}
			return withRetry(c.Context, func() error {
				return runBind(c.Context, client, os.Stdout, c.String("audit-file"), operator, sha, canonPubkeys)
			})
		},
	}
}

func unbindCommand() *cli.Command {
	return &cli.Command{
		Name:  "unbind",
		Usage: "remove an AC pubkey from a license's allowlist",
		Flags: commandFlags(operatorFlag(), auditFileFlag(),
			&cli.StringFlag{Name: "pubkey", Aliases: []string{"k"}, Required: true, Usage: "AC static pubkey to remove (padded standard base64)"},
			&cli.BoolFlag{Name: "yes", Usage: "confirm removing the LAST pubkey (which makes the license unbound), same guard as reset"},
		),
		Action: func(c *cli.Context) error {
			// Canonicalize the target first so an invalid pubkey fails fast —
			// before AWS config load / client construction — and is not
			// re-derived on each retry.
			canon, err := licenseadmin.CanonicalizeBoundPubKey(c.String("pubkey"))
			if err != nil {
				return cli.Exit(err, 1)
			}
			operator, sha, client, err := mutationSetup(c)
			if err != nil {
				return cli.Exit(err, 1)
			}
			return withRetry(c.Context, func() error {
				return runUnbind(c.Context, client, os.Stdout, c.String("audit-file"), operator, sha, canon, c.Bool("yes"))
			})
		},
	}
}

func resetCommand() *cli.Command {
	return &cli.Command{
		Name:  "reset",
		Usage: "clear a license's allowlist (back to unbound)",
		Flags: commandFlags(operatorFlag(), auditFileFlag(),
			&cli.BoolFlag{Name: "yes", Usage: "confirm: clearing makes the license unbound (permit-mode accept / strict-mode reject)"},
		),
		Action: func(c *cli.Context) error {
			// Check the confirmation first so a missing --yes fails before AWS
			// config load / client construction.
			if !c.Bool("yes") {
				return cli.Exit("refusing to reset without --yes (this makes the license unbound)", 1)
			}
			operator, sha, client, err := mutationSetup(c)
			if err != nil {
				return cli.Exit(err, 1)
			}
			return withRetry(c.Context, func() error {
				return runReset(c.Context, client, os.Stdout, c.String("audit-file"), operator, sha)
			})
		},
	}
}

func listRevokedCommand() *cli.Command {
	return listRevokedCommandWithDeps(func(c *cli.Context) (assignmentReader, error) {
		return openAssignmentClient(c)
	}, os.Stdout)
}

func listRevokedCommandWithDeps(open func(*cli.Context) (assignmentReader, error), out io.Writer) *cli.Command {
	return &cli.Command{
		Name:  "list-revoked",
		Usage: "print the revoked_pubkeys denylist for an AC assignment",
		Flags: assignmentCommandFlags(),
		Action: func(c *cli.Context) error {
			client, err := open(c)
			if err != nil {
				return cli.Exit(err, 1)
			}
			if err := runListRevoked(c.Context, client, out, c.String("ac-id")); err != nil {
				return cli.Exit(err, 1)
			}
			return nil
		},
	}
}

func revokeCommand() *cli.Command {
	return revokeCommandWithDeps(openAssignmentStore, os.Stdout)
}

func revokeCommandWithDeps(open func(*cli.Context) (assignmentStore, error), out io.Writer) *cli.Command {
	return &cli.Command{
		Name:  "revoke",
		Usage: "add an AC pubkey to one AC assignment's revoked-pubkey denylist",
		Flags: assignmentCommandFlags(operatorFlag(), auditFileFlag(),
			&cli.StringFlag{Name: "pubkey", Aliases: []string{"k"}, Required: true, Usage: "AC static pubkey to revoke (padded standard base64)"},
		),
		Action: func(c *cli.Context) error {
			operator, acID, pubkey, client, err := assignmentPubKeyMutationSetupWithDeps(c, "revoke", open)
			if err != nil {
				return cli.Exit(err, 1)
			}
			return withRetryOnExhaust(c.Context, func() error {
				return runRevoke(c.Context, client, out, c.String("audit-file"), operator, acID, pubkey)
			}, acRetryExhaustionAudit(c, "revoke", operator, acID, pubkey))
		},
	}
}

func openAssignmentStore(c *cli.Context) (assignmentStore, error) {
	return openAssignmentClient(c)
}

func acRetryExhaustionAudit(c *cli.Context, action, operator, acID, pubkey string) func(error) {
	return func(err error) {
		emitACErrorAudit(c.String("audit-file"), action, operator, acID, pubkey, err)
	}
}

func unrevokeCommand() *cli.Command {
	return unrevokeCommandWithDeps(openAssignmentStore, os.Stdout)
}

func unrevokeCommandWithDeps(open func(*cli.Context) (assignmentStore, error), out io.Writer) *cli.Command {
	return &cli.Command{
		Name:  "unrevoke",
		Usage: "remove an AC pubkey from one AC assignment's revoked-pubkey denylist",
		Flags: assignmentCommandFlags(operatorFlag(), auditFileFlag(),
			&cli.StringFlag{Name: "pubkey", Aliases: []string{"k"}, Required: true, Usage: "AC static pubkey to unrevoke (padded standard base64)"},
		),
		Action: func(c *cli.Context) error {
			operator, acID, pubkey, client, err := assignmentPubKeyMutationSetupWithDeps(c, "unrevoke", open)
			if err != nil {
				return cli.Exit(err, 1)
			}
			return withRetryOnExhaust(c.Context, func() error {
				return runUnrevoke(c.Context, client, out, c.String("audit-file"), operator, acID, pubkey)
			}, acRetryExhaustionAudit(c, "unrevoke", operator, acID, pubkey))
		},
	}
}

func assignmentPubKeyMutationSetupWithDeps(c *cli.Context, action string, open func(*cli.Context) (assignmentStore, error)) (operator, acID, pubkey string, client assignmentStore, err error) {
	if operator, acID, pubkey, err = assignmentPubKeyMutationInputs(c, action); err != nil {
		return "", "", "", nil, err
	}
	if client, err = open(c); err != nil {
		emitACErrorAudit(c.String("audit-file"), action, operator, acID, pubkey, err)
		return "", "", "", nil, err
	}
	return operator, acID, pubkey, client, nil
}

func assignmentPubKeyMutationInputs(c *cli.Context, action string) (operator, acID, pubkey string, err error) {
	if operator, err = requireOperator(c); err != nil {
		// Without a valid operator label there is no useful AC-audit subject; fail
		// before emitting the rejected attempt.
		return "", "", "", err
	}
	acID = strings.TrimSpace(c.String("ac-id"))
	if acID == "" {
		// cli/v2 Required catches an absent flag; keep this trim check for
		// whitespace-only values so rejected attempts still get an audit line.
		err = errors.New("--ac-id is required")
		emitACErrorAudit(c.String("audit-file"), action, operator, acID, c.String("pubkey"), err)
		return "", "", "", err
	}
	// Canonicalize before AWS config/client construction so malformed pubkey
	// input fails fast and can be audited without making any network calls. The
	// store layer still revalidates to keep AssignmentClient safe for non-CLI
	// callers.
	if pubkey, err = licenseadmin.CanonicalizeBoundPubKey(c.String("pubkey")); err != nil {
		emitACErrorAudit(c.String("audit-file"), action, operator, acID, c.String("pubkey"), err)
		return "", "", "", err
	}
	if strings.TrimSpace(c.String("audit-file")) == "" {
		fmt.Fprintln(os.Stderr, "warning: no --audit-file set; the mutation audit record will go only to stderr — capture stderr, or set --audit-file / NHP_ADMIN_AUDIT_FILE / NHP_LICENSE_ADMIN_AUDIT_FILE for a durable record")
	}
	return operator, acID, pubkey, nil
}

// resolveSHA256 derives the licenses-table partition key from the selector
// flags and the NHP_LICENSE_KEY env fallback. The flag-free logic lives in
// resolveLicenseSHA256 so it is unit-testable without a cli.Context.
func resolveSHA256(c *cli.Context) (string, error) {
	// Make the argv-leak path loud at the moment of use (symmetric with the
	// --endpoint warning). NHP_LICENSE_KEY is no longer bound to this flag, so a
	// non-empty value here came from the command line.
	if strings.TrimSpace(c.String("license-key")) != "" {
		fmt.Fprintln(os.Stderr, "warning: --license-key on the command line leaks into ps / /proc / shell history; prefer --license-sha256 or the NHP_LICENSE_KEY env var")
	}
	return resolveLicenseSHA256(c.String("license-sha256"), c.String("license-key"), os.Getenv("NHP_LICENSE_KEY"))
}

// resolveLicenseSHA256 derives the partition key. Passing both --license-sha256
// and --license-key explicitly is an error (ambiguous). Otherwise the source is
// chosen in order: --license-sha256 (the recommended selector), then
// --license-key, then the NHP_LICENSE_KEY env fallback. An exported
// NHP_LICENSE_KEY therefore does NOT block --license-sha256, so the two security
// recommendations (prefer sha256; pass the key via env rather than argv) don't
// collide.
func resolveLicenseSHA256(sha256Flag, keyFlag, envKey string) (string, error) {
	// Trim all inputs: a license key pasted from a file / heredoc often carries
	// a trailing newline, which would otherwise hash to a non-existent sha and
	// surface as a confusing "license not found" rather than a clear signal.
	// License keys are opaque whitespace-free tokens, so trimming is safe.
	sha := strings.ToLower(strings.TrimSpace(sha256Flag))
	key := strings.TrimSpace(keyFlag)
	env := strings.TrimSpace(envKey)
	switch {
	case sha != "" && key != "":
		return "", errors.New("provide exactly one of --license-sha256 or --license-key")
	case sha != "":
		if !isHex64(sha) {
			return "", fmt.Errorf("--license-sha256 must be 64 hex characters, got %d", len(sha))
		}
		return sha, nil
	case key != "":
		return licenseadmin.LicenseKeySHA256(key), nil
	case env != "":
		return licenseadmin.LicenseKeySHA256(env), nil
	default:
		return "", errors.New("one of --license-sha256 / --license-key / NHP_LICENSE_KEY is required")
	}
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

func openClient(c *cli.Context) (*licenseadmin.Client, error) {
	endpoint := c.String("endpoint")
	warnIfCustomEndpoint(endpoint)
	return licenseadmin.NewClient(c.Context, licenseadmin.Config{
		Region:        c.String("region"),
		LicensesTable: c.String("licenses-table"),
		Endpoint:      endpoint,
	})
}

func openAssignmentClient(c *cli.Context) (*licenseadmin.AssignmentClient, error) {
	endpoint := c.String("endpoint")
	warnIfCustomEndpoint(endpoint)
	return licenseadmin.NewAssignmentClient(c.Context, licenseadmin.AssignmentConfig{
		Region:             c.String("region"),
		ACAssignmentsTable: c.String("ac-assignments-table"),
		Endpoint:           endpoint,
	})
}

// warnIfCustomEndpoint makes a local-dev --endpoint override loud — a mis-set
// endpoint silently points writes at the wrong DynamoDB.
func warnIfCustomEndpoint(endpoint string) {
	if endpoint != "" {
		fmt.Fprintf(os.Stderr, "warning: using custom DynamoDB endpoint %q (local-development override)\n", endpoint)
	}
}

func requireOperator(c *cli.Context) (string, error) {
	op := strings.TrimSpace(c.String("operator"))
	if op == "" {
		return "", errors.New("--operator is required for mutations (set --operator, NHP_ADMIN_OPERATOR, or NHP_LICENSE_ADMIN_OPERATOR)")
	}
	if len(op) > maxOperatorLabelBytes {
		return "", fmt.Errorf("--operator must be at most %d bytes after trimming", maxOperatorLabelBytes)
	}
	return op, nil
}

// mutationSetup resolves the inputs every mutating command needs: the operator
// identity (required), the target license partition key, and a DynamoDB client.
func mutationSetup(c *cli.Context) (operator, sha string, client *licenseadmin.Client, err error) {
	if operator, err = requireOperator(c); err != nil {
		return "", "", nil, err
	}
	// Make the durable-record gap loud at the moment it matters: without
	// --audit-file the before/after lives only on stderr (CloudTrail doesn't
	// carry it), so a script that discards stderr loses the mutation record.
	if strings.TrimSpace(c.String("audit-file")) == "" {
		fmt.Fprintln(os.Stderr, "warning: no --audit-file set; the before/after audit record will go only to stderr — capture stderr, or set --audit-file / NHP_ADMIN_AUDIT_FILE / NHP_LICENSE_ADMIN_AUDIT_FILE for a durable record")
	}
	if sha, err = resolveSHA256(c); err != nil {
		return "", "", nil, err
	}
	if client, err = openClient(c); err != nil {
		return "", "", nil, err
	}
	return operator, sha, client, nil
}

// withRetry re-runs fn on an optimistic-lock conflict (a concurrent admin
// mutated the same license between our read and write). fn re-reads the license
// each attempt, so the retry recomputes against fresh state. Any other error
// aborts immediately. The backoff honors ctx, so Ctrl-C / SIGTERM interrupts it
// crisply instead of waiting out the sleep.
func withRetry(ctx context.Context, fn func() error) error {
	return withRetryOnExhaust(ctx, fn, nil)
}

func withRetryOnExhaust(ctx context.Context, fn func() error, onExhaust func(error)) error {
	const maxAttempts = 4
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		err := fn()
		if err == nil {
			return nil
		}
		if !errors.Is(err, licenseadmin.ErrConcurrentModification) {
			return cli.Exit(err, 1)
		}
		lastErr = err
		if attempt < maxAttempts {
			select {
			case <-ctx.Done():
				err := fmt.Errorf("interrupted during retry backoff: %w", ctx.Err())
				if onExhaust != nil {
					onExhaust(err)
				}
				return cli.Exit(err, 1)
			case <-time.After(retryBackoff(attempt)):
			}
		}
	}
	err := fmt.Errorf("aborted after %d retries due to concurrent modification: %w", maxAttempts, lastErr)
	if onExhaust != nil {
		onExhaust(err)
	}
	return cli.Exit(err, 1)
}

func retryBackoff(attempt int) time.Duration {
	base := time.Duration(attempt) * 50 * time.Millisecond
	return base + retryJitter()
}

func retryJitter() time.Duration {
	// Backoff jitter is only scheduling decorrelation; cryptographic
	// unpredictability is irrelevant and would just burn entropy.
	// #nosec G404 -- decorrelation only; not security-sensitive.
	return rand.N(25 * time.Millisecond)
}

func printList(out io.Writer, label string, keys []string) {
	if len(keys) == 0 {
		fmt.Fprintf(out, "%s: (none — unbound; gate verdict is verdictLicenseUnbound)\n", label)
		return
	}
	fmt.Fprintf(out, "%s (%d):\n", label, len(keys))
	for _, k := range keys {
		fmt.Fprintf(out, "  - %s\n", k)
	}
}

// licenseStore is the subset of *licenseadmin.Client the command cores use, so
// they can be unit-tested against a fake without a live DynamoDB.
type licenseStore interface {
	GetLicense(ctx context.Context, licenseKeySHA256 string) (*licenseadmin.License, error)
	UpdateBoundPubKeys(ctx context.Context, licenseKeySHA256 string, boundPubKeys []string, expectedUpdatedAt int64) (int64, error)
}

type assignmentReader interface {
	GetACAssignment(ctx context.Context, acID string) (*licenseadmin.ACAssignment, error)
}

type assignmentStore interface {
	assignmentReader
	AddRevokedPubKey(ctx context.Context, acID, pubkey string) (*licenseadmin.ACAssignment, string, bool, error)
	RemoveRevokedPubKey(ctx context.Context, acID, pubkey string) (*licenseadmin.ACAssignment, string, bool, error)
}

// runBind / runUnbind / runReset are the command cores: one read-modify-write
// pass each, returning raw errors so withRetry can classify conflicts. They take
// a licenseStore + io.Writer so the no-op and guard branches are unit-testable.

func runListRevoked(ctx context.Context, store assignmentReader, out io.Writer, acID string) error {
	assignment, err := store.GetACAssignment(ctx, acID)
	if err != nil {
		if errors.Is(err, licenseadmin.ErrACAssignmentNotFound) {
			return fmt.Errorf("%w (assigned ACs with an empty denylist print revoked_pubkeys: none)", err)
		}
		return err
	}
	printRevokedAssignment(out, assignment)
	return nil
}

func runBind(ctx context.Context, store licenseStore, out io.Writer, auditFile, operator, sha string, canonPubkeys []string) error {
	lic, err := store.GetLicense(ctx, sha)
	if err != nil {
		return err
	}
	// canonPubkeys are already canonical; AppendBoundPubKeys re-validates
	// idempotently (it stays self-contained for other callers).
	newList, added, err := licenseadmin.AppendBoundPubKeys(lic.BoundPubKeys, canonPubkeys)
	if err != nil {
		return err // validation error — not a conflict, won't retry
	}
	if len(added) == 0 {
		fmt.Fprintf(out, "no change: all %d pubkey(s) already bound to %s\n", len(canonPubkeys), sha)
		printList(out, "bound_pubkeys", lic.BoundPubKeys)
		return nil
	}
	if _, err := store.UpdateBoundPubKeys(ctx, sha, newList, lic.UpdatedAt); err != nil {
		return err
	}
	emitAudit(auditFile, "bind", operator, sha, lic.BoundPubKeys, newList, added)
	fmt.Fprintf(out, "bound %d pubkey(s) to license %s\n", len(added), sha)
	printList(out, "bound_pubkeys", newList)
	return nil
}

func runUnbind(ctx context.Context, store licenseStore, out io.Writer, auditFile, operator, sha, canon string, yes bool) error {
	lic, err := store.GetLicense(ctx, sha)
	if err != nil {
		return err
	}
	newList, removed, err := licenseadmin.RemoveBoundPubKey(lic.BoundPubKeys, canon)
	if err != nil {
		return err
	}
	if !removed {
		fmt.Fprintf(out, "no change: pubkey %s not bound to %s\n", canon, sha)
		printList(out, "bound_pubkeys", lic.BoundPubKeys)
		return nil
	}
	// Removing the last entry makes the license unbound — the same transition
	// reset guards with --yes, so require it here too. Not a conflict, so
	// withRetry aborts immediately (no retry).
	if len(newList) == 0 && !yes {
		return fmt.Errorf("refusing to remove the last pubkey from %s without --yes (this makes the license unbound); re-run with --yes or use `reset --yes`", sha)
	}
	if _, err := store.UpdateBoundPubKeys(ctx, sha, newList, lic.UpdatedAt); err != nil {
		return err
	}
	emitAudit(auditFile, "unbind", operator, sha, lic.BoundPubKeys, newList, []string{canon})
	fmt.Fprintf(out, "unbound 1 pubkey from license %s\n", sha)
	printList(out, "bound_pubkeys", newList)
	return nil
}

func runReset(ctx context.Context, store licenseStore, out io.Writer, auditFile, operator, sha string) error {
	lic, err := store.GetLicense(ctx, sha)
	if err != nil {
		return err
	}
	// len 0 covers both an absent attribute and a stored empty list []; both are
	// already-unbound (the gate agrees, via verdictLicenseUnbound). This tool
	// never writes [] (UpdateBoundPubKeys REMOVEs on empty), so a stray empty
	// list can't arise here in practice.
	if len(lic.BoundPubKeys) == 0 {
		fmt.Fprintf(out, "no change: license %s is already unbound\n", sha)
		printList(out, "bound_pubkeys", lic.BoundPubKeys)
		return nil
	}
	if _, err := store.UpdateBoundPubKeys(ctx, sha, nil, lic.UpdatedAt); err != nil {
		return err
	}
	emitAudit(auditFile, "reset", operator, sha, lic.BoundPubKeys, nil, lic.BoundPubKeys)
	fmt.Fprintf(out, "reset license %s to unbound (removed %d pubkey(s))\n", sha, len(lic.BoundPubKeys))
	printList(out, "bound_pubkeys", nil)
	return nil
}

func runRevoke(ctx context.Context, store assignmentStore, out io.Writer, auditFile, operator, acID, pubkey string) error {
	assignment, canon, changed, err := store.AddRevokedPubKey(ctx, acID, pubkey)
	if err != nil {
		if !errors.Is(err, licenseadmin.ErrConcurrentModification) {
			emitACErrorAudit(auditFile, "revoke", operator, acID, pubkey, err)
		}
		return err
	}
	emitACAudit(auditFile, "revoke", operator, acID, canon, changed, assignment.Version, assignment.RevokedPubKeys)
	if !changed {
		fmt.Fprintf(out, "no change: pubkey already revoked for AC %s (version unchanged)\n", acID)
		if revokedPubKeyDirtyTrimPresent(assignment.RevokedPubKeys, canon) {
			fmt.Fprintln(out, "note: a legacy non-canonical revoked_pubkeys entry also matches this pubkey; direct DynamoDB cleanup of the legacy member may still be needed")
		}
		printRevokedAssignment(out, assignment)
		return nil
	}
	fmt.Fprintf(out, "revoked pubkey for AC %s (version %d)\n", acID, assignment.Version)
	if revokedPubKeyDirtyTrimPresent(assignment.RevokedPubKeys, canon) {
		fmt.Fprintln(out, "note: a legacy non-canonical revoked_pubkeys entry already matched this pubkey at the gate; canonical duplicate was added, but direct DynamoDB cleanup of the legacy member may still be needed")
	} else {
		printACAssignmentPropagation(out, "reject the next registration")
	}
	printRevokedAssignment(out, assignment)
	return nil
}

func runUnrevoke(ctx context.Context, store assignmentStore, out io.Writer, auditFile, operator, acID, pubkey string) error {
	assignment, canon, changed, err := store.RemoveRevokedPubKey(ctx, acID, pubkey)
	if err != nil {
		if !errors.Is(err, licenseadmin.ErrConcurrentModification) {
			emitACErrorAudit(auditFile, "unrevoke", operator, acID, pubkey, err)
		}
		return err
	}
	emitACAudit(auditFile, "unrevoke", operator, acID, canon, changed, assignment.Version, assignment.RevokedPubKeys)
	if !changed {
		fmt.Fprintf(out, "no change: pubkey was not revoked for AC %s (version unchanged)\n", acID)
		printRevokedAssignment(out, assignment)
		return nil
	}
	fmt.Fprintf(out, "unrevoked pubkey for AC %s (version %d)\n", acID, assignment.Version)
	if revokedPubKeyDirtyTrimPresent(assignment.RevokedPubKeys, canon) {
		fmt.Fprintln(out, "warning: a non-canonical revoked_pubkeys entry still matches this pubkey after trimming; servers may keep rejecting until that legacy entry is cleaned directly in DynamoDB")
	} else {
		printACAssignmentPropagation(out, "stop rejecting")
	}
	printRevokedAssignment(out, assignment)
	return nil
}

func printACAssignmentPropagation(out io.Writer, behavior string) {
	// These strings mirror the F5 runbook and the server-side assignment-cache
	// TTLs without importing package server, whose init side effects are not
	// appropriate for the operator CLI.
	fmt.Fprintf(out, "propagation: servers %s after their AC-assignment cache refreshes (normally <=%s; <=%s during reassignment)\n",
		behavior, acAssignmentDefaultCacheTTL, acAssignmentReassignmentCacheTTL)
}

func printRevokedAssignment(out io.Writer, assignment *licenseadmin.ACAssignment) {
	if assignment == nil {
		fmt.Fprintln(out, "revoked_pubkeys: (unknown)")
		return
	}
	fmt.Fprintf(out, "ac_id: %s\nversion: %d\n", assignment.ACID, assignment.Version)
	keys := sortedNonNil(assignment.RevokedPubKeys)
	if len(keys) == 0 {
		fmt.Fprintln(out, "revoked_pubkeys: (none)")
		return
	}
	fmt.Fprintf(out, "revoked_pubkeys (%d):\n", len(keys))
	for _, k := range keys {
		fmt.Fprintf(out, "  - %s\n", k)
	}
}

// revokedPubKeyDirtyTrimPresent detects legacy entries that still match the
// server gate's trim semantics after DynamoDB's exact-match ADD/DELETE.
func revokedPubKeyDirtyTrimPresent(keys []string, pubkey string) bool {
	target := strings.TrimSpace(pubkey)
	for _, key := range keys {
		if strings.TrimSpace(key) == target && key != target {
			return true
		}
	}
	return false
}

// emitAudit writes a structured audit line to stderr. It complements — does not
// replace — the CloudTrail record of the DynamoDB mutation, which is the
// authoritative tamper-evident who/when source.
// auditRecord is the JSON shape emitted per mutation. The field names are an
// implicit contract for whatever parses the ops log — keep them stable (or
// update consumers). Locked by TestBuildAuditRecord.
//
// `changed` is the delta: keys added (bind) or removed (unbind). For reset it is
// the entire `before` list (reset removes everything, so the delta IS the whole
// list) — a consumer treating `changed` uniformly as a delta should expect
// `changed == before` on a reset.
type auditRecord struct {
	Audit    string   `json:"audit"`
	Action   string   `json:"action"`
	Operator string   `json:"operator"`
	License  string   `json:"license_key_sha256"`
	Before   []string `json:"before"`
	After    []string `json:"after"`
	Changed  []string `json:"changed"`
	TS       string   `json:"ts"`
}

// buildAuditRecord assembles the audit record (pure; ts injected) so its shape
// is unit-testable without capturing stderr.
func buildAuditRecord(action, operator, sha string, before, after, changed []string, ts string) auditRecord {
	return auditRecord{
		Audit:    "nhp-license-admin",
		Action:   action,
		Operator: operator,
		License:  sha,
		Before:   nonNil(before),
		After:    nonNil(after),
		Changed:  nonNil(changed),
		TS:       ts,
	}
}

// emitAudit writes the audit record to stderr and, if auditFile is non-empty,
// appends it there too for a durable record. The before/after attribute values
// live only in this record — they are NOT in CloudTrail (which, even with
// DynamoDB data-plane events enabled, captures the request, not the prior/next
// allowlist) — so a durable sink matters for a security-relevant change.
func emitAudit(auditFile, action, operator, sha string, before, after, changed []string) {
	rec := buildAuditRecord(action, operator, sha, before, after, changed, time.Now().UTC().Format(time.RFC3339))
	b, err := json.Marshal(rec)
	if err != nil {
		// Never silently drop the audit record — fall back to a readable form.
		writeAuditLine(auditFile, fmt.Sprintf("audit(json-marshal-failed) action=%s operator=%s license=%s before=%v after=%v changed=%v: %v",
			action, operator, sha, before, after, changed, err))
		return
	}
	writeAuditLine(auditFile, string(b))
}

// writeAuditLine emits one JSON audit line to stderr and, if auditFile is set,
// appends it there too. A file-append failure is surfaced as a warning on
// stderr so the operator sees the missing-durable-sink condition without
// losing the record itself.
func writeAuditLine(auditFile, line string) {
	fmt.Fprintln(os.Stderr, line)
	if auditFile == "" {
		return
	}
	if ferr := appendAuditLine(auditFile, line); ferr != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to append audit line to %s: %v (the line above on stderr is the only record)\n", auditFile, ferr)
	}
}

type acAuditRecord struct {
	Audit    string `json:"audit"`
	Action   string `json:"action"`
	Operator string `json:"operator"`
	ACID     string `json:"ac_id"`
	PubKey   string `json:"pubkey"`
	Changed  bool   `json:"changed"`
	Result   string `json:"result"`
	// Version is the observed assignment version; terminal failure records use 0.
	Version        int      `json:"version"`
	RevokedPubKeys []string `json:"revoked_pubkeys"`
	TS             string   `json:"ts"`
	Error          string   `json:"error,omitempty"`
}

func buildACAuditRecord(action, operator, acID, pubkey string, changed bool, version int, revokedPubKeys []string, ts string) acAuditRecord {
	return acAuditRecord{
		Audit:          "nhp-license-admin",
		Action:         action,
		Operator:       operator,
		ACID:           acID,
		PubKey:         pubkey,
		Changed:        changed,
		Result:         acAuditResult(changed),
		Version:        version,
		RevokedPubKeys: sortedNonNil(revokedPubKeys),
		TS:             ts,
	}
}

func acAuditResult(changed bool) string {
	if changed {
		return "mutated"
	}
	return "noop"
}

func buildACErrorAuditRecord(action, operator, acID, pubkey string, err error, ts string) acAuditRecord {
	rec := buildACAuditRecord(action, operator, acID, canonicalPubKeyForAudit(pubkey), false, 0, nil, ts)
	rec.Result = "error"
	if err != nil {
		rec.Error = err.Error()
	}
	return rec
}

func emitACAudit(auditFile, action, operator, acID, pubkey string, changed bool, version int, revokedPubKeys []string) {
	rec := buildACAuditRecord(action, operator, acID, pubkey, changed, version, revokedPubKeys, time.Now().UTC().Format(time.RFC3339))
	b, err := json.Marshal(rec)
	if err != nil {
		writeAuditLine(auditFile, fmt.Sprintf("audit(json-marshal-failed) action=%s operator=%s ac_id=%s pubkey=%s changed=%t version=%d revoked_pubkeys=%v: %v",
			action, operator, acID, pubkey, changed, version, revokedPubKeys, err))
		return
	}
	writeAuditLine(auditFile, string(b))
}

func emitACErrorAudit(auditFile, action, operator, acID, pubkey string, mutationErr error) {
	rec := buildACErrorAuditRecord(action, operator, acID, pubkey, mutationErr, time.Now().UTC().Format(time.RFC3339))
	b, err := json.Marshal(rec)
	if err != nil {
		writeAuditLine(auditFile, fmt.Sprintf("audit(json-marshal-failed) action=%s operator=%s ac_id=%s pubkey=%s error=%q: %v",
			action, operator, acID, pubkey, mutationErr, err))
		return
	}
	writeAuditLine(auditFile, string(b))
}

// appendAuditLine appends one line to path, creating it if needed. The write
// handle is writable, so both the write error and the Close error are
// propagated (a failed flush can surface only at Close) — the write error takes
// precedence; otherwise the Close error is returned. emitAudit prints a warning
// fallback on any non-nil return.
func appendAuditLine(path, line string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, werr := fmt.Fprintln(f, line)
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	return cerr
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func sortedNonNil(s []string) []string {
	out := slices.Clone(nonNil(s))
	slices.Sort(out)
	return out
}

func canonicalPubKeyForAudit(pubkey string) string {
	canon, err := licenseadmin.CanonicalizeBoundPubKey(pubkey)
	if err != nil {
		trimmed := strings.TrimSpace(pubkey)
		sum := sha256.Sum256([]byte(trimmed))
		return fmt.Sprintf("<invalid pubkey len=%d sha256=%x>", len(trimmed), sum[:8])
	}
	return canon
}

// gatherCanonicalPubkeys merges the repeatable --pubkey values with the
// --pubkeys-file lines, requires at least one, and canonicalizes every entry so
// a malformed key fails fast before any DynamoDB call. Duplicates (after
// canonicalization) are dropped, preserving first-seen order, so the bind
// "no change" count reflects distinct keys.
func gatherCanonicalPubkeys(inline []string, file string) ([]string, error) {
	keys := append([]string{}, inline...)
	if file != "" {
		extra, err := readPubkeysFile(file)
		if err != nil {
			return nil, err
		}
		keys = append(keys, extra...)
	}
	if len(keys) == 0 {
		return nil, errors.New("at least one --pubkey or --pubkeys-file is required")
	}
	canon := make([]string, 0, len(keys))
	seen := make(map[string]bool, len(keys))
	for _, k := range keys {
		c, err := licenseadmin.CanonicalizeBoundPubKey(k)
		if err != nil {
			return nil, err
		}
		if seen[c] {
			continue
		}
		seen[c] = true
		canon = append(canon, c)
	}
	return canon, nil
}

func readPubkeysFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read pubkeys file: %w", err)
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, nil
}
