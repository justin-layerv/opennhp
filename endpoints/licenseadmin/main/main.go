// Command nhp-license-admin provisions the License.BoundPubKeys allowlist that
// the server-side license_pubkey_gate (#1155) enforces.
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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/urfave/cli/v2"

	"github.com/OpenNHP/opennhp/endpoints/licenseadmin"
	"github.com/OpenNHP/opennhp/nhp/version"
)

func main() {
	app := &cli.App{
		Name:    "nhp-license-admin",
		Usage:   "provision License.BoundPubKeys allowlists for the #1155 license_pubkey_gate",
		Version: version.Version,
		Description: strings.TrimSpace(`
Binds AC static public keys to NHP license records so the server-side
license_pubkey_gate (#1155) can be flipped from permit to strict.

Writes the bound_pubkeys allowlist on the nhp-licenses DynamoDB table. Every
pubkey is validated as padded standard base64 (RFC 4648 §4) of a 32-byte
curve25519 key and stored in canonical form, so a provisioned key can never
silently mismatch a legitimate AC registration (which would look exactly like
a #1155 attack).

Run with AWS credentials for a role holding dynamodb:GetItem + dynamodb:UpdateItem
on the licenses table. Flags go AFTER the subcommand (e.g. "bind --operator x
--license-sha256 ..."). The before/after audit record is the JSON line on stderr
(and --audit-file, if set) — capture it: CloudTrail does NOT carry the before/after
allowlist values, and DynamoDB data-plane events (the IAM-principal who/when) are
off by default on the table. --operator is a self-asserted, advisory label.

Strict-flip runbook: docs/runbooks/license-pubkey-strict-flip.md`),
		Commands: []*cli.Command{
			showCommand(),
			bindCommand(),
			unbindCommand(),
			resetCommand(),
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
	return []cli.Flag{
		&cli.StringFlag{Name: "region", Value: "us-east-2", EnvVars: []string{"AWS_REGION"}, Usage: "AWS region of the licenses table"},
		&cli.StringFlag{Name: "licenses-table", Value: "nhp-licenses", Usage: "DynamoDB licenses table name"},
		&cli.StringFlag{Name: "endpoint", Usage: "custom DynamoDB endpoint (local development only)"},
	}
}

func operatorFlag() cli.Flag {
	return &cli.StringFlag{Name: "operator", EnvVars: []string{"NHP_LICENSE_ADMIN_OPERATOR"}, Usage: "identity of the admin running the command (recorded in the audit log)"}
}

func auditFileFlag() cli.Flag {
	return &cli.StringFlag{Name: "audit-file", EnvVars: []string{"NHP_LICENSE_ADMIN_AUDIT_FILE"}, Usage: "append the JSON audit line to this file for a durable record (stderr always gets it too)"}
}

// commandFlags composes the selector + connection flags shared by every command
// with any command-specific extras.
func commandFlags(extra ...cli.Flag) []cli.Flag {
	flags := append(selectorFlags(), connectionFlags()...)
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
	if endpoint != "" {
		// Make a local-dev override loud — a mis-set endpoint silently points
		// writes at the wrong DynamoDB.
		fmt.Fprintf(os.Stderr, "warning: using custom DynamoDB endpoint %q (local-development override)\n", endpoint)
	}
	return licenseadmin.NewClient(c.Context, licenseadmin.Config{
		Region:        c.String("region"),
		LicensesTable: c.String("licenses-table"),
		Endpoint:      endpoint,
	})
}

func requireOperator(c *cli.Context) (string, error) {
	op := strings.TrimSpace(c.String("operator"))
	if op == "" {
		return "", errors.New("--operator is required for mutations (set --operator or NHP_LICENSE_ADMIN_OPERATOR)")
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
		fmt.Fprintln(os.Stderr, "warning: no --audit-file set; the before/after audit record will go only to stderr — capture stderr, or set --audit-file / NHP_LICENSE_ADMIN_AUDIT_FILE for a durable record")
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
				return cli.Exit(fmt.Errorf("interrupted during retry backoff: %w", ctx.Err()), 1)
			case <-time.After(time.Duration(attempt) * 50 * time.Millisecond):
			}
		}
	}
	return cli.Exit(fmt.Errorf("aborted after %d retries due to concurrent modification: %w", maxAttempts, lastErr), 1)
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

// runBind / runUnbind / runReset are the command cores: one read-modify-write
// pass each, returning raw errors so withRetry can classify conflicts. They take
// a licenseStore + io.Writer so the no-op and guard branches are unit-testable.

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
		fmt.Fprintf(os.Stderr, "audit(json-marshal-failed) action=%s operator=%s license=%s before=%v after=%v changed=%v: %v\n",
			action, operator, sha, before, after, changed, err)
		return
	}
	fmt.Fprintln(os.Stderr, string(b))
	if auditFile != "" {
		if ferr := appendAuditLine(auditFile, string(b)); ferr != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to append audit line to %s: %v (the line above on stderr is the only record)\n", auditFile, ferr)
		}
	}
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
