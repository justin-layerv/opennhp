// Package licenseadmin provisions the License.BoundPubKeys allowlist that the
// server-side license_pubkey_gate (#1155) enforces.
//
// The console repo that historically wrote nhp-licenses rows was archived, so
// the BoundPubKeys provisioning workflow (#1262) now lives in this repo. This
// package is deliberately decoupled from package server: importing server
// drags in the KBS / confidential-containers init side-effects (an init() that
// generates cosign keys under /opt/confidential-containers), which have no
// business running inside a license-provisioning CLI. It therefore carries its
// own minimal License mirror and DynamoDB client.
//
// The License struct here MUST keep its dynamodbav tags in lockstep with
// server.License — enforced by TestLicenseAdminSchemaParity in package server.
//
// Strict-flip runbook + key-rotation workflow:
// docs/runbooks/license-pubkey-strict-flip.md
package licenseadmin

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// BoundPubKeyRawLen is the byte length of a curve25519 static public key.
// base64.StdEncoding of 32 bytes is the form the gate compares against.
const BoundPubKeyRawLen = 32

// operationTimeout bounds a single DynamoDB call.
const operationTimeout = 5 * time.Second

// Sentinel errors returned by the DynamoDB methods so the CLI can branch
// without depending on package server's StorageError type.
var (
	// ErrLicenseNotFound means no nhp-licenses row exists for the key.
	ErrLicenseNotFound = errors.New("license not found")
	// ErrConcurrentModification means the optimistic-lock condition failed:
	// another writer changed the license (or it was deleted) between our read
	// and write. Callers re-read and retry.
	ErrConcurrentModification = errors.New("license changed concurrently")
)

// License mirrors the subset of the nhp-licenses item this tool reads and
// writes. The dynamodbav tags MUST match server.License — a divergence would
// silently corrupt or miss the security-critical bound_pubkeys allowlist the
// gate reads. Parity is enforced by TestLicenseAdminSchemaParity in package
// server.
type License struct {
	// Load-bearing for the write path: the partition key, the optimistic-lock
	// token, and the allowlist the gate enforces.
	LicenseKeySHA256 string   `dynamodbav:"license_key_sha256"`
	UpdatedAt        int64    `dynamodbav:"updated_at"`
	BoundPubKeys     []string `dynamodbav:"bound_pubkeys,omitempty"`
	// Display-only: surfaced by `show`, never used for the gate or the write
	// path. They widen the parity test (a server-side rename of these trips it
	// too), which is acceptable — it keeps `show` honest.
	CustomerID string `dynamodbav:"customer_id"`
	Tier       string `dynamodbav:"tier"`
	Active     bool   `dynamodbav:"active"`
}

// CanonicalizeBoundPubKey validates raw as the canonical encoding the
// license_pubkey_gate requires and returns the canonical string to store in
// License.BoundPubKeys.
//
// The gate (verifyLicensePubkey) compares allowlist entries against
// base64.StdEncoding.EncodeToString(ppd.RemotePubKey) with exact string
// equality (after a symmetric TrimSpace). Anything that isn't padded standard
// base64 (RFC 4648 §4) of exactly 32 bytes would be silently un-matchable at
// registration time and surface as ErrLicensePubkeyMismatch —
// indistinguishable from a #1155 attack. So every non-canonical form is
// rejected HERE, at write time:
//
//   - URL-safe base64 (RFC 4648 §5, alphabet with - _)
//   - unpadded base64 (missing trailing =)
//   - non-canonical trailing bits (rejected by .Strict())
//   - any length other than 32 decoded bytes
//   - leading/trailing whitespace
//
// The returned value is the re-encoded canonical form, so even a
// decodable-but-noncanonical input cannot be persisted in a shape the gate
// would miss.
func CanonicalizeBoundPubKey(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", errors.New("empty pubkey")
	}
	// Explicit URL-safe check first: StdEncoding would also reject - and _,
	// but with a cryptic "illegal base64 data" message. Operators copy-pasting
	// a key from a tool that emits URL-safe base64 deserve a clear error.
	if strings.ContainsAny(s, "-_") {
		return "", fmt.Errorf("pubkey %q uses URL-safe base64 (RFC 4648 §5); padded standard base64 (alphabet A-Z a-z 0-9 + /) is required", s)
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil {
		return "", fmt.Errorf("pubkey %q is not valid padded standard base64 (RFC 4648 §4): %w", s, err)
	}
	if len(decoded) != BoundPubKeyRawLen {
		return "", fmt.Errorf("pubkey %q decodes to %d bytes, want %d (curve25519 static public key)", s, len(decoded), BoundPubKeyRawLen)
	}
	// Reject the all-zero key: it decodes cleanly but no legitimate AC presents
	// an all-zero static pubkey. This is input hygiene, NOT low-order-point
	// validation — BoundPubKeys is a string-equality allowlist, not a DH input,
	// so a bad key simply wouldn't match a real registration anyway. Rejecting
	// the one obvious junk value keeps the allowlist clean.
	allZero := true
	for _, b := range decoded {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return "", fmt.Errorf("pubkey %q is the all-zero curve25519 point, not a valid AC static key", s)
	}
	return base64.StdEncoding.EncodeToString(decoded), nil
}

// canonicalKey returns the comparison key for an allowlist entry. A canonical
// entry compares by its canonical form; a legacy entry that does NOT
// canonicalize (e.g. an externally-written URL-safe/unpadded encoding) falls
// back to a trimmed literal so an append/remove doesn't blow up. Consequence:
// binding the canonical form of a key that currently exists only in a
// non-canonical encoding appends a second (canonical) entry rather than
// de-duping against the legacy one. Harmless — the canonical entry is what the
// gate matches and the legacy one is dead weight — and this tool never writes
// non-canonical entries, so it can only arise from legacy/external data. (To
// clean up such a stray entry, reset + re-bind; see the runbook.)
func canonicalKey(entry string) string {
	if c, err := CanonicalizeBoundPubKey(entry); err == nil {
		return c
	}
	return strings.TrimSpace(entry)
}

// AppendBoundPubKeys canonicalizes each addition, appends any not already
// present (compared by canonical form), and returns the new allowlist plus the
// subset actually added (canonical). Existing entries are preserved verbatim. A
// non-canonical addition is a hard error — the whole append is rejected so a
// bad paste can never reach the table.
func AppendBoundPubKeys(existing, additions []string) (result, added []string, err error) {
	result = append(result, existing...)
	seen := make(map[string]bool, len(existing))
	for _, e := range existing {
		seen[canonicalKey(e)] = true
	}
	for _, a := range additions {
		c, cerr := CanonicalizeBoundPubKey(a)
		if cerr != nil {
			return nil, nil, cerr
		}
		if seen[c] {
			continue
		}
		seen[c] = true
		result = append(result, c)
		added = append(added, c)
	}
	return result, added, nil
}

// RemoveBoundPubKey canonicalizes target and returns existing with every entry
// whose canonical form equals target removed, plus whether any were removed.
func RemoveBoundPubKey(existing []string, target string) (result []string, removed bool, err error) {
	c, err := CanonicalizeBoundPubKey(target)
	if err != nil {
		return nil, false, err
	}
	for _, e := range existing {
		if canonicalKey(e) == c {
			removed = true
			continue
		}
		result = append(result, e)
	}
	return result, removed, nil
}

// LicenseKeySHA256 returns the hex-encoded SHA256 of a plaintext license key —
// the partition key of the nhp-licenses table. The plaintext key is shown only
// once at issuance, so operators typically work with this partition key
// directly.
func LicenseKeySHA256(licenseKey string) string {
	h := sha256.Sum256([]byte(licenseKey))
	return hex.EncodeToString(h[:])
}

// Config configures the DynamoDB License client.
type Config struct {
	Region        string
	LicensesTable string
	Endpoint      string // optional: custom endpoint for local development
}

// Client is a minimal DynamoDB accessor for the nhp-licenses table, scoped to
// what license provisioning needs (read a license, overwrite its allowlist).
type Client struct {
	ddb   *dynamodb.Client
	table string
}

// NewClient builds a DynamoDB License client. It does NOT ping — the admin
// command surfaces credential/connectivity errors on the first real call.
func NewClient(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.LicensesTable == "" {
		return nil, errors.New("licenses table name is required")
	}
	opts := []func(*config.LoadOptions) error{
		config.WithRegion(cfg.Region),
	}
	if cfg.Endpoint != "" {
		resolver := aws.EndpointResolverWithOptionsFunc(
			func(service, region string, options ...any) (aws.Endpoint, error) {
				return aws.Endpoint{URL: cfg.Endpoint, SigningRegion: cfg.Region}, nil
			},
		)
		opts = append(opts, config.WithEndpointResolverWithOptions(resolver))
	}
	awsCfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}
	return &Client{ddb: dynamodb.NewFromConfig(awsCfg), table: cfg.LicensesTable}, nil
}

// GetLicense retrieves a license by its partition key (hex SHA256). Returns
// ErrLicenseNotFound if absent.
func (c *Client) GetLicense(ctx context.Context, licenseKeySHA256 string) (*License, error) {
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()

	out, err := c.ddb.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(c.table),
		Key: map[string]types.AttributeValue{
			"license_key_sha256": &types.AttributeValueMemberS{Value: licenseKeySHA256},
		},
		// Strongly consistent: a provisioning tool wants read-your-writes, and
		// inside withRetry it avoids an eventually-consistent stale read causing
		// a needless optimistic-lock conflict + retry.
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return nil, fmt.Errorf("dynamodb GetItem: %w", err)
	}
	if out.Item == nil {
		return nil, fmt.Errorf("%w: %s", ErrLicenseNotFound, licenseKeySHA256)
	}
	var lic License
	if err := attributevalue.UnmarshalMap(out.Item, &lic); err != nil {
		return nil, fmt.Errorf("unmarshal license %s: %w", licenseKeySHA256, err)
	}
	return &lic, nil
}

// UpdateBoundPubKeys overwrites the bound_pubkeys allowlist for an existing
// license. boundPubKeys MUST already be canonical (build it via
// AppendBoundPubKeys / RemoveBoundPubKey). An empty list REMOVEs the attribute
// so the row matches the omitempty zero value the gate reads as
// verdictLicenseUnbound.
//
// Two guards:
//
//   - attribute_exists(license_key_sha256): never CREATE a license via this
//     path. A typo'd partition key fails loudly instead of minting a
//     half-populated row.
//   - updated_at = :expected: optimistic lock. On conflict it returns
//     ErrConcurrentModification and the caller re-reads and retries.
//
// Both guard failures (absent row, stale lock) surface as the SAME
// ErrConcurrentModification. Callers MUST GetLicense first (as the CLI does):
// that makes a genuinely-absent license return ErrLicenseNotFound and abort
// immediately, instead of burning the full retry budget on a misleading
// "concurrent modification". A future refactor must preserve that read-first
// ordering. Only a true delete-between-read-and-write TOCTOU reaches the
// conflated path, where retry-then-give-up is the correct behavior.
//
// Returns the new updated_at it wrote.
func (c *Client) UpdateBoundPubKeys(ctx context.Context, licenseKeySHA256 string, boundPubKeys []string, expectedUpdatedAt int64) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()

	now := nextVersion(time.Now().Unix(), expectedUpdatedAt)
	in, err := buildBoundPubKeysUpdate(c.table, licenseKeySHA256, boundPubKeys, expectedUpdatedAt, now)
	if err != nil {
		return 0, err
	}

	if _, err := c.ddb.UpdateItem(ctx, in); err != nil {
		var ccf *types.ConditionalCheckFailedException
		if errors.As(err, &ccf) {
			return 0, fmt.Errorf("%w: %s (expected updated_at %d, or license absent)", ErrConcurrentModification, licenseKeySHA256, expectedUpdatedAt)
		}
		return 0, fmt.Errorf("dynamodb UpdateItem: %w", err)
	}
	return now, nil
}

// nextVersion returns the updated_at version token to write given the wall-clock
// now and the value the caller read (expected). updated_at doubles as the
// optimistic-lock version, so the new token MUST differ from expected — a token
// that can equal its own predecessor is not a sound lock. Because Unix() has
// one-second granularity, two writers reading the same second would otherwise
// both write that same second value, and the second writer's `updated_at =
// :expected` condition would still match and silently clobber the first. Bumping
// to expected+1 whenever now <= expected makes every successful write strictly
// monotonic, so a concurrent same-second writer's condition fails and it
// retries. Under sustained same-license contention the token climbs by one per
// conflicting write, so it can in principle drift arbitrarily ahead of
// wall-clock — irrelevant at license-provisioning cadence, where same-row
// contention is rare and updated_at is only a lock token here, not a clock.
//
// Note this bumps updated_at on every successful write, so the field reflects
// "last write of any kind" rather than specifically a license-field change.
// Nothing reads updated_at semantically today (the server only reads the
// license for validation); a future consumer that wants a true "last changed"
// timestamp should not assume this field carries it.
func nextVersion(now, expected int64) int64 {
	if now <= expected {
		return expected + 1
	}
	return now
}

// buildBoundPubKeysUpdate constructs the UpdateItem that overwrites a license's
// allowlist. It is pure (now is injected) so the condition/update expressions
// and attribute values — the fiddliest, most regression-prone part of the write
// path — can be asserted in a unit test without a live table. An empty
// boundPubKeys REMOVEs the attribute so the row matches the omitempty zero value
// the gate reads as verdictLicenseUnbound, rather than leaving an empty list.
//
// Optimistic lock: the condition pins updated_at to the value the caller read,
// so a concurrent admin mutation is caught and retried. There is one subtlety —
// a legacy / externally-minted row may have NO updated_at attribute at all,
// which UnmarshalMap reads back as expectedUpdatedAt == 0. DynamoDB treats an
// absent attribute as != 0, so a plain `updated_at = 0` check would never match
// and the caller would loop its retries and abort with a misleading
// "concurrent modification". For the zero case we therefore also accept
// attribute_not_exists(updated_at). This stays correct as a lock: the very
// first successful write sets a non-zero updated_at, so a racing second writer
// fails both `attribute_not_exists(updated_at)` and `updated_at = 0`, gets a
// conflict, re-reads the now-present value, and retries. (Server-written rows
// always carry updated_at — server.License.UpdatedAt is not omitempty — so this
// only relaxes provisioning of legacy rows.)
func buildBoundPubKeysUpdate(table, licenseKeySHA256 string, boundPubKeys []string, expectedUpdatedAt, now int64) (*dynamodb.UpdateItemInput, error) {
	condition := "attribute_exists(license_key_sha256) AND updated_at = :expected"
	if expectedUpdatedAt == 0 {
		condition = "attribute_exists(license_key_sha256) AND (attribute_not_exists(updated_at) OR updated_at = :expected)"
	}
	in := &dynamodb.UpdateItemInput{
		TableName: aws.String(table),
		Key: map[string]types.AttributeValue{
			"license_key_sha256": &types.AttributeValueMemberS{Value: licenseKeySHA256},
		},
		ConditionExpression: aws.String(condition),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":expected": &types.AttributeValueMemberN{Value: strconv.FormatInt(expectedUpdatedAt, 10)},
			":now":      &types.AttributeValueMemberN{Value: strconv.FormatInt(now, 10)},
		},
	}
	if len(boundPubKeys) == 0 {
		in.UpdateExpression = aws.String("SET updated_at = :now REMOVE bound_pubkeys")
		return in, nil
	}
	av, err := attributevalue.Marshal(boundPubKeys)
	if err != nil {
		return nil, fmt.Errorf("marshal bound_pubkeys: %w", err)
	}
	in.UpdateExpression = aws.String("SET bound_pubkeys = :bpk, updated_at = :now")
	in.ExpressionAttributeValues[":bpk"] = av
	return in, nil
}
