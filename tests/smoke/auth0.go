//go:build smoke

package smoke

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

// Auth0 M2M token cost mitigation: rather than minting a fresh bearer
// on every `go test` invocation (~400 grants/month), we cache the token
// in an SSM SecureString with a TTL that expires before the Auth0 token
// does. Cache hit: one SSM GetParameter. Cache miss: one Auth0 grant +
// one SSM PutParameter.
//
// SSM schema:
//
//	/{env}/nhp/smoke/m2m-token-cache/access_token  SecureString (KMS)
//	/{env}/nhp/smoke/m2m-token-cache/expires_at    String, RFC3339
//
// Both parameters are scoped to a KMS key whose policy grants the smoke
// test IAM role kms:Decrypt/kms:Encrypt. See nhp/terraform/modules/ecr/main.tf.

// auth0CacheTTL: how long before token expiry we consider the cache
// stale and mint a fresh one. Auth0 tokens are 24h by default; we
// refresh 1h early so a test process that starts right at the
// boundary still has headroom.
const auth0CacheTTL = time.Hour

// getOrMintCachedAuth0Token looks up the SSM-cached Auth0 bearer. If the
// cache is empty or the cached token is within auth0CacheTTL of expiry,
// it mints a fresh token, writes it back to the cache (best-effort),
// and returns it. SSM write errors are logged but don't fail the caller
// — a failed cache write just means the next run will re-mint.
//
// Concurrency: two CI runs starting within seconds of each other can
// both miss the cache and both mint. That's fine — the second write
// clobbers the first, both runs use their own token, and the amortized
// grant count is still ~1/day per environment.
func getOrMintCachedAuth0Token(ctx context.Context, cfg *TestConfig) (string, error) {
	tok, exp, err := readTokenCache(ctx, cfg)
	if err == nil && time.Until(exp) > auth0CacheTTL {
		return tok, nil
	}

	fresh, lifetime, err := fetchAuth0Token(ctx, cfg)
	if err != nil {
		return "", fmt.Errorf("mint Auth0 token: %w", err)
	}

	// Best-effort cache write. A failure here just means the next run
	// re-mints. We intentionally do not surface the error to the caller.
	if writeErr := writeTokenCache(ctx, cfg, fresh, time.Now().Add(lifetime)); writeErr != nil {
		fmt.Printf("WARNING: Auth0 token cache write failed (non-fatal): %v\n", writeErr)
	}
	return fresh, nil
}

// readTokenCache fetches the cached token and its expiry. Returns an
// error if either parameter is missing or the expiry cannot be parsed.
func readTokenCache(ctx context.Context, cfg *TestConfig) (string, time.Time, error) {
	if cfg.SSMClient == nil {
		return "", time.Time{}, errors.New("ssm client not configured")
	}

	tokenParam := fmt.Sprintf("/%s/nhp/smoke/m2m-token-cache/access_token", cfg.Environment)
	expParam := fmt.Sprintf("/%s/nhp/smoke/m2m-token-cache/expires_at", cfg.Environment)

	tokenResp, err := cfg.SSMClient.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(tokenParam),
		WithDecryption: aws.Bool(true),
	})
	if err != nil {
		return "", time.Time{}, fmt.Errorf("read cached token: %w", err)
	}
	if tokenResp.Parameter == nil || tokenResp.Parameter.Value == nil {
		return "", time.Time{}, errors.New("cached token parameter is empty")
	}

	expResp, err := cfg.SSMClient.GetParameter(ctx, &ssm.GetParameterInput{
		Name: aws.String(expParam),
	})
	if err != nil {
		return "", time.Time{}, fmt.Errorf("read cached expiry: %w", err)
	}
	if expResp.Parameter == nil || expResp.Parameter.Value == nil {
		return "", time.Time{}, errors.New("cached expiry parameter is empty")
	}

	exp, err := time.Parse(time.RFC3339, *expResp.Parameter.Value)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("parse cached expiry %q: %w", *expResp.Parameter.Value, err)
	}
	return *tokenResp.Parameter.Value, exp, nil
}

// writeTokenCache writes a fresh token and its expiry to SSM. Errors
// here are non-fatal for callers — see getOrMintCachedAuth0Token.
func writeTokenCache(ctx context.Context, cfg *TestConfig, token string, expiresAt time.Time) error {
	if cfg.SSMClient == nil {
		return errors.New("ssm client not configured")
	}

	tokenParam := fmt.Sprintf("/%s/nhp/smoke/m2m-token-cache/access_token", cfg.Environment)
	expParam := fmt.Sprintf("/%s/nhp/smoke/m2m-token-cache/expires_at", cfg.Environment)

	if _, err := cfg.SSMClient.PutParameter(ctx, &ssm.PutParameterInput{
		Name:      aws.String(tokenParam),
		Value:     aws.String(token),
		Type:      ssmtypes.ParameterTypeSecureString,
		Overwrite: aws.Bool(true),
	}); err != nil {
		return fmt.Errorf("put token: %w", err)
	}

	if _, err := cfg.SSMClient.PutParameter(ctx, &ssm.PutParameterInput{
		Name:      aws.String(expParam),
		Value:     aws.String(expiresAt.UTC().Format(time.RFC3339)),
		Type:      ssmtypes.ParameterTypeString,
		Overwrite: aws.Bool(true),
	}); err != nil {
		return fmt.Errorf("put expiry: %w", err)
	}
	return nil
}

// fetchAuth0Token performs a client_credentials grant against Auth0 and
// returns the access token plus its declared lifetime. The lifetime is
// what Auth0 returns in `expires_in` (seconds). Callers subtract a
// safety margin before deciding the cache is still good.
func fetchAuth0Token(ctx context.Context, cfg *TestConfig) (string, time.Duration, error) {
	tokenURL := fmt.Sprintf("https://%s/oauth/token", cfg.Auth0Domain)
	payload := map[string]string{
		"client_id":     cfg.Auth0ClientID,
		"client_secret": cfg.Auth0ClientSecret,
		"audience":      cfg.Auth0Audience,
		"grant_type":    "client_credentials",
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", 0, fmt.Errorf("marshal request: %w", err)
	}

	reqCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, tokenURL, bytes.NewReader(body))
	if err != nil {
		return "", 0, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := cfg.HTTPClient.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("Auth0 status %d: %s", resp.StatusCode, string(respBody))
	}

	var parsed struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return "", 0, fmt.Errorf("parse token response: %w", err)
	}
	if parsed.AccessToken == "" {
		return "", 0, errors.New("empty access token in Auth0 response")
	}

	lifetime := time.Duration(parsed.ExpiresIn) * time.Second
	if lifetime <= 0 {
		// Defensive default: if Auth0 didn't declare a lifetime, assume
		// 24h which is the tenant default. Cache TTL margin will still
		// trigger a refresh in ~23h.
		lifetime = 24 * time.Hour
	}
	return parsed.AccessToken, lifetime, nil
}
