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
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// qurl_client.go is a thin, hand-rolled client for qurl-service's public
// API. It exists so Tier 2 resolve tests can mint a real QURL and
// exercise the production code path, without the smoke suite having to
// import the qurl-service Go module (which would couple NHP's test
// build graph to qurl's).
//
// This file ships in PR1 so the harness is complete; PR2 adds the
// resolve/knock tests that actually call MintQURL and DeleteQURL.

// MintOptions describes the QURL to create. Every smoke-minted QURL is
// labeled "smoke-<test>-<unix-ts>" and given a short TTL so a
// cleanup-on-cleanup failure is bounded.
//
// ExpiresIn is a Go-style duration string ("60s", "5m", "1h") as
// required by the qurl-service API. Defaults to "60s".
type MintOptions struct {
	Label     string // prefixed with "smoke-" by MintQURL
	TargetURL string // where the QURL points once resolved
	ExpiresIn string // duration string, e.g. "60s"; defaults to "60s"
}

// mintResourceNonce makes every smoke mint resolve to a DISTINCT
// qurl-service resource. See uniqueSmokeTarget for the why.
var mintResourceNonce atomic.Uint64

// uniqueSmokeTarget appends a unique query nonce to a smoke target URL so
// each mint creates its OWN qurl-service resource.
//
// qurl-service dedupes resources by (owner_id, NormalizeTargetURL(target)),
// and NormalizeTargetURL keeps the query string (it only lowercases
// scheme/host, drops the fragment, and trims a trailing slash). Without a
// per-mint nonce, every "https://example.com" QURL minted under the single
// smoke M2M owner collapses onto ONE resource that shares ONE per-resource
// max_sessions counter. The first resolve takes the lone session slot; every
// later token (a different token hash, so session reuse can't match) then
// trips max_sessions_reached, which the NHP qurl plugin renders as a 403
// "Access Link Invalid" — failing the resolve smoke tests in a way that
// worsens as the suite runs. A unique resource per mint restores test
// isolation and mirrors real usage (distinct customers/targets => distinct
// resources, no shared cap).
//
// The nonce is a no-op for the resolved content: example.com returns the
// same 200 "Example Domain" body regardless of query string. It MUST be a
// query param, not a path — example.com 404s on an unknown path, which would
// break the follow-redirect body assertion.
//
// UnixNano + a process-wide counter keeps it unique even for mints issued
// within the same nanosecond (retry loops, parallel subtests). A malformed
// or scheme-less target is returned untouched — such a target isn't
// exercising the dedupe-prone resolve path.
func uniqueSmokeTarget(rawTarget string) string {
	u, err := url.Parse(rawTarget)
	if err != nil || u.Scheme == "" {
		return rawTarget
	}
	q := u.Query()
	q.Set("nhp_smoke_nonce", fmt.Sprintf("%d-%d", time.Now().UnixNano(), mintResourceNonce.Add(1)))
	u.RawQuery = q.Encode()
	return u.String()
}

// QURLResponse holds the fields we care about from the QURL create
// response. Extra fields (meta.request_id, qurl_id, qurl_site,
// etc.) are ignored by the JSON decoder.
//
// qurl-service wraps responses in { "data": { ... } }, so the
// top-level Data field captures the nested shape. Verified 2026-04-09
// against sandbox.
type QURLResponse struct {
	Data struct {
		ResourceID string `json:"resource_id"`
		QURLLink   string `json:"qurl_link"` // e.g. https://qurl.link.layerv.xyz/#at_xxx
		ExpiresAt  string `json:"expires_at"`
	} `json:"data"`
}

// AccessToken extracts the "at_..." access token from the fragment
// of QURLLink. Returns empty string if the link has no fragment.
// The access token is what gets passed to /plugins/qurl?token=...
func (r *QURLResponse) AccessToken() string {
	link := r.Data.QURLLink
	if i := strings.Index(link, "#"); i >= 0 {
		return link[i+1:]
	}
	return ""
}

// MintQURL calls POST /v1/qurls on qurl-service with the cached Auth0
// bearer. Every smoke-minted QURL has label prefix "smoke-" so the
// orphan-sweep workflow (filed separately) can identify and delete
// them.
//
// Callers MUST register a t.Cleanup to DeleteQURL on the returned ID.
// The short TTL (60s default) is a fallback, not the primary cleanup
// path.
func MintQURL(ctx context.Context, t *testing.T, opts MintOptions) (*QURLResponse, error) {
	t.Helper()
	token := requireAuth0(t)

	if opts.ExpiresIn == "" {
		opts.ExpiresIn = "60s"
	}
	label := opts.Label
	if label == "" {
		label = t.Name()
	}
	body := map[string]interface{}{
		"description":  "smoke-" + label + "-" + fmt.Sprintf("%d", time.Now().Unix()),
		"target_url":   uniqueSmokeTarget(opts.TargetURL),
		"expires_in":   opts.ExpiresIn,
		"max_sessions": 1,
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal mint request: %w", err)
	}

	reqCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost,
		testConfig.QURLAPIBaseURL+"/v1/qurls", bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("build mint request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := testConfig.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("mint request: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("mint QURL status %d: %s", resp.StatusCode, truncate(respBody, 256))
	}

	var parsed QURLResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, fmt.Errorf("parse mint response: %w", err)
	}
	if parsed.Data.ResourceID == "" {
		return nil, errors.New("mint response missing data.resource_id")
	}
	return &parsed, nil
}

// DeleteQURL removes a minted QURL by resource_id. Safe to call on a
// missing ID (404 is swallowed). Intended for use from t.Cleanup.
func DeleteQURL(ctx context.Context, t *testing.T, resourceID string) {
	t.Helper()
	if resourceID == "" || testConfig.CachedAuth0Token == "" {
		return
	}

	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodDelete,
		testConfig.QURLAPIBaseURL+"/v1/qurls/"+resourceID, nil)
	if err != nil {
		t.Logf("cleanup: build DELETE for %s: %v", resourceID, err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+testConfig.CachedAuth0Token)

	resp, err := testConfig.HTTPClient.Do(req)
	if err != nil {
		t.Logf("cleanup: DELETE %s: %v", resourceID, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		t.Logf("cleanup: DELETE %s status=%d body=%s", resourceID, resp.StatusCode, truncate(body, 200))
	}
}
