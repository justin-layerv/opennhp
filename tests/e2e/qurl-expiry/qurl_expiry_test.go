//go:build e2e

package qurlexpiry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

var (
	eventQurlExpired   = expiryContract.Events.QurlExpired
	eventResourceClose = expiryContract.Events.ResourceClosed
	schemaMismatchHint = "possible qurl-service/qurl-api storage contract mismatch; see " + expiryContract.Issue
)

type expiryConfig struct {
	httpClient *http.Client
	ddb        *dynamodb.Client
	lambda     *lambda.Client
	sqs        *sqs.Client
	cw         *cloudwatch.Client
	sm         *secretsmanager.Client

	apiBaseURL         string
	accessToken        string
	auth0SecretID      string
	auth0TokenURL      string
	accessTokensTable  string
	resourcesTable     string
	sessionsTable      string
	webhookDedupeTable string
	scannerFunction    string
	queueName          string
	dlqName            string
	queueURL           string
	dlqURL             string
	ttl                string
	massTTL            string
	sessionDuration    string
	targetURLBase      string
	runID              string
	massCount          int
	testTimeout        time.Duration
	waitTimeout        time.Duration
	pollInterval       time.Duration
	requestSpacing     time.Duration
	apiRetryTimeout    time.Duration
	deferHold          time.Duration
	testStartedAt      time.Time
	invokeScanner      bool
	requireDLQEmpty    bool
	requireQueueEmpty  bool
	skipScannerErrors  bool
}

type qurlData struct {
	QURLID     string    `json:"qurl_id"`
	QURLLink   string    `json:"qurl_link"`
	QURLSite   string    `json:"qurl_site"`
	ResourceID string    `json:"resource_id"`
	ExpiresAt  time.Time `json:"expires_at"`
	Type       string    `json:"type"`
}

type createQURLResponse struct {
	Data  qurlData    `json:"data"`
	Error *apiError   `json:"error,omitempty"`
	Meta  interface{} `json:"meta,omitempty"`
}

type batchCreateResponse struct {
	Data struct {
		Succeeded int               `json:"succeeded"`
		Failed    int               `json:"failed"`
		Results   []batchItemResult `json:"results"`
	} `json:"data"`
	Error *apiError   `json:"error,omitempty"`
	Meta  interface{} `json:"meta,omitempty"`
}

type batchItemResult struct {
	Index      int       `json:"index"`
	Success    bool      `json:"success"`
	ResourceID string    `json:"resource_id"`
	QURLLink   string    `json:"qurl_link"`
	QURLSite   string    `json:"qurl_site"`
	ExpiresAt  time.Time `json:"expires_at"`
	Error      *apiError `json:"error,omitempty"`
}

type apiError struct {
	Code    string      `json:"code"`
	Message string      `json:"message"`
	Detail  interface{} `json:"detail,omitempty"`
}

type auth0Secret struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Audience     string `json:"audience"`
}

func TestQurlExpiry_TransitResourceClosesAndRemintReturns410(t *testing.T) {
	cfg := loadExpiryConfig(t)

	ctx, cancel := cfg.testContext()
	defer cancel()

	qurl := cfg.createTransitQURL(ctx, t, "base", false, "1m", cfg.ttl)
	cfg.driveExpiryBucket(ctx, t, qurl.ExpiresAt)

	cfg.waitForDedupeMarker(ctx, t, eventQurlExpired, qurl.QURLID)
	cfg.waitForDedupeMarker(ctx, t, eventResourceClose, qurl.ResourceID)
	cfg.waitForResourceTombstone(ctx, t, qurl.ResourceID)
	cfg.expectRemintGone(ctx, t, qurl.ResourceID)
	cfg.assertPostRunHealth(ctx, t)
}

func TestQurlExpiry_MassFanoutSameMinute(t *testing.T) {
	cfg := loadExpiryConfig(t)

	ctx, cancel := cfg.testContext()
	defer cancel()

	qurls := cfg.batchCreateTransitQURLs(ctx, t, "mass", cfg.massCount, cfg.massTTL)
	first := qurls[0]
	expiryBucket := first.ExpiresAt.UTC().Unix() / 60
	// The batch endpoint stamps a single server-side expiry for the request.
	// Keep the mass proof in one scanner bucket so it tests fan-out, not timing.
	for _, qurl := range qurls[1:] {
		if got := qurl.ExpiresAt.UTC().Unix() / 60; got != expiryBucket {
			t.Fatalf("mass qURL %s expires in bucket %d, want shared bucket %d", qurl.QURLID, got, expiryBucket)
		}
	}

	cfg.driveExpiryBucket(ctx, t, first.ExpiresAt)

	qurlIDs := make([]string, 0, len(qurls))
	resourceIDs := make([]string, 0, len(qurls))
	for _, qurl := range qurls {
		qurlIDs = append(qurlIDs, qurl.QURLID)
		resourceIDs = append(resourceIDs, qurl.ResourceID)
	}
	cfg.waitForAllDedupeMarkers(ctx, t, eventQurlExpired, qurlIDs, first.ExpiresAt)
	cfg.waitForAllDedupeMarkers(ctx, t, eventResourceClose, resourceIDs, first.ExpiresAt)
	for _, resourceID := range resourceIDs {
		cfg.waitForResourceTombstone(ctx, t, resourceID)
	}
	cfg.expectRemintGone(ctx, t, first.ResourceID)
	cfg.assertPostRunHealth(ctx, t)
}

func TestQurlExpiry_ActiveSessionDefersResourceClosed(t *testing.T) {
	cfg := loadExpiryConfig(t)

	ctx, cancel := cfg.testContext()
	defer cancel()

	qurl := cfg.createTransitQURL(ctx, t, "active-session", false, cfg.sessionDuration, cfg.ttl)
	accessToken := extractAccessToken(t, qurl.QURLLink)
	cfg.resolveAccessToken(ctx, t, accessToken)
	cfg.waitForActiveSession(ctx, t, qurl.ResourceID)

	cfg.driveExpiryBucket(ctx, t, qurl.ExpiresAt)
	cfg.waitForDedupeMarker(ctx, t, eventQurlExpired, qurl.QURLID)
	cfg.assertActiveSessionDefersResourceClose(ctx, t, qurl.ResourceID)

	cfg.waitForSessionDuration(ctx, t)
	// Replaying the same bucket is part of the scanner contract: the first pass
	// emits qurl.expired, and resource.closed is deferred until sessions drain.
	cfg.invokeScannerBucket(ctx, t, qurl.ExpiresAt)
	cfg.waitForDedupeMarker(ctx, t, eventResourceClose, qurl.ResourceID)
	cfg.waitForResourceTombstone(ctx, t, qurl.ResourceID)
	cfg.expectRemintGone(ctx, t, qurl.ResourceID)
	cfg.assertPostRunHealth(ctx, t)
}

func TestQurlExpiry_SelfDestructOneTimeUseClosesAfterBurn(t *testing.T) {
	cfg := loadExpiryConfig(t)

	ctx, cancel := cfg.testContext()
	defer cancel()

	qurl := cfg.createTransitQURL(ctx, t, "self-destruct", true, "1s", cfg.ttl)
	accessToken := extractAccessToken(t, qurl.QURLLink)
	cfg.resolveAccessToken(ctx, t, accessToken)

	cfg.driveExpiryBucket(ctx, t, qurl.ExpiresAt)
	cfg.waitForDedupeMarker(ctx, t, eventQurlExpired, qurl.QURLID)
	cfg.waitForDedupeMarker(ctx, t, eventResourceClose, qurl.ResourceID)
	cfg.waitForResourceTombstone(ctx, t, qurl.ResourceID)
	cfg.expectRemintGone(ctx, t, qurl.ResourceID)
	cfg.assertPostRunHealth(ctx, t)
}

func loadExpiryConfig(t *testing.T) *expiryConfig {
	t.Helper()

	if !envBool(t, "QURL_EXPIRY_E2E", false) {
		t.Skip("set QURL_EXPIRY_E2E=1 to run the live qurl-expiry cross-service harness")
	}

	region := envString("AWS_REGION", envString("AWS_DEFAULT_REGION", "us-east-2"))
	setupTimeout := durationEnv(t, "QURL_EXPIRY_E2E_SETUP_TIMEOUT", 60*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), setupTimeout)
	defer cancel()

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		t.Fatalf("load AWS config: %v", err)
	}

	namePrefix := envString("QURL_EXPIRY_E2E_NAME_PREFIX", "layerv-nhp-sandbox")
	cellID := envString("QURL_EXPIRY_E2E_CELL_ID", "cell0")
	tablePrefix := envString("QURL_EXPIRY_E2E_TABLE_PREFIX", namePrefix+"-"+cellID)
	queueName := envString("QURL_EXPIRY_E2E_QUEUE_NAME", tablePrefix+"-qurl-resource-lifecycle")
	dlqName := envString("QURL_EXPIRY_E2E_DLQ_NAME", queueName+"-dlq")

	cfg := &expiryConfig{
		httpClient:         &http.Client{Timeout: durationEnv(t, "QURL_EXPIRY_E2E_HTTP_TIMEOUT", 30*time.Second)},
		ddb:                dynamodb.NewFromConfig(awsCfg),
		lambda:             lambda.NewFromConfig(awsCfg),
		sqs:                sqs.NewFromConfig(awsCfg),
		cw:                 cloudwatch.NewFromConfig(awsCfg),
		sm:                 secretsmanager.NewFromConfig(awsCfg),
		apiBaseURL:         strings.TrimRight(envString("QURL_EXPIRY_E2E_API_BASE_URL", "https://api.layerv.xyz"), "/"),
		accessToken:        os.Getenv("QURL_EXPIRY_E2E_ACCESS_TOKEN"),
		auth0SecretID:      envString("QURL_EXPIRY_E2E_AUTH0_SECRET_ID", "layerv-nhp-sandbox-auth0-backend-credentials"),
		auth0TokenURL:      envString("QURL_EXPIRY_E2E_AUTH0_TOKEN_URL", "https://auth.layerv.ai/oauth/token"),
		accessTokensTable:  envString("QURL_EXPIRY_E2E_ACCESS_TOKENS_TABLE", tablePrefix+"-"+expiryContract.AccessTokens.Table),
		resourcesTable:     envString("QURL_EXPIRY_E2E_RESOURCES_TABLE", tablePrefix+"-"+expiryContract.Resources.Table),
		sessionsTable:      envString("QURL_EXPIRY_E2E_SESSIONS_TABLE", tablePrefix+"-"+expiryContract.Sessions.Table),
		webhookDedupeTable: envString("QURL_EXPIRY_E2E_WEBHOOK_DEDUPE_TABLE", tablePrefix+"-"+expiryContract.WebhookDedupe.Table),
		// The scanner Lambda name is a harness trigger, not a mirrored qurl-service storage/link contract.
		scannerFunction:   envString("QURL_EXPIRY_E2E_SCANNER_FUNCTION", tablePrefix+"-qurl-scanner"),
		queueName:         queueName,
		dlqName:           dlqName,
		ttl:               envString("QURL_EXPIRY_E2E_TTL", "1m"),
		massTTL:           envString("QURL_EXPIRY_E2E_MASS_TTL", "3m"),
		sessionDuration:   envString("QURL_EXPIRY_E2E_SESSION_DURATION", "90s"),
		targetURLBase:     strings.TrimRight(envString("QURL_EXPIRY_E2E_TARGET_URL_BASE", "https://example.com/qurl-expiry-e2e"), "/"),
		runID:             envString("QURL_EXPIRY_E2E_RUN_ID", strconv.FormatInt(time.Now().UTC().UnixNano(), 36)),
		massCount:         intEnv(t, "QURL_EXPIRY_E2E_MASS_COUNT", 50),
		testTimeout:       durationEnv(t, "QURL_EXPIRY_E2E_TEST_TIMEOUT", 20*time.Minute),
		waitTimeout:       durationEnv(t, "QURL_EXPIRY_E2E_WAIT_TIMEOUT", 8*time.Minute),
		pollInterval:      durationEnv(t, "QURL_EXPIRY_E2E_POLL_INTERVAL", 3*time.Second),
		requestSpacing:    durationEnv(t, "QURL_EXPIRY_E2E_REQUEST_SPACING", 1300*time.Millisecond),
		apiRetryTimeout:   durationEnv(t, "QURL_EXPIRY_E2E_API_RETRY_TIMEOUT", 3*time.Minute),
		deferHold:         durationEnv(t, "QURL_EXPIRY_E2E_DEFER_HOLD", 20*time.Second),
		testStartedAt:     time.Now().UTC(),
		invokeScanner:     envBool(t, "QURL_EXPIRY_E2E_INVOKE_SCANNER", true),
		requireDLQEmpty:   !envBool(t, "QURL_EXPIRY_E2E_ALLOW_SHARED_DLQ_BACKLOG", false),
		requireQueueEmpty: !envBool(t, "QURL_EXPIRY_E2E_ALLOW_SHARED_QUEUE_BACKLOG", false),
		skipScannerErrors: envBool(t, "QURL_EXPIRY_E2E_SKIP_SCANNER_ERROR_CHECK", false),
	}
	if cfg.massCount < 2 {
		t.Fatalf("QURL_EXPIRY_E2E_MASS_COUNT=%d; want at least 2", cfg.massCount)
	}

	cfg.queueURL = envString("QURL_EXPIRY_E2E_QUEUE_URL", cfg.lookupQueueURL(ctx, t, cfg.queueName))
	cfg.dlqURL = envString("QURL_EXPIRY_E2E_DLQ_URL", cfg.lookupQueueURL(ctx, t, cfg.dlqName))
	if cfg.accessToken == "" {
		cfg.accessToken = cfg.mintAuth0Token(ctx, t)
	}

	return cfg
}

func (cfg *expiryConfig) testContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), cfg.testTimeout)
}

func (cfg *expiryConfig) createTransitQURL(ctx context.Context, t *testing.T, label string, oneTimeUse bool, sessionDuration, expiresIn string) qurlData {
	t.Helper()

	body := map[string]any{
		"type":         "transit",
		"target_url":   cfg.targetURL(label),
		"expires_in":   expiresIn,
		"one_time_use": oneTimeUse,
		"max_sessions": 0,
		"label":        cfg.testLabel(label),
	}
	if sessionDuration != "" {
		body["session_duration"] = sessionDuration
	}

	var out createQURLResponse
	cfg.doJSON(ctx, t, http.MethodPost, "/v1/qurls", body, http.StatusCreated, &out)
	requireQURLData(t, out.Data)
	return out.Data
}

func (cfg *expiryConfig) batchCreateTransitQURLs(ctx context.Context, t *testing.T, labelPrefix string, count int, expiresIn string) []qurlData {
	t.Helper()

	items := make([]map[string]any, 0, count)
	for i := 0; i < count; i++ {
		label := fmt.Sprintf("%s-%02d", labelPrefix, i)
		items = append(items, map[string]any{
			"type":         "transit",
			"target_url":   cfg.targetURL(label),
			"expires_in":   expiresIn,
			"one_time_use": false,
			"max_sessions": 0,
			"label":        cfg.testLabel(label),
		})
	}

	var out batchCreateResponse
	cfg.doJSON(ctx, t, http.MethodPost, "/v1/qurls/batch", map[string]any{"items": items}, http.StatusCreated, &out)
	if out.Data.Succeeded != count || out.Data.Failed != 0 || len(out.Data.Results) != count {
		t.Fatalf("batch create succeeded=%d failed=%d results=%d, want succeeded=%d failed=0 results=%d", out.Data.Succeeded, out.Data.Failed, len(out.Data.Results), count, count)
	}

	qurls := make([]qurlData, count)
	seen := make([]bool, count)
	for _, result := range out.Data.Results {
		if result.Index < 0 || result.Index >= count {
			t.Fatalf("batch item index %d outside 0..%d", result.Index, count-1)
		}
		if seen[result.Index] {
			t.Fatalf("batch item index %d appeared more than once", result.Index)
		}
		if !result.Success {
			t.Fatalf("batch item %d failed: %+v", result.Index, result.Error)
		}
		data := qurlData{
			QURLID:     cfg.lookupQURLIDForResource(ctx, t, result.ResourceID),
			QURLLink:   result.QURLLink,
			QURLSite:   result.QURLSite,
			ResourceID: result.ResourceID,
			ExpiresAt:  result.ExpiresAt,
			Type:       "transit",
		}
		requireQURLData(t, data)
		qurls[result.Index] = data
		seen[result.Index] = true
	}
	for i, ok := range seen {
		if !ok {
			t.Fatalf("batch create response missing result index %d", i)
		}
	}
	return qurls
}

func (cfg *expiryConfig) resolveAccessToken(ctx context.Context, t *testing.T, accessToken string) {
	t.Helper()

	var out struct {
		Data struct {
			ResourceID string `json:"resource_id"`
		} `json:"data"`
		Error *apiError `json:"error,omitempty"`
	}
	cfg.doJSON(ctx, t, http.MethodPost, "/v1/resolve", map[string]any{"access_token": accessToken}, http.StatusOK, &out)
	if out.Data.ResourceID == "" {
		t.Fatalf("resolve returned empty data.resource_id")
	}
}

func (cfg *expiryConfig) expectRemintGone(ctx context.Context, t *testing.T, resourceID string) {
	t.Helper()

	status, raw := cfg.doJSONStatus(ctx, t, http.MethodPost, "/v1/resources/"+url.PathEscape(resourceID)+"/qurls", map[string]any{
		"expires_in":   "5m",
		"one_time_use": false,
		"label":        cfg.testLabel("remint-after-close"),
	})
	if status != http.StatusGone {
		t.Fatalf("re-mint to tombstoned resource status = %d, want 410; body=%s", status, redactedBodyForLog(raw))
	}

	var out struct {
		Error apiError `json:"error"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("parse 410 body: %v; body=%s", err, redactedBodyForLog(raw))
	}
	if out.Error.Code != "resource_tombstoned" {
		t.Fatalf("410 error.code = %q, want resource_tombstoned; body=%s", out.Error.Code, redactedBodyForLog(raw))
	}
}

func (cfg *expiryConfig) driveExpiryBucket(ctx context.Context, t *testing.T, expiresAt time.Time) {
	t.Helper()
	cfg.waitUntilBucketClosed(ctx, t, expiresAt)
	cfg.invokeScannerBucket(ctx, t, expiresAt)
}

func (cfg *expiryConfig) waitUntilBucketClosed(ctx context.Context, t *testing.T, expiresAt time.Time) {
	t.Helper()

	bucketEnd := time.Unix((expiresAt.UTC().Unix()/60+1)*60, 0).Add(3 * time.Second)
	if delay := time.Until(bucketEnd); delay > 0 {
		t.Logf("waiting %s for expiry bucket %d to close", delay.Round(time.Second), expiresAt.UTC().Unix()/60)
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			t.Fatalf("context ended before expiry bucket closed: %v", ctx.Err())
		case <-timer.C:
		}
	}
}

func (cfg *expiryConfig) invokeScannerBucket(ctx context.Context, t *testing.T, expiresAt time.Time) {
	t.Helper()
	if err := cfg.invokeScannerBucketOnce(ctx, expiresAt); err != nil {
		t.Fatal(err)
	}
}

func (cfg *expiryConfig) invokeScannerBucketOnce(ctx context.Context, expiresAt time.Time) error {
	if !cfg.invokeScanner {
		return nil
	}
	bucket := expiresAt.UTC().Unix() / 60
	payload, err := json.Marshal(map[string]int64{"bucket": bucket})
	if err != nil {
		return fmt.Errorf("marshal scanner invoke payload: %w", err)
	}
	out, err := cfg.lambda.Invoke(ctx, &lambda.InvokeInput{
		FunctionName:   aws.String(cfg.scannerFunction),
		InvocationType: lambdatypes.InvocationTypeRequestResponse,
		Payload:        payload,
	})
	if err != nil {
		return fmt.Errorf("invoke scanner %s bucket %d: %w", cfg.scannerFunction, bucket, err)
	}
	if out.StatusCode < 200 || out.StatusCode > 299 || out.FunctionError != nil {
		return fmt.Errorf("invoke scanner %s bucket %d status=%d function_error=%v payload=%s", cfg.scannerFunction, bucket, out.StatusCode, aws.ToString(out.FunctionError), string(out.Payload))
	}
	return nil
}

func (cfg *expiryConfig) waitForDedupeMarker(ctx context.Context, t *testing.T, eventType, primaryID string) {
	t.Helper()

	err := cfg.waitFor(ctx, "dedupe marker "+eventType+"/"+primaryID, func(ctx context.Context) (bool, error) {
		found, err := cfg.hasDedupeMarker(ctx, eventType, primaryID)
		return found, err
	})
	if err != nil {
		t.Fatalf("%v (%s)", err, schemaMismatchHint)
	}
}

func (cfg *expiryConfig) waitForAllDedupeMarkers(ctx context.Context, t *testing.T, eventType string, primaryIDs []string, expiresAt time.Time) {
	t.Helper()

	missing := make(map[string]struct{}, len(primaryIDs))
	for _, id := range primaryIDs {
		missing[id] = struct{}{}
	}

	deadline, cancel := context.WithTimeout(ctx, cfg.waitTimeout)
	defer cancel()
	ticker := time.NewTicker(cfg.pollInterval)
	defer ticker.Stop()
	nextReplay := time.Now().Add(45 * time.Second)
	var lastErr error

	for {
		// Keep per-marker ConsistentRead diagnostics even in the mass case; this
		// manual harness favors clear missing-marker failures over BatchGetItem's
		// partial-response bookkeeping.
		for id := range missing {
			found, err := cfg.hasDedupeMarker(deadline, eventType, id)
			if err != nil {
				lastErr = fmt.Errorf("check dedupe marker %s/%s: %w", eventType, id, err)
				continue
			}
			if found {
				delete(missing, id)
			}
		}
		if len(missing) == 0 {
			return
		}

		now := time.Now()
		if !now.Before(nextReplay) {
			err := cfg.invokeScannerBucketOnce(deadline, expiresAt)
			if err != nil && deadline.Err() == nil {
				lastErr = err
			}
			nextReplay = now.Add(60 * time.Second)
		}

		select {
		case <-deadline.Done():
			if lastErr != nil {
				t.Fatalf("timed out waiting for %d %s markers; missing sample=%v; last error: %v (%s)", len(missing), eventType, sampleKeys(missing, 5), lastErr, schemaMismatchHint)
			}
			t.Fatalf("timed out waiting for %d %s markers; missing sample=%v (%s)", len(missing), eventType, sampleKeys(missing, 5), schemaMismatchHint)
		case <-ticker.C:
		}
	}
}

func (cfg *expiryConfig) assertActiveSessionDefersResourceClose(ctx context.Context, t *testing.T, resourceID string) {
	t.Helper()

	deferCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 2)
	go func() {
		errCh <- cfg.verifyNoDedupeMarkerFor(deferCtx, eventResourceClose, resourceID, cfg.deferHold)
	}()
	go func() {
		errCh <- cfg.verifyResourceNotTombstonedFor(deferCtx, resourceID, cfg.deferHold)
	}()

	var firstErr error
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil && firstErr == nil {
			firstErr = err
			cancel()
		}
	}
	if firstErr != nil {
		t.Fatal(firstErr)
	}
}

func (cfg *expiryConfig) verifyNoDedupeMarkerFor(ctx context.Context, eventType, primaryID string, duration time.Duration) error {
	deadline := time.NewTimer(duration)
	defer deadline.Stop()
	ticker := time.NewTicker(cfg.pollInterval)
	defer ticker.Stop()
	var checked bool
	var lastErr error

	for {
		found, err := cfg.hasDedupeMarker(ctx, eventType, primaryID)
		if err != nil {
			lastErr = fmt.Errorf("check dedupe marker %s/%s: %w", eventType, primaryID, err)
		} else if found {
			return fmt.Errorf("dedupe marker %s/%s appeared during %s deferral window", eventType, primaryID, duration)
		} else {
			checked = true
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("context ended while checking absence of %s/%s: %w", eventType, primaryID, ctx.Err())
		case <-deadline.C:
			if !checked && lastErr != nil {
				return fmt.Errorf("could not verify absence of %s/%s for %s: last error: %w", eventType, primaryID, duration, lastErr)
			}
			return nil
		case <-ticker.C:
		}
	}
}

func (cfg *expiryConfig) hasDedupeMarker(ctx context.Context, eventType, primaryID string) (bool, error) {
	out, err := cfg.ddb.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(cfg.webhookDedupeTable),
		Key: map[string]ddbtypes.AttributeValue{
			expiryContract.WebhookDedupe.PartitionKey: &ddbtypes.AttributeValueMemberS{Value: webhookEventDedupePK(eventType, primaryID)},
		},
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return false, err
	}
	if len(out.Item) == 0 {
		return false, nil
	}
	if got := stringAttr(out.Item, expiryContract.WebhookDedupe.EventTypeAttribute); got != eventType {
		return false, fmt.Errorf("dedupe marker %s = %q, want %q", expiryContract.WebhookDedupe.EventTypeAttribute, got, eventType)
	}
	if got := stringAttr(out.Item, expiryContract.WebhookDedupe.PrimaryIDAttribute); got != primaryID {
		return false, fmt.Errorf("dedupe marker %s = %q, want %q", expiryContract.WebhookDedupe.PrimaryIDAttribute, got, primaryID)
	}
	return true, nil
}

func (cfg *expiryConfig) waitForResourceTombstone(ctx context.Context, t *testing.T, resourceID string) {
	t.Helper()

	err := cfg.waitFor(ctx, "resource tombstone "+resourceID, func(ctx context.Context) (bool, error) {
		return cfg.resourceTombstoned(ctx, resourceID)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func (cfg *expiryConfig) verifyResourceNotTombstonedFor(ctx context.Context, resourceID string, duration time.Duration) error {
	deadline := time.NewTimer(duration)
	defer deadline.Stop()
	ticker := time.NewTicker(cfg.pollInterval)
	defer ticker.Stop()
	var checked bool
	var lastErr error

	for {
		tombstoned, err := cfg.resourceTombstoned(ctx, resourceID)
		if err != nil {
			lastErr = fmt.Errorf("check resource tombstone %s: %w", resourceID, err)
		} else if tombstoned {
			return fmt.Errorf("resource %s was tombstoned during %s active-session deferral window", resourceID, duration)
		} else {
			checked = true
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("context ended while checking resource %s tombstone absence: %w", resourceID, ctx.Err())
		case <-deadline.C:
			if !checked && lastErr != nil {
				return fmt.Errorf("could not verify resource %s was not tombstoned for %s: last error: %w", resourceID, duration, lastErr)
			}
			return nil
		case <-ticker.C:
		}
	}
}

func (cfg *expiryConfig) resourceTombstoned(ctx context.Context, resourceID string) (bool, error) {
	out, err := cfg.ddb.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(cfg.resourcesTable),
		Key: map[string]ddbtypes.AttributeValue{
			expiryContract.Resources.PartitionKey: &ddbtypes.AttributeValueMemberS{Value: resourceID},
			expiryContract.Resources.SortKey:      &ddbtypes.AttributeValueMemberS{Value: expiryContract.Resources.ResourceSortKeyValue},
		},
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return false, err
	}
	if len(out.Item) == 0 {
		return false, fmt.Errorf("resource %s not found in %s", resourceID, cfg.resourcesTable)
	}
	if stringAttr(out.Item, expiryContract.Resources.TombstonedAtAttribute) == "" {
		return false, nil
	}
	ttl := numberAttr(out.Item, expiryContract.Resources.TombstoneTTLAttribute)
	if ttl == "" {
		return false, nil
	}
	parsedTTL, err := strconv.ParseInt(ttl, 10, 64)
	if err != nil {
		return false, fmt.Errorf("resource %s tombstone_ttl = %q: %w", resourceID, ttl, err)
	}
	return parsedTTL > 0, nil
}

func (cfg *expiryConfig) lookupQURLIDForResource(ctx context.Context, t *testing.T, resourceID string) string {
	t.Helper()

	var qurlID string
	err := cfg.waitFor(ctx, "qURL id for resource "+resourceID, func(ctx context.Context) (bool, error) {
		out, err := cfg.ddb.Query(ctx, &dynamodb.QueryInput{
			TableName:              aws.String(cfg.accessTokensTable),
			IndexName:              aws.String(expiryContract.AccessTokens.ResourceIndex),
			KeyConditionExpression: aws.String(expiryContract.AccessTokens.ResourceIndexPartitionKey + " = :rid"),
			ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{
				":rid": &ddbtypes.AttributeValueMemberS{Value: resourceID},
			},
			ProjectionExpression: aws.String(expiryContract.AccessTokens.QURLIDProjectionAttribute),
			Limit:                aws.Int32(1),
		})
		if err != nil {
			return false, err
		}
		if len(out.Items) == 0 {
			return false, nil
		}
		qurlID = stringAttr(out.Items[0], expiryContract.AccessTokens.QURLIDProjectionAttribute)
		return qurlID != "", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return qurlID
}

func (cfg *expiryConfig) waitForActiveSession(ctx context.Context, t *testing.T, resourceID string) {
	t.Helper()

	err := cfg.waitFor(ctx, "active session for resource "+resourceID, func(ctx context.Context) (bool, error) {
		out, err := cfg.ddb.Query(ctx, &dynamodb.QueryInput{
			TableName:              aws.String(cfg.sessionsTable),
			KeyConditionExpression: aws.String(expiryContract.Sessions.PartitionKey + " = :rid"),
			FilterExpression:       aws.String(expiryContract.Sessions.ActiveFilterExpression),
			ExpressionAttributeNames: map[string]string{
				expiryContract.Sessions.TTLPlaceholder: expiryContract.Sessions.TTLAttribute,
			},
			ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{
				":rid": &ddbtypes.AttributeValueMemberS{Value: resourceID},
				":now": &ddbtypes.AttributeValueMemberN{Value: strconv.FormatInt(time.Now().Unix(), 10)},
			},
			Limit: aws.Int32(1),
		})
		if err != nil {
			return false, err
		}
		return len(out.Items) > 0, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func (cfg *expiryConfig) waitForSessionDuration(ctx context.Context, t *testing.T) {
	t.Helper()

	d, err := time.ParseDuration(cfg.sessionDuration)
	if err != nil {
		t.Fatalf("parse session duration %q: %v", cfg.sessionDuration, err)
	}
	// qurl-service documents that the page-load/front-edge window can make
	// wall-clock access last up to roughly twice session_duration.
	timer := time.NewTimer(2*d + 10*time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		t.Fatalf("context ended before session duration elapsed: %v", ctx.Err())
	case <-timer.C:
	}
}

func (cfg *expiryConfig) assertPostRunHealth(ctx context.Context, t *testing.T) {
	t.Helper()

	// These checks read global scanner/queue state; keep these tests sequential,
	// do not add t.Parallel, or use the shared-sandbox escape hatches when
	// other traffic is expected.
	cfg.assertDLQEmpty(ctx, t)
	cfg.assertMainQueueDrained(ctx, t)
	cfg.assertScannerErrorsZero(ctx, t)
}

func (cfg *expiryConfig) assertDLQEmpty(ctx context.Context, t *testing.T) {
	t.Helper()

	depth := cfg.queueDepth(ctx, t, cfg.dlqURL)
	if depth == 0 {
		return
	}
	if cfg.requireDLQEmpty {
		depth = cfg.waitForQueueDrained(ctx, t, "resource-lifecycle DLQ", cfg.dlqURL)
		if depth == 0 {
			return
		}
		t.Fatalf("resource-lifecycle DLQ depth = %d, want 0", depth)
	}
	t.Logf("resource-lifecycle DLQ depth = %d; allowed by QURL_EXPIRY_E2E_ALLOW_SHARED_DLQ_BACKLOG", depth)
}

func (cfg *expiryConfig) assertMainQueueDrained(ctx context.Context, t *testing.T) {
	t.Helper()

	depth := cfg.queueDepth(ctx, t, cfg.queueURL)
	if depth == 0 {
		return
	}
	if cfg.requireQueueEmpty {
		depth = cfg.waitForQueueDrained(ctx, t, "resource-lifecycle main queue", cfg.queueURL)
		if depth == 0 {
			return
		}
		t.Fatalf("resource-lifecycle main queue depth = %d, want 0 (set QURL_EXPIRY_E2E_ALLOW_SHARED_QUEUE_BACKLOG=true for shared-env diagnostics)", depth)
	}
	t.Logf("resource-lifecycle main queue depth = %d; allowed by QURL_EXPIRY_E2E_ALLOW_SHARED_QUEUE_BACKLOG", depth)
}

func (cfg *expiryConfig) waitForQueueDrained(ctx context.Context, t *testing.T, name, queueURL string) int64 {
	t.Helper()

	queueDrainTimeout := 90 * time.Second
	if cfg.waitTimeout < queueDrainTimeout {
		queueDrainTimeout = cfg.waitTimeout
	}
	deadline, cancel := context.WithTimeout(ctx, queueDrainTimeout)
	defer cancel()
	ticker := time.NewTicker(cfg.pollInterval)
	defer ticker.Stop()

	var depth int64
	for {
		depth = cfg.queueDepth(deadline, t, queueURL)
		if depth == 0 {
			return 0
		}
		select {
		case <-deadline.Done():
			t.Logf("timed out waiting for %s to drain after %s; last depth=%d", name, queueDrainTimeout, depth)
			return depth
		case <-ticker.C:
		}
	}
}

func (cfg *expiryConfig) queueDepth(ctx context.Context, t *testing.T, queueURL string) int64 {
	t.Helper()

	out, err := cfg.sqs.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{
		QueueUrl: aws.String(queueURL),
		AttributeNames: []sqstypes.QueueAttributeName{
			sqstypes.QueueAttributeNameApproximateNumberOfMessages,
			sqstypes.QueueAttributeNameApproximateNumberOfMessagesDelayed,
			sqstypes.QueueAttributeNameApproximateNumberOfMessagesNotVisible,
		},
	})
	if err != nil {
		t.Fatalf("get queue attributes for %s: %v", queueURL, err)
	}
	var total int64
	for _, name := range []sqstypes.QueueAttributeName{
		sqstypes.QueueAttributeNameApproximateNumberOfMessages,
		sqstypes.QueueAttributeNameApproximateNumberOfMessagesDelayed,
		sqstypes.QueueAttributeNameApproximateNumberOfMessagesNotVisible,
	} {
		value := out.Attributes[string(name)]
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			t.Fatalf("parse queue attribute %s=%q: %v", name, value, err)
		}
		total += n
	}
	return total
}

func (cfg *expiryConfig) assertScannerErrorsZero(ctx context.Context, t *testing.T) {
	t.Helper()
	if cfg.skipScannerErrors {
		return
	}

	now := time.Now().UTC()
	// CloudWatch Lambda Errors is function-global and can lag, so this is a
	// best-effort shared-sandbox guard rather than a per-test attribution.
	out, err := cfg.cw.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
		Namespace:  aws.String("AWS/Lambda"),
		MetricName: aws.String("Errors"),
		Dimensions: []cwtypes.Dimension{
			{Name: aws.String("FunctionName"), Value: aws.String(cfg.scannerFunction)},
		},
		StartTime:  aws.Time(cfg.testStartedAt.Add(-1 * time.Minute)),
		EndTime:    aws.Time(now.Add(1 * time.Minute)),
		Period:     aws.Int32(60),
		Statistics: []cwtypes.Statistic{cwtypes.StatisticSum},
	})
	if err != nil {
		t.Fatalf("get scanner Errors metric: %v", err)
	}
	var errorsSeen float64
	for _, dp := range out.Datapoints {
		errorsSeen += aws.ToFloat64(dp.Sum)
	}
	if errorsSeen != 0 {
		t.Fatalf("scanner Lambda Errors sum since %s = %.0f, want 0", cfg.testStartedAt.Format(time.RFC3339), errorsSeen)
	}
}

func (cfg *expiryConfig) lookupQueueURL(ctx context.Context, t *testing.T, queueName string) string {
	t.Helper()
	out, err := cfg.sqs.GetQueueUrl(ctx, &sqs.GetQueueUrlInput{QueueName: aws.String(queueName)})
	if err != nil {
		t.Fatalf("lookup queue URL for %s: %v", queueName, err)
	}
	return aws.ToString(out.QueueUrl)
}

func (cfg *expiryConfig) mintAuth0Token(ctx context.Context, t *testing.T) string {
	t.Helper()

	secretOut, err := cfg.sm.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(cfg.auth0SecretID),
	})
	if err != nil {
		t.Fatalf("read Auth0 secret %s: %v", cfg.auth0SecretID, err)
	}
	var secret auth0Secret
	if err := json.Unmarshal([]byte(aws.ToString(secretOut.SecretString)), &secret); err != nil {
		t.Fatalf("parse Auth0 secret %s: %v", cfg.auth0SecretID, err)
	}
	if secret.ClientID == "" || secret.ClientSecret == "" || secret.Audience == "" {
		t.Fatalf("Auth0 secret %s missing client_id/client_secret/audience", cfg.auth0SecretID)
	}

	body, err := json.Marshal(map[string]string{
		"client_id":     secret.ClientID,
		"client_secret": secret.ClientSecret,
		"audience":      secret.Audience,
		"grant_type":    "client_credentials",
	})
	if err != nil {
		t.Fatalf("marshal Auth0 request: %v", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.auth0TokenURL, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new Auth0 request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := cfg.httpClient.Do(req)
	if err != nil {
		t.Fatalf("Auth0 token request: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Auth0 token status = %d, want 200; body=<redacted>", resp.StatusCode)
	}

	var tokenOut struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(raw, &tokenOut); err != nil {
		t.Fatalf("parse Auth0 token response: %v; body=<redacted>", err)
	}
	if tokenOut.AccessToken == "" {
		t.Fatalf("Auth0 token response missing access_token")
	}
	return tokenOut.AccessToken
}

func (cfg *expiryConfig) doJSON(ctx context.Context, t *testing.T, method, path string, body any, wantStatus int, out any) {
	t.Helper()
	status, raw := cfg.doJSONStatus(ctx, t, method, path, body)
	if status != wantStatus {
		t.Fatalf("%s %s status = %d, want %d; body=%s", method, path, status, wantStatus, redactedBodyForLog(raw))
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			t.Fatalf("parse %s %s response: %v; body=%s", method, path, err, redactedBodyForLog(raw))
		}
	}
}

func (cfg *expiryConfig) doJSONStatus(ctx context.Context, t *testing.T, method, path string, body any) (int, []byte) {
	t.Helper()

	retryCtx, cancel := context.WithTimeout(ctx, cfg.apiRetryTimeout)
	defer cancel()
	idempotencyKey := cfg.idempotencyKey(method, path)

	var lastStatus int
	var lastRaw []byte
	var lastErr error
	for attempt := 0; ; attempt++ {
		// Keep owner-tier request spacing separate from retry backoff; retries pay
		// both delays so rate limits and transient failures are handled distinctly.
		if cfg.requestSpacing > 0 {
			timer := time.NewTimer(cfg.requestSpacing)
			select {
			case <-retryCtx.Done():
				timer.Stop()
				if lastStatus != 0 {
					return lastStatus, lastRaw
				}
				if lastErr != nil {
					t.Fatalf("context ended before %s %s retry: last error: %v", method, path, lastErr)
				}
				t.Fatalf("context ended before %s %s attempt: %v", method, path, retryCtx.Err())
			case <-timer.C:
			}
		}

		status, raw, headers, err := cfg.doJSONStatusOnce(retryCtx, t, method, path, body, idempotencyKey)
		if err == nil && status != http.StatusTooManyRequests && status < 500 {
			return status, raw
		}

		if err != nil {
			lastErr = err
		} else {
			lastStatus, lastRaw = status, raw
		}
		var retryAfter string
		if headers != nil {
			retryAfter = headers.Get("Retry-After")
		}
		delay := retryDelay(retryAfter, attempt)
		timer := time.NewTimer(delay)
		select {
		case <-retryCtx.Done():
			timer.Stop()
			if lastStatus != 0 {
				return lastStatus, lastRaw
			}
			if lastErr != nil {
				t.Fatalf("%s %s failed after retries: %v", method, path, lastErr)
			}
			return status, raw
		case <-timer.C:
		}
	}
}

func (cfg *expiryConfig) doJSONStatusOnce(ctx context.Context, t *testing.T, method, path string, body any, idempotencyKey string) (int, []byte, http.Header, error) {
	t.Helper()

	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal %s %s body: %v", method, path, err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, cfg.apiBaseURL+path, reader)
	if err != nil {
		t.Fatalf("new %s %s request: %v", method, path, err)
	}
	req.Header.Set("Authorization", "Bearer "+cfg.accessToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", idempotencyKey)

	resp, err := cfg.httpClient.Do(req)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return resp.StatusCode, raw, resp.Header.Clone(), fmt.Errorf("read %s %s response: %w", method, path, err)
	}
	return resp.StatusCode, raw, resp.Header.Clone(), nil
}

func (cfg *expiryConfig) idempotencyKey(method, path string) string {
	cleanPath := strings.Trim(strings.ReplaceAll(path, "/", "-"), "-")
	return cfg.runID + "-" + method + "-" + cleanPath + "-" + strconv.FormatInt(time.Now().UnixNano(), 36)
}

func retryDelay(retryAfter string, attempt int) time.Duration {
	if retryAfter != "" {
		if seconds, err := strconv.Atoi(strings.TrimSpace(retryAfter)); err == nil && seconds > 0 {
			return time.Duration(seconds) * time.Second
		}
		if when, err := http.ParseTime(retryAfter); err == nil {
			if delay := time.Until(when); delay > 0 {
				return delay
			}
		}
	}

	delay := time.Duration(1<<min(attempt, 5)) * time.Second
	if delay > 30*time.Second {
		return 30 * time.Second
	}
	return delay
}

func (cfg *expiryConfig) waitFor(ctx context.Context, name string, fn func(context.Context) (bool, error)) error {
	deadline, cancel := context.WithTimeout(ctx, cfg.waitTimeout)
	defer cancel()

	ticker := time.NewTicker(cfg.pollInterval)
	defer ticker.Stop()
	var lastErr error
	for {
		ok, err := fn(deadline)
		if err != nil {
			lastErr = err
		} else if ok {
			return nil
		}

		select {
		case <-deadline.Done():
			if lastErr != nil {
				return fmt.Errorf("timed out waiting for %s: last error: %w", name, lastErr)
			}
			return fmt.Errorf("timed out waiting for %s", name)
		case <-ticker.C:
		}
	}
}

func (cfg *expiryConfig) targetURL(label string) string {
	return fmt.Sprintf("%s/%s/%s", cfg.targetURLBase, url.PathEscape(cfg.runID), url.PathEscape(label))
}

func (cfg *expiryConfig) testLabel(label string) string {
	return "nhp-2488-" + cfg.runID + "-" + label
}

func requireQURLData(t *testing.T, data qurlData) {
	t.Helper()
	redacted := data
	if redacted.QURLLink != "" {
		redacted.QURLLink = "<redacted>"
	}
	if data.QURLID == "" {
		t.Fatalf("qurl response missing qurl_id: %+v", redacted)
	}
	if data.ResourceID == "" {
		t.Fatalf("qurl response missing resource_id: %+v", redacted)
	}
	if data.QURLLink == "" {
		t.Fatalf("qurl response missing qurl_link: %+v", redacted)
	}
	if data.ExpiresAt.IsZero() {
		t.Fatalf("qurl response missing expires_at: %+v", redacted)
	}
}

func redactedBodyForLog(raw []byte) string {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return "<redacted non-JSON response body>"
	}
	redactJSONSecrets(value)
	out, err := json.Marshal(value)
	if err != nil {
		return "<redacted>"
	}
	return string(out)
}

func redactJSONSecrets(value any) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if sensitiveJSONKey(key) || opaqueSecretString(child) {
				typed[key] = "<redacted>"
				continue
			}
			redactJSONSecrets(child)
		}
	case []any:
		for i, child := range typed {
			if opaqueSecretString(child) {
				typed[i] = "<redacted>"
				continue
			}
			redactJSONSecrets(child)
		}
	}
}

func sensitiveJSONKey(key string) bool {
	switch strings.ToLower(key) {
	case "qurl_link", "access_token", "authorization", "client_secret", "id_token", "refresh_token", "token":
		return true
	default:
		return false
	}
}

func opaqueSecretString(value any) bool {
	const minOpaqueSecretLength = 80
	text, ok := value.(string)
	if !ok || len(text) < minOpaqueSecretLength {
		return false
	}
	return !strings.ContainsAny(text, " \t\r\n")
}

func extractAccessToken(t *testing.T, qurlLink string) string {
	t.Helper()

	accessToken, err := extractAccessTokenFromQURLLink(qurlLink)
	if err != nil {
		t.Fatal(err)
	}
	return accessToken
}

func stringAttr(item map[string]ddbtypes.AttributeValue, key string) string {
	if attr, ok := item[key].(*ddbtypes.AttributeValueMemberS); ok {
		return attr.Value
	}
	return ""
}

func numberAttr(item map[string]ddbtypes.AttributeValue, key string) string {
	if attr, ok := item[key].(*ddbtypes.AttributeValueMemberN); ok {
		return attr.Value
	}
	return ""
}

func sampleKeys(values map[string]struct{}, limit int) []string {
	sample := make([]string, 0, limit)
	for value := range values {
		sample = append(sample, value)
		if len(sample) == limit {
			break
		}
	}
	return sample
}

func envString(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func envBool(t *testing.T, key string, defaultValue bool) bool {
	t.Helper()

	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return defaultValue
	}
	switch strings.ToLower(value) {
	case "1", "true", "t", "yes", "y", "on":
		return true
	case "0", "false", "f", "no", "n", "off":
		return false
	default:
		t.Fatalf("%s=%q is not a valid boolean", key, value)
		return defaultValue
	}
}

func intEnv(t *testing.T, key string, defaultValue int) int {
	t.Helper()

	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return defaultValue
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		t.Fatalf("parse %s=%q as int: %v", key, value, err)
	}
	return parsed
}

func durationEnv(t *testing.T, key string, defaultValue time.Duration) time.Duration {
	t.Helper()

	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return defaultValue
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		t.Fatalf("parse %s=%q as duration: %v", key, value, err)
	}
	return parsed
}
