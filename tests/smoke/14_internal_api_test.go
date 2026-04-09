//go:build smoke

package smoke

// Tier 2: /nhp/internal/knock VPC-only enforcement.
//
// Capability: the server's internal knock endpoint is registered
// at /nhp/internal/knock and protected by an RFC1918 source-IP
// check in the handler (endpoints/server/httpserver.go:897-901).
// The NLB's security group allows 0.0.0.0/0 on port 8888 to
// support preserve_client_ip for the resolve flow (MEMORY gotcha
// #7), so the ONLY thing stopping an external attacker from
// reaching this endpoint is the handler's in-process source-IP
// check. That makes the negative fence critical: a regression
// here would silently expose the knock-forwarding API to the
// public internet.
//
// The positive fence (VPC source accepted) requires constructing
// a valid HttpKnockForwardRequest body, which needs deep knowledge
// of the NHP protocol struct shape that changes with the wire
// format. Deferred to a later PR where we can wrap the protocol
// in a stable test helper. For PR2 the negative fence is
// sufficient.

import (
	"net/http"
	"strings"
	"testing"
)

// TestInternalAPI_PublicIPRejected fences the source-IP guard on
// /nhp/internal/knock. A POST from the public GitHub runner (or
// any non-RFC1918 source) must return 403 with {"error":"forbidden"}.
//
// A regression here — e.g., someone replacing `isPrivateIP` with a
// less strict check, or middleware ordering changing so the guard
// is bypassed — would fail this test the first time CI runs.
//
// Note on body: we send {} rather than a well-formed
// HttpKnockForwardRequest because we want to exercise the IP check
// specifically. If the handler's JSON decode fires before the IP
// check, the test would see 400 ("invalid request body") instead
// of 403 — which is itself a regression (the IP check must run
// first, before any body parsing, so an attacker can't probe the
// endpoint's internals by sending malformed JSON). The assertion
// is specifically 403, not "4xx-class".
func TestInternalAPI_PublicIPRejected(t *testing.T) {
	emptyBody := strings.NewReader("{}")

	resp, body := doRequest(t, testConfig.HTTPClient, http.MethodPost,
		testConfig.NHPServerBaseURL+"/nhp/internal/knock",
		emptyBody,
		map[string]string{"Content-Type": "application/json"},
	)
	assertStatusCode(t, resp, http.StatusForbidden)

	if !strings.Contains(string(body), "forbidden") {
		t.Fatalf("403 body does not contain %q (body: %s)", "forbidden", truncate(body, 200))
	}
}
