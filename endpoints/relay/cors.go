package relay

import (
	"net/http"
	"strings"
)

// CORS for the browser relay endpoint (#2631).
//
// The relay's ONLY caller is the qURL knock page — `qurl.link/#at_xxx`, the page
// that (in the browser-knock model) POSTs the NHP knock to the relay in place of
// today's server-side resolve. It is a different origin from the relay
// (`relay.qurl.link`), so the browser preflights. Everything else is the DATA
// PLANE: once the knock opens the AC pinhole, the browser connects DIRECTLY to
// the resource (`{appId}.qurl.site` or a customer whitelabel domain) through the
// AC — that never touches the relay. So the allowlist is the knock-portal origin
// ONLY (qurl.link, per env), NOT the resource domains and NOT "*".
//
// The knock page is always qurl.link (it cannot be hosted on a customer domain),
// so a single exact origin per env suffices — no wildcard matching, and nothing
// shared with the server's wildcard CORS matcher.

// corsMaxAgeSeconds caps how long the browser caches the preflight. 7200 is
// Chrome's hard ceiling (higher is silently clamped). It matters because every
// cross-origin knock is OPTIONS + POST and the relay ALB's per-source-IP WAF rate
// rule counts both, so caching the preflight keeps a renewing client from
// spending 2x its budget. The advertised headers are static, so a long cache is
// free.
const corsMaxAgeSeconds = "7200"

// corsAllowlist is the set of browser Origins permitted to call the relay
// cross-origin (the qURL knock portal). Exact match; an empty set disables CORS.
type corsAllowlist map[string]bool

// newCORSAllowlist parses a comma-separated origin list (e.g. "https://qurl.link").
// An empty/whitespace list yields an allowlist that permits nothing, so CORS
// stays off (no Access-Control-* headers) until origins are configured — the
// relay is then behaviorally dark to cross-origin browsers.
func newCORSAllowlist(raw string) corsAllowlist {
	set := corsAllowlist{}
	for _, p := range strings.Split(raw, ",") {
		if o := strings.TrimSpace(p); o != "" {
			set[o] = true
		}
	}
	return set
}

// allowed reports whether origin (the request's Origin header) is permitted. An
// empty Origin (same-origin or a non-browser client) is never allowed — such
// requests need no CORS headers and are unaffected. The match is case-sensitive,
// which is safe because browsers send Origin as a normalized lowercase
// scheme+host (the configured allowlist is likewise lowercase).
func (a corsAllowlist) allowed(origin string) bool {
	return origin != "" && a[origin]
}

// setHeaders writes the CORS response headers for an already-matched origin,
// ECHOING that origin back (never "*"). Vary: Origin is set unconditionally by
// the caller (the response varies by Origin), so it is not set here. No
// Access-Control-Allow-Credentials — the js-agent fetch sends none. The
// advertised method/header are exactly what the js-agent uses (POST with
// Content-Type: application/octet-stream).
func (a corsAllowlist) setHeaders(w http.ResponseWriter, origin string) {
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", origin)
	h.Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	h.Set("Access-Control-Allow-Headers", "Content-Type")
	h.Set("Access-Control-Max-Age", corsMaxAgeSeconds)
}
