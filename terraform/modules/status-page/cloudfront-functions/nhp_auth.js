// CloudFront Function: NHP Authentication Gate
//
// Checks for a valid nhp_token cookie on viewer-request.
// If absent, redirects to the configured QURL login portal URL.
// After QURL authentication, the user is redirected back to the
// status page with nhp_token/nhp_refresh_token cookies set by
// the NHP server resolve flow.
//
// CloudFront Functions runtime: cloudfront-js-2.0 (ES6+ supported).
// Max 10KB code size, 1ms max execution time.
//
// Cookie flow:
//   1. User visits status page -> no nhp_token cookie -> redirect to QURL link
//   2. QURL link page extracts token from URL fragment -> redirects to NHP resolve
//   3. NHP server validates token, performs knock, sets nhp_token cookie on cookie_domain
//   4. User redirected back to status page -> nhp_token cookie present -> request passes through

// QURL_URL and COOKIE_NAME are replaced by Terraform templatefile() at deploy
// time. The terraform variable validation enforces a strict charset on both
// values so they cannot break out of these JavaScript string literals.
var QURL_URL = '${qurl_url}';
// Keep this lowercase: CloudFront Functions normalize cookie keys to lowercase
// in request.cookies, so we always look the cookie up by its lowercase name.
var COOKIE_NAME = ('${cookie_name}').toLowerCase();

// Redirect loop protection: if the user bounces back to the status page
// without acquiring a valid cookie (e.g. cookie domain mismatch, QURL flow
// misconfiguration), we'll normally redirect them again indefinitely. Set a
// short-lived breadcrumb cookie on the first unauthenticated request and, on
// subsequent requests within the window, return a 403 with a diagnostic
// message instead of looping. 30 seconds is long enough to cover the QURL
// round trip but short enough that legitimate users recover on their next
// visit if they eventually fix the underlying issue.
var LOOP_COOKIE = 'nhp_auth_attempt';
var LOOP_COOKIE_MAX_AGE = 30;

// Permissive base64url charset check for JWT segments. Real JWT segments are
// base64url-encoded, so anything outside [A-Za-z0-9_-] (with optional '=')
// indicates a malformed or attacker-injected token. This is still cheap to
// evaluate within the 1ms budget and gives us a slightly stronger structural
// gate than length-only.
var JWT_SEGMENT_RE = /^[A-Za-z0-9_=-]+$/;

// Minimum plausible JWT length. The smallest valid HS256 JWT has a ~36 char
// header, ~20+ char payload (claims like exp/iat/sub) and a 43 char signature
// plus two dots, so ~100 chars is a realistic floor. We use 80 to leave a bit
// of slack for unusual but legitimate tokens while still rejecting obvious
// junk that happens to contain two dots.
var MIN_JWT_LENGTH = 80;

function handler(event) {
    var request = event.request;
    var cookies = request.cookies || {};
    var uri = request.uri || '/';

    // Check for the NHP authentication cookie.
    //
    // We only validate JWT *structure* here (3 non-empty base64url parts,
    // minimum length) — we do NOT verify the signature or expiry. This is
    // intentional: CloudFront Functions have a 1ms execution budget which
    // rules out HMAC/RSA crypto, and the authoritative validation happens at
    // the NHP server and the protected backend. This gate exists purely to
    // force unauthenticated users through the QURL auth flow before they can
    // request the origin. An attacker with a forged-structure token will be
    // rejected by the real JWT validation downstream.
    var tokenCookie = cookies[COOKIE_NAME];
    if (tokenCookie && tokenCookie.value) {
        var val = tokenCookie.value;
        var parts = val.split('.');
        if (
            val.length >= MIN_JWT_LENGTH &&
            parts.length === 3 &&
            JWT_SEGMENT_RE.test(parts[0]) &&
            JWT_SEGMENT_RE.test(parts[1]) &&
            JWT_SEGMENT_RE.test(parts[2])
        ) {
            // Token has valid JWT structure — allow the request through.
            // We intentionally do NOT log on the happy path: CloudFront
            // Function logs go to CloudWatch and incur per-request cost, and
            // a status page can take heavy traffic during incidents. The
            // redirect/loop/403 paths below are the ones worth logging.
            return request;
        }
        console.log('nhp_auth: token cookie present but malformed, treating as unauthenticated');
    }

    // If we already tried to authenticate recently and still arrived here
    // without a cookie, we're in a redirect loop. Break it with a 403 so
    // the user sees a useful error instead of an infinite bounce.
    // Note: in a viewer-request handler, cookies on generated responses are
    // set via the Set-Cookie header rather than response.cookies (that field
    // is for viewer-response events only).
    var attemptCookie = cookies[LOOP_COOKIE];
    if (attemptCookie && attemptCookie.value === '1') {
        console.log('nhp_auth: loop detected, returning 403 for ' + uri);
        return {
            statusCode: 403,
            statusDescription: 'Forbidden',
            headers: {
                'content-type': { value: 'text/plain; charset=utf-8' },
                'cache-control': { value: 'no-store, no-cache, must-revalidate' },
                'x-content-type-options': { value: 'nosniff' },
                'x-frame-options': { value: 'DENY' },
                'referrer-policy': { value: 'no-referrer' },
                // Clear the breadcrumb so the user can retry on the next visit.
                'set-cookie': { value: LOOP_COOKIE + '=; Max-Age=0; HttpOnly; Secure; SameSite=Strict; Path=/' }
            },
            body: 'Authentication failed: no ' + COOKIE_NAME + ' cookie after QURL redirect. ' +
                  'This usually means the cookie domain does not cover this host. ' +
                  'Please contact support.'
        };
    }

    // No valid auth cookie — redirect to QURL login portal.
    // The QURL link URL contains an access token fragment that starts the
    // NHP authentication flow. After authentication, the resolve endpoint
    // sets cookies and redirects back to the protected resource (this status page).
    // Also set a short-lived breadcrumb cookie so that a subsequent
    // unauthenticated hit is recognized as a loop and surfaces a 403.
    console.log('nhp_auth: no valid token, redirecting ' + uri + ' to QURL');
    var response = {
        statusCode: 302,
        statusDescription: 'Found',
        headers: {
            'location': { value: QURL_URL },
            'cache-control': { value: 'no-store, no-cache, must-revalidate' },
            'set-cookie': {
                value: LOOP_COOKIE + '=1; Max-Age=' + LOOP_COOKIE_MAX_AGE + '; HttpOnly; Secure; SameSite=Strict; Path=/'
            }
        }
    };

    return response;
}
