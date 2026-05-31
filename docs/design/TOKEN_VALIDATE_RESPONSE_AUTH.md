# Token Validate Response Authentication

`POST /nhp/internal/token/validate` supports nonce-bound response authentication for callers that need to trust the token-validation body across an internal HTTP hop.

## Wire Contract

- A caller opts in by sending `X-Nhp-Nonce`.
- The nonce must be exactly 32 lowercase hexadecimal characters.
- The request must still pass the normal `X-Nhp-Auth` request HMAC check.
- When request auth succeeds and the nonce is well formed, the server returns `X-Nhp-Auth` over:
  - method: `POST`
  - path: `/nhp/internal/token/validate/response/<nonce>`
  - body: the exact JSON bytes written to the wire
- Callers that omit the nonce keep receiving legacy unsigned responses during rollout.
- Pre-auth rejects, strict request-auth rejects, permit-mode unverified requests, malformed nonces, marshal failures, and signer-unavailable failures are intentionally unsigned.
- The endpoint does not apply response compression. Verifiers should request `Accept-Encoding: identity`; if compression is ever introduced, the server and verifier must coordinate so the signed bytes and verified bytes are identical.

The response signing path is not an HTTP route. It exists only to separate response signatures from request signatures and to bind the response to the caller's in-flight nonce.

## Verifier Obligations

The server validates nonce shape, not nonce uniqueness. Replay resistance depends on the verifier:

- Generate a fresh single-use nonce for every validation request.
- Retain the nonce locally and verify the response against that locally retained value.
- Reject any nonce-bearing response that is missing or fails `X-Nhp-Auth`, including unsigned 500s.
- Verify the signature over the exact response bytes before trusting `valid`, `owner_id`, `expires_at`, or any other response field.
- Treat the HTTP status as outside the signature. A verifier may still fail closed on non-200 status, but trust decisions must come from the signed JSON body, not status alone.
- Treat nonce-header tampering as fail-closed denial of service. The request HMAC does not cover `X-Nhp-Nonce`, so a hop can make nhp-server sign a different nonce, but the verifier must check against its locally retained nonce and reject the mismatch.
- Treat an empty or stripped nonce response as unsigned legacy output and reject it when the verifier opted in with a non-empty nonce. In permit mode, a request-auth failure with a nonce is also unsigned; an opted-in verifier therefore fails closed even while NHP still permits unverified callers for rollout.
- Keep verifier and server clocks within `internalauth.DefaultMaxClockSkew`; response signatures carry the server timestamp, so skew failures are fail-closed and should be triaged as clock sync before assuming body tamper.

A signed non-200 response is valid evidence that nhp-server produced that error body. It is not a successful validation result. The paired qurl verifier verifies signed non-200 bodies for audit fidelity, including the operationally common 503 `token store unavailable` path, then still treats the non-200 status as a validator transport failure.

## Server-Side Semantics

After request HMAC verification succeeds and the nonce is valid, downstream validation and store errors are signed too. This includes invalid JSON, missing token, overlong `agent_run_id`, invalid token responses, expired token responses, and token-store unavailability. Signing those bodies prevents an internal path-positioned tamper point from forging the error payload.

The response signature uses the same shared internal-auth secret as request auth. It protects against tamper by a hop that lacks the secret; it does not protect against a compromised authenticated caller that already has the shared secret.

`MetricInternalAuthSuccess` means request HMAC verification succeeded. It is intentionally emitted before response-nonce validation, so an authenticated caller that sends a malformed opt-in nonce increments success, increments `MetricInternalTokenValidateBadNonce`, and receives an unsigned 400. The success, strict-fail, and permit-fail counters remain mutually exclusive request-auth metrics rather than endpoint-outcome metrics; the bad-nonce counter is the rollout signal for verifier nonce-shape mistakes.

If request auth fails in permit mode, nonce validation is skipped and the response remains unsigned; dashboards should attribute that case to `MetricInternalAuthFailPermit`, not `MetricInternalTokenValidateBadNonce`.
