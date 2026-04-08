/**
 * Tests for Auth0 M2M Client Secret Rotation Lambda - Credential Cleanup
 *
 * Run with: node --test terraform/modules/auth0/lambda/rotate_secret.test.js
 *
 * Mocks the AWS SDK since it's only available in the Lambda runtime.
 */

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const Module = require("node:module");

// ---------------------------------------------------------------------------
// Mock AWS SDK before loading the module under test
// ---------------------------------------------------------------------------

const originalResolveFilename = Module._resolveFilename;
Module._resolveFilename = function (request, parent, isMain, options) {
  if (request === "@aws-sdk/client-secrets-manager") {
    // Return a fake path that we'll intercept in _cache
    return "__mock_aws_sdk__";
  }
  return originalResolveFilename.call(this, request, parent, isMain, options);
};

// Pre-populate the module cache with mock SDK classes
require.cache["__mock_aws_sdk__"] = {
  id: "__mock_aws_sdk__",
  filename: "__mock_aws_sdk__",
  loaded: true,
  exports: {
    SecretsManagerClient: class MockSecretsManagerClient {
      send() { return Promise.resolve({}); }
    },
    GetSecretValueCommand: class MockGetSecretValueCommand {
      constructor(params) { this.params = params; }
    },
    PutSecretValueCommand: class MockPutSecretValueCommand {
      constructor(params) { this.params = params; }
    },
    UpdateSecretVersionStageCommand: class MockUpdateSecretVersionStageCommand {
      constructor(params) { this.params = params; }
    },
    DescribeSecretCommand: class MockDescribeSecretCommand {
      constructor(params) { this.params = params; }
    },
  },
};

// Set test environment before loading module
process.env.NODE_ENV = "test";
process.env.AUTH0_DOMAIN = "test.us.auth0.com";
process.env.AUTH0_MANAGEMENT_SECRET_ARN = "arn:aws:secretsmanager:us-east-1:123456789:secret:mgmt";
process.env.AUTH0_API_AUDIENCE = "https://api.test.com";

const mod = require("./rotate_secret");
const {
  sanitizeErrorResponse,
  cleanupOldCredentials,
  decideCredentialCleanup,
  finishSecret,
} = mod._test;

// Restore original resolve after loading
Module._resolveFilename = originalResolveFilename;

// ---------------------------------------------------------------------------
// sanitizeErrorResponse
// ---------------------------------------------------------------------------

describe("sanitizeErrorResponse", () => {
  it("handles null response", () => {
    const result = sanitizeErrorResponse(null);
    assert.match(result, /empty response/);
  });

  it("handles response with no body", () => {
    const result = sanitizeErrorResponse({ statusCode: 500 });
    assert.match(result, /empty response.*500/);
  });

  it("extracts only safe error fields from JSON body", () => {
    const response = {
      statusCode: 400,
      body: JSON.stringify({
        error: "invalid_grant",
        error_description: "Bad credentials",
        secret_data: "SHOULD_NOT_APPEAR",
      }),
    };
    const result = sanitizeErrorResponse(response);
    const parsed = JSON.parse(result);
    assert.equal(parsed.error, "invalid_grant");
    assert.equal(parsed.error_description, "Bad credentials");
    assert.equal(parsed.secret_data, undefined);
  });

  it("handles unparseable body", () => {
    const result = sanitizeErrorResponse({ statusCode: 502, body: "not json" });
    assert.match(result, /unparseable/);
  });

  it("returns no details for empty JSON error", () => {
    const result = sanitizeErrorResponse({ statusCode: 500, body: "{}" });
    assert.match(result, /no error details/);
  });
});

// ---------------------------------------------------------------------------
// decideCredentialCleanup — pure decision function exercised end-to-end
// ---------------------------------------------------------------------------

describe("decideCredentialCleanup", () => {
  it("returns 'none' for empty list", () => {
    const result = decideCredentialCleanup([], "cred-1");
    assert.equal(result.strategy, "none");
    assert.equal(result.toDelete.length, 0);
  });

  it("returns 'none' for non-array input", () => {
    const result = decideCredentialCleanup(undefined, "cred-1");
    assert.equal(result.strategy, "none");
    assert.equal(result.toDelete.length, 0);
  });

  it("returns 'none' for single credential and exposes its id", () => {
    const result = decideCredentialCleanup(
      [{ id: "cred-only", created_at: "2024-01-01T00:00:00.000Z" }],
      "cred-only"
    );
    assert.equal(result.strategy, "none");
    assert.equal(result.keptId, "cred-only");
    assert.equal(result.toDelete.length, 0);
  });

  it("uses id-match strategy and deletes everything else when newCredentialId is present", () => {
    // Includes a credential created AFTER the rotated one to verify we do
    // not fall back to timestamp logic when the rotated id is found.
    const credentials = [
      { id: "cred-stale", created_at: "2024-01-01T00:00:00.000Z" },
      { id: "cred-rotated", created_at: "2024-06-15T12:00:00.000Z" },
      { id: "cred-newer-race", created_at: "2024-06-15T12:00:05.000Z" },
    ];
    const result = decideCredentialCleanup(credentials, "cred-rotated");
    assert.equal(result.strategy, "id-match");
    assert.equal(result.keptId, "cred-rotated");
    const ids = result.toDelete.map((c) => c.id).sort();
    assert.deepEqual(ids, ["cred-newer-race", "cred-stale"]);
    assert.equal(result.skipped.length, 0);
  });

  it("falls back to timestamp strategy when newCredentialId is not in the list", () => {
    const credentials = [
      { id: "cred-a", created_at: "2024-01-01T00:00:00.000Z" },
      { id: "cred-b", created_at: "2024-06-15T12:00:00.000Z" },
    ];
    const result = decideCredentialCleanup(credentials, "cred-missing");
    assert.equal(result.strategy, "timestamp-fallback");
    assert.equal(result.keptId, "cred-b");
    assert.equal(result.toDelete.length, 1);
    assert.equal(result.toDelete[0].id, "cred-a");
  });

  it("falls back to timestamp strategy when newCredentialId is omitted", () => {
    const credentials = [
      { id: "cred-old", created_at: "2024-01-01T00:00:00.000Z" },
      { id: "cred-mid", created_at: "2024-03-01T00:00:00.000Z" },
      { id: "cred-new", created_at: "2024-06-15T12:00:00.000Z" },
    ];
    const result = decideCredentialCleanup(credentials);
    assert.equal(result.strategy, "timestamp-fallback");
    assert.equal(result.keptId, "cred-new");
    const deletedIds = result.toDelete.map((c) => c.id).sort();
    assert.deepEqual(deletedIds, ["cred-mid", "cred-old"]);
  });

  it("never deletes credentials that are missing created_at in the fallback path", () => {
    const credentials = [
      { id: "cred-no-date" },
      { id: "cred-old", created_at: "2024-01-01T00:00:00.000Z" },
      { id: "cred-new", created_at: "2024-06-15T12:00:00.000Z" },
    ];
    const result = decideCredentialCleanup(credentials);
    assert.equal(result.strategy, "timestamp-fallback");
    assert.equal(result.keptId, "cred-new");
    assert.deepEqual(result.toDelete.map((c) => c.id), ["cred-old"]);
    assert.deepEqual(result.skipped.map((c) => c.id), ["cred-no-date"]);
  });

  it("returns no deletes when fallback finds zero dated credentials", () => {
    const credentials = [
      { id: "cred-no-date-1" },
      { id: "cred-no-date-2" },
    ];
    const result = decideCredentialCleanup(credentials);
    assert.equal(result.strategy, "timestamp-fallback");
    assert.equal(result.keptId, null);
    assert.equal(result.toDelete.length, 0);
    assert.equal(result.skipped.length, 2);
  });
});

// ---------------------------------------------------------------------------
// cleanupOldCredentials — exercises the full function with mocked HTTP layer
// ---------------------------------------------------------------------------

describe("cleanupOldCredentials (HTTP-mocked)", () => {
  // We can't easily monkey-patch listClientCredentials/deleteClientCredential
  // because they are referenced internally by their original closures, but we
  // CAN intercept https.request, which is what they ultimately call. The
  // helper below sets up a fake https.request implementation, drives
  // cleanupOldCredentials, and returns the captured calls.
  function withMockedHttps(fakeHandler, fn) {
    const https = require("node:https");
    const original = https.request;
    const calls = [];
    https.request = function (options, cb) {
      calls.push({ method: options.method, path: options.path });
      // Reset the handler's per-call statusCode to 200 before invoking it,
      // so handlers that override it for a specific path don't leak the
      // status across subsequent unrelated calls.
      fakeHandler.statusCode = 200;
      const body = fakeHandler(options) || "";
      const status = fakeHandler.statusCode;
      // Build a minimal response object the way httpsRequest expects.
      const res = {
        on: function (event, handler) {
          if (event === "data") {
            handler(Buffer.from(body));
          } else if (event === "end") {
            handler();
          }
        },
        statusCode: status,
      };
      // Call the callback synchronously so the request body completes.
      process.nextTick(() => cb(res));
      return {
        on: function () {},
        write: function () {},
        setTimeout: function () {},
        destroy: function () {},
        end: function () {},
      };
    };
    return fn(calls).finally(() => {
      https.request = original;
    });
  }

  it("calls DELETE on every non-rotated credential when newCredentialId matches", async () => {
    const credentials = [
      { id: "cred-old-1", created_at: "2024-01-01T00:00:00.000Z" },
      { id: "cred-rotated", created_at: "2024-06-15T12:00:00.000Z" },
      { id: "cred-old-2", created_at: "2024-02-01T00:00:00.000Z" },
    ];

    const handler = (options) => {
      if (options.method === "GET" && options.path.includes("/credentials")) {
        return JSON.stringify(credentials);
      }
      return "";
    };
    handler.statusCode = 200;

    await withMockedHttps(handler, async (calls) => {
      // DELETE returns 204 in the real Auth0 API; our mock above always
      // returns statusCode 200, which deleteClientCredential also accepts.
      await cleanupOldCredentials("test.auth0.com", "tok", "client-1", "cred-rotated");

      const deletes = calls.filter((c) => c.method === "DELETE");
      const deletedIds = deletes.map((c) => c.path.split("/").pop()).sort();
      assert.deepEqual(deletedIds, ["cred-old-1", "cred-old-2"]);
      // Must NOT have deleted the rotated one.
      assert.ok(!deletedIds.includes("cred-rotated"));
    });
  });

  it("does not throw when DELETE fails for one credential and continues with the rest", async () => {
    const credentials = [
      { id: "cred-rotated", created_at: "2024-06-15T12:00:00.000Z" },
      { id: "cred-fails", created_at: "2024-01-01T00:00:00.000Z" },
      { id: "cred-ok", created_at: "2024-02-01T00:00:00.000Z" },
    ];

    const handler = (options) => {
      if (options.method === "GET") {
        return JSON.stringify(credentials);
      }
      // Simulate one failing DELETE by returning a 500
      if (options.path.endsWith("/cred-fails")) {
        handler.statusCode = 500;
        return JSON.stringify({ error: "boom" });
      }
      handler.statusCode = 200;
      return "";
    };
    handler.statusCode = 200;

    let threw = false;
    await withMockedHttps(handler, async (calls) => {
      try {
        await cleanupOldCredentials("test.auth0.com", "tok", "client-1", "cred-rotated");
      } catch (err) {
        threw = true;
      }
      const deletes = calls.filter((c) => c.method === "DELETE");
      // Both deletes were attempted; the failure was caught and logged.
      const deletedIds = deletes.map((c) => c.path.split("/").pop()).sort();
      assert.deepEqual(deletedIds, ["cred-fails", "cred-ok"]);
    });
    assert.equal(threw, false, "cleanupOldCredentials must swallow per-credential delete failures");
  });

  it("issues no DELETE calls when only the rotated credential exists", async () => {
    const credentials = [
      { id: "cred-rotated", created_at: "2024-06-15T12:00:00.000Z" },
    ];
    const handler = () => JSON.stringify(credentials);
    handler.statusCode = 200;

    await withMockedHttps(handler, async (calls) => {
      await cleanupOldCredentials("test.auth0.com", "tok", "client-1", "cred-rotated");
      const deletes = calls.filter((c) => c.method === "DELETE");
      assert.equal(deletes.length, 0);
    });
  });

  it("treats DELETE 404 as success so retried cleanups stay quiet", async () => {
    // Simulates the retried-finishSecret case: a credential we want to delete
    // is already gone (e.g. another concurrent rotation removed it). The
    // Auth0 API returns 404, which deleteClientCredential must absorb so the
    // overall cleanup keeps going and the rotation isn't logged as "failed".
    const credentials = [
      { id: "cred-rotated", created_at: "2024-06-15T12:00:00.000Z" },
      { id: "cred-already-gone", created_at: "2024-01-01T00:00:00.000Z" },
      { id: "cred-still-here", created_at: "2024-02-01T00:00:00.000Z" },
    ];

    const handler = (options) => {
      if (options.method === "GET") {
        handler.statusCode = 200;
        return JSON.stringify(credentials);
      }
      if (options.path.endsWith("/cred-already-gone")) {
        handler.statusCode = 404;
        return JSON.stringify({ error: "not_found" });
      }
      handler.statusCode = 204;
      return "";
    };
    handler.statusCode = 200;

    let threw = false;
    await withMockedHttps(handler, async (calls) => {
      try {
        await cleanupOldCredentials("test.auth0.com", "tok", "client-1", "cred-rotated");
      } catch (_err) {
        threw = true;
      }
      const deletes = calls.filter((c) => c.method === "DELETE");
      const deletedIds = deletes.map((c) => c.path.split("/").pop()).sort();
      // Both deletes were attempted; the 404 was treated as success.
      assert.deepEqual(deletedIds, ["cred-already-gone", "cred-still-here"]);
    });
    assert.equal(threw, false, "404 from DELETE must not propagate as an error");
  });
});

// ---------------------------------------------------------------------------
// finishSecret idempotency: cleanup must run on retried invocations
// ---------------------------------------------------------------------------

describe("finishSecret idempotency", () => {
  // Build a fake SecretsManagerClient whose send() inspects the command
  // payload and returns a canned response. Captures all sent commands so we
  // can assert behaviour.
  function fakeClient(behaviour) {
    const sent = [];
    return {
      sent,
      send: async function (command) {
        const name = command.constructor.name;
        sent.push({ name, params: command.params });
        if (behaviour[name]) {
          return behaviour[name](command.params);
        }
        return {};
      },
    };
  }

  it("does not call UpdateSecretVersionStage when token is already AWSCURRENT, but still attempts cleanup", async () => {
    process.env.AUTH0_CLEANUP_OLD_CREDENTIALS = "true";
    const token = "version-token-123";

    const client = fakeClient({
      MockDescribeSecretCommand: () => ({
        VersionIdsToStages: {
          [token]: ["AWSCURRENT"],
        },
      }),
      MockGetSecretValueCommand: (params) => {
        if (params.VersionStage === "AWSCURRENT") {
          return {
            SecretString: JSON.stringify({
              client_id: "client-1",
              client_secret: "secret",
              audience: "https://api.test",
              credential_id: "cred-rotated",
            }),
          };
        }
        // Management secret fetch (no VersionStage)
        return {
          SecretString: JSON.stringify({
            client_id: "mgmt-id",
            client_secret: "mgmt-secret",
          }),
        };
      },
    });

    // Stub the Auth0 HTTP layer and record every request so we can assert
    // the cleanup path actually issued the GET /credentials call.
    const https = require("node:https");
    const originalRequest = https.request;
    const httpCalls = [];
    https.request = function (options, cb) {
      httpCalls.push({ method: options.method, path: options.path });
      const res = {
        on: function (event, handler) {
          if (event === "data") {
            if (options.path === "/oauth/token") {
              handler(Buffer.from(JSON.stringify({ access_token: "tok" })));
            } else if (
              options.method === "GET" &&
              options.path.includes("/credentials")
            ) {
              handler(
                Buffer.from(
                  JSON.stringify([
                    { id: "cred-rotated", created_at: "2024-06-15T12:00:00.000Z" },
                  ])
                )
              );
            } else {
              handler(Buffer.from(""));
            }
          } else if (event === "end") {
            handler();
          }
        },
        statusCode: 200,
      };
      process.nextTick(() => cb(res));
      return {
        on: function () {},
        write: function () {},
        setTimeout: function () {},
        destroy: function () {},
        end: function () {},
      };
    };

    try {
      await finishSecret(
        client,
        "secret-arn",
        token,
        "test.us.auth0.com",
        "arn:aws:secretsmanager:us-east-1:123456789:secret:mgmt"
      );
    } finally {
      https.request = originalRequest;
    }

    // Promotion path must NOT have been taken (idempotent path).
    const updates = client.sent.filter(
      (s) => s.name === "MockUpdateSecretVersionStageCommand"
    );
    assert.equal(updates.length, 0, "must not call UpdateSecretVersionStage when token is already AWSCURRENT");

    // Cleanup path must have actually issued a GET to /credentials. This is
    // the regression we're guarding against: before the fix, an early
    // `return` on the idempotent path skipped cleanup entirely. Asserting on
    // the HTTP call (not just on the AWS SDK call) makes the test fail loudly
    // if a future refactor short-circuits the cleanup HTTP path.
    const credentialsListCalls = httpCalls.filter(
      (c) => c.method === "GET" && c.path.includes("/credentials")
    );
    assert.ok(
      credentialsListCalls.length >= 1,
      `expected at least one GET /credentials call on the idempotent cleanup path; saw: ${JSON.stringify(httpCalls)}`
    );
  });
});
