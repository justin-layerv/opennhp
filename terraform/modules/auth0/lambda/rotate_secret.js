/**
 * Auth0 M2M Client Secret Rotation Lambda
 *
 * Implements the AWS Secrets Manager 4-step rotation protocol for Auth0 M2M client secrets.
 * Uses the Auth0 Management API to rotate the client secret, then tests the new credentials
 * against the token endpoint before finalizing the rotation.
 *
 * Environment variables:
 *   AUTH0_DOMAIN - Auth0 tenant domain (e.g., dev-xxx.us.auth0.com)
 *   AUTH0_MANAGEMENT_SECRET_ARN - Secrets Manager ARN for Management API credentials
 *   AUTH0_API_AUDIENCE - API audience for testing new credentials (optional, defaults from secret)
 *   AUTH0_CLEANUP_OLD_CREDENTIALS - Set to "true" to delete old credentials after rotation (optional, default: false)
 *
 * Rotation protocol steps:
 *   1. createSecret - Get new secret from Auth0 Management API, store as AWSPENDING
 *   2. setSecret - N/A (Auth0 handles this atomically when generating new secret)
 *   3. testSecret - Verify new credentials work against Auth0 token endpoint
 *   4. finishSecret - Promote AWSPENDING to AWSCURRENT, optionally clean up old credentials
 *
 * Auth0 Credential Management:
 *   Each rotation creates a new credential via POST /api/v2/clients/{id}/credentials.
 *   Auth0 allows multiple credentials per client (up to 2 by default for client_secret_post).
 *   Old credentials remain valid until explicitly deleted or the limit is reached.
 *   When the credential limit is reached, Auth0 automatically removes the oldest credential.
 *
 *   When AUTH0_CLEANUP_OLD_CREDENTIALS is "true", the finishSecret step will list all
 *   credentials for the client and delete any that are older than the newly promoted one.
 *   This shortens the window where old credentials remain valid. Cleanup failures are
 *   logged but do not fail the rotation -- the rotation is already complete at that point.
 */

const {
  SecretsManagerClient,
  GetSecretValueCommand,
  PutSecretValueCommand,
  UpdateSecretVersionStageCommand,
  DescribeSecretCommand,
} = require("@aws-sdk/client-secrets-manager");
const https = require("https");

/**
 * Sanitizes an error response for logging by extracting only safe fields.
 * Prevents leaking sensitive data like tokens or secrets to CloudWatch logs.
 * @param {Object} response - HTTP response object
 * @returns {string} - Safe error message for logging
 */
function sanitizeErrorResponse(response) {
  // Defensive check for undefined or empty response
  if (!response || !response.body) {
    return `(empty response, status ${response?.statusCode || "unknown"})`;
  }

  try {
    const data = JSON.parse(response.body);
    // Only include known safe Auth0 error fields
    const safeFields = {
      error: data.error,
      error_description: data.error_description,
      statusCode: data.statusCode,
      message: data.message,
    };
    // Filter out undefined values
    const filtered = Object.fromEntries(
      Object.entries(safeFields).filter(([_, v]) => v !== undefined)
    );
    return Object.keys(filtered).length > 0
      ? JSON.stringify(filtered)
      : `(no error details available)`;
  } catch {
    // If we can't parse JSON, return a generic message
    return `(unparseable response, status ${response.statusCode})`;
  }
}

/**
 * Makes an HTTPS request and returns a promise with the response.
 * @param {Object} options - https request options
 * @param {string|null} body - request body (JSON string)
 * @returns {Promise<{statusCode: number, body: string}>}
 */
function httpsRequest(options, body = null) {
  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => {
        resolve({ statusCode: res.statusCode, body: data });
      });
    });

    req.on("error", reject);
    req.setTimeout(30000, () => {
      req.destroy();
      reject(new Error("Request timeout"));
    });

    if (body) {
      req.write(body);
    }
    req.end();
  });
}

/**
 * Gets an Auth0 Management API access token using the management credentials.
 * @param {string} domain - Auth0 domain
 * @param {string} clientId - Management API client ID
 * @param {string} clientSecret - Management API client secret
 * @returns {Promise<string>} - Access token
 */
async function getManagementToken(domain, clientId, clientSecret) {
  const body = JSON.stringify({
    client_id: clientId,
    client_secret: clientSecret,
    audience: `https://${domain}/api/v2/`,
    grant_type: "client_credentials",
  });

  const options = {
    hostname: domain,
    port: 443,
    path: "/oauth/token",
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(body),
    },
  };

  const response = await httpsRequest(options, body);

  if (response.statusCode !== 200) {
    throw new Error(
      `Failed to get management token: ${response.statusCode} - ${sanitizeErrorResponse(response)}`
    );
  }

  const data = JSON.parse(response.body);
  return data.access_token;
}

/**
 * Fetches the Auth0 Management API credentials from Secrets Manager and
 * exchanges them for a Management API access token. Both `createSecret` and
 * the cleanup branch of `finishSecret` need this exact bootstrap.
 *
 * Throws if the secret is missing client_id/client_secret or if the token
 * exchange fails. Callers in non-fatal contexts (e.g. finishSecret cleanup)
 * are expected to wrap the call in try/catch.
 *
 * @param {Object} client - SecretsManagerClient
 * @param {string} auth0Domain - Auth0 tenant domain
 * @param {string} managementSecretArn - ARN of the secret containing
 *   Management API client_id and client_secret
 * @returns {Promise<string>} - Management API access token
 */
async function getManagementTokenFromSecret(client, auth0Domain, managementSecretArn) {
  const managementSecretResponse = await client.send(
    new GetSecretValueCommand({
      SecretId: managementSecretArn,
    })
  );
  const managementCreds = JSON.parse(managementSecretResponse.SecretString);

  if (!managementCreds.client_id || !managementCreds.client_secret) {
    throw new Error("Management secret is missing client_id or client_secret");
  }

  return getManagementToken(
    auth0Domain,
    managementCreds.client_id,
    managementCreds.client_secret
  );
}

/**
 * Rotates an Auth0 client secret using the Management API.
 * POST /api/v2/clients/{clientId}/credentials
 * @param {string} domain - Auth0 domain
 * @param {string} managementToken - Management API access token
 * @param {string} clientId - Client ID to rotate secret for
 * @returns {Promise<{clientSecret: string, credentialId: string}>} - New client secret and credential ID
 */
async function rotateClientSecret(domain, managementToken, clientId) {
  const body = JSON.stringify({
    credential_type: "client_secret_post",
  });

  const options = {
    hostname: domain,
    port: 443,
    path: `/api/v2/clients/${clientId}/credentials`,
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${managementToken}`,
      "Content-Length": Buffer.byteLength(body),
    },
  };

  const response = await httpsRequest(options, body);

  if (response.statusCode !== 201 && response.statusCode !== 200) {
    throw new Error(
      `Failed to rotate client secret: ${response.statusCode} - ${sanitizeErrorResponse(response)}`
    );
  }

  const data = JSON.parse(response.body);

  if (!data.client_secret) {
    const safeResponse = { id: data.id, credential_type: data.credential_type };
    throw new Error(
      `Auth0 did not return a client_secret in response: ${JSON.stringify(safeResponse)}`
    );
  }

  return { clientSecret: data.client_secret, credentialId: data.id };
}

/**
 * Lists all credentials for an Auth0 client.
 * GET /api/v2/clients/{clientId}/credentials
 *
 * `per_page=100` is set explicitly so the implementation does not silently
 * depend on Auth0's default page size if the per-client credential cap ever
 * grows beyond the current default of 2.
 *
 * @param {string} domain - Auth0 domain
 * @param {string} managementToken - Management API access token
 * @param {string} clientId - Client ID to list credentials for
 * @returns {Promise<Array<{id: string, credential_type: string, created_at: string}>>}
 */
async function listClientCredentials(domain, managementToken, clientId) {
  const options = {
    hostname: domain,
    port: 443,
    path: `/api/v2/clients/${clientId}/credentials?per_page=100&include_totals=false`,
    method: "GET",
    headers: {
      Authorization: `Bearer ${managementToken}`,
    },
  };

  const response = await httpsRequest(options);

  if (response.statusCode !== 200) {
    throw new Error(
      `Failed to list client credentials: ${response.statusCode} - ${sanitizeErrorResponse(response)}`
    );
  }

  return JSON.parse(response.body);
}

/**
 * Deletes a specific credential from an Auth0 client.
 * DELETE /api/v2/clients/{clientId}/credentials/{credentialId}
 *
 * Idempotent: 404 is treated as success because it means the credential is
 * already gone, which is what the caller wanted. This makes retried cleanup
 * runs (e.g. when finishSecret is re-invoked after a previous partial
 * cleanup) safe and avoids needlessly noisy error logs.
 *
 * @param {string} domain - Auth0 domain
 * @param {string} managementToken - Management API access token
 * @param {string} clientId - Client ID
 * @param {string} credentialId - Credential ID to delete
 * @returns {Promise<void>}
 */
async function deleteClientCredential(domain, managementToken, clientId, credentialId) {
  const options = {
    hostname: domain,
    port: 443,
    path: `/api/v2/clients/${clientId}/credentials/${credentialId}`,
    method: "DELETE",
    headers: {
      Authorization: `Bearer ${managementToken}`,
    },
  };

  const response = await httpsRequest(options);

  if (response.statusCode === 204 || response.statusCode === 200) {
    return;
  }
  if (response.statusCode === 404) {
    console.log(
      `deleteClientCredential: credential ${credentialId} already absent (404), treating as success`
    );
    return;
  }

  throw new Error(
    `Failed to delete credential ${credentialId}: ${response.statusCode} - ${sanitizeErrorResponse(response)}`
  );
}

/**
 * Pure helper that decides which credentials to delete and which to keep.
 *
 * Preferred strategy: if `newCredentialId` is present in the list, keep that
 * one and delete every other entry. This is robust against clock skew between
 * Auth0 and Lambda, and against any credential created by another process
 * between rotation and cleanup.
 *
 * Fallback strategy (when `newCredentialId` is unknown or not in the list,
 * e.g. for legacy secrets that pre-date credential_id tracking): keep the
 * credential with the newest `created_at` and delete everything else with a
 * known timestamp. Credentials missing `created_at` are NEVER deleted in the
 * fallback path because their age cannot be ranked.
 *
 * Returns a plain object describing the decision so callers can both act on
 * it and log/test it without re-implementing the logic.
 *
 * @param {Array<{id: string, created_at?: string}>} credentials
 * @param {string} [newCredentialId]
 * @returns {{
 *   strategy: 'none' | 'id-match' | 'timestamp-fallback',
 *   keptId: string | null,
 *   toDelete: Array<{id: string, created_at?: string}>,
 *   skipped: Array<{id: string, created_at?: string}>,
 *   reason: string,
 * }}
 */
function decideCredentialCleanup(credentials, newCredentialId) {
  if (!Array.isArray(credentials) || credentials.length <= 1) {
    return {
      strategy: "none",
      keptId: credentials && credentials[0] ? credentials[0].id : null,
      toDelete: [],
      skipped: [],
      reason: "<=1 credential present",
    };
  }

  if (newCredentialId) {
    const match = credentials.find((c) => c.id === newCredentialId);
    if (match) {
      return {
        strategy: "id-match",
        keptId: newCredentialId,
        toDelete: credentials.filter((c) => c.id !== newCredentialId),
        skipped: [],
        reason: `keeping rotated credential ${newCredentialId}`,
      };
    }
  }

  // Fallback: keep the newest by created_at, delete everything else with a
  // known timestamp, and explicitly skip credentials with no timestamp so we
  // never blow away an entry whose age we cannot determine.
  const dated = credentials.filter((c) => c.created_at);
  const skipped = credentials.filter((c) => !c.created_at);

  if (dated.length === 0) {
    return {
      strategy: "timestamp-fallback",
      keptId: null,
      toDelete: [],
      skipped,
      reason: "no credentials have created_at, cannot rank by age",
    };
  }

  const sorted = [...dated].sort(
    (a, b) => new Date(b.created_at) - new Date(a.created_at)
  );
  const newest = sorted[0];
  return {
    strategy: "timestamp-fallback",
    keptId: newest.id,
    toDelete: sorted.slice(1),
    skipped,
    reason: `keeping newest credential ${newest.id} by created_at`,
  };
}

/**
 * Cleans up old Auth0 credentials after rotation.
 * Lists all credentials for the client, decides which to delete via
 * decideCredentialCleanup, and issues DELETE calls for each. Prefers matching
 * by `newCredentialId` so we never accidentally delete the credential Secrets
 * Manager just promoted.
 *
 * This is a best-effort operation -- per-credential failures are logged but
 * do not throw, because the rotation itself is already complete at this point.
 *
 * @param {string} domain - Auth0 domain
 * @param {string} managementToken - Management API access token
 * @param {string} clientId - Client ID to clean up credentials for
 * @param {string} [newCredentialId] - Credential ID of the just-rotated secret.
 *   When provided, this credential is always preserved and all others are
 *   deleted. When absent, falls back to timestamp-based "keep newest" logic.
 */
async function cleanupOldCredentials(domain, managementToken, clientId, newCredentialId) {
  const credentials = await listClientCredentials(domain, managementToken, clientId);

  if (!newCredentialId) {
    console.warn(
      "cleanupOldCredentials: newCredentialId missing (likely a pre-credential-id secret), " +
        "falling back to timestamp-based cleanup"
    );
  }

  const decision = decideCredentialCleanup(credentials, newCredentialId);

  if (decision.strategy === "none") {
    console.log(`cleanupOldCredentials: Nothing to clean up (${decision.reason})`);
    return;
  }

  if (decision.strategy === "timestamp-fallback" && newCredentialId) {
    console.warn(
      `cleanupOldCredentials: newCredentialId ${newCredentialId} not found in credential list, ` +
        `falling back to timestamp-based cleanup`
    );
  }

  if (decision.skipped.length > 0) {
    console.warn(
      `cleanupOldCredentials: ${decision.skipped.length} credential(s) missing created_at ` +
        `(ids: ${decision.skipped.map((c) => c.id).join(", ")}), skipping them`
    );
  }

  if (decision.toDelete.length === 0) {
    console.log(
      `cleanupOldCredentials: Nothing to delete (${decision.reason})`
    );
    return;
  }

  console.log(
    `cleanupOldCredentials: Strategy=${decision.strategy}, ${decision.reason}, ` +
      `deleting ${decision.toDelete.length} old credential(s)`
  );

  let deleted = 0;
  let failed = 0;
  for (const cred of decision.toDelete) {
    try {
      await deleteClientCredential(domain, managementToken, clientId, cred.id);
      deleted += 1;
      console.log(
        `cleanupOldCredentials: Deleted credential ${cred.id} (created ${cred.created_at || "unknown"})`
      );
    } catch (err) {
      failed += 1;
      console.error(
        `cleanupOldCredentials: Failed to delete credential ${cred.id}: ${err.message}`
      );
    }
  }

  // Summary log makes CloudWatch analysis easier than counting individual
  // delete log lines.
  console.log(
    `cleanupOldCredentials: Completed - deleted ${deleted}/${decision.toDelete.length} credential(s)` +
      (failed > 0 ? `, ${failed} failed` : "")
  );
}

/**
 * Tests Auth0 credentials by attempting to get a token.
 * @param {string} domain - Auth0 domain
 * @param {string} clientId - Client ID
 * @param {string} clientSecret - Client secret to test
 * @param {string} audience - API audience
 * @returns {Promise<boolean>} - True if credentials work
 */
async function testCredentials(domain, clientId, clientSecret, audience) {
  const body = JSON.stringify({
    client_id: clientId,
    client_secret: clientSecret,
    audience: audience,
    grant_type: "client_credentials",
  });

  const options = {
    hostname: domain,
    port: 443,
    path: "/oauth/token",
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(body),
    },
  };

  const response = await httpsRequest(options, body);

  if (response.statusCode === 200) {
    const data = JSON.parse(response.body);
    return !!data.access_token;
  }

  console.log(`Test credentials failed: ${response.statusCode} - ${sanitizeErrorResponse(response)}`);
  return false;
}

/**
 * Lambda handler for Secrets Manager rotation.
 * @param {Object} event - Rotation event from Secrets Manager
 * @param {Object} context - Lambda context
 */
exports.handler = async (event, context) => {
  // Log only safe event fields - avoid logging any potentially sensitive data
  const safeEvent = {
    SecretId: event.SecretId,
    Step: event.Step,
    ClientRequestToken: event.ClientRequestToken ? "[REDACTED]" : undefined,
  };
  console.log("Rotation event:", JSON.stringify(safeEvent, null, 2));

  const client = new SecretsManagerClient({});
  const secretId = event.SecretId;
  const step = event.Step;
  const token = event.ClientRequestToken;

  const auth0Domain = process.env.AUTH0_DOMAIN;
  const managementSecretArn = process.env.AUTH0_MANAGEMENT_SECRET_ARN;

  if (!auth0Domain) {
    throw new Error("AUTH0_DOMAIN environment variable is required");
  }
  if (!managementSecretArn) {
    throw new Error("AUTH0_MANAGEMENT_SECRET_ARN environment variable is required");
  }

  switch (step) {
    case "createSecret":
      await createSecret(client, secretId, token, auth0Domain, managementSecretArn);
      break;

    case "setSecret":
      // Auth0 handles this atomically when we create the new credential
      console.log("setSecret: No action needed - Auth0 applies new secret atomically");
      break;

    case "testSecret":
      await testSecret(client, secretId, token, auth0Domain);
      break;

    case "finishSecret":
      await finishSecret(client, secretId, token, auth0Domain, managementSecretArn);
      break;

    default:
      throw new Error(`Unknown step: ${step}`);
  }

  return { statusCode: 200 };
};

/**
 * createSecret step: Generate new secret via Auth0 Management API and store as AWSPENDING.
 */
async function createSecret(client, secretId, token, auth0Domain, managementSecretArn) {
  // Check if AWSPENDING already exists for this token
  try {
    await client.send(
      new GetSecretValueCommand({
        SecretId: secretId,
        VersionStage: "AWSPENDING",
        VersionId: token,
      })
    );
    console.log("createSecret: AWSPENDING already exists for this token, skipping");
    return;
  } catch (err) {
    if (err.name !== "ResourceNotFoundException") {
      throw err;
    }
    // AWSPENDING doesn't exist, continue with creation
  }

  // Get current secret to extract client_id and audience
  const currentSecretResponse = await client.send(
    new GetSecretValueCommand({
      SecretId: secretId,
      VersionStage: "AWSCURRENT",
    })
  );
  const currentSecret = JSON.parse(currentSecretResponse.SecretString);

  if (!currentSecret.client_id) {
    throw new Error("Current secret is missing client_id");
  }

  console.log("createSecret: Getting Auth0 Management API token...");
  const managementToken = await getManagementTokenFromSecret(
    client,
    auth0Domain,
    managementSecretArn
  );

  // Rotate the client secret
  console.log(`createSecret: Rotating secret for client ${currentSecret.client_id}...`);
  const { clientSecret: newClientSecret, credentialId: newCredentialId } = await rotateClientSecret(
    auth0Domain,
    managementToken,
    currentSecret.client_id
  );
  console.log(`createSecret: New credential ID: ${newCredentialId}`);

  // Create new secret version with AWSPENDING.
  //
  // Schema (consumed by NHP server, smoke tests, and any caller fetching
  // the secret via SecretsManager):
  //   client_id      - Auth0 M2M client ID (stable across rotations)
  //   client_secret  - the just-minted credential secret
  //   audience       - Auth0 API audience the credential is for
  //   credential_id  - Auth0's internal ID for the just-minted credential.
  //                    Used by finishSecret cleanup to preserve exactly the
  //                    rotated credential and delete all others (id-match
  //                    strategy in decideCredentialCleanup). Operators
  //                    inspecting the secret can ignore this field — it is
  //                    only meaningful to the rotation Lambda itself.
  const newSecret = {
    client_id: currentSecret.client_id,
    client_secret: newClientSecret,
    audience: currentSecret.audience || process.env.AUTH0_API_AUDIENCE,
    credential_id: newCredentialId,
  };

  await client.send(
    new PutSecretValueCommand({
      SecretId: secretId,
      ClientRequestToken: token,
      SecretString: JSON.stringify(newSecret),
      VersionStages: ["AWSPENDING"],
    })
  );

  console.log("createSecret: New secret stored as AWSPENDING");
}

/**
 * testSecret step: Verify the new credentials work against Auth0 token endpoint.
 */
async function testSecret(client, secretId, token, auth0Domain) {
  // Get the pending secret
  const pendingSecretResponse = await client.send(
    new GetSecretValueCommand({
      SecretId: secretId,
      VersionStage: "AWSPENDING",
      VersionId: token,
    })
  );
  const pendingSecret = JSON.parse(pendingSecretResponse.SecretString);

  if (!pendingSecret.client_id || !pendingSecret.client_secret) {
    throw new Error("Pending secret is missing client_id or client_secret");
  }

  if (!pendingSecret.audience) {
    throw new Error("Pending secret is missing audience");
  }

  console.log(`testSecret: Testing credentials for client ${pendingSecret.client_id}...`);

  const isValid = await testCredentials(
    auth0Domain,
    pendingSecret.client_id,
    pendingSecret.client_secret,
    pendingSecret.audience
  );

  if (!isValid) {
    throw new Error("testSecret: New credentials failed validation against Auth0 token endpoint");
  }

  console.log("testSecret: New credentials validated successfully");
}

/**
 * finishSecret step: Promote AWSPENDING to AWSCURRENT, then optionally clean up
 * old Auth0 credentials if AUTH0_CLEANUP_OLD_CREDENTIALS is "true".
 *
 * Idempotency note: cleanup runs even when the promotion is a no-op (token
 * already AWSCURRENT). This ensures that a retried finishSecret invocation —
 * which can happen when a previous attempt's cleanup failed silently and was
 * the only chance to remove old credentials — still gets a chance to drain
 * stale credentials. Cleanup itself is idempotent: deleteClientCredential
 * explicitly treats 404 as success so re-deleting a missing credential is a
 * no-op rather than a logged error.
 */
async function finishSecret(client, secretId, token, auth0Domain, managementSecretArn) {
  // Get secret metadata to find current version
  const describeResponse = await client.send(
    new DescribeSecretCommand({
      SecretId: secretId,
    })
  );

  const versionIdsToStages = describeResponse.VersionIdsToStages || {};

  // Find the current version
  let currentVersionId = null;
  let alreadyPromoted = false;
  for (const [versionId, stages] of Object.entries(versionIdsToStages)) {
    if (stages.includes("AWSCURRENT")) {
      if (versionId === token) {
        console.log("finishSecret: Token already marked as AWSCURRENT, skipping promotion");
        alreadyPromoted = true;
      } else {
        currentVersionId = versionId;
      }
      break;
    }
  }

  if (!alreadyPromoted) {
    // Move AWSCURRENT from old version to new version
    await client.send(
      new UpdateSecretVersionStageCommand({
        SecretId: secretId,
        VersionStage: "AWSCURRENT",
        MoveToVersionId: token,
        RemoveFromVersionId: currentVersionId,
      })
    );

    console.log("finishSecret: Rotation completed - AWSPENDING promoted to AWSCURRENT");
  }

  // Optionally clean up old Auth0 credentials.
  // Strict string comparison: only the lowercase string "true" enables cleanup.
  // Values like "TRUE", "1", or "yes" are intentionally rejected to make the
  // security-sensitive setting unambiguous.
  const cleanupEnabled = process.env.AUTH0_CLEANUP_OLD_CREDENTIALS === "true";
  if (!cleanupEnabled) {
    console.log("finishSecret: Credential cleanup disabled (AUTH0_CLEANUP_OLD_CREDENTIALS != 'true')");
    return;
  }

  console.log("finishSecret: Credential cleanup enabled, removing old credentials...");

  try {
    // Get the promoted secret to extract client_id
    const promotedSecretResponse = await client.send(
      new GetSecretValueCommand({
        SecretId: secretId,
        VersionStage: "AWSCURRENT",
      })
    );
    const promotedSecret = JSON.parse(promotedSecretResponse.SecretString);

    if (!promotedSecret.client_id) {
      console.error("finishSecret: Cannot clean up credentials - promoted secret missing client_id");
      return;
    }

    if (!promotedSecret.credential_id) {
      console.warn(
        "finishSecret: Promoted secret missing credential_id (likely a legacy secret " +
          "created before credential ID tracking). Cleanup will fall back to " +
          "timestamp-based 'keep newest' logic."
      );
    }

    const managementToken = await getManagementTokenFromSecret(
      client,
      auth0Domain,
      managementSecretArn
    );

    await cleanupOldCredentials(auth0Domain, managementToken, promotedSecret.client_id, promotedSecret.credential_id);

    console.log("finishSecret: Credential cleanup completed");
  } catch (err) {
    // Cleanup failure must not fail the rotation
    console.error(`finishSecret: Credential cleanup failed (non-fatal): ${err.message}`);
  }
}

// Export internal functions for testing
if (process.env.NODE_ENV === "test") {
  exports._test = {
    sanitizeErrorResponse,
    cleanupOldCredentials,
    decideCredentialCleanup,
    finishSecret,
  };
}
