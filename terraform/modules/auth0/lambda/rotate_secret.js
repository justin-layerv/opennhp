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
 *
 * Rotation protocol steps:
 *   1. createSecret - Get new secret from Auth0 Management API, store as AWSPENDING
 *   2. setSecret - N/A (Auth0 handles this atomically when generating new secret)
 *   3. testSecret - Verify new credentials work against Auth0 token endpoint
 *   4. finishSecret - Promote AWSPENDING to AWSCURRENT
 *
 * Auth0 Credential Management:
 *   Each rotation creates a new credential via POST /api/v2/clients/{id}/credentials.
 *   Auth0 allows multiple credentials per client (up to 2 by default for client_secret_post).
 *   Old credentials remain valid until explicitly deleted or the limit is reached.
 *   When the credential limit is reached, Auth0 automatically removes the oldest credential.
 *   This behavior is acceptable for rotation as it provides a brief overlap period where
 *   both old and new credentials work, ensuring zero-downtime rotation.
 *
 *   To manually clean up old credentials, use the Auth0 Management API:
 *     DELETE /api/v2/clients/{clientId}/credentials/{credentialId}
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
 * Rotates an Auth0 client secret using the Management API.
 * POST /api/v2/clients/{clientId}/credentials
 * @param {string} domain - Auth0 domain
 * @param {string} managementToken - Management API access token
 * @param {string} clientId - Client ID to rotate secret for
 * @returns {Promise<string>} - New client secret
 */
async function rotateClientSecret(domain, managementToken, clientId) {
  // Auth0 requires a POST to /clients/{id}/credentials to generate a new credential
  // This creates a new client_secret_post credential
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

  // The response contains the new credential with client_secret
  if (!data.client_secret) {
    // Log only safe fields from the response
    const safeResponse = { id: data.id, credential_type: data.credential_type };
    throw new Error(
      `Auth0 did not return a client_secret in response: ${JSON.stringify(safeResponse)}`
    );
  }

  return data.client_secret;
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
      await finishSecret(client, secretId, token);
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

  // Get management credentials
  const managementSecretResponse = await client.send(
    new GetSecretValueCommand({
      SecretId: managementSecretArn,
    })
  );
  const managementCreds = JSON.parse(managementSecretResponse.SecretString);

  if (!managementCreds.client_id || !managementCreds.client_secret) {
    throw new Error("Management secret is missing client_id or client_secret");
  }

  // Get management token
  console.log("createSecret: Getting Auth0 Management API token...");
  const managementToken = await getManagementToken(
    auth0Domain,
    managementCreds.client_id,
    managementCreds.client_secret
  );

  // Rotate the client secret
  console.log(`createSecret: Rotating secret for client ${currentSecret.client_id}...`);
  const newClientSecret = await rotateClientSecret(
    auth0Domain,
    managementToken,
    currentSecret.client_id
  );

  // Create new secret version with AWSPENDING
  const newSecret = {
    client_id: currentSecret.client_id,
    client_secret: newClientSecret,
    audience: currentSecret.audience || process.env.AUTH0_API_AUDIENCE,
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
 * finishSecret step: Promote AWSPENDING to AWSCURRENT.
 */
async function finishSecret(client, secretId, token) {
  // Get secret metadata to find current version
  const describeResponse = await client.send(
    new DescribeSecretCommand({
      SecretId: secretId,
    })
  );

  const versionIdsToStages = describeResponse.VersionIdsToStages || {};

  // Find the current version
  let currentVersionId = null;
  for (const [versionId, stages] of Object.entries(versionIdsToStages)) {
    if (stages.includes("AWSCURRENT")) {
      if (versionId === token) {
        console.log("finishSecret: Token already marked as AWSCURRENT, nothing to do");
        return;
      }
      currentVersionId = versionId;
      break;
    }
  }

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
