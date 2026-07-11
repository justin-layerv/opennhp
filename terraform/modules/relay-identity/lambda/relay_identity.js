"use strict";

const crypto = require("crypto");
const {
  DescribeSecretCommand,
  GetSecretValueCommand,
  PutSecretValueCommand,
  SecretsManagerClient,
} = require("@aws-sdk/client-secrets-manager");
const { GetParameterCommand, PutParameterCommand, SSMClient } = require("@aws-sdk/client-ssm");

const PRIVATE_DER_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");
const PUBLICATION_CONFIRM_ATTEMPTS = 10;
const PUBLICATION_CONFIRM_INITIAL_DELAY_MS = 100;
const PUBLICATION_CONFIRM_MAX_DELAY_MS = 1000;
const defaultSecrets = new SecretsManagerClient({});
const defaultSsm = new SSMClient({});

class RelayIdentityError extends Error {
  constructor(code) {
    super(code);
    this.name = "RelayIdentityError";
  }
}

function fail(code) {
  // Never interpolate SDK messages or secret payloads into operator-visible
  // errors. The stable code is enough to diagnose the failed operation.
  return new RelayIdentityError(code);
}

function sleep(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function decodeCanonicalKey(value, field) {
  // This prefilter pins length/alphabet only. The encode round-trip below is
  // the canonicality check and rejects non-zero pad bits, matching Terraform's
  // stricter final-character class without duplicating that opaque alphabet.
  if (typeof value !== "string" || !/^[A-Za-z0-9+/]{43}=$/.test(value)) {
    throw fail(`invalid-${field}`);
  }
  const raw = Buffer.from(value, "base64");
  if (raw.length !== 32 || raw.toString("base64") !== value) {
    throw fail(`invalid-${field}`);
  }
  return raw;
}

function validateKeyPair(secretString, expectedEnvironment) {
  let parsed;
  try {
    parsed = JSON.parse(secretString);
  } catch {
    throw fail("invalid-secret-json");
  }
  if (!parsed || parsed.environment !== expectedEnvironment) {
    throw fail("invalid-secret-environment");
  }
  const privateRaw = decodeCanonicalKey(parsed.privateKey, "private-key");
  const publicRaw = decodeCanonicalKey(parsed.publicKey, "public-key");
  let derived;
  try {
    const privateKey = crypto.createPrivateKey({
      key: Buffer.concat([PRIVATE_DER_PREFIX, privateRaw]),
      format: "der",
      type: "pkcs8",
    });
    const publicDer = crypto.createPublicKey(privateKey).export({ format: "der", type: "spki" });
    derived = publicDer.subarray(-32);
  } catch {
    throw fail("invalid-private-key");
  }
  if (!crypto.timingSafeEqual(derived, publicRaw)) {
    throw fail("keypair-mismatch");
  }
  return parsed.publicKey;
}

function generateKeyPair(environment) {
  const pair = crypto.generateKeyPairSync("x25519");
  const privateKey = pair.privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32).toString("base64");
  const publicKey = pair.publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("base64");
  return { privateKey, publicKey, environment };
}

function stageMap(description) {
  return description && description.VersionIdsToStages ? description.VersionIdsToStages : {};
}

function versionForStage(versions, stage) {
  const matches = Object.entries(versions)
    .filter(([, stages]) => Array.isArray(stages) && stages.includes(stage))
    .map(([versionId]) => versionId);
  if (matches.length > 1) {
    throw fail(`multiple-${stage.toLowerCase()}`);
  }
  return matches[0] || null;
}

function requireEvent(event) {
  const action = event && event.Action;
  const props = event && event.ResourceProperties;
  if (!props || typeof props.SecretId !== "string" || typeof props.Environment !== "string" || typeof props.PublicKeyParameter !== "string") {
    throw fail("invalid-event");
  }
  // Intentional runtime defense in depth: Terraform validates configured
  // environments, but invocation payloads cross a separate trust boundary.
  if (!/^(sandbox|prod)$/.test(props.Environment)) {
    throw fail("invalid-environment");
  }
  if (props.PublicKeyParameter !== `/${props.Environment}/nhp/relay/identity/current-public-key`) {
    throw fail("invalid-public-key-parameter");
  }
  if (!["ensure-current", "publish-current", "stage-pending", "status", "confirmed-status"].includes(action)) {
    throw fail("invalid-action");
  }
  return { action, props };
}

async function readVersion(secrets, secretId, environment, versionId, versionStage) {
  let response;
  try {
    response = await secrets.send(new GetSecretValueCommand({
      SecretId: secretId,
      ...(versionId ? { VersionId: versionId } : {}),
      ...(versionStage ? { VersionStage: versionStage } : {}),
    }));
  } catch {
    throw fail("secret-read-failed");
  }
  if (!response || typeof response.SecretString !== "string") {
    throw fail("secret-value-missing");
  }
  return {
    versionId: response.VersionId || versionId || null,
    publicKey: validateKeyPair(response.SecretString, environment),
  };
}

async function describe(secrets, secretId) {
  try {
    return await secrets.send(new DescribeSecretCommand({ SecretId: secretId }));
  } catch {
    throw fail("secret-describe-failed");
  }
}

async function confirmPublished(ssm, parameterName, publicKey, sleepFn, warn) {
  // Parameter Store reads are eventually consistent. Do not authorize the
  // Terraform consumer merely because PutParameter returned success: a read
  // immediately after the write can still return the bootstrap placeholder.
  // Confirm the exact public value with bounded backoff before reporting a
  // successful publication. Read errors stay redacted and consume the same
  // finite budget as stale values. This same-client confirmation narrows but
  // cannot eliminate cross-principal visibility lag. Terraform therefore uses
  // this invocation's validated public-key result rather than racing a second
  // Parameter Store read from another session.
  let readErrorLogged = false;
  for (let attempt = 0; attempt < PUBLICATION_CONFIRM_ATTEMPTS; attempt += 1) {
    try {
      const response = await ssm.send(new GetParameterCommand({ Name: parameterName }));
      if (response && response.Parameter && response.Parameter.Value === publicKey) return;
    } catch {
      // Intentionally treat every GetParameter exception as a retryable read
      // failure. SDK error taxonomies can change; the finite budget, fixed log,
      // and code-only terminal error preserve both diagnosis and fail-closed
      // behavior without reflecting an unexpected exception shape.
      if (!readErrorLogged) {
        // Preserve a diagnostic distinction without reflecting SDK messages,
        // parameter values, or secret material into CloudWatch.
        warn("relay identity public-key confirmation read failed");
        readErrorLogged = true;
      }
    }
    if (attempt + 1 < PUBLICATION_CONFIRM_ATTEMPTS) {
      const delay = Math.min(
        PUBLICATION_CONFIRM_INITIAL_DELAY_MS * (2 ** attempt),
        PUBLICATION_CONFIRM_MAX_DELAY_MS,
      );
      await sleepFn(delay);
    }
  }
  throw fail("public-key-confirmation-failed");
}

async function publish(ssm, parameterName, publicKey, sleepFn, warn) {
  try {
    await ssm.send(new PutParameterCommand({ Name: parameterName, Type: "String", Value: publicKey, Overwrite: true }));
  } catch {
    throw fail("public-key-publish-failed");
  }
  await confirmPublished(ssm, parameterName, publicKey, sleepFn, warn);
}

async function ensureCurrent(secrets, props) {
  const versions = stageMap(await describe(secrets, props.SecretId));
  const currentId = versionForStage(versions, "AWSCURRENT");
  let current;
  if (currentId) {
    current = await readVersion(secrets, props.SecretId, props.Environment, currentId, "AWSCURRENT");
  } else {
    // Generate only after DescribeSecret proves there is no AWSCURRENT. Access,
    // KMS, parse, and validation failures above never enter this branch.
    const value = generateKeyPair(props.Environment);
    try {
      const response = await secrets.send(new PutSecretValueCommand({
        SecretId: props.SecretId,
        SecretString: JSON.stringify(value),
        VersionStages: ["AWSCURRENT"],
      }));
      current = { versionId: response.VersionId || null, publicKey: value.publicKey };
    } catch {
      throw fail("secret-bootstrap-failed");
    }
  }
  return { action: "ensure-current", currentVersionId: current.versionId, currentPublicKey: current.publicKey };
}

async function publishCurrent(secrets, ssm, props, sleepFn, warn) {
  const versions = stageMap(await describe(secrets, props.SecretId));
  const currentId = versionForStage(versions, "AWSCURRENT");
  if (!currentId) {
    // Publishing must never bootstrap or rotate identity. Only the historical
    // keygen action may create the first AWSCURRENT version.
    throw fail("current-version-missing");
  }
  const current = await readVersion(secrets, props.SecretId, props.Environment, currentId, "AWSCURRENT");
  await publish(ssm, props.PublicKeyParameter, current.publicKey, sleepFn, warn);
  return { action: "publish-current", currentVersionId: current.versionId, currentPublicKey: current.publicKey };
}

async function stagePending(secrets, props) {
  const token = props.ClientRequestToken;
  if (typeof token !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(token)) {
    throw fail("invalid-client-request-token");
  }
  const versions = stageMap(await describe(secrets, props.SecretId));
  const currentId = versionForStage(versions, "AWSCURRENT");
  if (!currentId) {
    throw fail("current-version-missing");
  }
  const pendingId = versionForStage(versions, "AWSPENDING");
  if (pendingId) {
    if (pendingId !== token) {
      throw fail("pending-version-conflict");
    }
    const pending = await readVersion(secrets, props.SecretId, props.Environment, token, "AWSPENDING");
    return { action: "stage-pending", currentVersionId: currentId, pendingVersionId: token, pendingPublicKey: pending.publicKey };
  }
  const value = generateKeyPair(props.Environment);
  try {
    await secrets.send(new PutSecretValueCommand({
      SecretId: props.SecretId,
      SecretString: JSON.stringify(value),
      ClientRequestToken: token,
      VersionStages: ["AWSPENDING"],
    }));
  } catch {
    throw fail("pending-stage-failed");
  }
  return { action: "stage-pending", currentVersionId: currentId, pendingVersionId: token, pendingPublicKey: value.publicKey };
}

async function status(secrets, props) {
  const versions = stageMap(await describe(secrets, props.SecretId));
  const result = { action: "status", versions: {} };
  // AWSPREVIOUS is validated as strictly as current/pending on purpose. A
  // rollback target that cannot prove a canonical matching keypair is unsafe
  // identity material and must block rollback rather than merely be surfaced.
  for (const stage of ["AWSCURRENT", "AWSPENDING", "AWSPREVIOUS"]) {
    const versionId = versionForStage(versions, stage);
    if (versionId) {
      const value = await readVersion(secrets, props.SecretId, props.Environment, versionId, stage);
      result.versions[stage] = { versionId, publicKey: value.publicKey };
    }
  }
  return result;
}

async function confirmedStatus(secrets, ssm, props, sleepFn, warn) {
  const result = await status(secrets, props);
  const current = result.versions.AWSCURRENT;
  if (!current) {
    throw fail("current-version-missing");
  }
  // Terraform alone uses this stricter action as its refreshable trust source.
  // Ordinary status must remain introspection-only so the rotation helper can
  // diagnose and repair an intentional partial-promotion SSM mismatch.
  await confirmPublished(ssm, props.PublicKeyParameter, current.publicKey, sleepFn, warn);
  result.action = "confirmed-status";
  return result;
}

async function run(event, clients = {}) {
  const { action, props } = requireEvent(event);
  // Keep confirmed-status exclusive to statusHandler's read-only execution
  // role; the multi-action keygen handler must never become a second entrypoint.
  if (action === "confirmed-status") {
    throw fail("invalid-event");
  }
  const secrets = clients.secrets || defaultSecrets;
  const ssm = clients.ssm || defaultSsm;
  const sleepFn = clients.sleep || sleep;
  const warn = clients.warn || console.warn;
  if (action === "ensure-current") return ensureCurrent(secrets, props);
  if (action === "publish-current") return publishCurrent(secrets, ssm, props, sleepFn, warn);
  if (action === "stage-pending") return stagePending(secrets, props);
  return status(secrets, props);
}

async function handle(event, clients = {}) {
  try {
    const action = event && event.Action;
    console.log("relay identity action", typeof action === "string" ? action : "invalid");
    return await run(event, clients);
  } catch (error) {
    // Only our stable, code-only errors may cross the Lambda boundary. This
    // also protects the invariant if a future runtime path forgets to wrap an
    // SDK error or throws an unexpected TypeError.
    if (error instanceof RelayIdentityError) throw error;
    throw fail("internal-error");
  }
}

async function handleConfirmedStatus(event, clients = {}) {
  try {
    const { action, props } = requireEvent(event);
    if (action !== "confirmed-status") {
      throw fail("invalid-event");
    }
    const secrets = clients.secrets || defaultSecrets;
    const ssm = clients.ssm || defaultSsm;
    const sleepFn = clients.sleep || sleep;
    const warn = clients.warn || console.warn;
    console.log("relay identity read-only action", action);
    return await confirmedStatus(secrets, ssm, props, sleepFn, warn);
  } catch (error) {
    if (error instanceof RelayIdentityError) throw error;
    throw fail("internal-error");
  }
}

exports.handler = async (event) => handle(event);
// This distinct handler is the only entry point exposed to the PR-plan role.
// It cannot dispatch mutation actions, and its Lambda execution role has no
// relay-identity mutation permissions even if a future refactor widens this guard.
exports.statusHandler = async (event) => handleConfirmedStatus(event);

exports._test = { generateKeyPair, handle, handleConfirmedStatus, run, validateKeyPair, versionForStage };
