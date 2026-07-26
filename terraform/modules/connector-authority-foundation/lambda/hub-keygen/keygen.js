"use strict";

// Seed the Connector Hub's X25519 identity and cookie keys without allowing key
// bytes to cross the Lambda boundary into Terraform state. The handler is
// CREATE_ONLY, but it deliberately repairs a partial first invocation: if the
// secret already has AWSCURRENT, it validates and reuses that private key before
// publishing the derived public key.

const crypto = require("crypto");
const {
  DescribeSecretCommand,
  GetSecretValueCommand,
  PutSecretValueCommand,
  SecretsManagerClient,
} = require("@aws-sdk/client-secrets-manager");
const {
  GetParameterCommand,
  PutParameterCommand,
  SSMClient,
} = require("@aws-sdk/client-ssm");

const PRIVATE_DER_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");
const PUBLICATION_CONFIRM_ATTEMPTS = 10;
const PUBLICATION_CONFIRM_INITIAL_DELAY_MS = 100;
const PUBLICATION_CONFIRM_MAX_DELAY_MS = 1000;
const SECRET_KEYS = Object.freeze([
  "active_cookie_key",
  "previous_cookie_key",
  "private_key",
]);
const defaultSecrets = new SecretsManagerClient({});
const defaultSsm = new SSMClient({});

class HubKeygenError extends Error {
  constructor(code) {
    super(code);
    this.name = "HubKeygenError";
  }
}

function fail(code) {
  // Do not reflect SDK messages, payload bytes, or rejected configuration.
  return new HubKeygenError(code);
}

function sleep(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function isAllZero(value) {
  let combined = 0;
  for (const byte of value) combined |= byte;
  return combined === 0;
}

function decodeCanonicalBase64(value, field, allowEmpty = false) {
  if (allowEmpty && value === "") return null;
  if (typeof value !== "string" || !/^[A-Za-z0-9+/]{43}=$/.test(value)) {
    throw fail(`invalid-${field}`);
  }
  const raw = Buffer.from(value, "base64");
  if (
    raw.length !== 32
    || raw.toString("base64") !== value
    || isAllZero(raw)
  ) {
    throw fail(`invalid-${field}`);
  }
  return raw;
}

function decodeCanonicalBase64Url(value, field) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(value)) {
    throw fail(`invalid-${field}`);
  }
  const raw = Buffer.from(value, "base64url");
  if (
    raw.length !== 32
    || raw.toString("base64url") !== value
    || isAllZero(raw)
  ) {
    throw fail(`invalid-${field}`);
  }
  return raw;
}

function publicKeyFromPrivateRaw(privateRaw) {
  let privateKey;
  let privateJwk;
  let publicJwk;
  try {
    // The secret intentionally preserves its existing raw-private-key schema,
    // so recovery imports that raw value through the standard PKCS8 X25519
    // envelope. Generated keys are exported as JWK below; no DER tail slicing
    // is used to discover either d or x.
    privateKey = crypto.createPrivateKey({
      key: Buffer.concat([PRIVATE_DER_PREFIX, privateRaw]),
      format: "der",
      type: "pkcs8",
    });
    privateJwk = privateKey.export({ format: "jwk" });
    publicJwk = crypto.createPublicKey(privateKey).export({ format: "jwk" });
  } catch {
    throw fail("invalid-private-key");
  }
  if (
    !privateJwk
    || privateJwk.kty !== "OKP"
    || privateJwk.crv !== "X25519"
    || !publicJwk
    || publicJwk.kty !== "OKP"
    || publicJwk.crv !== "X25519"
  ) {
    throw fail("invalid-private-key");
  }
  const exportedPrivate = decodeCanonicalBase64Url(privateJwk.d, "private-key");
  const privatePublic = decodeCanonicalBase64Url(privateJwk.x, "public-key");
  const derivedPublic = decodeCanonicalBase64Url(publicJwk.x, "public-key");
  if (
    !crypto.timingSafeEqual(exportedPrivate, privateRaw)
    || !crypto.timingSafeEqual(privatePublic, derivedPublic)
  ) {
    throw fail("keypair-mismatch");
  }
  return derivedPublic;
}

function generatedIdentity(generateKeyPair = crypto.generateKeyPairSync) {
  let pair;
  let privateJwk;
  let publicJwk;
  try {
    pair = generateKeyPair("x25519");
    privateJwk = pair.privateKey.export({ format: "jwk" });
    publicJwk = pair.publicKey.export({ format: "jwk" });
  } catch {
    throw fail("key-generation-failed");
  }
  if (
    !privateJwk
    || privateJwk.kty !== "OKP"
    || privateJwk.crv !== "X25519"
    || !publicJwk
    || publicJwk.kty !== "OKP"
    || publicJwk.crv !== "X25519"
  ) {
    throw fail("key-generation-failed");
  }
  const privateRaw = decodeCanonicalBase64Url(privateJwk.d, "private-key");
  const embeddedPublic = decodeCanonicalBase64Url(privateJwk.x, "public-key");
  const exportedPublic = decodeCanonicalBase64Url(publicJwk.x, "public-key");
  const derivedPublic = publicKeyFromPrivateRaw(privateRaw);
  if (
    !crypto.timingSafeEqual(embeddedPublic, exportedPublic)
    || !crypto.timingSafeEqual(exportedPublic, derivedPublic)
  ) {
    throw fail("keypair-mismatch");
  }
  return { privateRaw, publicRaw: derivedPublic };
}

function validateSecret(secretString) {
  if (typeof secretString !== "string") {
    throw fail("invalid-secret-json");
  }
  // The secret schema is a flat object containing only canonical base64
  // strings. Parse that exact grammar instead of JSON.parse, which silently
  // accepts duplicate object keys. Field order and JSON whitespace may vary;
  // escapes, nested values, duplicate keys, and trailing data fail closed.
  const whitespace = "[\\x20\\x09\\x0a\\x0d]*";
  const pair = '"([^"\\\\]*)"' + whitespace + ":" + whitespace + '"([^"\\\\]*)"';
  const exactObject = new RegExp(
    "^" + whitespace + "\\{" + whitespace
      + pair + whitespace + "," + whitespace
      + pair + whitespace + "," + whitespace
      + pair + whitespace + "\\}" + whitespace + "$",
  );
  const match = exactObject.exec(secretString);
  if (!match) throw fail("invalid-secret-json");
  const pairs = [
    [match[1], match[2]],
    [match[3], match[4]],
    [match[5], match[6]],
  ];
  const keys = pairs.map(([key]) => key).sort();
  if (
    JSON.stringify(keys) !== JSON.stringify(SECRET_KEYS)
  ) {
    throw fail("invalid-secret-shape");
  }
  const value = Object.fromEntries(pairs);
  const privateRaw = decodeCanonicalBase64(value.private_key, "private-key");
  decodeCanonicalBase64(value.active_cookie_key, "active-cookie-key");
  decodeCanonicalBase64(value.previous_cookie_key, "previous-cookie-key", true);
  return {
    privateRaw,
    publicRaw: publicKeyFromPrivateRaw(privateRaw),
  };
}

function requireInvocation(event, environment) {
  if (
    !event
    || Array.isArray(event)
    || typeof event !== "object"
    || Object.keys(event).length !== 0
  ) {
    throw fail("invalid-event");
  }
  const secretId = environment.SECRET_ID;
  const deployment = environment.ENVIRONMENT;
  const publicKeyParameter = environment.PUBLIC_KEY_PARAMETER;
  if (
    typeof secretId !== "string"
    || secretId === ""
    || !/^(sandbox|prod)$/.test(deployment || "")
    || publicKeyParameter
      !== `/${deployment}/nhp/control/hub/identity/public-key`
  ) {
    throw fail("invalid-configuration");
  }
  return { secretId, publicKeyParameter };
}

function currentVersionId(description) {
  const versions = description && description.VersionIdsToStages;
  if (versions === undefined) return null;
  if (!versions || typeof versions !== "object" || Array.isArray(versions)) {
    throw fail("secret-description-invalid");
  }
  const entries = Object.entries(versions);
  for (const [versionId, stages] of entries) {
    if (
      versionId === ""
      || !Array.isArray(stages)
      || stages.length === 0
      || !stages.every((stage) => typeof stage === "string" && stage !== "")
    ) {
      throw fail("secret-description-invalid");
    }
  }
  const current = entries
    .filter(([, stages]) => stages.includes("AWSCURRENT"))
    .map(([versionId]) => versionId);
  if (current.length > 1) throw fail("multiple-current-versions");
  if (entries.length > 0 && current.length === 0) {
    throw fail("current-version-missing");
  }
  return current[0] || null;
}

async function describeSecret(secrets, secretId) {
  try {
    return await secrets.send(new DescribeSecretCommand({ SecretId: secretId }));
  } catch {
    throw fail("secret-describe-failed");
  }
}

async function readCurrentSecret(secrets, secretId, versionId = null) {
  let response;
  try {
    response = await secrets.send(new GetSecretValueCommand({
      SecretId: secretId,
      VersionStage: "AWSCURRENT",
      ...(versionId ? { VersionId: versionId } : {}),
    }));
  } catch {
    throw fail("secret-read-failed");
  }
  if (!response || typeof response.SecretString !== "string") {
    throw fail("secret-value-missing");
  }
  return validateSecret(response.SecretString);
}

function seedToken(secretId) {
  return crypto
    .createHash("sha256")
    .update("layerv-connector-hub-keygen-v1\0", "utf8")
    .update(secretId, "utf8")
    .digest("hex");
}

async function ensureCurrentSecret(secrets, secretId, dependencies) {
  const versionId = currentVersionId(await describeSecret(secrets, secretId));
  if (versionId) {
    return readCurrentSecret(secrets, secretId, versionId);
  }

  const identity = generatedIdentity(dependencies.generateKeyPair);
  let activeCookieKey;
  try {
    activeCookieKey = dependencies.randomBytes(32);
  } catch {
    throw fail("cookie-generation-failed");
  }
  if (
    !Buffer.isBuffer(activeCookieKey)
    || activeCookieKey.length !== 32
    || isAllZero(activeCookieKey)
  ) {
    throw fail("cookie-generation-failed");
  }
  const secret = JSON.stringify({
    private_key: identity.privateRaw.toString("base64"),
    active_cookie_key: activeCookieKey.toString("base64"),
    previous_cookie_key: "",
  });
  // Validate generated bytes through the same strict boundary used on repair.
  validateSecret(secret);
  try {
    await secrets.send(new PutSecretValueCommand({
      SecretId: secretId,
      SecretString: secret,
      ClientRequestToken: seedToken(secretId),
      VersionStages: ["AWSCURRENT"],
    }));
  } catch {
    throw fail("secret-seed-failed");
  }

  // Re-read AWSCURRENT instead of trusting the write response. This catches an
  // unexpected concurrent stage move and makes the published key derive from
  // the exact persisted secret.
  const persisted = await readCurrentSecret(secrets, secretId);
  if (!crypto.timingSafeEqual(persisted.privateRaw, identity.privateRaw)) {
    throw fail("secret-seed-conflict");
  }
  return persisted;
}

async function confirmPublished(ssm, parameterName, expected, dependencies) {
  let readFailureLogged = false;
  for (let attempt = 0; attempt < PUBLICATION_CONFIRM_ATTEMPTS; attempt += 1) {
    try {
      const response = await ssm.send(new GetParameterCommand({
        Name: parameterName,
        WithDecryption: false,
      }));
      if (
        response
        && response.Parameter
        && response.Parameter.Value === expected
      ) {
        return;
      }
    } catch {
      if (!readFailureLogged) {
        dependencies.warn("hub identity public-key confirmation read failed");
        readFailureLogged = true;
      }
    }
    if (attempt + 1 < PUBLICATION_CONFIRM_ATTEMPTS) {
      const delay = Math.min(
        PUBLICATION_CONFIRM_INITIAL_DELAY_MS * (2 ** attempt),
        PUBLICATION_CONFIRM_MAX_DELAY_MS,
      );
      await dependencies.sleep(delay);
    }
  }
  throw fail("public-key-confirmation-failed");
}

async function publishPublicKey(ssm, parameterName, publicRaw, dependencies) {
  const publicKey = publicRaw.toString("base64");
  let current;
  try {
    const response = await ssm.send(new GetParameterCommand({
      Name: parameterName,
      WithDecryption: false,
    }));
    current = response && response.Parameter && response.Parameter.Value;
  } catch {
    throw fail("public-key-read-failed");
  }
  if (current === publicKey) {
    return;
  }
  if (current !== "pending-keygen") {
    throw fail("public-key-conflict");
  }
  try {
    await ssm.send(new PutParameterCommand({
      Name: parameterName,
      Type: "String",
      Value: publicKey,
      Overwrite: true,
    }));
  } catch {
    throw fail("public-key-publish-failed");
  }
  await confirmPublished(ssm, parameterName, publicKey, dependencies);
}

async function run(event, environment, clients = {}) {
  const configuration = requireInvocation(event, environment);
  const dependencies = {
    generateKeyPair: clients.generateKeyPair || crypto.generateKeyPairSync,
    randomBytes: clients.randomBytes || crypto.randomBytes,
    sleep: clients.sleep || sleep,
    warn: clients.warn || console.warn,
  };
  const secrets = clients.secrets || defaultSecrets;
  const ssm = clients.ssm || defaultSsm;
  const current = await ensureCurrentSecret(
    secrets,
    configuration.secretId,
    dependencies,
  );
  await publishPublicKey(
    ssm,
    configuration.publicKeyParameter,
    current.publicRaw,
    dependencies,
  );
  // aws_lambda_invocation stores this result in Terraform state. Keep it exact
  // and constant: no public key, private key, version ID, or cookie metadata.
  return { seeded: true };
}

async function handle(event, environment = process.env, clients = {}) {
  try {
    console.log("hub identity seed action");
    return await run(event, environment, clients);
  } catch (error) {
    if (error instanceof HubKeygenError) throw error;
    throw fail("internal-error");
  }
}

exports.handler = async (event) => handle(event);
exports._test = {
  HubKeygenError,
  generatedIdentity,
  handle,
  publicKeyFromPrivateRaw,
  run,
  seedToken,
  validateSecret,
};
