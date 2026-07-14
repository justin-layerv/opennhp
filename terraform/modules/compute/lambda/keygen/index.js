"use strict";

// Shared artifact for the stateful keygen Lambda and the read-only key-validator Lambda.
const crypto = require("crypto");
const {
  GetSecretValueCommand,
  PutSecretValueCommand,
  SecretsManagerClient,
} = require("@aws-sdk/client-secrets-manager");

const PRIVATE_DER_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");
const PUBLIC_DER_PREFIX = Buffer.from("302a300506032b656e032100", "hex");
const X25519_FIELD_PRIME = (1n << 255n) - 19n;
// Fixed non-secret scalar used only to probe candidate public keys for low-order output.
const PROBE_PRIVATE_RAW = Buffer.from(
  "0900000000000000000000000000000000000000000000000000000000000000",
  "hex",
);
const defaultSecrets = new SecretsManagerClient({});

class KeygenError extends Error {
  constructor(code) {
    super(code);
    this.name = "KeygenError";
    this.code = code;
  }
}

function fail(code) {
  return new KeygenError(code);
}

function decodeCanonicalKey(value, field) {
  if (typeof value !== "string" || !/^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/.test(value)) {
    throw fail(`invalid-${field}`);
  }
  const raw = Buffer.from(value, "base64");
  if (raw.length !== 32 || raw.toString("base64") !== value) {
    throw fail(`invalid-${field}`);
  }
  return raw;
}

function littleEndianInteger(raw) {
  let result = 0n;
  for (let index = raw.length - 1; index >= 0; index -= 1) {
    result = (result << 8n) | BigInt(raw[index]);
  }
  return result;
}

function publicKeyObject(raw) {
  return crypto.createPublicKey({
    key: Buffer.concat([PUBLIC_DER_PREFIX, raw]),
    format: "der",
    type: "spki",
  });
}

function privateKeyObject(raw) {
  return crypto.createPrivateKey({
    key: Buffer.concat([PRIVATE_DER_PREFIX, raw]),
    format: "der",
    type: "pkcs8",
  });
}

function validatePublicKey(raw) {
  // RFC 7748 encodes the X25519 u-coordinate little-endian. qurl-service
  // requires the canonical field element, not an alias accepted by a lax
  // decoder: bit 255 clear and u < 2^255-19.
  if ((raw[31] & 0x80) !== 0 || littleEndianInteger(raw) >= X25519_FIELD_PRIME) {
    throw fail("invalid-public-key-coordinate");
  }

  // Keep the common low-order case independent of provider-specific OpenSSL
  // diagnostics so operators get the same fail-closed reason across runtimes.
  if (raw.every((byte) => byte === 0)) {
    throw fail("low-order-public-key");
  }

  // OpenSSL rejects other unusable or low-order inputs during X25519
  // derivation. Do not classify every provider/runtime failure as low order:
  // that would turn a future OpenSSL regression into a misleading diagnosis.
  try {
    const shared = crypto.diffieHellman({
      privateKey: privateKeyObject(PROBE_PRIVATE_RAW),
      publicKey: publicKeyObject(raw),
    });
    if (shared.every((byte) => byte === 0)) {
      throw fail("low-order-public-key");
    }
  } catch (error) {
    if (error instanceof KeygenError) throw error;
    throw fail("unusable-public-key");
  }
}

function validateKeyPair(secretString, expected = {}) {
  let parsed;
  try {
    parsed = JSON.parse(secretString);
  } catch {
    throw fail("invalid-secret-json");
  }
  if (!parsed || typeof parsed !== "object") {
    throw fail("invalid-secret-json");
  }

  const privateRaw = decodeCanonicalKey(parsed.privateKey, "private-key");
  const publicRaw = decodeCanonicalKey(parsed.publicKey, "public-key");
  validatePublicKey(publicRaw);

  let derived;
  try {
    derived = crypto.createPublicKey(privateKeyObject(privateRaw))
      .export({ format: "der", type: "spki" })
      .subarray(-32);
  } catch {
    throw fail("invalid-private-key");
  }
  if (!crypto.timingSafeEqual(derived, publicRaw)) {
    throw fail("keypair-mismatch");
  }
  if (expected.Hostname !== undefined && parsed.hostname !== expected.Hostname) {
    throw fail("hostname-mismatch");
  }
  if (expected.Environment !== undefined && parsed.environment !== expected.Environment) {
    throw fail("environment-mismatch");
  }
  return parsed;
}

function generateKeyPair(hostname, environment) {
  const pair = crypto.generateKeyPairSync("x25519");
  const generated = {
    privateKey: pair.privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32).toString("base64"),
    publicKey: pair.publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("base64"),
    hostname,
    environment,
  };
  // Defense in depth: validate fresh provider output through the same producer boundary as reused state.
  validateKeyPair(JSON.stringify(generated));
  return generated;
}

function requireProps(event) {
  if (!event || typeof event !== "object") throw fail("invalid-event");
  const props = event.ResourceProperties;
  if (
    !props
    || typeof props.SecretId !== "string"
    || props.SecretId === ""
    || typeof props.Hostname !== "string"
    || props.Hostname === ""
    || typeof props.Environment !== "string"
    || props.Environment === ""
  ) {
    throw fail("invalid-event");
  }
  return props;
}

async function run(mode, event, secrets = defaultSecrets) {
  // Mode comes only from the configured Lambda handler, never the caller's
  // payload. This keeps the separately invokable validator from selecting Seed.
  if (mode !== "Seed" && mode !== "Validate") {
    throw fail("unsupported-request-type");
  }
  const props = requireProps(event);

  let existing;
  try {
    existing = await secrets.send(new GetSecretValueCommand({
      SecretId: props.SecretId,
      VersionStage: "AWSCURRENT",
    }));
  } catch (error) {
    if (!error || error.name !== "ResourceNotFoundException") {
      throw fail("secret-read-failed");
    }
    if (mode === "Validate") {
      throw fail("secret-missing");
    }
  }

  if (existing !== undefined) {
    if (typeof existing.SecretString !== "string") {
      throw fail("invalid-existing-secret");
    }
    const validated = validateKeyPair(existing.SecretString, props);
    return {
      PhysicalResourceId: event.PhysicalResourceId || props.SecretId,
      PublicKey: validated.publicKey,
    };
  }

  // Only the stateful Terraform Seed invocation may create identity. Validate
  // is deliberately GET-only so a plan/refresh cannot rotate missing state.
  const generated = generateKeyPair(props.Hostname, props.Environment);
  try {
    await secrets.send(new PutSecretValueCommand({
      SecretId: props.SecretId,
      SecretString: JSON.stringify(generated),
    }));
  } catch {
    throw fail("secret-write-failed");
  }
  return {
    PhysicalResourceId: event.PhysicalResourceId || props.SecretId,
    PublicKey: generated.publicKey,
  };
}

async function handle(mode, event) {
  try {
    return await run(mode, event);
  } catch (error) {
    const safeError = error instanceof KeygenError ? error : fail("internal-error");
    // Log only the stable classification. Never log the original error,
    // event, secret id, or secret value: plan-time operators need a useful
    // diagnostic without turning the encrypted log group into a data leak.
    console.error("compute-server-key-error", safeError.code);
    throw safeError;
  }
}

exports.seedHandler = async (event) => handle("Seed", event);
exports.validateHandler = async (event) => handle("Validate", event);

exports._test = {
  decodeCanonicalKey,
  generateKeyPair,
  littleEndianInteger,
  run,
  validateKeyPair,
  validatePublicKey,
};
