"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const Module = require("node:module");
const fs = require("node:fs");
const path = require("node:path");

const originalResolveFilename = Module._resolveFilename;
Module._resolveFilename = function resolve(request, parent, isMain, options) {
  if (request === "@aws-sdk/client-secrets-manager") return "__mock_compute_keygen_secrets__";
  return originalResolveFilename.call(this, request, parent, isMain, options);
};

function command(name) {
  return class {
    constructor(params) {
      this.name = name;
      this.params = params;
    }
  };
}

let defaultSecretsHandler = async () => { throw new Error("unmocked"); };
require.cache.__mock_compute_keygen_secrets__ = {
  id: "__mock_compute_keygen_secrets__",
  filename: "__mock_compute_keygen_secrets__",
  loaded: true,
  exports: {
    SecretsManagerClient: class { async send(cmd) { return defaultSecretsHandler(cmd); } },
    GetSecretValueCommand: command("GetSecretValue"),
    PutSecretValueCommand: command("PutSecretValue"),
  },
};

const { _test, seedHandler, validateHandler } = require("./index");
Module._resolveFilename = originalResolveFilename;

function event(requestType) {
  const value = {
    PhysicalResourceId: "physical-id",
    ResourceProperties: {
      SecretId: "server-secret",
      Hostname: "cell0.nhp.layerv.xyz",
      Environment: "sandbox",
    },
  };
  // Caller-controlled mode-looking input is retained only for security tests;
  // exported handlers must ignore it and select their configured mode.
  if (requestType !== undefined) value.RequestType = requestType;
  return value;
}

function fixture(handler) {
  const calls = [];
  return {
    calls,
    client: {
      send: async (cmd) => {
        calls.push(cmd);
        return handler(cmd);
      },
    },
  };
}

function terraformResource(terraform, type, name) {
  const marker = `resource "${type}" "${name}"`;
  const start = terraform.indexOf(marker);
  assert.notEqual(start, -1, `${marker} must exist`);
  const open = terraform.indexOf("{", start + marker.length);
  let depth = 0;
  for (let index = open; index < terraform.length; index += 1) {
    if (terraform[index] === "{") depth += 1;
    if (terraform[index] === "}") depth -= 1;
    if (depth === 0) return terraform.slice(start, index + 1);
  }
  assert.fail(`${marker} has no closing brace`);
}

describe("compute server key producer", () => {
  it("keeps Terraform source_file and handler aligned", () => {
    const terraform = fs.readFileSync(path.join(__dirname, "..", "..", "main.tf"), "utf8");
    const outputs = fs.readFileSync(path.join(__dirname, "..", "..", "outputs.tf"), "utf8");
    assert.match(terraform, /source_file\s*=\s*"\$\{path\.module\}\/lambda\/keygen\/index\.js"/);
    assert.match(terraform, /handler\s*=\s*"index\.seedHandler"/);
    assert.match(terraform, /handler\s*=\s*"index\.validateHandler"/);
    const invocation = terraform.match(/resource "aws_lambda_invocation" "keygen" \{([\s\S]*?)\n\}/);
    assert.ok(invocation, "keygen invocation must remain statically inspectable");
    // The historical stateful invocation keeps its ignored Create-shaped
    // payload; seedHandler, not caller input, selects Seed.
    assert.match(invocation[1], /RequestType\s*=\s*"Create"/);
    assert.match(invocation[1], /lifecycle_scope\s*=\s*"CREATE_ONLY"/);
    assert.doesNotMatch(invocation[1], /triggers\s*=/);
    assert.doesNotMatch(terraform, /data "aws_lambda_invocation" "server_key_validation"/);
    assert.match(terraform, /data "aws_secretsmanager_secret_version" "server"/);
    assert.match(outputs, /jsondecode\(data\.aws_secretsmanager_secret_version\.server\.secret_string\)\.publicKey/);
  });

  it("pins the validator to an encrypted log group and exact read-only execution actions", () => {
    const terraform = fs.readFileSync(path.join(__dirname, "..", "..", "main.tf"), "utf8");
    const logGroup = terraformResource(terraform, "aws_cloudwatch_log_group", "key_validator");
    assert.match(logGroup, /kms_key_id\s*=\s*var\.logs_kms_key_arn/);
    assert.match(logGroup, /precondition\s*\{/);
    assert.match(
      logGroup,
      /condition\s*=\s*try\(trimspace\(var\.logs_kms_key_arn\)\s*!=\s*"",\s*false\)/,
    );

    const validator = terraformResource(terraform, "aws_lambda_function", "key_validator");
    assert.match(validator, /time_sleep\.key_validator_iam_propagation/);
    assert.match(validator, /aws_cloudwatch_log_group\.key_validator/);

    const wait = terraformResource(terraform, "time_sleep", "key_validator_iam_propagation");
    assert.match(wait, /create_duration\s*=\s*"180s"/);
    assert.match(wait, /sha256\(aws_iam_role\.key_validator_lambda\.assume_role_policy\)/);
    assert.match(wait, /sha256\(aws_iam_role_policy\.key_validator_lambda_access\.policy\)/);

    const policy = terraformResource(terraform, "aws_iam_role_policy", "key_validator_lambda_access");
    const actions = [...policy.matchAll(/"([a-z]+:[A-Za-z*]+)"/g)]
      .map((match) => match[1])
      .sort();
    assert.deepEqual(actions, [
      "kms:Decrypt",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "secretsmanager:GetSecretValue",
    ]);
    assert.match(policy, /Resource\s*=\s*\[aws_secretsmanager_secret\.server\.arn\]/);
    assert.doesNotMatch(policy, /PutSecretValue|GenerateDataKey|kms:Encrypt|DescribeSecret/);
  });

  it("validates generated keys and exact private/public derivation", () => {
    const pair = _test.generateKeyPair(event().ResourceProperties.Hostname, "sandbox");
    assert.equal(_test.validateKeyPair(JSON.stringify(pair)).publicKey, pair.publicKey);

    const mismatch = { ...pair, publicKey: _test.generateKeyPair("host", "sandbox").publicKey };
    assert.throws(() => _test.validateKeyPair(JSON.stringify(mismatch)), /keypair-mismatch/);
  });

  it("rejects noncanonical base64, noncanonical field elements, and low order", () => {
    const pair = _test.generateKeyPair(event().ResourceProperties.Hostname, "sandbox");
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const finalIndex = alphabet.indexOf(pair.publicKey.at(-2));
    const alias = `${pair.publicKey.slice(0, -2)}${alphabet[finalIndex + 1]}=`;
    assert.throws(() => _test.decodeCanonicalKey(alias, "public-key"), /invalid-public-key/);

    const highBit = Buffer.alloc(32);
    highBit[31] = 0x80;
    assert.throws(() => _test.validatePublicKey(highBit), /invalid-public-key-coordinate/);

    const fieldPrime = Buffer.from("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "hex");
    assert.throws(() => _test.validatePublicKey(fieldPrime), /invalid-public-key-coordinate/);
    assert.throws(() => _test.validatePublicKey(Buffer.alloc(32)), /low-order-public-key/);
  });

  it("classifies provider rejection without leaking its diagnostic", () => {
    const pair = _test.generateKeyPair(event().ResourceProperties.Hostname, "sandbox");
    const publicRaw = Buffer.from(pair.publicKey, "base64");
    const originalDiffieHellman = crypto.diffieHellman;
    crypto.diffieHellman = () => { throw new Error("OpenSSL PRIVATE-SENTINEL"); };
    try {
      assert.throws(
        () => _test.validatePublicKey(publicRaw),
        /^KeygenError: unusable-public-key$/,
      );
    } finally {
      crypto.diffieHellman = originalDiffieHellman;
    }
  });

  it("rejects incomplete events before reading state", async () => {
    const validProps = event().ResourceProperties;
    const invalidEvents = [
      null,
      {},
      { ResourceProperties: {} },
      ...["SecretId", "Hostname", "Environment"].flatMap((field) => [
        { ResourceProperties: { ...validProps, [field]: undefined } },
        { ResourceProperties: { ...validProps, [field]: "" } },
      ]),
    ];
    for (const invalidEvent of invalidEvents) {
      const fake = fixture(async () => { throw new Error("must not be called"); });
      await assert.rejects(
        _test.run("Validate", invalidEvent, fake.client),
        /^KeygenError: invalid-event$/,
      );
      assert.deepEqual(fake.calls, []);
    }
  });

  it("Seed and Validate return only a validated existing public key without writing", async () => {
    const pair = _test.generateKeyPair(event().ResourceProperties.Hostname, "sandbox");
    for (const mode of ["Seed", "Validate"]) {
      const fake = fixture(async (cmd) => {
        assert.equal(cmd.name, "GetSecretValue");
        assert.deepEqual(cmd.params, { SecretId: "server-secret", VersionStage: "AWSCURRENT" });
        return { SecretString: JSON.stringify(pair) };
      });
      const result = await _test.run(mode, event(), fake.client);
      assert.deepEqual(result, {
        PhysicalResourceId: event().PhysicalResourceId,
        PublicKey: pair.publicKey,
      });
      assert.equal(JSON.stringify(result).includes(pair.privateKey), false);
      assert.deepEqual(fake.calls.map((call) => call.name), ["GetSecretValue"]);
    }
  });

  it("returns only the validated public identity through the Lambda handler", async () => {
    const pair = _test.generateKeyPair(event().ResourceProperties.Hostname, "sandbox");
    defaultSecretsHandler = async (cmd) => {
      assert.equal(cmd.name, "GetSecretValue");
      return { SecretString: JSON.stringify(pair) };
    };
    try {
      const result = await validateHandler(event("Seed"));
      assert.deepEqual(result, {
        PhysicalResourceId: event().PhysicalResourceId,
        PublicKey: pair.publicKey,
      });
      assert.equal(JSON.stringify(result).includes(pair.privateKey), false);
    } finally {
      defaultSecretsHandler = async () => { throw new Error("unmocked"); };
    }
  });

  it("Seed and Validate fail closed on malformed existing state without writing", async () => {
    for (const mode of ["Seed", "Validate"]) {
      const fake = fixture(async (cmd) => {
        assert.equal(cmd.name, "GetSecretValue");
        return { SecretString: JSON.stringify({ privateKey: "A".repeat(44), publicKey: "B".repeat(44) }) };
      });
      await assert.rejects(_test.run(mode, event(), fake.client), /invalid-private-key/);
      assert.deepEqual(fake.calls.map((call) => call.name), ["GetSecretValue"]);
    }
  });

  it("rejects invalid JSON and non-string existing secrets without writing", async () => {
    for (const [existing, expectedError] of [
      [{ SecretString: "not-json" }, /^KeygenError: invalid-secret-json$/],
      [{ SecretString: "null" }, /^KeygenError: invalid-secret-json$/],
      [{}, /^KeygenError: invalid-existing-secret$/],
    ]) {
      const fake = fixture(async (cmd) => {
        assert.equal(cmd.name, "GetSecretValue");
        return existing;
      });
      await assert.rejects(_test.run("Validate", event(), fake.client), expectedError);
      assert.deepEqual(fake.calls.map((call) => call.name), ["GetSecretValue"]);
    }
  });

  it("Seed and Validate reject stale identity metadata without writing", async () => {
    const pair = _test.generateKeyPair(event().ResourceProperties.Hostname, "sandbox");
    for (const [field, value, expectedError] of [
      ["hostname", "wrong.nhp.example", /hostname-mismatch/],
      ["environment", "prod", /environment-mismatch/],
    ]) {
      for (const mode of ["Seed", "Validate"]) {
        const fake = fixture(async (cmd) => {
          assert.equal(cmd.name, "GetSecretValue");
          return { SecretString: JSON.stringify({ ...pair, [field]: value }) };
        });
        await assert.rejects(_test.run(mode, event(), fake.client), expectedError);
        assert.deepEqual(fake.calls.map((call) => call.name), ["GetSecretValue"]);
      }
    }
  });

  it("Validate fails closed on missing state without writing", async () => {
    const fake = fixture(async (cmd) => {
      assert.equal(cmd.name, "GetSecretValue");
      assert.deepEqual(cmd.params, { SecretId: "server-secret", VersionStage: "AWSCURRENT" });
      const error = new Error("missing");
      error.name = "ResourceNotFoundException";
      throw error;
    });
    await assert.rejects(_test.run("Validate", event(), fake.client), /^KeygenError: secret-missing$/);
    assert.deepEqual(fake.calls.map((call) => call.name), ["GetSecretValue"]);
  });

  it("Seed generates, validates, and writes a missing secret exactly once", async () => {
    const fake = fixture(async (cmd) => {
      if (cmd.name === "GetSecretValue") {
        assert.deepEqual(cmd.params, { SecretId: "server-secret", VersionStage: "AWSCURRENT" });
        const error = new Error("missing");
        error.name = "ResourceNotFoundException";
        throw error;
      }
      if (cmd.name === "PutSecretValue") {
        const parsed = _test.validateKeyPair(cmd.params.SecretString);
        assert.equal(parsed.hostname, event().ResourceProperties.Hostname);
        assert.equal(parsed.environment, event().ResourceProperties.Environment);
        return {};
      }
      throw new Error(`unexpected ${cmd.name}`);
    });
    const result = await _test.run("Seed", event(), fake.client);
    assert.equal(typeof result.PublicKey, "string");
    assert.deepEqual(fake.calls.map((call) => call.name), ["GetSecretValue", "PutSecretValue"]);
  });

  it("fails closed when Seed cannot persist newly generated state", async () => {
    const fake = fixture(async (cmd) => {
      if (cmd.name === "GetSecretValue") {
        const error = new Error("missing");
        error.name = "ResourceNotFoundException";
        throw error;
      }
      if (cmd.name === "PutSecretValue") {
        throw new Error("write failed PRIVATE-SENTINEL");
      }
      throw new Error(`unexpected ${cmd.name}`);
    });
    await assert.rejects(
      _test.run("Seed", event(), fake.client),
      /^KeygenError: secret-write-failed$/,
    );
    assert.deepEqual(fake.calls.map((call) => call.name), ["GetSecretValue", "PutSecretValue"]);
  });

  it("does not turn read failures into an identity rotation", async () => {
    const fake = fixture(async () => { throw new Error("AccessDenied PRIVATE-SENTINEL"); });
    await assert.rejects(_test.run("Validate", event(), fake.client), /^KeygenError: secret-read-failed$/);
    assert.deepEqual(fake.calls.map((call) => call.name), ["GetSecretValue"]);
  });

  it("logs only a stable failure code through the configured handler", async () => {
    const originalConsoleError = console.error;
    const logs = [];
    console.error = (...args) => logs.push(args);
    defaultSecretsHandler = async () => { throw new Error("AccessDenied PRIVATE-SENTINEL"); };
    try {
      await assert.rejects(validateHandler(event()), /^KeygenError: secret-read-failed$/);
    } finally {
      defaultSecretsHandler = async () => { throw new Error("unmocked"); };
      console.error = originalConsoleError;
    }
    assert.deepEqual(logs, [["compute-server-key-error", "secret-read-failed"]]);
    assert.equal(JSON.stringify(logs).includes("PRIVATE-SENTINEL"), false);
  });

  it("rejects unsupported request types before touching Secrets Manager", async () => {
    const fake = fixture(async () => { throw new Error("must not be called"); });
    await assert.rejects(_test.run("Delete", event(), fake.client), /^KeygenError: unsupported-request-type$/);
    assert.deepEqual(fake.calls, []);
  });

  it("validateHandler cannot be payload-selected into Seed", async () => {
    const originalConsoleError = console.error;
    const logs = [];
    console.error = (...args) => logs.push(args);
    const calls = [];
    defaultSecretsHandler = async (cmd) => {
      calls.push(cmd);
      const error = new Error("missing");
      error.name = "ResourceNotFoundException";
      throw error;
    };
    try {
      await assert.rejects(validateHandler(event("Seed")), /^KeygenError: secret-missing$/);
      assert.deepEqual(calls.map((call) => call.name), ["GetSecretValue"]);
      assert.deepEqual(logs, [["compute-server-key-error", "secret-missing"]]);
    } finally {
      defaultSecretsHandler = async () => { throw new Error("unmocked"); };
      console.error = originalConsoleError;
    }
  });

  it("seedHandler selects Seed independently of the payload", async () => {
    const pair = _test.generateKeyPair(event().ResourceProperties.Hostname, "sandbox");
    defaultSecretsHandler = async (cmd) => {
      assert.equal(cmd.name, "GetSecretValue");
      return { SecretString: JSON.stringify(pair) };
    };
    try {
      const result = await seedHandler(event("Validate"));
      assert.equal(result.PublicKey, pair.publicKey);
    } finally {
      defaultSecretsHandler = async () => { throw new Error("unmocked"); };
    }
  });
});
