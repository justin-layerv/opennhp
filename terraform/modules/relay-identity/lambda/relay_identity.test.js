"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const Module = require("node:module");
const fs = require("node:fs");
const path = require("node:path");

const originalResolveFilename = Module._resolveFilename;
Module._resolveFilename = function (request, parent, isMain, options) {
  if (request === "@aws-sdk/client-secrets-manager") return "__mock_relay_secrets__";
  if (request === "@aws-sdk/client-ssm") return "__mock_relay_ssm__";
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

require.cache.__mock_relay_secrets__ = {
  id: "__mock_relay_secrets__",
  filename: "__mock_relay_secrets__",
  loaded: true,
  exports: {
    SecretsManagerClient: class { async send() { throw new Error("unmocked"); } },
    DescribeSecretCommand: command("DescribeSecret"),
    GetSecretValueCommand: command("GetSecretValue"),
    PutSecretValueCommand: command("PutSecretValue"),
  },
};
require.cache.__mock_relay_ssm__ = {
  id: "__mock_relay_ssm__",
  filename: "__mock_relay_ssm__",
  loaded: true,
  exports: {
    SSMClient: class { async send() { throw new Error("unmocked"); } },
    PutParameterCommand: command("PutParameter"),
  },
};

const { _test } = require("./relay_identity");
Module._resolveFilename = originalResolveFilename;

const environment = "sandbox";
const secretId = "layerv-nhp-sandbox-relay";
const parameter = "/sandbox/nhp/relay/identity/current-public-key";
const token = "123e4567-e89b-42d3-a456-426614174000";

function event(action, extra = {}) {
  return {
    Action: action,
    ResourceProperties: {
      SecretId: secretId,
      Environment: environment,
      PublicKeyParameter: parameter,
      ...extra,
    },
  };
}

function clients(handler) {
  const calls = [];
  return {
    calls,
    clients: {
      secrets: { send: async (cmd) => { calls.push(cmd); return handler(cmd); } },
      ssm: { send: async (cmd) => { calls.push(cmd); return handler(cmd); } },
    },
  };
}

async function assertBoundaryRejects(input, code) {
  const fixture = clients(async (cmd) => { throw new Error(`unexpected ${cmd.name}`); });
  await assert.rejects(
    _test.run(input, fixture.clients),
    (error) => error.name === "RelayIdentityError" && error.message === code,
  );
  assert.equal(fixture.calls.length, 0, "invalid invocation must not reach an AWS client");
}

function currentFixture() {
  return _test.generateKeyPair(environment);
}

describe("relay identity validation", () => {
  it("keeps the Terraform handler aligned with the archived source basename", () => {
    const terraform = fs.readFileSync(path.join(__dirname, "..", "main.tf"), "utf8");
    const source = terraform.match(/source_file\s*=\s*"[^\"]*\/([^/\"]+)"/);
    const handler = terraform.match(/handler\s*=\s*"([^\"]+)\.handler"/);
    assert.ok(source && handler, "source_file and handler must remain statically inspectable");
    assert.equal(path.parse(source[1]).name, handler[1]);
  });

  it("keeps the greenfield Terraform invocation chain explicit and fail closed", () => {
    const terraform = fs.readFileSync(path.join(__dirname, "..", "main.tf"), "utf8");
    const publish = terraform.match(/resource "aws_lambda_invocation" "publish_public_key" \{([\s\S]*?)\n\}/);
    const publicRead = terraform.match(/data "aws_ssm_parameter" "relay_public_key" \{([\s\S]*?)\n\}/);
    const propagation = terraform.match(/resource "time_sleep" "keygen_iam_propagation" \{([\s\S]*?)\n\}/);
    const lambda = terraform.match(/resource "aws_lambda_function" "keygen" \{([\s\S]*?)\n\}/);
    assert.ok(publish && publicRead && propagation && lambda, "publish, propagation, Lambda, and public-read boundaries must remain inspectable");
    assert.match(propagation[1], /assume_role_policy_hash/);
    assert.match(propagation[1], /secrets_policy_hash/);
    assert.match(propagation[1], /basic_policy_attachment_id/);
    assert.match(lambda[1], /depends_on\s*=\s*\[time_sleep\.keygen_iam_propagation\]/);
    assert.match(publish[1], /Action\s*=\s*"publish-current"/);
    assert.match(publish[1], /aws_lambda_invocation\.keygen/);
    assert.match(publish[1], /postcondition[\s\S]*self\.result[\s\S]*"publish-current"/);
    assert.match(publicRead[1], /aws_lambda_invocation\.publish_public_key/);
    assert.match(publicRead[1], /postcondition[\s\S]*length\(base64decode\(self\.value\)\) == 32/);
    assert.match(publicRead[1], /base64encode\(base64decode\(self\.value\)\) == self\.value/);
  });

  it("validates a derived X25519 keypair", () => {
    const pair = currentFixture();
    assert.equal(_test.validateKeyPair(JSON.stringify(pair), environment), pair.publicKey);
  });

  it("rejects a public key that does not derive from the private key", () => {
    const pair = currentFixture();
    pair.publicKey = currentFixture().publicKey;
    assert.throws(() => _test.validateKeyPair(JSON.stringify(pair), environment), /keypair-mismatch/);
  });

  it("rejects malformed JSON without reflecting it", () => {
    const sentinel = "PRIVATE-SENTINEL";
    assert.throws(
      () => _test.validateKeyPair(`{${sentinel}`, environment),
      (error) => error.message === "invalid-secret-json" && !error.message.includes(sentinel),
    );
  });
});

describe("runtime invocation boundary", () => {
  it("rejects a missing resource-properties envelope before using AWS clients", async () => {
    await assertBoundaryRejects({ Action: "status" }, "invalid-event");
  });

  it("rejects an unsupported environment before using AWS clients", async () => {
    await assertBoundaryRejects(event("status", {
      Environment: "staging",
      PublicKeyParameter: "/staging/nhp/relay/identity/current-public-key",
    }), "invalid-environment");
  });

  it("rejects a public-key parameter outside the environment boundary", async () => {
    await assertBoundaryRejects(
      event("status", { PublicKeyParameter: "/prod/nhp/relay/identity/current-public-key" }),
      "invalid-public-key-parameter",
    );
  });

  it("rejects an unsupported action before using AWS clients", async () => {
    await assertBoundaryRejects(event("delete"), "invalid-action");
  });

  it("maps unexpected runtime errors to a code-only internal error", async () => {
    const brokenClients = {};
    Object.defineProperty(brokenClients, "secrets", {
      get() { throw new Error("PRIVATE-SENTINEL raw runtime failure"); },
    });
    await assert.rejects(
      _test.handle(event("status"), brokenClients),
      (error) => error.name === "RelayIdentityError"
        && error.message === "internal-error"
        && !error.message.includes("PRIVATE-SENTINEL"),
    );
  });
});

describe("ensure-current", () => {
  it("preserves an existing current public key without any write", async () => {
    const pair = currentFixture();
    const fixture = clients(async (cmd) => {
      if (cmd.name === "DescribeSecret") return { VersionIdsToStages: { current: ["AWSCURRENT"] } };
      if (cmd.name === "GetSecretValue") return { VersionId: "current", SecretString: JSON.stringify(pair) };
      throw new Error(`unexpected ${cmd.name}`);
    });
    const result = await _test.run(event("ensure-current"), fixture.clients);
    assert.equal(result.currentPublicKey, pair.publicKey);
    assert.equal(fixture.calls.filter((call) => call.name === "PutSecretValue").length, 0);
    assert.equal(fixture.calls.filter((call) => call.name === "PutParameter").length, 0);
  });

  it("fails closed on DescribeSecret access failure", async () => {
    const fixture = clients(async () => { throw new Error("AccessDenied PRIVATE-SENTINEL"); });
    await assert.rejects(_test.run(event("ensure-current"), fixture.clients), /^RelayIdentityError: secret-describe-failed$/);
    assert.equal(fixture.calls.filter((call) => call.name === "PutSecretValue").length, 0);
  });

  it("fails closed on malformed current data", async () => {
    const fixture = clients(async (cmd) => {
      if (cmd.name === "DescribeSecret") return { VersionIdsToStages: { current: ["AWSCURRENT"] } };
      if (cmd.name === "GetSecretValue") return { VersionId: "current", SecretString: "PRIVATE-SENTINEL" };
      throw new Error(`unexpected ${cmd.name}`);
    });
    await assert.rejects(_test.run(event("ensure-current"), fixture.clients), /invalid-secret-json/);
    assert.equal(fixture.calls.filter((call) => call.name === "PutSecretValue").length, 0);
  });

  it("bootstraps only when no AWSCURRENT exists", async () => {
    const fixture = clients(async (cmd) => {
      if (cmd.name === "DescribeSecret") return { VersionIdsToStages: {} };
      if (cmd.name === "PutSecretValue") {
        assert.deepEqual(cmd.params.VersionStages, ["AWSCURRENT"]);
        return { VersionId: "created" };
      }
      throw new Error(`unexpected ${cmd.name}`);
    });
    const result = await _test.run(event("ensure-current"), fixture.clients);
    assert.equal(result.currentVersionId, "created");
    assert.equal(fixture.calls.filter((call) => call.name === "PutSecretValue").length, 1);
    assert.equal(fixture.calls.filter((call) => call.name === "PutParameter").length, 0);
  });
});

describe("publish-current", () => {
  it("publishes an existing current key without any secret write", async () => {
    const pair = currentFixture();
    const fixture = clients(async (cmd) => {
      if (cmd.name === "DescribeSecret") return { VersionIdsToStages: { current: ["AWSCURRENT"] } };
      if (cmd.name === "GetSecretValue") return { VersionId: "current", SecretString: JSON.stringify(pair) };
      if (cmd.name === "PutParameter") return {};
      throw new Error(`unexpected ${cmd.name}`);
    });
    const result = await _test.run(event("publish-current"), fixture.clients);
    assert.equal(result.action, "publish-current");
    assert.equal(result.currentPublicKey, pair.publicKey);
    assert.equal(fixture.calls.filter((call) => call.name === "PutSecretValue").length, 0);
  });

  it("refuses to mint an identity when AWSCURRENT is absent", async () => {
    const fixture = clients(async (cmd) => {
      if (cmd.name === "DescribeSecret") return { VersionIdsToStages: {} };
      throw new Error(`unexpected ${cmd.name}`);
    });
    await assert.rejects(_test.run(event("publish-current"), fixture.clients), /current-version-missing/);
    assert.equal(fixture.calls.filter((call) => call.name === "PutSecretValue").length, 0);
    assert.equal(fixture.calls.filter((call) => call.name === "PutParameter").length, 0);
  });

  it("supports the declared greenfield keygen then publish ordering", async () => {
    let stored = null;
    const fixture = clients(async (cmd) => {
      if (cmd.name === "DescribeSecret") {
        return { VersionIdsToStages: stored ? { created: ["AWSCURRENT"] } : {} };
      }
      if (cmd.name === "PutSecretValue") {
        stored = cmd.params.SecretString;
        return { VersionId: "created" };
      }
      if (cmd.name === "GetSecretValue") return { VersionId: "created", SecretString: stored };
      if (cmd.name === "PutParameter") return {};
      throw new Error(`unexpected ${cmd.name}`);
    });
    await _test.run(event("ensure-current"), fixture.clients);
    const published = await _test.run(event("publish-current"), fixture.clients);
    assert.equal(published.currentVersionId, "created");
    assert.equal(fixture.calls.filter((call) => call.name === "PutSecretValue").length, 1);
    assert.equal(fixture.calls.filter((call) => call.name === "PutParameter").length, 1);
  });
});

describe("stage-pending", () => {
  it("creates exactly one AWSPENDING version with the requested token", async () => {
    const fixture = clients(async (cmd) => {
      if (cmd.name === "DescribeSecret") return { VersionIdsToStages: { current: ["AWSCURRENT"] } };
      if (cmd.name === "PutSecretValue") return { VersionId: token };
      throw new Error(`unexpected ${cmd.name}`);
    });
    const result = await _test.run(event("stage-pending", { ClientRequestToken: token }), fixture.clients);
    assert.equal(result.pendingVersionId, token);
    const write = fixture.calls.find((call) => call.name === "PutSecretValue");
    assert.equal(write.params.ClientRequestToken, token);
    assert.deepEqual(write.params.VersionStages, ["AWSPENDING"]);
    assert.equal(fixture.calls.filter((call) => call.name === "PutParameter").length, 0);
  });

  it("is idempotent for a retry with the same pending token", async () => {
    const pair = currentFixture();
    const fixture = clients(async (cmd) => {
      if (cmd.name === "DescribeSecret") return { VersionIdsToStages: { current: ["AWSCURRENT"], [token]: ["AWSPENDING"] } };
      if (cmd.name === "GetSecretValue") return { VersionId: token, SecretString: JSON.stringify(pair) };
      throw new Error(`unexpected ${cmd.name}`);
    });
    const result = await _test.run(event("stage-pending", { ClientRequestToken: token }), fixture.clients);
    assert.equal(result.pendingPublicKey, pair.publicKey);
    assert.equal(fixture.calls.filter((call) => call.name === "PutSecretValue").length, 0);
  });

  it("refuses an AWSPENDING version owned by another token", async () => {
    const fixture = clients(async (cmd) => {
      if (cmd.name === "DescribeSecret") return { VersionIdsToStages: { current: ["AWSCURRENT"], other: ["AWSPENDING"] } };
      throw new Error(`unexpected ${cmd.name}`);
    });
    await assert.rejects(_test.run(event("stage-pending", { ClientRequestToken: token }), fixture.clients), /pending-version-conflict/);
    assert.equal(fixture.calls.filter((call) => call.name === "PutSecretValue").length, 0);
  });

  it("refuses to mint a pending identity when AWSCURRENT is absent", async () => {
    const fixture = clients(async (cmd) => {
      if (cmd.name === "DescribeSecret") return { VersionIdsToStages: {} };
      throw new Error(`unexpected ${cmd.name}`);
    });
    await assert.rejects(
      _test.run(event("stage-pending", { ClientRequestToken: token }), fixture.clients),
      /^RelayIdentityError: current-version-missing$/,
    );
    assert.equal(fixture.calls.filter((call) => call.name === "PutSecretValue").length, 0);
  });
});

describe("status redaction", () => {
  it("returns only version ids and public keys", async () => {
    const pair = currentFixture();
    const fixture = clients(async (cmd) => {
      if (cmd.name === "DescribeSecret") return { VersionIdsToStages: { current: ["AWSCURRENT"] } };
      if (cmd.name === "GetSecretValue") return { VersionId: "current", SecretString: JSON.stringify(pair) };
      throw new Error(`unexpected ${cmd.name}`);
    });
    const result = await _test.run(event("status"), fixture.clients);
    const serialized = JSON.stringify(result);
    assert.equal(result.versions.AWSCURRENT.publicKey, pair.publicKey);
    assert.equal(serialized.includes(pair.privateKey), false);
    assert.equal(serialized.includes("privateKey"), false);
  });

  it("fails closed when the AWSPREVIOUS rollback target is malformed", async () => {
    const fixture = clients(async (cmd) => {
      if (cmd.name === "DescribeSecret") return { VersionIdsToStages: { previous: ["AWSPREVIOUS"] } };
      if (cmd.name === "GetSecretValue") {
        return { VersionId: "previous", SecretString: "PRIVATE-SENTINEL" };
      }
      throw new Error(`unexpected ${cmd.name}`);
    });
    await assert.rejects(
      _test.run(event("status"), fixture.clients),
      (error) => error.name === "RelayIdentityError"
        && error.message === "invalid-secret-json"
        && !error.message.includes("PRIVATE-SENTINEL"),
    );
  });

  it("rejects a stage label attached to more than one version", () => {
    assert.throws(
      () => _test.versionForStage({ first: ["AWSPREVIOUS"], second: ["AWSPREVIOUS"] }, "AWSPREVIOUS"),
      /^RelayIdentityError: multiple-awsprevious$/,
    );
  });
});
