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
    GetParameterCommand: command("GetParameter"),
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
    const outputs = fs.readFileSync(path.join(__dirname, "..", "outputs.tf"), "utf8");
    const planPolicy = fs.readFileSync(path.join(__dirname, "..", "..", "ecr", "main.tf"), "utf8");
    const rotation = fs.readFileSync(path.join(__dirname, "..", "..", "..", "..", "scripts", "rotate-relay-identity.sh"), "utf8");
    const publish = terraform.match(/resource "aws_lambda_invocation" "publish_public_key" \{([\s\S]*?)\n\}/);
    const status = terraform.match(/data "aws_lambda_invocation" "status" \{([\s\S]*?)\n\}/);
    const propagation = terraform.match(/resource "time_sleep" "keygen_iam_propagation" \{([\s\S]*?)\n\}/);
    const lambda = terraform.match(/resource "aws_lambda_function" "keygen" \{([\s\S]*?)\n\}/);
    const statusLambda = terraform.match(/resource "aws_lambda_function" "status" \{([\s\S]*?)\n\}/);
    const statusPolicy = terraform.match(/resource "aws_iam_role_policy" "status_lambda_access" \{([\s\S]*?)\n\}/);
    assert.ok(publish && status && propagation && lambda && statusLambda && statusPolicy,
      "publish, status, propagation, and Lambda boundaries must remain inspectable");
    assert.match(propagation[1], /assume_role_policy_hash/);
    assert.match(propagation[1], /secrets_policy_hash/);
    assert.match(propagation[1], /keygen_basic_policy_attachment_id/);
    assert.doesNotMatch(propagation[1], /status_basic_policy_attachment_id/);
    assert.match(terraform, /Action\s*=\s*\["ssm:GetParameter", "ssm:PutParameter"\]/);
    assert.match(lambda[1], /depends_on\s*=\s*\[time_sleep\.keygen_iam_propagation\]/);
    assert.match(statusLambda[1], /handler\s*=\s*"relay_identity\.statusHandler"/);
    assert.match(statusLambda[1], /role\s*=\s*aws_iam_role\.status_lambda\.arn/);
    const statusActions = [...statusPolicy[1].matchAll(/Action\s*=\s*\[([^\]]*)\]/g)]
      .flatMap((block) => [...block[1].matchAll(/"([^"]+)"/g)].map((match) => match[1]))
      .sort();
    assert.deepEqual(statusActions, [
      "kms:Decrypt",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "secretsmanager:DescribeSecret",
      "secretsmanager:GetSecretValue",
      "ssm:GetParameter",
    ]);
    assert.match(statusPolicy[1], /Resource\s*=\s*\[aws_secretsmanager_secret\.relay\.arn\]/);
    assert.match(statusPolicy[1], /Resource\s*=\s*\[aws_ssm_parameter\.relay_public_key\.arn\]/);
    assert.match(statusPolicy[1], /Resource\s*=\s*\["\$\{aws_cloudwatch_log_group\.status\.arn\}:\*"\]/);
    assert.match(statusPolicy[1], /Resource\s*=\s*\[var\.secrets_kms_key_arn\]/);
    assert.doesNotMatch(terraform, /resource "aws_iam_role_policy_attachment" "status_lambda_basic"/);
    assert.match(planPolicy, /Sid\s*=\s*"RelayIdentityStatusInvoke"[\s\S]*Action\s*=\s*\["lambda:InvokeFunction"\][\s\S]*function:\$\{var\.name_prefix\}-relay-status/);
    assert.match(statusLambda[1], /function_name\s*=\s*"\$\{var\.name_prefix\}-relay-status"/);
    assert.match(publish[1], /Action\s*=\s*"publish-current"/);
    assert.match(publish[1], /aws_lambda_invocation\.keygen/);
    assert.match(publish[1], /postcondition[\s\S]*self\.result[\s\S]*"publish-current"/);
    assert.match(publish[1], /can\(regex\([\s\S]*"\^\[A-Za-z0-9\+\/\]\{42\}\[AEIMQUYcgkosw048\]=\$"[\s\S]*currentPublicKey/);
    assert.match(status[1], /Action\s*=\s*"confirmed-status"/);
    assert.match(status[1], /aws_lambda_function\.status\.function_name/);
    assert.match(status[1], /aws_lambda_invocation\.publish_public_key/);
    assert.match(status[1], /versions\.AWSCURRENT[\s\S]*publicKey/);
    assert.doesNotMatch(terraform, /data "aws_ssm_parameter" "relay_public_key"/);
    assert.match(outputs, /value\s*=\s*jsondecode\(data\.aws_lambda_invocation\.status\.result\)\.versions\.AWSCURRENT\.publicKey/);
    assert.doesNotMatch(outputs, /value\s*=\s*nonsensitive\(/);
    assert.match(rotation, /invoke_identity status/);
    assert.doesNotMatch(rotation, /invoke_identity confirmed-status/);
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

  it("keeps every non-confirmed action outside the PR-plan handler", async () => {
    for (const action of ["ensure-current", "publish-current", "stage-pending", "status", "delete"]) {
      const fixture = clients(async (cmd) => { throw new Error(`unexpected ${cmd.name}`); });
      await assert.rejects(
        _test.handleConfirmedStatus(event(action), fixture.clients),
        (error) => error.name === "RelayIdentityError"
          && error.message === (action === "delete" ? "invalid-action" : "invalid-event"),
      );
      assert.equal(fixture.calls.length, 0, `${action} must not reach an AWS client`);
    }
  });

  it("keeps confirmed-status outside the multi-action keygen handler", async () => {
    const fixture = clients(async (cmd) => { throw new Error(`unexpected ${cmd.name}`); });
    await assert.rejects(
      _test.handle(event("confirmed-status"), fixture.clients),
      /^RelayIdentityError: invalid-event$/,
    );
    assert.equal(fixture.calls.length, 0);
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
      if (cmd.name === "GetParameter") return { Parameter: { Value: pair.publicKey } };
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
      if (cmd.name === "GetParameter") {
        return { Parameter: { Value: JSON.parse(stored).publicKey } };
      }
      throw new Error(`unexpected ${cmd.name}`);
    });
    await _test.run(event("ensure-current"), fixture.clients);
    const published = await _test.run(event("publish-current"), fixture.clients);
    assert.equal(published.currentVersionId, "created");
    assert.equal(fixture.calls.filter((call) => call.name === "PutSecretValue").length, 1);
    assert.equal(fixture.calls.filter((call) => call.name === "PutParameter").length, 1);
  });

  it("waits until Parameter Store reads the public key it accepted", async () => {
    const pair = currentFixture();
    const delays = [];
    let reads = 0;
    const fixture = clients(async (cmd) => {
      if (cmd.name === "DescribeSecret") return { VersionIdsToStages: { current: ["AWSCURRENT"] } };
      if (cmd.name === "GetSecretValue") return { VersionId: "current", SecretString: JSON.stringify(pair) };
      if (cmd.name === "PutParameter") return { Version: 2 };
      if (cmd.name === "GetParameter") {
        reads += 1;
        return { Parameter: { Value: reads < 3 ? "pending-keygen" : pair.publicKey } };
      }
      throw new Error(`unexpected ${cmd.name}`);
    });
    fixture.clients.sleep = async (milliseconds) => { delays.push(milliseconds); };

    const result = await _test.run(event("publish-current"), fixture.clients);

    assert.equal(result.currentPublicKey, pair.publicKey);
    assert.equal(reads, 3);
    assert.deepEqual(delays, [100, 200]);
  });

  it("fails closed when Parameter Store never confirms the published key", async () => {
    const pair = currentFixture();
    const delays = [];
    const fixture = clients(async (cmd) => {
      if (cmd.name === "DescribeSecret") return { VersionIdsToStages: { current: ["AWSCURRENT"] } };
      if (cmd.name === "GetSecretValue") return { VersionId: "current", SecretString: JSON.stringify(pair) };
      if (cmd.name === "PutParameter") return { Version: 2 };
      if (cmd.name === "GetParameter") return { Parameter: { Value: "pending-keygen" } };
      throw new Error(`unexpected ${cmd.name}`);
    });
    fixture.clients.sleep = async (milliseconds) => { delays.push(milliseconds); };

    await assert.rejects(
      _test.run(event("publish-current"), fixture.clients),
      /^RelayIdentityError: public-key-confirmation-failed$/,
    );
    assert.equal(fixture.calls.filter((call) => call.name === "GetParameter").length, 10);
    assert.deepEqual(delays, [100, 200, 400, 800, 1000, 1000, 1000, 1000, 1000]);
  });

  it("redacts repeated Parameter Store read failures before failing closed", async () => {
    const pair = currentFixture();
    const warnings = [];
    const fixture = clients(async (cmd) => {
      if (cmd.name === "DescribeSecret") return { VersionIdsToStages: { current: ["AWSCURRENT"] } };
      if (cmd.name === "GetSecretValue") return { VersionId: "current", SecretString: JSON.stringify(pair) };
      if (cmd.name === "PutParameter") return { Version: 2 };
      if (cmd.name === "GetParameter") throw new Error("PRIVATE-SENTINEL transient SSM read");
      throw new Error(`unexpected ${cmd.name}`);
    });
    fixture.clients.sleep = async () => {};
    fixture.clients.warn = (message) => { warnings.push(message); };

    await assert.rejects(
      _test.run(event("publish-current"), fixture.clients),
      (error) => error.name === "RelayIdentityError"
        && error.message === "public-key-confirmation-failed"
        && !error.message.includes("PRIVATE-SENTINEL"),
    );
    assert.equal(fixture.calls.filter((call) => call.name === "GetParameter").length, 10);
    assert.deepEqual(warnings, ["relay identity public-key confirmation read failed"]);
    assert.ok(!warnings.join(" ").includes("PRIVATE-SENTINEL"));
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

  it("refreshes AWSCURRENT after rotation and confirms the matching public parameter", async () => {
    const before = currentFixture();
    const after = currentFixture();
    let current = { versionId: "before", pair: before };
    const fixture = clients(async (cmd) => {
      if (cmd.name === "DescribeSecret") return { VersionIdsToStages: { [current.versionId]: ["AWSCURRENT"] } };
      if (cmd.name === "GetSecretValue") return { VersionId: current.versionId, SecretString: JSON.stringify(current.pair) };
      if (cmd.name === "GetParameter") return { Parameter: { Value: current.pair.publicKey } };
      throw new Error(`unexpected ${cmd.name}`);
    });

    const first = await _test.handleConfirmedStatus(event("confirmed-status"), fixture.clients);
    current = { versionId: "after", pair: after };
    const second = await _test.handleConfirmedStatus(event("confirmed-status"), fixture.clients);

    assert.equal(first.versions.AWSCURRENT.publicKey, before.publicKey);
    assert.equal(second.versions.AWSCURRENT.publicKey, after.publicKey);
  });

  it("fails closed when AWSCURRENT and the published parameter diverge", async () => {
    const pair = currentFixture();
    const fixture = clients(async (cmd) => {
      if (cmd.name === "DescribeSecret") return { VersionIdsToStages: { current: ["AWSCURRENT"] } };
      if (cmd.name === "GetSecretValue") return { VersionId: "current", SecretString: JSON.stringify(pair) };
      if (cmd.name === "GetParameter") return { Parameter: { Value: "pending-keygen" } };
      throw new Error(`unexpected ${cmd.name}`);
    });
    fixture.clients.sleep = async () => {};

    await assert.rejects(
      _test.handleConfirmedStatus(event("confirmed-status"), fixture.clients),
      /^RelayIdentityError: public-key-confirmation-failed$/,
    );
  });

  it("keeps diagnostic status available during a repairable public-key mismatch", async () => {
    const pair = currentFixture();
    const fixture = clients(async (cmd) => {
      if (cmd.name === "DescribeSecret") return { VersionIdsToStages: { current: ["AWSCURRENT"] } };
      if (cmd.name === "GetSecretValue") return { VersionId: "current", SecretString: JSON.stringify(pair) };
      throw new Error(`unexpected ${cmd.name}`);
    });

    const result = await _test.run(event("status"), fixture.clients);

    assert.equal(result.action, "status");
    assert.equal(result.versions.AWSCURRENT.publicKey, pair.publicKey);
    assert.equal(fixture.calls.filter((call) => call.name === "GetParameter").length, 0);
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
