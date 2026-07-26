"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const Module = require("node:module");
const path = require("node:path");
const { describe, it } = require("node:test");

const originalResolveFilename = Module._resolveFilename;
Module._resolveFilename = function (request, parent, isMain, options) {
  if (request === "@aws-sdk/client-secrets-manager") return "__mock_hub_secrets__";
  if (request === "@aws-sdk/client-ssm") return "__mock_hub_ssm__";
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

require.cache.__mock_hub_secrets__ = {
  id: "__mock_hub_secrets__",
  filename: "__mock_hub_secrets__",
  loaded: true,
  exports: {
    SecretsManagerClient: class { async send() { throw new Error("unmocked"); } },
    DescribeSecretCommand: command("DescribeSecret"),
    GetSecretValueCommand: command("GetSecretValue"),
    PutSecretValueCommand: command("PutSecretValue"),
  },
};
require.cache.__mock_hub_ssm__ = {
  id: "__mock_hub_ssm__",
  filename: "__mock_hub_ssm__",
  loaded: true,
  exports: {
    SSMClient: class { async send() { throw new Error("unmocked"); } },
    GetParameterCommand: command("GetParameter"),
    PutParameterCommand: command("PutParameter"),
  },
};

const { _test } = require("./keygen");
Module._resolveFilename = originalResolveFilename;

const environment = Object.freeze({
  ENVIRONMENT: "sandbox",
  PUBLIC_KEY_PARAMETER: "/sandbox/nhp/control/hub/identity/public-key",
  SECRET_ID: "arn:aws:secretsmanager:us-east-2:767397897469:secret:hub-AbCdEf",
});
const cookie = Buffer.alloc(32, 0xa5).toString("base64");

function secretFor(privateHex, overrides = {}) {
  return JSON.stringify({
    private_key: Buffer.from(privateHex, "hex").toString("base64"),
    active_cookie_key: cookie,
    previous_cookie_key: "",
    ...overrides,
  });
}

function fixture(handler) {
  const calls = [];
  return {
    calls,
    clients: {
      randomBytes: (size) => {
        assert.equal(size, 32);
        return Buffer.alloc(32, 0xa5);
      },
      secrets: {
        send: async (cmd) => {
          calls.push(cmd);
          return handler(cmd);
        },
      },
      sleep: async () => {},
      ssm: {
        send: async (cmd) => {
          calls.push(cmd);
          return handler(cmd);
        },
      },
      warn: () => {},
    },
  };
}

async function rejectBeforeAws(event, env, code) {
  const state = fixture(async (cmd) => {
    throw new Error(`unexpected ${cmd.name}`);
  });
  await assert.rejects(
    _test.run(event, env, state.clients),
    (error) => error.name === "HubKeygenError" && error.message === code,
  );
  assert.equal(state.calls.length, 0);
}

describe("X25519 identity derivation", () => {
  it("matches RFC 7748 section 6.1 and the NHP Go curve25519 vector", () => {
    // endpoints/js-agent/test/dh.test.ts pins this same RFC vector as parity
    // with the Go curve25519.X25519 implementation used by NHP server.
    const privateRaw = Buffer.from(
      "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
      "hex",
    );
    const expected = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
    assert.equal(_test.publicKeyFromPrivateRaw(privateRaw).toString("hex"), expected);
  });

  it("matches the qurl-conformance Go-generated relay-knock golden keypair", () => {
    // This testdata is the NHP copy of the qurl-conformance Go-generated
    // relay-knock vector. Read the checked-in vector instead of repeating its
    // key bytes so the repository's conformance-parity gate and this seeder
    // exercise one source of truth.
    const golden = JSON.parse(fs.readFileSync(
      path.resolve(
        __dirname,
        "../../../../..",
        "endpoints/js-agent/test/testdata/knock.json",
      ),
      "utf8",
    ));
    assert.match(golden.serverStaticPrivHex, /^[0-9a-f]{64}$/);
    assert.match(golden.serverStaticPubHex, /^[0-9a-f]{64}$/);
    const privateRaw = Buffer.from(golden.serverStaticPrivHex, "hex");
    assert.equal(
      _test.publicKeyFromPrivateRaw(privateRaw).toString("hex"),
      golden.serverStaticPubHex,
    );
  });

  it("exports generated d/x through strict JWK and re-derives x", () => {
    const identity = _test.generatedIdentity();
    assert.equal(identity.privateRaw.length, 32);
    assert.equal(identity.publicRaw.length, 32);
    assert.deepEqual(
      _test.publicKeyFromPrivateRaw(identity.privateRaw),
      identity.publicRaw,
    );
  });
});

describe("secret boundary", () => {
  const rfcPrivate =
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";

  it("accepts the exact existing schema and an empty previous cookie", () => {
    const parsed = _test.validateSecret(secretFor(rfcPrivate));
    assert.equal(parsed.privateRaw.toString("hex"), rfcPrivate);
    assert.equal(
      parsed.publicRaw.toString("hex"),
      "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
    );
  });

  it("accepts a canonical 32-byte previous cookie", () => {
    assert.doesNotThrow(() => _test.validateSecret(
      secretFor(rfcPrivate, { previous_cookie_key: cookie }),
    ));
  });

  it("rejects missing, extra, malformed, and noncanonical fields", () => {
    const exact = JSON.parse(secretFor(rfcPrivate));
    const cases = [
      JSON.stringify({ ...exact, public_key: cookie }),
      JSON.stringify({ ...exact, active_cookie_key: undefined }),
      JSON.stringify({ ...exact, private_key: "AAAA" }),
      JSON.stringify({ ...exact, previous_cookie_key: "AAAA" }),
      JSON.stringify({ ...exact, active_cookie_key: `${cookie.slice(0, -1)}A` }),
      JSON.stringify({ ...exact, private_key: Buffer.alloc(32).toString("base64") }),
      JSON.stringify({
        ...exact,
        active_cookie_key: Buffer.alloc(32).toString("base64"),
      }),
      "PRIVATE-SENTINEL",
    ];
    for (const value of cases) {
      assert.throws(
        () => _test.validateSecret(value),
        (error) => error.name === "HubKeygenError"
          && !error.message.includes("PRIVATE-SENTINEL"),
      );
    }
  });

  it("rejects duplicate or escaped schema keys instead of accepting JSON last-wins", () => {
    const exact = JSON.parse(secretFor(rfcPrivate));
    const duplicate = JSON.stringify(exact).replace(
      `"private_key":"${exact.private_key}"`,
      `"private_key":"${exact.private_key}","private_key":"${exact.private_key}"`,
    );
    const escaped = JSON.stringify(exact).replace(
      '"private_key"',
      '"private_\\u006bey"',
    );
    for (const value of [duplicate, escaped]) {
      assert.throws(
        () => _test.validateSecret(value),
        (error) => error.name === "HubKeygenError",
      );
    }
  });

  it("accepts arbitrary field order and JSON whitespace without weakening shape", () => {
    const exact = JSON.parse(secretFor(rfcPrivate));
    const reordered = `{
      "previous_cookie_key": "",
      "private_key": "${exact.private_key}",
      "active_cookie_key": "${exact.active_cookie_key}"
    }`;
    assert.doesNotThrow(() => _test.validateSecret(reordered));
  });
});

describe("invocation boundary", () => {
  it("rejects nonempty input and configuration drift before AWS calls", async () => {
    await rejectBeforeAws({ rotate: true }, environment, "invalid-event");
    await rejectBeforeAws({}, {
      ...environment,
      ENVIRONMENT: "prod",
    }, "invalid-configuration");
    await rejectBeforeAws({}, {
      ...environment,
      PUBLIC_KEY_PARAMETER: "/sandbox/nhp/control/hub/identity/other",
    }, "invalid-configuration");
  });

  it("maps unexpected failures to a stable redacted internal error", async () => {
    const clients = {};
    Object.defineProperty(clients, "secrets", {
      get() {
        throw new Error("PRIVATE-SENTINEL");
      },
    });
    await assert.rejects(
      _test.handle({}, environment, clients),
      (error) => error.name === "HubKeygenError"
        && error.message === "internal-error"
        && !error.message.includes("PRIVATE-SENTINEL"),
    );
  });
});

describe("seed and publication transaction", () => {
  it("seeds once, conditionally replaces the placeholder, and returns no key material", async () => {
    let stored;
    let parameter = "pending-keygen";
    const state = fixture(async (cmd) => {
      if (cmd.name === "DescribeSecret") return { VersionIdsToStages: {} };
      if (cmd.name === "PutSecretValue") {
        stored = cmd.params.SecretString;
        assert.deepEqual(cmd.params.VersionStages, ["AWSCURRENT"]);
        assert.match(cmd.params.ClientRequestToken, /^[0-9a-f]{64}$/);
        return { VersionId: "created" };
      }
      if (cmd.name === "GetSecretValue") {
        return { VersionId: "created", SecretString: stored };
      }
      if (cmd.name === "GetParameter") {
        return { Parameter: { Value: parameter } };
      }
      if (cmd.name === "PutParameter") {
        assert.equal(cmd.params.Name, environment.PUBLIC_KEY_PARAMETER);
        assert.equal(cmd.params.Type, "String");
        assert.equal(cmd.params.Overwrite, true);
        parameter = cmd.params.Value;
        return { Version: 2 };
      }
      throw new Error(`unexpected ${cmd.name}`);
    });

    const result = await _test.run({}, environment, state.clients);
    assert.deepEqual(result, { seeded: true });
    assert.deepEqual(Object.keys(JSON.parse(stored)).sort(), [
      "active_cookie_key",
      "previous_cookie_key",
      "private_key",
    ]);
    assert.ok(!stored.includes(parameter));
    assert.ok(!JSON.stringify(result).includes(parameter));
    assert.equal(state.calls.filter((call) => call.name === "PutSecretValue").length, 1);
    assert.equal(state.calls.filter((call) => call.name === "PutParameter").length, 1);
  });

  it("repairs secret-write/publication partial failure without generating or overwriting identity", async () => {
    let stored;
    let parameter = "pending-keygen";
    let failPublish = true;
    const first = fixture(async (cmd) => {
      if (cmd.name === "DescribeSecret") return { VersionIdsToStages: {} };
      if (cmd.name === "PutSecretValue") {
        stored = cmd.params.SecretString;
        return { VersionId: "created" };
      }
      if (cmd.name === "GetSecretValue") return { SecretString: stored };
      if (cmd.name === "GetParameter") return { Parameter: { Value: parameter } };
      if (cmd.name === "PutParameter") {
        if (failPublish) throw new Error("PRIVATE-SENTINEL");
        parameter = cmd.params.Value;
        return { Version: 2 };
      }
      throw new Error(`unexpected ${cmd.name}`);
    });
    await assert.rejects(
      _test.run({}, environment, first.clients),
      /^HubKeygenError: public-key-publish-failed$/,
    );

    failPublish = false;
    const second = fixture(async (cmd) => {
      if (cmd.name === "DescribeSecret") {
        return { VersionIdsToStages: { created: ["AWSCURRENT"] } };
      }
      if (cmd.name === "GetSecretValue") {
        return { VersionId: "created", SecretString: stored };
      }
      if (cmd.name === "GetParameter") return { Parameter: { Value: parameter } };
      if (cmd.name === "PutParameter") {
        parameter = cmd.params.Value;
        return { Version: 2 };
      }
      throw new Error(`unexpected ${cmd.name}`);
    });
    second.clients.generateKeyPair = () => {
      throw new Error("must not generate on repair");
    };
    second.clients.randomBytes = () => {
      throw new Error("must not generate cookies on repair");
    };
    assert.deepEqual(await _test.run({}, environment, second.clients), { seeded: true });
    assert.equal(second.calls.filter((call) => call.name === "PutSecretValue").length, 0);
    assert.equal(second.calls.filter((call) => call.name === "PutParameter").length, 1);
  });

  it("does not write when the public parameter already equals AWSCURRENT", async () => {
    const privateHex =
      "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    const publicKey = Buffer.from(
      "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
      "hex",
    ).toString("base64");
    const state = fixture(async (cmd) => {
      if (cmd.name === "DescribeSecret") {
        return { VersionIdsToStages: { current: ["AWSCURRENT"] } };
      }
      if (cmd.name === "GetSecretValue") {
        return { SecretString: secretFor(privateHex) };
      }
      if (cmd.name === "GetParameter") {
        return { Parameter: { Value: publicKey } };
      }
      throw new Error(`unexpected ${cmd.name}`);
    });
    assert.deepEqual(await _test.run({}, environment, state.clients), { seeded: true });
    assert.equal(state.calls.filter((call) => call.name === "PutParameter").length, 0);
    assert.equal(state.calls.filter((call) => call.name === "PutSecretValue").length, 0);
  });

  it("fails closed on a third public value and performs no Put", async () => {
    const privateHex =
      "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    const state = fixture(async (cmd) => {
      if (cmd.name === "DescribeSecret") {
        return { VersionIdsToStages: { current: ["AWSCURRENT"] } };
      }
      if (cmd.name === "GetSecretValue") {
        return { SecretString: secretFor(privateHex) };
      }
      if (cmd.name === "GetParameter") {
        return { Parameter: { Value: "OUT-OF-BAND-MISMATCH" } };
      }
      throw new Error(`unexpected ${cmd.name}`);
    });
    await assert.rejects(
      _test.run({}, environment, state.clients),
      /^HubKeygenError: public-key-conflict$/,
    );
    assert.equal(state.calls.filter((call) => call.name === "PutParameter").length, 0);
    assert.equal(state.calls.filter((call) => call.name === "PutSecretValue").length, 0);
  });

  it("fails closed if AWSCURRENT moves after the seed write", async () => {
    const conflicting = secretFor(
      "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
    );
    const state = fixture(async (cmd) => {
      if (cmd.name === "DescribeSecret") return { VersionIdsToStages: {} };
      if (cmd.name === "PutSecretValue") return { VersionId: "created" };
      if (cmd.name === "GetSecretValue") return { SecretString: conflicting };
      throw new Error(`unexpected ${cmd.name}`);
    });
    await assert.rejects(
      _test.run({}, environment, state.clients),
      /^HubKeygenError: secret-seed-conflict$/,
    );
    assert.equal(state.calls.filter((call) => call.name === "PutParameter").length, 0);
  });

  it("rejects malformed or staged-without-current version maps before mutation", async () => {
    for (const versions of [
      { pending: ["AWSPENDING"] },
      { malformed: "AWSCURRENT" },
      { empty: [] },
      {
        first: ["AWSCURRENT"],
        second: ["AWSCURRENT"],
      },
    ]) {
      const state = fixture(async (cmd) => {
        if (cmd.name === "DescribeSecret") {
          return { VersionIdsToStages: versions };
        }
        throw new Error(`unexpected ${cmd.name}`);
      });
      await assert.rejects(
        _test.run({}, environment, state.clients),
        (error) => error.name === "HubKeygenError",
      );
      assert.deepEqual(
        state.calls.map((call) => call.name),
        ["DescribeSecret"],
      );
    }
  });

  it("rejects an all-zero generated cookie before writing the secret", async () => {
    const state = fixture(async (cmd) => {
      if (cmd.name === "DescribeSecret") return { VersionIdsToStages: {} };
      throw new Error(`unexpected ${cmd.name}`);
    });
    state.clients.randomBytes = () => Buffer.alloc(32);
    await assert.rejects(
      _test.run({}, environment, state.clients),
      /^HubKeygenError: cookie-generation-failed$/,
    );
    assert.equal(state.calls.filter((call) => call.name === "PutSecretValue").length, 0);
  });

  it("confirms an eventually consistent placeholder replacement with bounded backoff", async () => {
    const privateHex =
      "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    const delays = [];
    let reads = 0;
    let published;
    const state = fixture(async (cmd) => {
      if (cmd.name === "DescribeSecret") {
        return { VersionIdsToStages: { current: ["AWSCURRENT"] } };
      }
      if (cmd.name === "GetSecretValue") {
        return { SecretString: secretFor(privateHex) };
      }
      if (cmd.name === "GetParameter") {
        reads += 1;
        if (reads < 4) {
          return { Parameter: { Value: "pending-keygen" } };
        }
        return { Parameter: { Value: published } };
      }
      if (cmd.name === "PutParameter") {
        published = cmd.params.Value;
        return { Version: 2 };
      }
      throw new Error(`unexpected ${cmd.name}`);
    });
    state.clients.sleep = async (milliseconds) => {
      delays.push(milliseconds);
    };
    assert.deepEqual(await _test.run({}, environment, state.clients), { seeded: true });
    assert.deepEqual(delays, [100, 200]);
  });

  it("redacts public-read and confirmation failures", async () => {
    const privateHex =
      "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    const warnings = [];
    let reads = 0;
    const state = fixture(async (cmd) => {
      if (cmd.name === "DescribeSecret") {
        return { VersionIdsToStages: { current: ["AWSCURRENT"] } };
      }
      if (cmd.name === "GetSecretValue") {
        return { SecretString: secretFor(privateHex) };
      }
      if (cmd.name === "GetParameter") {
        reads += 1;
        if (reads === 1) return { Parameter: { Value: "pending-keygen" } };
        throw new Error("PRIVATE-SENTINEL");
      }
      if (cmd.name === "PutParameter") return { Version: 2 };
      throw new Error(`unexpected ${cmd.name}`);
    });
    state.clients.warn = (message) => warnings.push(message);
    await assert.rejects(
      _test.run({}, environment, state.clients),
      (error) => error.message === "public-key-confirmation-failed"
        && !error.message.includes("PRIVATE-SENTINEL"),
    );
    assert.deepEqual(warnings, ["hub identity public-key confirmation read failed"]);
    assert.ok(!warnings.join(" ").includes("PRIVATE-SENTINEL"));
  });

  it("does not turn an initial public-parameter read failure into a write", async () => {
    const privateHex =
      "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    const state = fixture(async (cmd) => {
      if (cmd.name === "DescribeSecret") {
        return { VersionIdsToStages: { current: ["AWSCURRENT"] } };
      }
      if (cmd.name === "GetSecretValue") {
        return { SecretString: secretFor(privateHex) };
      }
      if (cmd.name === "GetParameter") throw new Error("PRIVATE-SENTINEL");
      throw new Error(`unexpected ${cmd.name}`);
    });
    await assert.rejects(
      _test.run({}, environment, state.clients),
      (error) => error.message === "public-key-read-failed"
        && !error.message.includes("PRIVATE-SENTINEL"),
    );
    assert.equal(state.calls.filter((call) => call.name === "PutParameter").length, 0);
  });
});

describe("Terraform boundary", () => {
  it("pins Node 22, singleton concurrency, exact public parameter, and constant result", () => {
    const terraform = fs.readFileSync(
      path.join(__dirname, "..", "..", "hub_keygen.tf"),
      "utf8",
    );
    const main = fs.readFileSync(
      path.join(__dirname, "..", "..", "main.tf"),
      "utf8",
    );
    assert.match(terraform, /runtime\s*=\s*"nodejs22\.x"/);
    assert.match(terraform, /handler\s*=\s*"keygen\.handler"/);
    assert.match(terraform, /reserved_concurrent_executions\s*=\s*1/);
    assert.match(terraform, /name\s*=\s*local\.hub_public_key_parameter_name/);
    assert.match(
      main,
      /hub_public_key_parameter_name\s*=\s*"\/\$\{var\.environment\}\/nhp\/control\/hub\/identity\/public-key"/,
    );
    assert.match(terraform, /value\s*=\s*"pending-keygen"/);
    assert.match(terraform, /ignore_changes\s*=\s*\[value\]/);
    assert.match(terraform, /"secretsmanager:DescribeSecret"/);
    assert.match(terraform, /"secretsmanager:GetSecretValue"/);
    assert.match(terraform, /"secretsmanager:PutSecretValue"/);
    assert.match(terraform, /"ssm:GetParameter"/);
    assert.match(terraform, /"ssm:PutParameter"/);
    assert.match(terraform, /jsondecode\(self\.result\)[\s\S]*seeded = true/);
    assert.match(
      terraform,
      /resource "aws_lambda_invocation" "hub_identity_publication"[\s\S]*depends_on = \[[\s\S]*aws_lambda_invocation\.hub_keygen/,
    );
  });
});
