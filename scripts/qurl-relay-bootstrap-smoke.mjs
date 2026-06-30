#!/usr/bin/env node
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const DEFAULT_TIMEOUT_MS = 15_000;
const DEFAULT_BOGUS_TOKEN = "at_nonexistentyyyyyyyyyyy";
const FETCH_ATTEMPTS = 3;
const FETCH_BACKOFF_MS = 500;
const KNOCK_ATTEMPTS = 3;
const KNOCK_BACKOFF_MS = 750;
const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const COMMITTED_AGENT_BUNDLE = resolve(SCRIPT_DIR, "../terraform/modules/qurl-link/frontend/nhp-agent.min.js");
// Static qurl.link config should only point at first-party relay origins. Keep
// this in sync with relay DNS names when qURL relay origins change.
const ALLOWED_RELAY_HOSTS = new Set(["relay.qurl.link", "relay.qurl.link.layerv.xyz"]);

function usage() {
  return `Usage: node scripts/qurl-relay-bootstrap-smoke.mjs <qurl-link-origin>

Fetches qurl.link, imports its deployed /nhp-agent.min.js bundle, and sends a
shaped bogus qURL bootstrap knock through the configured relay. The expected
result is a reResolve ACK, proving the browser relay ingress, nhp-server reply
path, and qurl-service lookup path are live without minting a real qURL.

Requires Node.js 18+ for global fetch and AbortSignal.timeout; CI pins Node 22.

Environment:
  QURL_LINK_URL                     origin fallback when no argument is passed
  QURL_RELAY_SMOKE_TOKEN            shaped bogus at_ token override
  QURL_RELAY_SMOKE_TIMEOUT_MS       per-fetch-attempt and relay-knock timeout, default ${DEFAULT_TIMEOUT_MS}
`;
}

function fail(message) {
  throw new Error(message);
}

function assert(condition, message) {
  if (!condition) fail(message);
}

function assertBareHttpsOrigin(parsed, label) {
  assert(parsed.protocol === "https:", `${label} must be https:, got ${parsed.href}`);
  assert(parsed.username === "" && parsed.password === "", `${label} must not contain userinfo`);
  assert(parsed.pathname === "/" && parsed.search === "" && parsed.hash === "", `${label} must be an origin, got ${parsed.href}`);
}

function normalizeOrigin(raw) {
  if (!raw) fail(`missing qurl-link origin\n\n${usage()}`);
  let parsed;
  try {
    parsed = new URL(raw);
  } catch (error) {
    fail(`qurl-link origin ${JSON.stringify(raw)} is not a URL: ${error.message}`);
  }
  assertBareHttpsOrigin(parsed, "qurl-link origin");
  return parsed.origin;
}

function parseTimeoutMs(raw = process.env.QURL_RELAY_SMOKE_TIMEOUT_MS || String(DEFAULT_TIMEOUT_MS)) {
  const value = Number(raw);
  assert(Number.isSafeInteger(value) && value > 0, `QURL_RELAY_SMOKE_TIMEOUT_MS must be a positive integer, got ${JSON.stringify(raw)}`);
  return value;
}

async function fetchBytes(url, timeoutMs, sleepFn = sleep, fetchFn = fetch) {
  let lastError;

  for (let attempt = 1; attempt <= FETCH_ATTEMPTS; attempt += 1) {
    try {
      const response = await fetchFn(url, {
        cache: "no-store",
        headers: { "Accept-Encoding": "identity" },
        signal: AbortSignal.timeout(timeoutMs),
      });
      const shouldRetryStatus = response.status >= 500 && attempt < FETCH_ATTEMPTS;
      const bytes = new Uint8Array(await response.arrayBuffer());
      if (!shouldRetryStatus) return { response, bytes };
      lastError = new Error(`HTTP ${response.status}`);
    } catch (error) {
      lastError = error;
    }

    if (attempt < FETCH_ATTEMPTS) await sleepFn(FETCH_BACKOFF_MS * attempt);
  }

  fail(`fetch ${url} failed after ${FETCH_ATTEMPTS} attempts: ${lastError instanceof Error ? lastError.message : String(lastError)}`);
}

async function fetchText(url, timeoutMs, sleepFn = sleep, fetchFn = fetch) {
  const { response, bytes } = await fetchBytes(url, timeoutMs, sleepFn, fetchFn);
  return { response, text: new TextDecoder().decode(bytes) };
}

// Coupled to the QURL_LINK_CONFIG literal rendered by
// terraform/modules/qurl-link/frontend/index.html; drift should fail loudly.
// Returns the object body with JS comments removed before field extraction.
function extractQurlLinkConfigBlock(html) {
  const match = /\bQURL_LINK_CONFIG\s*=\s*\{/.exec(html);
  assert(match, "qurl.link verifier config is missing QURL_LINK_CONFIG");

  const openBrace = match.index + match[0].length - 1;
  let block = "";
  let depth = 0;
  let quote = "";
  let escaped = false;
  let lineComment = false;
  let blockComment = false;

  for (let i = openBrace; i < html.length; i += 1) {
    const char = html[i];
    const next = html[i + 1] || "";

    if (lineComment) {
      if (char === "\n" || char === "\r") {
        lineComment = false;
        if (depth > 0) block += char;
      }
      continue;
    }

    if (blockComment) {
      if (char === "*" && next === "/") {
        blockComment = false;
        i += 1;
      } else if ((char === "\n" || char === "\r") && depth > 0) {
        block += char;
      }
      continue;
    }

    if (quote) {
      if (depth > 0) block += char;
      if (escaped) {
        escaped = false;
      } else if (char === "\\") {
        escaped = true;
      } else if (char === quote) {
        quote = "";
      }
      continue;
    }

    if (char === "/" && next === "/") {
      lineComment = true;
      i += 1;
    } else if (char === "/" && next === "*") {
      blockComment = true;
      i += 1;
    } else if (char === "\"" || char === "'" || char === "`") {
      quote = char;
      if (depth > 0) block += char;
    } else if (char === "{") {
      depth += 1;
      if (depth > 1) block += char;
    } else if (char === "}") {
      depth -= 1;
      if (depth === 0) return block;
      block += char;
    } else if (depth > 0) {
      block += char;
    }
  }

  fail("qurl.link verifier config block is not closed");
}

function extractStringField(html, field) {
  const re = new RegExp(`\\b${field}\\s*:\\s*"([^"]*)"`);
  const match = re.exec(html);
  assert(match, `qurl.link verifier config is missing ${field}`);
  return match[1];
}

function extractBoolField(html, field) {
  const re = new RegExp(`\\b${field}\\s*:\\s*(true|false)\\b`);
  const match = re.exec(html);
  assert(match, `qurl.link verifier config is missing ${field}`);
  return match[1] === "true";
}

function parseQurlLinkConfig(html) {
  const configBlock = extractQurlLinkConfigBlock(html);
  return {
    jsAgentEnabled: extractBoolField(configBlock, "jsAgentEnabled"),
    relayBaseUrl: extractStringField(configBlock, "relayBaseUrl"),
    serverStaticPubB64: extractStringField(configBlock, "serverStaticPubB64"),
  };
}

function findAgentScriptTag(html) {
  const match = /<script\b[^>]*\bsrc=["']\/nhp-agent\.min\.js["'][^>]*>/i.exec(html);
  assert(match, "qurl.link JS-agent mode is enabled, but /nhp-agent.min.js script tag is missing");
  return match[0];
}

function attrValue(tag, name) {
  const re = new RegExp(`\\b${name}\\s*=\\s*["']([^"']+)["']`, "i");
  const match = re.exec(tag);
  return match ? match[1] : "";
}

function sha384SRI(bytes) {
  return `sha384-${createHash("sha384").update(bytes).digest("base64")}`;
}

function parseRelayOrigin(raw) {
  let parsed;
  try {
    parsed = new URL(raw);
  } catch (error) {
    fail(`relayBaseUrl ${JSON.stringify(raw)} is not a URL: ${error.message}`);
  }
  assertBareHttpsOrigin(parsed, "relayBaseUrl");
  assert(ALLOWED_RELAY_HOSTS.has(parsed.hostname.toLowerCase()), `relayBaseUrl host ${parsed.hostname} is not an expected qURL relay host`);
  return parsed.origin;
}

async function committedAgentIntegrity() {
  try {
    return sha384SRI(await readFile(COMMITTED_AGENT_BUNDLE));
  } catch (error) {
    fail(`failed to read committed qurl-link agent bundle at ${COMMITTED_AGENT_BUNDLE}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

function validateConfig(config) {
  // #2680 is the sandbox traffic cutover: after this point, flagging the qURL
  // link verifier out of JS-agent mode is a broken deploy, not a graceful skip.
  // An intentional rollback needs an audited workflow escape hatch (tracked in
  // #2929); auto-skipping here would mask a broken forward cutover.
  assert(config.jsAgentEnabled, "qurl.link jsAgentEnabled is false; sandbox #2680 relay cutover smoke expects the browser agent path");
  assert(/^[A-Za-z0-9+/]{43}=$/.test(config.serverStaticPubB64), "serverStaticPubB64 is not a 44-character standard-base64 X25519 key");
  return {
    ...config,
    relayBaseUrl: parseRelayOrigin(config.relayBaseUrl),
  };
}

function validateToken(token) {
  assert(/^at_[A-Za-z0-9_-]{22}$/.test(token), `smoke token must match at_ + 22 base64url chars, got ${JSON.stringify(token)}`);
}

async function importAgentBundle(bytes) {
  const dir = await mkdtemp(join(tmpdir(), "nhp-qurl-relay-smoke-"));
  const modulePath = join(dir, "nhp-agent.min.mjs");
  await writeFile(modulePath, bytes);
  try {
    return await import(pathToFileURL(modulePath).href);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

async function withTimeout(promise, timeoutMs, label) {
  let timeout;
  let didTimeout = false;
  const guardedPromise = Promise.resolve(promise).catch((error) => {
    if (didTimeout) return new Promise(() => {});
    throw error;
  });

  try {
    return await Promise.race([
      guardedPromise,
      new Promise((_, reject) => {
        timeout = setTimeout(() => {
          didTimeout = true;
          reject(new Error(`${label} timed out after ${timeoutMs}ms`));
        }, timeoutMs);
      }),
    ]);
  } finally {
    clearTimeout(timeout);
  }
}

async function sleep(ms) {
  await new Promise((resolveSleep) => {
    setTimeout(resolveSleep, ms);
  });
}

async function knockWithRetry(agent, request, timeoutMs, sleepFn = sleep) {
  let lastError;
  let lastResult;

  for (let attempt = 1; attempt <= KNOCK_ATTEMPTS; attempt += 1) {
    try {
      // The bundle owns the underlying transport; this bounds the helper's wait
      // so CI can retry/exit even though it cannot abort the in-flight request.
      lastResult = await withTimeout(
        agent.knock(request),
        timeoutMs,
        `relay knock attempt ${attempt}`,
      );
      if (lastResult?.kind !== "cookieChallenge") return lastResult;
    } catch (error) {
      lastError = error;
      lastResult = undefined;
    }

    if (attempt < KNOCK_ATTEMPTS) await sleepFn(KNOCK_BACKOFF_MS * attempt);
  }

  if (lastResult?.kind === "cookieChallenge") {
    fail(`relay knock returned cookieChallenge after ${KNOCK_ATTEMPTS} attempts; qurl-service token lookup was not reached`);
  }
  fail(
    `relay knock failed after ${KNOCK_ATTEMPTS} attempts: ${lastError instanceof Error ? lastError.message : String(lastError)}`,
  );
}

async function run(origin, timeoutMs, token) {
  validateToken(token);

  const rootUrl = `${origin}/`;
  const { response: htmlResponse, text: html } = await fetchText(rootUrl, timeoutMs);
  assert(htmlResponse.ok, `GET ${rootUrl} returned ${htmlResponse.status}`);

  // This post-deploy gate validates the static relayBaseUrl rendered into
  // QURL_LINK_CONFIG. Minted qv1 fragments can override it at runtime; those
  // route-level overrides belong in qurl-service/browser E2E coverage.
  const config = validateConfig(parseQurlLinkConfig(html));

  const scriptTag = findAgentScriptTag(html);
  const integrity = attrValue(scriptTag, "integrity");
  assert(integrity.startsWith("sha384-"), `agent script integrity must be sha384, got ${JSON.stringify(integrity)}`);

  const bundleUrl = `${origin}/nhp-agent.min.js`;
  const { response: bundleResponse, bytes: bundleBytes } = await fetchBytes(bundleUrl, timeoutMs);
  assert(bundleResponse.ok, `GET ${bundleUrl} returned ${bundleResponse.status}`);
  const contentType = bundleResponse.headers.get("content-type") || "";
  const mediaType = contentType.split(";")[0].trim().toLowerCase();
  assert(mediaType === "text/javascript" || mediaType === "application/javascript", `GET ${bundleUrl} returned Content-Type ${JSON.stringify(contentType)}, want JavaScript`);

  // The SRI comparison mirrors the browser's script gate; the committed-bundle
  // comparison anchors the imported bytes to this checkout before CI executes
  // the deployed module.
  const actualIntegrity = sha384SRI(bundleBytes);
  assert(actualIntegrity === integrity, `deployed agent SRI mismatch: tag ${integrity}, bytes ${actualIntegrity}`);
  const expectedIntegrity = await committedAgentIntegrity();
  assert(actualIntegrity === expectedIntegrity, `deployed agent differs from committed qurl-link bundle: deployed ${actualIntegrity}, committed ${expectedIntegrity}`);

  const agent = await importAgentBundle(bundleBytes);
  for (const name of ["generateDeviceKeyPair", "knock", "x25519KeyFromBase64"]) {
    assert(typeof agent[name] === "function", `deployed agent bundle does not export ${name}`);
  }

  const keyPair = agent.generateDeviceKeyPair();
  const result = await knockWithRetry(
    agent,
    {
      deviceStaticPriv: keyPair.deviceStaticPriv,
      serverStaticPub: agent.x25519KeyFromBase64(config.serverStaticPubB64),
      relayBaseUrl: config.relayBaseUrl,
      authServiceId: "qurl",
      qurlAccessToken: token,
      qurlUserAgent: "nhp-qurl-relay-smoke/1 issue-2680",
    },
    timeoutMs,
  );

  assert(result && typeof result.kind === "string", `relay knock returned malformed result: ${JSON.stringify(result)}`);
  // cookieChallenge proves relay/server reachability, but not the qurl-service
  // token lookup #2680 needs. reResolve is qurl-service's unknown-token
  // contract for shaped bogus at_ tokens; update this gate with any service
  // contract change rather than loosening it here.
  assert(
    result.kind === "reResolve",
    `relay knock should return reResolve for the bogus token, got ${JSON.stringify(result)}`,
  );

  console.log(`qURL relay bootstrap smoke OK: origin=${origin} relay=${config.relayBaseUrl} result=${result.kind}`);
}

async function selfTest() {
  const sample = `
    <script>
      const QURL_LINK_CONFIG = {
        allowedHosts: ["qurl.link.layerv.xyz"],
        jsAgentEnabled: true,
        relayBaseUrl: "https://relay.qurl.link.layerv.xyz",
        serverStaticPubB64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
      };
    </script>
    <script type="module" integrity="sha384-example" src="/nhp-agent.min.js"></script>
  `;
  const config = parseQurlLinkConfig(sample);
  assert(config.jsAgentEnabled === true, "self-test jsAgentEnabled parse failed");
  assert(config.relayBaseUrl === "https://relay.qurl.link.layerv.xyz", "self-test relay parse failed");
  assert(findAgentScriptTag(sample).includes("nhp-agent.min.js"), "self-test script tag parse failed");
  const noisyConfig = parseQurlLinkConfig(`
    <script>
      const QURL_LINK_CONFIG = {
        metadata: { note: "literal } brace" },
        // jsAgentEnabled: false,
        /* relayBaseUrl: "https://relay.qurl.link.evil.test", */
        // } should not terminate the config block
        /* } should not terminate the config block either */
        jsAgentEnabled: true,
        relayBaseUrl: "https://relay.qurl.link.layerv.xyz",
        serverStaticPubB64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
      };
    </script>
  `);
  assert(noisyConfig.relayBaseUrl === "https://relay.qurl.link.layerv.xyz", "self-test noisy config block parse failed");
  assert(attrValue(findAgentScriptTag(sample), "integrity") === "sha384-example", "self-test script integrity attr parse failed");
  assert(
    sha384SRI(new TextEncoder().encode("abc")) === "sha384-ywB1P0WjXou1oD1pmsZQBycsMqsO3tFjGotgWkP/W+2AhgcroefMI1i67KE0yCWn",
    "self-test sha384 SRI failed",
  );
  assertThrows(
    () => parseQurlLinkConfig("<script>const notConfig = { relayBaseUrl: \"https://relay.qurl.link\" }</script>"),
    "self-test missing config block rejection failed",
  );
  assertThrows(
    () => parseQurlLinkConfig("<script>const QURL_LINK_CONFIG = { relayBaseUrl: \"https://relay.qurl.link\" }</script>"),
    "self-test missing config field rejection failed",
  );
  assert(normalizeOrigin("https://qurl.link.layerv.xyz") === "https://qurl.link.layerv.xyz", "self-test qurl origin normalize failed");
  assertThrows(() => normalizeOrigin("http://qurl.link.layerv.xyz"), "self-test non-https qurl origin rejection failed");
  assert(parseTimeoutMs("123") === 123, "self-test timeout parse failed");
  assertThrows(() => parseTimeoutMs("0"), "self-test zero timeout rejection failed");
  assertThrows(() => parseTimeoutMs("12.5"), "self-test fractional timeout rejection failed");
  let fetchAttempts = 0;
  const fetchRetryResult = await fetchBytes(
    "https://qurl.link.layerv.xyz/",
    DEFAULT_TIMEOUT_MS,
    async () => {},
    async () => {
      fetchAttempts += 1;
      if (fetchAttempts === 1) throw new Error("transient fetch error");
      if (fetchAttempts === 2) return new Response("retry", { status: 503 });
      return new Response("ok", { status: 200 });
    },
  );
  assert(new TextDecoder().decode(fetchRetryResult.bytes) === "ok" && fetchAttempts === 3, "self-test fetch retry failed");
  validateToken(DEFAULT_BOGUS_TOKEN);
  validateToken("at_ABCdef0123456789_-wxyz");
  assertThrows(() => validateToken("at_short"), "self-test token rejection failed");
  const configWithSlash = { ...config, relayBaseUrl: "https://relay.qurl.link.layerv.xyz/" };
  const normalizedConfig = validateConfig(configWithSlash);
  assert(normalizedConfig.relayBaseUrl === "https://relay.qurl.link.layerv.xyz", "self-test relay origin normalize failed");
  assert(configWithSlash.relayBaseUrl === "https://relay.qurl.link.layerv.xyz/", "self-test validateConfig should not mutate input");
  assertThrows(() => validateConfig({ ...config, jsAgentEnabled: false }), "self-test jsAgentEnabled=false rejection failed");
  assertThrows(() => validateConfig({ ...config, relayBaseUrl: "http://relay.qurl.link.layerv.xyz" }), "self-test non-https relay rejection failed");
  assertThrows(() => validateConfig({ ...config, relayBaseUrl: "https://relay.qurl.link.evil.test" }), "self-test relay host rejection failed");
  assertThrows(() => validateConfig({ ...config, serverStaticPubB64: "bad" }), "self-test X25519 key rejection failed");
  let knockAttempts = 0;
  const retryResult = await knockWithRetry(
    {
      knock: async () => {
        knockAttempts += 1;
        return knockAttempts === 1 ? { kind: "cookieChallenge" } : { kind: "reResolve" };
      },
    },
    {},
    DEFAULT_TIMEOUT_MS,
    async () => {},
  );
  assert(retryResult.kind === "reResolve" && knockAttempts === 2, "self-test cookieChallenge retry failed");

  let errorRetryAttempts = 0;
  const errorRetryResult = await knockWithRetry(
    {
      knock: async () => {
        errorRetryAttempts += 1;
        if (errorRetryAttempts === 1) throw new Error("transient relay error");
        return { kind: "reResolve" };
      },
    },
    {},
    DEFAULT_TIMEOUT_MS,
    async () => {},
  );
  assert(errorRetryResult.kind === "reResolve" && errorRetryAttempts === 2, "self-test thrown-error retry failed");

  let lateTimeoutRejectionUnhandled = false;
  const lateTimeoutRejectionListener = () => {
    lateTimeoutRejectionUnhandled = true;
  };
  process.once("unhandledRejection", lateTimeoutRejectionListener);
  try {
    await assertRejects(
      () => withTimeout(
        new Promise((_, reject) => setTimeout(() => reject(new Error("late relay rejection")), 10)),
        1,
        "self-test relay timeout",
      ),
      "self-test relay timeout rejection failed",
    );
    await sleep(25);
  } finally {
    process.removeListener("unhandledRejection", lateTimeoutRejectionListener);
  }
  assert(!lateTimeoutRejectionUnhandled, "self-test timed-out relay knock rejection escaped");

  await assertRejects(
    () => knockWithRetry(
      { knock: async () => ({ kind: "cookieChallenge" }) },
      {},
      DEFAULT_TIMEOUT_MS,
      async () => {},
    ),
    "self-test persistent cookieChallenge rejection failed",
  );
  console.log("qurl-relay-bootstrap-smoke self-test OK");
}

function assertThrows(fn, message) {
  try {
    fn();
  } catch {
    return;
  }
  fail(message);
}

async function assertRejects(fn, message) {
  try {
    await fn();
  } catch {
    return;
  }
  fail(message);
}

if (process.argv.includes("--self-test")) {
  selfTest().catch((error) => {
    console.error(`qurl-relay-bootstrap-smoke self-test failed: ${error instanceof Error ? error.message : String(error)}`);
    process.exit(1);
  });
} else {
  const origin = normalizeOrigin(process.argv[2] || process.env.QURL_LINK_URL);
  const timeoutMs = parseTimeoutMs();
  const token = process.env.QURL_RELAY_SMOKE_TOKEN || DEFAULT_BOGUS_TOKEN;
  run(origin, timeoutMs, token)
    .then(() => process.exit(0))
    .catch((error) => {
      console.error(`qURL relay bootstrap smoke failed: ${error instanceof Error ? error.message : String(error)}`);
      process.exit(1);
    });
}
