import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { knock } from "../src/agent/loop";
import type { KnockEntropy } from "../src/agent/knock";
import type { RelayTransport } from "../src/agent/relay";
import { pubKeyFingerprint } from "../src/crypto/fingerprint";
import { fromHex } from "./hex";
import { fixedEntropy, u64be } from "./entropy";

function fixture<T>(name: string): T {
  return JSON.parse(
    readFileSync(new URL(`./testdata/${name}`, import.meta.url), "utf8"),
  ) as T;
}

// PR-4 success ACK (errCode 0); the deny ACK (52024); the overload cookie reply.
const ackSuccess = fixture<{
  agentStaticPrivHex: string;
  serverStaticPubHex: string;
  ackPacketHex: string;
}>("ack.json");
const ack52024 = fixture<{ replyPacketHex: string }>("ack-52024.json");
const ackError = fixture<{ replyPacketHex: string; bodyHex: string }>(
  "ack-error.json",
);
const ackSuccessEmpty = fixture<{ replyPacketHex: string }>(
  "ack-success-empty.json",
);
const cok = fixture<{ replyPacketHex: string }>("cok.json");
const ackWrongType = fixture<{ replyPacketHex: string }>("ack-wrongtype.json");
const ackBadJson = fixture<{ replyPacketHex: string }>("ack-badjson.json");

// The fixtures share the Go generator's keys (0x41 agent, 0x01 server). The ACK
// fixtures echo KNOCK_COUNTER. The COK fixture deliberately carries a distinct
// legacy counter because the current loop returns cookieChallenge before the
// NHP_RKN cookie-answer path; real server COK packets now echo KNOCK_COUNTER for
// relay dispatch (#2648). KNOCK_COUNTER MUST equal the counter baked into
// ack.json (PR-4's TransactionId): the success test reuses that fixture, and the
// loop's reply-counter correlation only passes when the injected knock counter
// matches it. If ack.json is ever regenerated with a different counter, update
// this constant.
const AGENT_PRIV = fromHex(ackSuccess.agentStaticPrivHex);
const SERVER_PUB = fromHex(ackSuccess.serverStaticPubHex);
const KNOCK_COUNTER = 0x1122334455667788n;

const REQ = {
  deviceStaticPriv: AGENT_PRIV,
  serverStaticPub: SERVER_PUB,
  relayBaseUrl: "https://relay.example",
  authServiceId: "asp_test",
  resourceId: "r_jsagent",
};

/** Entropy that pins the knock counter (so the ACK correlation matches the
 * fixture) and is otherwise arbitrary — the mock transport ignores the knock. */
function entropyWithCounter(counter: bigint): KnockEntropy {
  return fixedEntropy(
    [
      new Uint8Array(32).fill(0xaa),
      u64be(counter),
      new Uint8Array(4).fill(0xbb),
    ],
    1_700_000_000_000_000_000n,
  );
}

/** A transport that ignores the knock and returns the given reply packet. */
function replyWith(replyHex: string): RelayTransport {
  const bytes = fromHex(replyHex);
  return async () => bytes;
}

describe("knock (qURL agent loop)", () => {
  it("returns success with the resource hosts + AC tokens on a 0-errCode ACK", async () => {
    const result = await knock(REQ, {
      transport: replyWith(ackSuccess.ackPacketHex),
      entropy: entropyWithCounter(KNOCK_COUNTER),
    });
    expect(result).toEqual({
      kind: "success",
      resourceHosts: { r_jsagent: "10.0.0.7" },
      acTokens: { r_jsagent: "tok-abc123" },
      openTimeSeconds: 900,
      agentAddr: "203.0.113.9",
      redirectUrl: "",
    });
  });

  it("treats an empty-string errCode as success (Go IsSuccessErrCode)", async () => {
    const result = await knock(REQ, {
      transport: replyWith(ackSuccessEmpty.replyPacketHex),
      entropy: entropyWithCounter(KNOCK_COUNTER),
    });
    expect(result).toEqual({
      kind: "success",
      resourceHosts: { r_jsagent: "10.0.0.7" },
      acTokens: { r_jsagent: "tok-abc123" },
      openTimeSeconds: 900,
      agentAddr: "203.0.113.9",
      redirectUrl: "",
    });
  });

  it("returns reResolve on the 52024 session-expired deny ACK", async () => {
    const result = await knock(REQ, {
      transport: replyWith(ack52024.replyPacketHex),
      entropy: entropyWithCounter(KNOCK_COUNTER),
    });
    expect(result.kind).toBe("reResolve");
  });

  it("returns serverError on a non-0/non-52024 errCode ACK", async () => {
    const result = await knock(REQ, {
      transport: replyWith(ackError.replyPacketHex),
      entropy: entropyWithCounter(KNOCK_COUNTER),
    });
    const body = JSON.parse(
      new TextDecoder().decode(fromHex(ackError.bodyHex)),
    );
    expect(result).toEqual({
      kind: "serverError",
      errCode: body.errCode,
      errMsg: body.errMsg,
    });
  });

  it("returns cookieChallenge on an NHP_COK reply before cookie-answer handling", async () => {
    const result = await knock(REQ, {
      transport: replyWith(cok.replyPacketHex),
      entropy: entropyWithCounter(KNOCK_COUNTER),
    });
    expect(result.kind).toBe("cookieChallenge");
  });

  it("routes by the server-pubkey fingerprint (serverId)", async () => {
    let seenId = "";
    await knock(REQ, {
      transport: async (serverId) => {
        seenId = serverId;
        return fromHex(ackSuccess.ackPacketHex);
      },
      entropy: entropyWithCounter(KNOCK_COUNTER),
    });
    expect(seenId).toBe(pubKeyFingerprint(SERVER_PUB));
  });

  it("throws when the ACK counter does not correlate to the knock", async () => {
    await expect(
      knock(REQ, {
        transport: replyWith(ackSuccess.ackPacketHex),
        entropy: entropyWithCounter(KNOCK_COUNTER + 1n), // wrong knock counter
      }),
    ).rejects.toThrow(/counter/i);
  });

  it("propagates a transport fault", async () => {
    await expect(
      knock(REQ, {
        transport: async () => {
          throw new Error("relay down");
        },
        entropy: entropyWithCounter(KNOCK_COUNTER),
      }),
    ).rejects.toThrow(/relay down/);
  });

  it("throws on an unexpected (authenticated) reply type", async () => {
    await expect(
      knock(REQ, {
        transport: replyWith(ackWrongType.replyPacketHex),
        entropy: entropyWithCounter(KNOCK_COUNTER),
      }),
    ).rejects.toThrow(/unexpected reply type/i);
  });

  it("throws on a malformed (non-JSON) ACK body", async () => {
    await expect(
      knock(REQ, {
        transport: replyWith(ackBadJson.replyPacketHex),
        entropy: entropyWithCounter(KNOCK_COUNTER),
      }),
    ).rejects.toThrow(); // JSON.parse SyntaxError on the authenticated body
  });
});
