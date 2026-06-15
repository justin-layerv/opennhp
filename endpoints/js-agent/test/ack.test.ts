import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { decryptReply } from "../src/crypto/ack";
import { NHP_ACK, HEADER_SIZE, PACKET_BUFFER_SIZE } from "../src/crypto/packet";
import { toHex, fromHex } from "./hex";

// The TS half of the cross-language ACK fence. The committed fixture
// (test/testdata/ack.json) is Go-generated (the server's ephemeral is random, so
// TS can't reproduce it — only decrypt it). Both this suite and the Go responder
// test (nhp/core/js_agent_ack_roundtrip_test.go) decrypt the same bytes and
// assert the same ServerKnockAckMsg, so a drift on either side fails its suite.
const fixture = JSON.parse(
  readFileSync(new URL("./testdata/ack.json", import.meta.url), "utf8"),
) as {
  serverStaticPubHex: string;
  agentStaticPrivHex: string;
  timestampNanos: string;
  bodyHex: string;
  ackPacketHex: string;
};

const AGENT_PRIV = fromHex(fixture.agentStaticPrivHex);
const SERVER_PUB = fromHex(fixture.serverStaticPubHex);
const ACK_PACKET = fromHex(fixture.ackPacketHex);

describe("decryptReply (server ACK, cross-language fixture)", () => {
  it("decrypts the Go-produced ACK and recovers the ServerKnockAckMsg", async () => {
    const reply = await decryptReply(AGENT_PRIV, SERVER_PUB, ACK_PACKET);

    expect(reply.headerType).toBe(NHP_ACK);
    expect(toHex(reply.serverStaticPub)).toBe(fixture.serverStaticPubHex); // the auth check passed
    expect(reply.timestampNanos).toBe(BigInt(fixture.timestampNanos));
    expect(toHex(reply.body)).toBe(fixture.bodyHex); // decrypted + inflated == committed body

    // Exercise the actual JSON shape, not an empty struct.
    const msg = JSON.parse(new TextDecoder().decode(reply.body));
    expect(msg.errCode).toBe("0");
    expect(msg.opnTime).toBe(900);
    expect(msg.resHost.r_jsagent).toBe("10.0.0.7");
    expect(msg.acTokens.r_jsagent).toBe("tok-abc123");
    expect(msg.agentAddr).toBe("203.0.113.9");
  });

  it("rejects packets outside the [HEADER_SIZE, PACKET_BUFFER_SIZE] range", async () => {
    await expect(
      decryptReply(AGENT_PRIV, SERVER_PUB, new Uint8Array(HEADER_SIZE - 1)),
    ).rejects.toThrow(/too short/i);
    await expect(
      decryptReply(
        AGENT_PRIV,
        SERVER_PUB,
        new Uint8Array(PACKET_BUFFER_SIZE + 1),
      ),
    ).rejects.toThrow(/too long/i);
  });

  it("rejects an ACK whose static key isn't the expected server (the auth)", async () => {
    // The static field still opens (es doesn't depend on the expected key), but the
    // recovered server pubkey != the one we knocked → decryptReply throws.
    const wrongServer = new Uint8Array(SERVER_PUB.length).fill(0x99);
    await expect(
      decryptReply(AGENT_PRIV, wrongServer, ACK_PACKET),
    ).rejects.toThrow();
  });

  it("rejects a tampered ACK body (AEAD tag)", async () => {
    const tampered = ACK_PACKET.slice();
    const last = tampered.length - 1;
    tampered[last] = (tampered[last] ?? 0) ^ 0x01; // flip a bit in the sealed body
    await expect(
      decryptReply(AGENT_PRIV, SERVER_PUB, tampered),
    ).rejects.toThrow();
  });

  it("rejects a tampered header digest (stage 1, before any AEAD)", async () => {
    const tampered = ACK_PACKET.slice();
    // Flip a reserved byte (HeaderCommon[12:16]) inside the digest-covered prefix
    // header[0:208]; it feeds nothing but the digest, so this fences the digest
    // stage independently of the static/timestamp/body AEAD tags.
    tampered[12] = (tampered[12] ?? 0) ^ 0x01;
    await expect(
      decryptReply(AGENT_PRIV, SERVER_PUB, tampered),
    ).rejects.toThrow(/digest/i);
  });
});
