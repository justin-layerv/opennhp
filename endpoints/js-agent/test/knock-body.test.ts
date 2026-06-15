import { describe, it, expect } from "vitest";
import { readFileSync, writeFileSync } from "node:fs";
import { buildKnockBody } from "../src/agent/knock";
import { NHP_KNK } from "../src/crypto/packet";
import { toHex } from "./hex";

const fixturePath = new URL("./testdata/knock-body.json", import.meta.url);
const PARAMS = { authServiceId: "asp_test", resourceId: "r_jsagent" };

describe("buildKnockBody (qURL AgentKnockMsg)", () => {
  it("regenerates the committed fixture when UPDATE_JS_AGENT_FIXTURES=1", () => {
    if (!process.env.UPDATE_JS_AGENT_FIXTURES) return;
    const fixture = { ...PARAMS, bodyHex: toHex(buildKnockBody(PARAMS)) };
    writeFileSync(fixturePath, JSON.stringify(fixture, null, 2) + "\n");
  });

  it("serializes only {headerType: NHP_KNK, aspId, resId} — the fields the server reads", () => {
    const msg = JSON.parse(new TextDecoder().decode(buildKnockBody(PARAMS)));
    expect(msg.headerType).toBe(NHP_KNK); // #1154 invariant, owned by the builder
    expect(msg.aspId).toBe("asp_test"); // routes to the qURL plugin
    expect(msg.resId).toBe("r_jsagent"); // the r_ id the plugin resolves
    // exactly those three — the browser omits the inert AgentKnockMsg fields
    expect(Object.keys(msg).sort()).toEqual(["aspId", "headerType", "resId"]);
  });

  it("matches the committed cross-language fixture (decoded by the Go contract test)", () => {
    const fixture = JSON.parse(readFileSync(fixturePath, "utf8")) as {
      bodyHex: string;
    };
    expect(toHex(buildKnockBody(PARAMS))).toBe(fixture.bodyHex);
  });
});
