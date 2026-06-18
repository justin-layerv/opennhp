import { describe, it, expect } from "vitest";
import { readFileSync, writeFileSync } from "node:fs";
import {
  QURL_ACCESS_TOKEN_USER_DATA_KEY,
  QURL_BOOTSTRAP_RESOURCE_ID,
  QURL_USER_AGENT_USER_DATA_KEY,
  buildKnockBody,
} from "../src/agent/knock";
import { NHP_KNK } from "../src/crypto/packet";
import { toHex } from "./hex";

const fixturePath = new URL("./testdata/knock-body.json", import.meta.url);
const PARAMS = {
  authServiceId: "qurl",
  qurlAccessToken: "at_1234567890123456789012",
  qurlUserAgent: "Mozilla/5.0 qurl-link-test",
};

describe("buildKnockBody (qURL AgentKnockMsg)", () => {
  it("regenerates the committed fixture when UPDATE_JS_AGENT_FIXTURES=1", () => {
    if (!process.env.UPDATE_JS_AGENT_FIXTURES) return;
    const fixture = {
      ...PARAMS,
      resourceId: QURL_BOOTSTRAP_RESOURCE_ID,
      bodyHex: toHex(buildKnockBody(PARAMS)),
    };
    writeFileSync(fixturePath, JSON.stringify(fixture, null, 2) + "\n");
  });

  it("serializes the relay bootstrap token inside encrypted usrData", () => {
    const msg = JSON.parse(new TextDecoder().decode(buildKnockBody(PARAMS)));
    expect(msg.headerType).toBe(NHP_KNK); // #1154 invariant, owned by the builder
    expect(msg.aspId).toBe("qurl"); // routes to the qURL plugin
    expect(msg.resId).toBe(QURL_BOOTSTRAP_RESOURCE_ID);
    expect(msg.usrData).toEqual({
      [QURL_ACCESS_TOKEN_USER_DATA_KEY]: PARAMS.qurlAccessToken,
      [QURL_USER_AGENT_USER_DATA_KEY]: PARAMS.qurlUserAgent,
    });
    expect(Object.keys(msg).sort()).toEqual([
      "aspId",
      "headerType",
      "resId",
      "usrData",
    ]);
  });

  it("serializes a tokenless steady-state resource re-knock", () => {
    const msg = JSON.parse(
      new TextDecoder().decode(
        buildKnockBody({ authServiceId: "qurl", resourceId: "r_jsagent" }),
      ),
    );
    expect(msg).toEqual({
      headerType: NHP_KNK,
      aspId: "qurl",
      resId: "r_jsagent",
    });
  });

  it("matches the committed cross-language fixture (decoded by the Go contract test)", () => {
    const fixture = JSON.parse(readFileSync(fixturePath, "utf8")) as {
      bodyHex: string;
    };
    expect(toHex(buildKnockBody(PARAMS))).toBe(fixture.bodyHex);
  });
});
