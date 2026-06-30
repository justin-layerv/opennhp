import { describe, it, expect, vi, afterEach } from "vitest";
import {
  validateRelayUrl,
  RelayAllowlist,
  RelayUrlError,
} from "../src/qurl/relay-url";

// relay_url validation tests — the browser/headless port of Go relay_test.go. The
// security cases (http rejection, off-allowlist, userinfo bypass, fail-closed)
// must match Go exactly; the default-port matching is the one documented WHATWG
// divergence (a `:443` ENTRY won't match a default-port URL; use the bare host).

describe("validateRelayUrl (mirrors Go TestValidateRelayURL)", () => {
  const allow = new RelayAllowlist([
    "relay.example.com",
    "relay2.example.com:8443",
  ]);

  const cases: Array<{ name: string; url: string; wantErr: boolean }> = [
    {
      name: "https allowed host",
      url: "https://relay.example.com",
      wantErr: false,
    },
    {
      name: "https allowed host with path",
      url: "https://relay.example.com/relay/abc",
      wantErr: false,
    },
    {
      name: "https allowed host any port (host-only entry)",
      url: "https://relay.example.com:9000",
      wantErr: false,
    },
    {
      name: "https allowed host:port exact",
      url: "https://relay2.example.com:8443",
      wantErr: false,
    },
    { name: "http rejected", url: "http://relay.example.com", wantErr: true },
    {
      name: "host not on allowlist",
      url: "https://evil.example.com",
      wantErr: true,
    },
    {
      name: "host:port not matching entry port",
      url: "https://relay2.example.com:9999",
      wantErr: true,
    },
    { name: "missing scheme", url: "relay.example.com", wantErr: true },
    {
      name: "userinfo rejected",
      url: "https://user:pass@relay.example.com",
      wantErr: true,
    },
    { name: "empty", url: "", wantErr: true },
  ];

  for (const tc of cases) {
    it(`${tc.name} → ${tc.wantErr ? "reject" : "accept"}`, () => {
      if (tc.wantErr) {
        expect(() => validateRelayUrl(tc.url, allow)).toThrow(RelayUrlError);
      } else {
        expect(() => validateRelayUrl(tc.url, allow)).not.toThrow();
      }
    });
  }
});

describe("validateRelayUrl default-port semantics (WHATWG divergence, documented)", () => {
  it("a bare-host entry matches default + explicit :443 + other ports", () => {
    const allow = new RelayAllowlist(["relay.example.com"]);
    for (const u of [
      "https://relay.example.com",
      "https://relay.example.com:443",
      "https://relay.example.com:9000",
    ]) {
      expect(
        () => validateRelayUrl(u, allow),
        `bare-host must match ${u}`,
      ).not.toThrow();
    }
  });

  it("a :443 ENTRY does not match (WHATWG strips the default port) — fail closed", () => {
    // This is the deliberate JS-side divergence from Go's literal url.Host match:
    // WHATWG normalizes :443 away, so the entry can't match. It is fail-closed
    // (rejects a legit relay, never admits an off-allowlist one). Use the bare host.
    const allow = new RelayAllowlist(["relay.example.com:443"]);
    expect(() => validateRelayUrl("https://relay.example.com", allow)).toThrow(
      RelayUrlError,
    );
  });

  it("warns at construction when an entry carries an explicit :443 (surface the footgun)", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    new RelayAllowlist(["relay.example.com:443"]);
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn.mock.calls[0]![0]).toMatch(/:443/);
    expect(warn.mock.calls[0]![0]).toMatch(/bare host/);
    // A bare host or a non-default explicit port does NOT warn.
    warn.mockClear();
    new RelayAllowlist(["relay.example.com", "relay.example.com:8443"]);
    expect(warn).not.toHaveBeenCalled();
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("validateRelayUrl embedded-credentials bypass (mirrors Go TestValidateRelayURL_EmbeddedCredentialsBypass)", () => {
  // Allowlist deliberately lists the decoy host to make the bypass attractive.
  const allow = new RelayAllowlist(["allowed.example.com"]);
  const cases: Array<{ name: string; url: string }> = [
    {
      name: "userinfo decoy as bare host",
      url: "https://allowed.example.com@evil.example.com",
    },
    {
      name: "userinfo decoy with path",
      url: "https://allowed.example.com@evil.example.com/relay/abc",
    },
    {
      name: "userinfo decoy with explicit port",
      url: "https://allowed.example.com@evil.example.com:8443",
    },
    {
      name: "user:pass decoy form",
      url: "https://allowed.example.com:tok@evil.example.com",
    },
    {
      // The decisive case: even when the REAL host equals the allowlisted host,
      // the userinfo guard (not the allowlist) must reject it.
      name: "userinfo bearing, real host allowlisted",
      url: "https://allowed.example.com@allowed.example.com",
    },
  ];
  for (const tc of cases) {
    it(`rejects ${tc.name}`, () => {
      expect(() => validateRelayUrl(tc.url, allow)).toThrow(RelayUrlError);
    });
  }
});

describe("validateRelayUrl fail-closed allowlist (mirrors Go TestValidateRelayURL_NilAndEmptyAllowlistFailClosed)", () => {
  it("rejects with a null allowlist", () => {
    expect(() => validateRelayUrl("https://relay.example.com", null)).toThrow(
      RelayUrlError,
    );
  });
  it("rejects with an empty allowlist", () => {
    expect(() =>
      validateRelayUrl("https://relay.example.com", new RelayAllowlist([])),
    ).toThrow(RelayUrlError);
  });
});
