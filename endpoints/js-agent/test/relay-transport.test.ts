import { describe, it, expect, vi, afterEach } from "vitest";
import { relayPost, RelayError } from "../src/agent/relay";
import { fromHex, toHex } from "./hex";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("relayPost (NHP-Relay HTTPS transport)", () => {
  it("POSTs the packet to /relay/{serverId} as octet-stream and returns the reply", async () => {
    const packet = fromHex("deadbeef");
    const reply = fromHex("0badf00d");
    const fetchMock = vi.fn<typeof fetch>(
      async () => new Response(new Uint8Array(reply), { status: 200 }),
    );
    vi.stubGlobal("fetch", fetchMock);

    // base URL has a trailing slash — the transport must not double it
    const out = await relayPost("https://relay.example/")("fp_abc", packet);
    expect(toHex(out)).toBe(toHex(reply));

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe("https://relay.example/relay/fp_abc");
    expect(init?.method).toBe("POST");
    expect((init?.headers as Record<string, string>)["Content-Type"]).toBe(
      "application/octet-stream",
    );
    expect(toHex(init?.body as Uint8Array)).toBe(toHex(packet));
  });

  it("throws RelayError carrying the HTTP status on a non-200 reply (404 + 5xx)", async () => {
    for (const status of [404, 502]) {
      vi.stubGlobal(
        "fetch",
        vi.fn<typeof fetch>(
          // Go's http.Error appends a trailing newline to the body.
          async () => new Response("relay said no\n", { status }),
        ),
      );
      const err = (await relayPost("https://relay.example")(
        "fp_x",
        fromHex("00"),
      ).catch((e) => e)) as RelayError;
      expect(err).toBeInstanceOf(RelayError);
      expect(err.status).toBe(status);
      expect(err.message).not.toMatch(/\n/); // detail is trimmed
    }
  });

  it("throws RelayError (status 0) on a request timeout", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(async () => {
        throw new DOMException("aborted", "TimeoutError");
      }),
    );
    const err = (await relayPost("https://relay.example", 5)(
      "fp_x",
      fromHex("00"),
    ).catch((e) => e)) as RelayError;
    expect(err).toBeInstanceOf(RelayError);
    expect(err.status).toBe(0);
    expect(err.message).toMatch(/timed out after 5ms/);
  });

  it("throws RelayError (status 0) on a network failure", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(async () => {
        throw new TypeError("Failed to fetch");
      }),
    );
    const err = (await relayPost("https://relay.example")(
      "fp_x",
      fromHex("00"),
    ).catch((e) => e)) as RelayError;
    expect(err).toBeInstanceOf(RelayError);
    expect(err.status).toBe(0);
    expect(err.message).toMatch(/Failed to fetch/);
  });
});
