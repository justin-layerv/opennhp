import { describe, it, expect, vi } from "vitest";
import { startRenewal, type RenewalEnv } from "../src/agent/scheduler";
import type { KnockResult, KnockSuccess } from "../src/agent/loop";

function grant(openTimeSeconds: number): KnockSuccess {
  return {
    kind: "success",
    resourceHosts: {},
    acTokens: {},
    openTimeSeconds,
    agentAddr: "",
    redirectUrl: "",
  };
}

/** A deterministic timer/clock/visibility/jitter env. `advance` moves the clock
 * AND fires due timers; `advanceClockOnly` moves the clock WITHOUT firing them
 * (simulating a clamped/suspended background timer). */
function makeEnv(jitterVal = 0.5) {
  let now = 0;
  let nextId = 1;
  const timers = new Map<number, { fn: () => void; at: number }>();
  let visibleFn: (() => void) | undefined;
  // jitterVal: 0.5 (default) centers to no jitter; 0 → −jitterFraction, 1 → +jitterFraction
  const env: RenewalEnv = {
    setTimer: (fn, ms) => {
      const id = nextId++;
      timers.set(id, { fn, at: now + ms });
      return id;
    },
    clearTimer: (id) => {
      timers.delete(id);
    },
    nowMs: () => now,
    onVisible: (fn) => {
      visibleFn = fn;
      return () => {
        visibleFn = undefined;
      };
    },
    jitter: () => jitterVal,
  };
  function fireDue() {
    const due = [...timers.entries()]
      .filter(([, t]) => t.at <= now)
      .sort((a, b) => a[1].at - b[1].at);
    for (const [id, t] of due) if (timers.delete(id)) t.fn();
  }
  return {
    env,
    advance(ms: number) {
      now += ms;
      fireDue();
    },
    advanceClockOnly(ms: number) {
      now += ms;
    },
    fireVisible() {
      visibleFn?.();
    },
    pending: () => timers.size,
    nextAt: () => Math.min(...[...timers.values()].map((t) => t.at)),
  };
}

const flush = async () => {
  for (let i = 0; i < 5; i++) await Promise.resolve();
};

describe("startRenewal (re-knock scheduler)", () => {
  it("renews at openTime × (1 − margin) and reschedules off the new grant", async () => {
    const h = makeEnv();
    const reKnock = vi.fn(async (): Promise<KnockResult> => grant(100));
    const onRenewed = vi.fn();
    startRenewal(grant(100), reKnock, { onRenewed }, { env: h.env });

    h.advance(84_000);
    await flush();
    expect(reKnock).not.toHaveBeenCalled(); // before the 85s renewal point

    h.advance(1_000);
    await flush();
    expect(reKnock).toHaveBeenCalledTimes(1);
    expect(onRenewed).toHaveBeenCalledWith(
      expect.objectContaining({ kind: "success" }),
    );
    expect(h.pending()).toBe(1); // rescheduled off the new grant
  });

  it("applies ± jitter within bounds and never schedules past the deadline", async () => {
    const reKnock = vi.fn(async (): Promise<KnockResult> => grant(100));
    // base = 100000 × (1 − 0.15) = 85000; ± jitterFraction(0.1) · base = ± 8500
    const lo = makeEnv(0); // jitter 0 → −8500 → fires earliest
    startRenewal(grant(100), reKnock, {}, { env: lo.env });
    expect(lo.nextAt()).toBe(76_500);

    const hi = makeEnv(1); // jitter 1 → +8500 → fires latest
    startRenewal(grant(100), reKnock, {}, { env: hi.env });
    expect(hi.nextAt()).toBe(93_500);
    expect(hi.nextAt()).toBeLessThan(100_000); // still inside the access deadline
  });

  it("clamps an out-of-range marginFraction / jitterFraction (never 0-arms or fires past the deadline)", async () => {
    // marginFraction >= 1 would make base <= 0 → a 0 ms tight loop; jitter > margin
    // could push the fire past the deadline. Both are clamped at construction.
    const h = makeEnv(1); // maximal positive jitter
    const reKnock = vi.fn(async (): Promise<KnockResult> => grant(100));
    startRenewal(
      grant(100),
      reKnock,
      {},
      { env: h.env, marginFraction: 5, jitterFraction: 10 },
    );
    // margin → 0.9, jitter → 0.9: base = 10000, + 0.9·base = 19000 (toBeCloseTo:
    // 1 − 0.9 isn't exact in float, so the product lands a hair under 19000)
    expect(h.nextAt()).toBeCloseTo(19_000);
    expect(h.nextAt()).toBeGreaterThan(0); // never a 0 ms arm
    expect(h.nextAt()).toBeLessThan(100_000); // never past the 100s deadline
  });

  it("recovers on foreground when the background timer was clamped past the deadline", async () => {
    const h = makeEnv();
    const reKnock = vi.fn(async (): Promise<KnockResult> => grant(100));
    startRenewal(grant(100), reKnock, {}, { env: h.env });

    // tab backgrounded: the clock sails past the 85s renewal WITHOUT the timer firing
    h.advanceClockOnly(90_000);
    expect(reKnock).not.toHaveBeenCalled();

    // tab returns to foreground → immediate re-knock (the path that holds in the wild)
    h.fireVisible();
    await flush();
    expect(reKnock).toHaveBeenCalledTimes(1);
  });

  it("ignores a visibility event that fires before the renewal is due", async () => {
    const h = makeEnv();
    const reKnock = vi.fn(async (): Promise<KnockResult> => grant(100));
    startRenewal(grant(100), reKnock, {}, { env: h.env });

    // tab refocused well before the 85s renewal point — maybeRecover's overdue
    // gate (now >= fireAtMs) must hold, so no premature re-knock
    h.advance(10_000);
    h.fireVisible();
    await flush();
    expect(reKnock).not.toHaveBeenCalled();
    expect(h.pending()).toBe(1); // original timer still armed, untouched
  });

  it("single-flights a timer-fire and a concurrent visibility event", async () => {
    const h = makeEnv();
    let resolve!: (r: KnockResult) => void;
    const reKnock = vi.fn(
      () =>
        new Promise<KnockResult>((r) => {
          resolve = r;
        }),
    );
    startRenewal(grant(100), reKnock, {}, { env: h.env });

    h.advance(85_000); // timer fires → renew in-flight, awaiting reKnock
    h.fireVisible(); // concurrent foreground event must NOT launch a 2nd re-knock
    await flush();
    resolve(grant(100));
    await flush();
    expect(reKnock).toHaveBeenCalledTimes(1);
  });

  it("ignores an in-flight reKnock result after stop() (teardown mid-knock)", async () => {
    const h = makeEnv();
    let resolve!: (r: KnockResult) => void;
    const reKnock = vi.fn(
      () =>
        new Promise<KnockResult>((r) => {
          resolve = r;
        }),
    );
    const onRenewed = vi.fn();
    const ctl = startRenewal(
      grant(100),
      reKnock,
      { onRenewed },
      { env: h.env },
    );

    h.advance(85_000); // timer fires → renew() in-flight, awaiting reKnock
    expect(reKnock).toHaveBeenCalledTimes(1);

    ctl.stop(); // page tears the scheduler down while the knock is on the wire
    resolve(grant(100)); // the in-flight knock finally settles
    await flush();

    expect(onRenewed).not.toHaveBeenCalled(); // late result dropped, not adopted
    expect(h.pending()).toBe(0); // not rescheduled
  });

  it("retries within the remaining budget on a transient fault, then succeeds", async () => {
    const h = makeEnv();
    let calls = 0;
    const reKnock = vi.fn(async (): Promise<KnockResult> => {
      calls++;
      if (calls === 1) throw new Error("relay hiccup");
      return grant(100);
    });
    const onRenewed = vi.fn();
    const onExpired = vi.fn();
    startRenewal(
      grant(100),
      reKnock,
      { onRenewed, onExpired },
      { env: h.env, retryBackoffMs: 5000 },
    );

    h.advance(85_000);
    await flush(); // renewal fails → retry armed within budget
    expect(reKnock).toHaveBeenCalledTimes(1);
    expect(onExpired).not.toHaveBeenCalled();

    h.advance(5_000);
    await flush(); // retry succeeds
    expect(reKnock).toHaveBeenCalledTimes(2);
    expect(onRenewed).toHaveBeenCalledTimes(1);
  });

  it("recovers on foreground when a retry-backoff timer was clamped past its deadline", async () => {
    const h = makeEnv();
    let calls = 0;
    const reKnock = vi.fn(async (): Promise<KnockResult> => {
      calls++;
      if (calls === 1) throw new Error("relay hiccup"); // 1st renewal faults
      return grant(100);
    });
    const onRenewed = vi.fn();
    startRenewal(
      grant(100),
      reKnock,
      { onRenewed },
      { env: h.env, retryBackoffMs: 5000 },
    );

    h.advance(85_000);
    await flush(); // renewal faults → retry-backoff timer armed (fireAt = 90s)
    expect(reKnock).toHaveBeenCalledTimes(1);

    // tab backgrounded: the clock sails past the RETRY timer's fireAt (not the
    // initial schedule's) without it firing; foreground must recover off it too
    h.advanceClockOnly(10_000); // now 95s > retry fireAt 90s
    h.fireVisible();
    await flush();
    expect(reKnock).toHaveBeenCalledTimes(2); // retried on foreground
    expect(onRenewed).toHaveBeenCalledTimes(1);
  });

  it("gives up with budgetExhausted when a fault persists past the access deadline", async () => {
    const h = makeEnv();
    const reKnock = vi.fn(async (): Promise<KnockResult> => {
      throw new Error("relay down");
    });
    const onExpired = vi.fn();
    startRenewal(
      grant(100),
      reKnock,
      { onExpired },
      { env: h.env, retryBackoffMs: 5000 },
    );

    h.advance(85_000);
    await flush(); // renewal fails; budget = 15s
    for (let t = 0; t < 3; t++) {
      h.advance(5_000); // retry every 5s until the 100s deadline
      await flush();
    }
    expect(onExpired).toHaveBeenCalledWith("budgetExhausted");
  });

  it("stops and signals reResolve on a 52024 deny", async () => {
    const h = makeEnv();
    const reKnock = vi.fn(
      async (): Promise<KnockResult> => ({ kind: "reResolve" }),
    );
    const onExpired = vi.fn();
    startRenewal(grant(100), reKnock, { onExpired }, { env: h.env });

    h.advance(85_000);
    await flush();
    expect(onExpired).toHaveBeenCalledWith("reResolve");
    expect(h.pending()).toBe(0); // stopped — no further renewal
  });

  it("stop() cancels the timer and the visibility handler", async () => {
    const h = makeEnv();
    const reKnock = vi.fn(async (): Promise<KnockResult> => grant(100));
    const ctl = startRenewal(grant(100), reKnock, {}, { env: h.env });
    ctl.stop();
    expect(h.pending()).toBe(0);

    h.advanceClockOnly(90_000);
    h.fireVisible();
    await flush();
    expect(reKnock).not.toHaveBeenCalled();
  });

  it("stop() is idempotent — a second call is a harmless no-op", async () => {
    const h = makeEnv();
    const reKnock = vi.fn(async (): Promise<KnockResult> => grant(100));
    const ctl = startRenewal(grant(100), reKnock, {}, { env: h.env });
    ctl.stop();
    expect(() => ctl.stop()).not.toThrow(); // double clearTimer / unsubscribe no-op
    expect(h.pending()).toBe(0);
  });

  it("rejects a non-positive openTime as invalidGrant instead of tight-looping", async () => {
    const h = makeEnv();
    const reKnock = vi.fn(async (): Promise<KnockResult> => grant(100));
    const onExpired = vi.fn();
    startRenewal(grant(0), reKnock, { onExpired }, { env: h.env });
    expect(onExpired).toHaveBeenCalledWith("invalidGrant");
    expect(h.pending()).toBe(0); // no timer armed

    h.advance(60_000);
    await flush();
    expect(reKnock).not.toHaveBeenCalled(); // no re-knock loop
  });

  it("clamps the timer for an implausibly long grant, then re-knocks at the clamp", async () => {
    const h = makeEnv();
    const reKnock = vi.fn(async (): Promise<KnockResult> => grant(100));
    // openTime ~70 days → renewal delay (× 0.85) exceeds the 32-bit setTimeout
    // ceiling; a raw setTimeout would wrap and fire immediately.
    startRenewal(grant(6_000_000), reKnock, {}, { env: h.env });

    expect(h.pending()).toBe(1);
    expect(h.nextAt()).toBe(2_147_483_647); // clamped, not 6e9 × 0.85
    h.advance(60_000); // a minute passes — far past where an overflow would fire
    await flush();
    expect(reKnock).not.toHaveBeenCalled();

    // at the clamp it does the documented thing — re-knock early and reschedule
    // off the fresh (100s) grant, not a no-op re-evaluation
    h.advance(2_147_483_647 - 60_000);
    await flush();
    expect(reKnock).toHaveBeenCalledTimes(1);
    expect(h.pending()).toBe(1); // rearmed off the new grant (85s, un-clamped)
    expect(h.nextAt()).toBe(2_147_483_647 + 85_000);
  });

  it("on a renewal returning success-with-zero-openTime, expires and does NOT fire onRenewed", async () => {
    const h = makeEnv();
    let calls = 0;
    const reKnock = vi.fn(async (): Promise<KnockResult> => {
      calls++;
      return grant(calls === 1 ? 0 : 100); // the renewal reports a 0 duration
    });
    const onRenewed = vi.fn();
    const onExpired = vi.fn();
    startRenewal(grant(100), reKnock, { onRenewed, onExpired }, { env: h.env });

    h.advance(85_000);
    await flush();
    expect(onExpired).toHaveBeenCalledWith("invalidGrant");
    expect(onRenewed).not.toHaveBeenCalled(); // not both, for the same grant
    expect(h.pending()).toBe(0); // stopped
  });

  it("retries within budget on a serverError reply (the default branch)", async () => {
    const h = makeEnv();
    let calls = 0;
    const reKnock = vi.fn(async (): Promise<KnockResult> => {
      calls++;
      if (calls === 1)
        return { kind: "serverError", errCode: "52007", errMsg: "x" };
      return grant(100);
    });
    const onRenewed = vi.fn();
    startRenewal(
      grant(100),
      reKnock,
      { onRenewed },
      { env: h.env, retryBackoffMs: 5000 },
    );

    h.advance(85_000);
    await flush(); // serverError → retry armed within budget
    expect(reKnock).toHaveBeenCalledTimes(1);

    h.advance(5_000);
    await flush(); // retry succeeds
    expect(reKnock).toHaveBeenCalledTimes(2);
    expect(onRenewed).toHaveBeenCalledTimes(1);
  });

  it("retries within budget on a cookieChallenge reply (shares the default branch)", async () => {
    const h = makeEnv();
    let calls = 0;
    const reKnock = vi.fn(async (): Promise<KnockResult> => {
      calls++;
      if (calls === 1) return { kind: "cookieChallenge" };
      return grant(100);
    });
    const onRenewed = vi.fn();
    startRenewal(
      grant(100),
      reKnock,
      { onRenewed },
      { env: h.env, retryBackoffMs: 5000 },
    );

    h.advance(85_000);
    await flush(); // cookieChallenge → retry armed within budget (COK backoff is 5c)
    expect(reKnock).toHaveBeenCalledTimes(1);

    h.advance(5_000);
    await flush(); // retry succeeds
    expect(reKnock).toHaveBeenCalledTimes(2);
    expect(onRenewed).toHaveBeenCalledTimes(1);
  });

  it("floors retryBackoffMs so a 0 backoff does not tight-loop at the same instant", async () => {
    const h = makeEnv();
    const reKnock = vi.fn(async (): Promise<KnockResult> => {
      throw new Error("always fails");
    });
    startRenewal(grant(100), reKnock, {}, { env: h.env, retryBackoffMs: 0 });

    h.advance(85_000);
    await flush(); // fault → retry armed; the floor keeps the delay > 0
    expect(h.pending()).toBe(1);
    expect(h.nextAt()).toBeGreaterThan(85_000); // not a 0 ms re-arm at the same instant
  });

  it("contains a throwing onRenewed — chain stays scheduled, surfaced not swallowed", async () => {
    const h = makeEnv();
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const reKnock = vi.fn(async (): Promise<KnockResult> => grant(100));
    const onRenewed = vi.fn(() => {
      throw new Error("page handler blew up");
    });
    startRenewal(grant(100), reKnock, { onRenewed }, { env: h.env });

    h.advance(85_000);
    await flush(); // renew → success → scheduleFrom arms BEFORE onRenewed throws
    expect(onRenewed).toHaveBeenCalledTimes(1);
    expect(h.pending()).toBe(1); // rescheduled despite the throw (contained by fireRenew)
    expect(errSpy).toHaveBeenCalled(); // contained, but logged — not silently swallowed

    // the throw didn't wedge the loop — the next cycle still renews
    h.advance(85_000);
    await flush();
    expect(reKnock).toHaveBeenCalledTimes(2);
    errSpy.mockRestore();
  });

  it("contains a throwing onExpired on the running-loop path (reResolve)", async () => {
    const h = makeEnv();
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const reKnock = vi.fn(
      async (): Promise<KnockResult> => ({ kind: "reResolve" }),
    );
    const onExpired = vi.fn(() => {
      throw new Error("page onExpired blew up");
    });
    startRenewal(grant(100), reKnock, { onExpired }, { env: h.env });

    h.advance(85_000);
    await flush(); // reResolve → stop() runs, THEN onExpired throws → contained by fireRenew
    expect(onExpired).toHaveBeenCalledWith("reResolve");
    expect(h.pending()).toBe(0); // stopped before the throw, chain not left armed
    expect(errSpy).toHaveBeenCalled(); // running-loop throw is contained AND surfaced
    errSpy.mockRestore();
  });
});
