import type { KnockResult, KnockSuccess } from "./loop.js";

/** A grant whose duration is at or below this (a `0` from a missing `opnTime`, a
 * negative, NaN, or an implausibly short window) is treated as unrenewable —
 * scheduling off it would arm at ~0 ms and tight-loop re-knocks. The server only
 * issues `opnTime <= 1` as a *closing* sentinel (the `NHP_EXT` "timeout in 1s",
 * the qurl-service#498 self-destruct floor the AC documents as "effectively
 * un-refreshable", and `CloseWindowOpenTimeSec`), never a renewable window — so
 * rejecting it here matches the AC's own treatment rather than fighting it. */
const MIN_RENEWABLE_SECONDS = 1;

/** `setTimeout` stores its delay as a 32-bit signed int, so a delay past this
 * (~24.8 days) wraps and fires immediately — the high-end twin of the
 * {@link MIN_RENEWABLE_SECONDS} tight loop. {@link armTimer} clamps to it, so an
 * implausibly long grant wakes early and reschedules off a fresh grant. */
const MAX_TIMER_MS = 2_147_483_647;

/** Upper clamp for `marginFraction`. Keeps `base = duration × (1 − margin)` at
 * ≥ 10% of the duration — clear of a 0 ms arm — so a caller can't turn the renewal
 * into the very tight loop the MIN/MAX guards prevent (`margin >= 1` → `base <= 0`).
 * The design intends 0.1–0.2; this only catches absurd / degenerate values. */
const MAX_MARGIN_FRACTION = 0.9;

/**
 * Injectable timer / clock / visibility / jitter seams. Production uses the
 * browser globals ({@link browserRenewalEnv}); tests pin them deterministically
 * (the same seam pattern as `KnockEntropy` for `createKnock`).
 */
export interface RenewalEnv {
  setTimer(fn: () => void, ms: number): number;
  clearTimer(id: number): void;
  nowMs(): number;
  /** Subscribe to "tab became visible"; returns an unsubscribe. */
  onVisible(fn: () => void): () => void;
  /** A `[0, 1)` sample for renewal jitter (default `Math.random`). */
  jitter(): number;
}

/** Production seams: `setTimeout`/`Date.now` and the Page Visibility API. */
const browserRenewalEnv: RenewalEnv = {
  setTimer: (fn, ms) => setTimeout(fn, ms) as unknown as number,
  clearTimer: (id) => clearTimeout(id),
  // Wall-clock (`Date.now`), deliberately NOT `performance.now`: during
  // bfcache/suspension the monotonic clock pauses while wall-clock keeps advancing,
  // so `Date.now` is what reflects true elapsed time across a suspension — which is
  // exactly what `maybeRecover`'s overdue check needs. A "monotonic is more precise"
  // refactor would silently break foreground recovery. The tradeoff: a *backward*
  // wall-clock jump (NTP correction, user clock change) can transiently delay the
  // overdue check and inflate the budget — benign and rare next to the suspension win.
  nowMs: () => Date.now(),
  onVisible: (fn) => {
    const onVisibilityChange = () => {
      if (document.visibilityState === "visible") fn();
    };
    // A bfcache restore fires `pageshow` and may NOT fire a visibilitychange, so
    // recover on both — bfcache suspension is one of the two failure modes the
    // scheduler doc-comment names. pageshow signals a *restore*, so fire `fn`
    // unconditionally; the visibilitychange path gates on `visible` because it also
    // fires on hide. `fn` (maybeRecover) is idempotent and overdue-gated, so an
    // extra call — or one into a still-hidden restored tab — is a harmless no-op.
    document.addEventListener("visibilitychange", onVisibilityChange);
    window.addEventListener("pageshow", fn);
    return () => {
      document.removeEventListener("visibilitychange", onVisibilityChange);
      window.removeEventListener("pageshow", fn);
    };
  },
  jitter: () => Math.random(),
};

export interface RenewalOptions {
  /** Renew at `openTime × (1 − marginFraction)`, leaving roughly `marginFraction`
   * of the access duration as a retry budget. Positive jitter trades against it —
   * at the 0.15 / 0.1 defaults the worst case (`0.85 × 1.1`) still leaves ~6.5%.
   * Default 0.15 (10–20% per the design); clamped to `[0, 0.9]`. */
  marginFraction?: number;
  /** ± jitter as a fraction of the renewal delay, to avoid a thundering herd of
   * agents renewing in lock-step. Default 0.1; clamped to `[0, marginFraction]` so
   * a renewal never schedules past the deadline. */
  jitterFraction?: number;
  /** Backoff between retries after a transient fault, capped by the remaining
   * budget. Default 5000 ms. */
  retryBackoffMs?: number;
  env?: RenewalEnv;
}

export interface RenewalHandlers {
  /** A renewal succeeded; `grant` is the new ACK (the scheduler reschedules off
   * it). The page should adopt the new resource hosts / AC tokens. */
  onRenewed?(grant: KnockSuccess): void;
  /**
   * The session can no longer be renewed silently — the page must re-resolve the
   * qURL link to mint a fresh one. `reResolve`: the server denied (52024).
   * `budgetExhausted`: a transient fault persisted until the access duration ran
   * out. `invalidGrant`: a grant with a non-positive / implausibly-short duration
   * that cannot be renewed. The next step is the same (re-resolve); the reason is
   * surfaced for telemetry.
   */
  onExpired?(reason: "reResolve" | "budgetExhausted" | "invalidGrant"): void;
}

export interface RenewalController {
  stop(): void;
}

/**
 * Keeps an open grant alive by re-knocking (a fresh `NHP_KNK` via `reKnock`)
 * before the access duration expires.
 *
 * Renews at `openTime × (1 − margin) ± jitter`, leaving `margin` of the duration
 * as a **retry budget**: a transport / server fault is an *unknown* outcome (the
 * grant may still be open) with valid session left, so the scheduler retries
 * within the remaining budget — a re-knock is idempotent, it re-grants — and only
 * gives up (`onExpired("budgetExhausted")`) if the budget runs out. A `reResolve`
 * (52024) is a definite "session gone" → `onExpired("reResolve")` immediately.
 *
 * `reKnock` **must settle** (resolve or reject). The scheduler clears its timer
 * before awaiting it and has no independent watchdog, so a closure that hangs
 * forever wedges renewal silently — no `onExpired` fires. The bundled transport is
 * safe (`relayPost` bounds every `fetch` with `AbortSignal.timeout`); a custom
 * `reKnock` must carry its own timeout.
 *
 * **Background-tab limitation — the hard part.** Browsers clamp background
 * `setTimeout` (≥ 1 min) and suspend timers under memory pressure / bfcache, so a
 * backgrounded tab can sail past its renewal deadline and the L3 window closes
 * mid-session. There is **no JS-side fix** — the server/relay-side *grace window*
 * that would tolerate a late re-knock is tracked separately (a server change).
 * What the scheduler does instead is **recover on foreground**: a Page Visibility
 * handler re-knocks immediately when the tab returns if the renewal is overdue.
 * So the contract is **"a backgrounded session may need a fresh knock on
 * return"** — refocusing a long-backgrounded tab can cost a brief reconnect.
 *
 * Contract note: if `initial` is itself unrenewable
 * (`openTimeSeconds <= MIN_RENEWABLE_SECONDS`), `onExpired("invalidGrant")` fires
 * **synchronously**, before this returns — so a caller must not assume the
 * returned controller is bound inside that callback, and a throw from that handler
 * propagates straight out of `startRenewal`. (The running-loop callback
 * invocations are instead contained by `fireRenew`'s `.catch`; only this initial
 * one has a real caller to surface a throw to.)
 */
export function startRenewal(
  initial: KnockSuccess,
  reKnock: () => Promise<KnockResult>,
  handlers: RenewalHandlers = {},
  opts: RenewalOptions = {},
): RenewalController {
  const env = opts.env ?? browserRenewalEnv;
  // Clamp the caller-supplied fractions to keep the module's "never tight-loop /
  // never fire past the deadline" guarantees for all callers, not just the defaults
  // (PR-6 owns these values). margin in [0, MAX_MARGIN_FRACTION] keeps
  // base = duration·(1−margin) clear of a 0 ms arm; jitter in [0, margin] keeps the
  // worst-case fire base·(1+jitter) < the deadline, since (1−m)(1+m) = 1−m² < 1.
  const margin = Math.min(
    Math.max(opts.marginFraction ?? 0.15, 0),
    MAX_MARGIN_FRACTION,
  );
  const jitterFraction = Math.min(
    Math.max(opts.jitterFraction ?? 0.1, 0),
    margin,
  );
  // Floor at 1 ms: a caller passing 0/negative would make retryWithinBudget arm a
  // 0 ms delay — the tight retry loop this module exists to avoid (the same
  // philosophy as the MIN/MAX guards). The budget still bounds it, but don't spin.
  const retryBackoffMs = Math.max(1, opts.retryBackoffMs ?? 5000);

  let timer: number | undefined;
  let stopped = false;
  let inFlight = false; // single-flight guard: a timer-fire and a visibility
  // event must never launch two concurrent re-knocks.
  let deadlineMs = 0; // when the current grant's access actually expires.
  let fireAtMs = 0; // when the next renewal is due (for foreground recovery).

  const unsubscribe = env.onVisible(maybeRecover);

  function clearTimer(): void {
    if (timer !== undefined) {
      env.clearTimer(timer);
      timer = undefined;
    }
  }

  function armTimer(delayMs: number): void {
    // Clamp to the 32-bit setTimeout ceiling (see MAX_TIMER_MS): a longer delay
    // wraps and fires immediately — the tight loop the guards exist to avoid. A
    // clamped wake re-knocks early (idempotent) and reschedules off the fresh
    // grant — only reachable for an implausibly long (>24.8-day) grant.
    const ms = Math.min(delayMs, MAX_TIMER_MS);
    fireAtMs = env.nowMs() + ms;
    clearTimer();
    timer = env.setTimer(fireRenew, ms);
  }

  // Drive renew() without surfacing its promise. renew() rejects only if a page
  // callback (onRenewed/onExpired) throws — the page's own concern, and the chain
  // is already (re)scheduled by then — so contain it rather than letting it become
  // a spurious unhandled rejection from the renewal internals. Still log it: a
  // silently-swallowed handler throw would hide a real page-side bug during PR-6
  // integration.
  function fireRenew(): void {
    void renew().catch((err) =>
      console.error("nhp renewal callback threw", err),
    );
  }

  /** Arms the next renewal off `grant`. Returns `false` (without arming) if the
   * duration is unrenewable — in which case it has already expired the session,
   * so the caller must NOT then fire `onRenewed`. */
  function scheduleFrom(grant: KnockSuccess): boolean {
    if (!(grant.openTimeSeconds > MIN_RENEWABLE_SECONDS)) {
      // Unrenewable duration (also catches NaN via the negated comparison): don't
      // arm a ~0 ms tight loop — the grant is unusable, so the page must
      // re-resolve for a valid session.
      stop();
      handlers.onExpired?.("invalidGrant");
      return false;
    }
    const durationMs = grant.openTimeSeconds * 1000;
    // Client-side estimate: the server started counting the access duration when
    // it issued the grant — ~one relay round-trip before this resolved — so the
    // true expiry is slightly earlier than deadlineMs. Benign: on a string of slow
    // re-knocks the budget can outlast the real window by ~RTT before
    // budgetExhausted, exactly what the (scoped-out) server/relay grace window absorbs.
    deadlineMs = env.nowMs() + durationMs;
    const base = durationMs * (1 - margin);
    const jit = base * jitterFraction * (env.jitter() * 2 - 1); // ±jitterFraction
    armTimer(Math.max(0, base + jit));
    return true;
  }

  function retryWithinBudget(): void {
    const remaining = deadlineMs - env.nowMs();
    if (remaining <= 0) {
      stop();
      handlers.onExpired?.("budgetExhausted");
      return;
    }
    armTimer(Math.min(remaining, retryBackoffMs));
  }

  async function renew(): Promise<void> {
    if (stopped || inFlight) return;
    // Set the guard BEFORE the first await: a synchronous re-entrant — a
    // visibility event firing right after the timer does — then sees inFlight
    // already up and bails, so the two never launch concurrent re-knocks.
    inFlight = true;
    clearTimer();
    let result: KnockResult;
    try {
      result = await reKnock();
    } catch {
      // transport / crypto fault — outcome unknown, retry within the budget.
      inFlight = false;
      if (!stopped) retryWithinBudget();
      return;
    }
    inFlight = false;
    if (stopped) return;
    // Dispatch outside the reKnock try, and do the scheduler's own work
    // (reschedule / stop) *before* the page callbacks — so a throwing handler is
    // not mistaken for a knock fault and cannot leave the chain unscheduled (its
    // throw is contained by fireRenew, not surfaced as an unhandled rejection).
    switch (result.kind) {
      case "success":
        // Fire onRenewed only when scheduleFrom actually armed — an unrenewable
        // grant expires the session instead and must not also report a new grant.
        if (scheduleFrom(result)) handlers.onRenewed?.(result);
        break;
      case "reResolve":
        stop();
        handlers.onExpired?.("reResolve");
        break;
      default:
        // serverError | cookieChallenge — outcome uncertain, session may still be
        // open; retry within the budget rather than abandoning it. (A COK is an
        // explicit overload signal; overload-specific backoff lands with the real
        // cookie handling in 5c, #2611 — here it stays fixed-interval, budget-bounded.)
        // All non-52024 errCodes retry within budget today; fast-pathing
        // known-terminal codes straight to reResolve is a refinement tracked in #2613.
        retryWithinBudget();
        break;
    }
  }

  function maybeRecover(): void {
    // Foreground recovery: if the background timer was clamped/suspended past the
    // renewal deadline, re-knock now rather than waiting for it to (maybe) fire.
    if (stopped || inFlight) return;
    if (env.nowMs() >= fireAtMs) fireRenew();
  }

  function stop(): void {
    stopped = true;
    clearTimer();
    unsubscribe();
  }

  scheduleFrom(initial);
  return { stop };
}
