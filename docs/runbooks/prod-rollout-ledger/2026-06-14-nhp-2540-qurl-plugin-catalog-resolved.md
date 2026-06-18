# 2026-06-14 · issue #2540 · qURL plugin path resolves AC routing from catalog

- **Owner:** prod rollout coordinator
- **Source:** [issue #2540](https://github.com/layervai/nhp/issues/2540) · [#1209](https://github.com/layervai/nhp/issues/1209) · [#2310](https://github.com/layervai/nhp/pull/2310) · [layervai/qurl-service#855](https://github.com/layervai/qurl-service/pull/855) (q_ catalog writer) · [layervai/qurl-service#823](https://github.com/layervai/qurl-service/issues/823) (field removal, blocked on this)

The in-process qURL plugin path now resolves AC pinhole routing from the
server-owned catalog by `(qurl, NHPResourceID)` instead of the qurl-service
`/internal/v1/resolve` response body — the plugin twin of #2310's headless
migration. Deploy this NHP server change **before** qurl-service #823 drops the
`resources` field; #823 must not go first.

- [ ] Pre-rollout (**coverage, not just "writer runs" — blocking**): the `q_`
      catalog rows must exist for **every currently-resolvable qURL**, not only
      newly-minted ones. `upsertNHPCatalogForToken` (qurl-service #855) fires
      only on mint/create/update — never on resolve — and qurl-service has **no
      backfill** for `nhp_resources`. So a qURL minted before #855 reached prod
      and never updated has no catalog row and will fail closed
      (`QurlResolveFailResolveCatalog`) on this path where it succeeds today off
      the body. Before cutover confirm **either** #855 has been live in prod ≥
      the maximum qURL lifetime (so every still-valid qURL was minted post-#855),
      **or** a one-time backfill populated `nhp_resources` for pre-#855 tokens.
      _Current 2026-06-18: this gate is **not satisfied**. Prod qurl-service is
      still SSM-pinned to `db5d703` from 2026-06-02, before #855. Prod
      `layerv-nhp-prod-cell0-resources` has `Count=0` rows whose
      `resource_id` begins with `q_`, while prod `qurl-resources` has 772 active
      non-expired resources. Do not cut over the plugin path until #855 has
      lived past max qURL lifetime or a backfill populates those catalog rows._
- [x] Pre-rollout: confirm qurl-service #823 stays draft/blocked until this NHP
      change deploys (its current `resources` response is no longer consumed but
      is still sent). _Done/current 2026-06-17: qurl-service #823 remains OPEN
      and prod qurl-service is still pinned to SSM image tag `db5d703`, predating
      the cleanup._
- [ ] Rollout: deploy this NHP server change before qurl-service #823. No flag —
      the plugin path resolves from the catalog as soon as the image is live.
- [ ] Shared-path note (validate alongside the headless path): this PR also adds
      an empty-`ac_id` reject to `resourceDataFromRow`, which is shared with the
      headless `/nhp/internal/knock` path and the static ASP/agent catalog. A row
      with an empty `ac_id` now fails closed at the lookup boundary
      (`ErrResourceNotFound` + `ResourceLookupMalformedRow`) instead of reaching
      the knock and failing downstream. Such a row never actually opened a
      pinhole, so this is strictly safer, but it is a new metric attribution on a
      path this PR isn't nominally about — confirm `ResourceLookupMalformedRow`
      doesn't step off zero for agent/headless resources post-deploy.
- [ ] Post-rollout: run a prod browser-path qURL resolve smoke (`/plugins/qurl`
      → 302/redirect) and **follow the redirect through to the protected
      resource** so the minted `nhp_token` is exercised on a live token, not just
      inferred. (The token is signed from `res.ResourceId` (the public `r_` id,
      unchanged) + OpenTime — `jwt.GenerateAll` does not encode the `Resources`
      map — so the catalog map-key change cannot alter token semantics; this
      step validates that end-to-end rather than relying on the inference.)
      On the "Resolve Outcomes" panel of `qurl-operations.json`
      confirm knock success and that `QurlResolveFailResolveCatalog` stays ~0 (a
      sustained non-zero rate means qurl-service is not publishing `q_` catalog
      rows the plugin now requires). There is no alarm on this metric yet
      (tracked in [#2577](https://github.com/layervai/nhp/issues/2577)) —
      **strongly consider landing #2577's alarm before/with cutover**, since the
      rollout's safety leans on this signal; absent that, an operator must
      actively watch the dashboard through the cutover window (a **manual
      dashboard watch**, not a passive page). Confirm no new
      `knock_failed` 500s and that `QurlResolveCatalogResolveMs` p50 is sub-ms
      (catalog cache hit). Also watch `QurlResolveCatalogResolveMs` **p999**:
      during the cold-cache window each fresh-mint miss adds a DynamoDB `GetItem`,
      so a systematic lookup-latency regression shows there. The lookup runs on
      the server lifecycle context (not the browser request — so it can't be cut
      short by a client close or write deadline and won't masquerade as a
      cancel), which is exactly why p999 is the clean signal. `FailResolveCatalog`
      stays a pure publish-gap signal; `QurlResolveFailCanceled` at the catalog
      step only fires on a graceful-shutdown drain race (expect ~0 outside
      deploys).
- [ ] Rollback: if plugin-path knocks fail with `QurlResolveFailResolveCatalog`
      after deploy, roll back this NHP server image (restores body-supplied
      routing). qurl-service still sends `resources` until #823, so rollback is
      self-contained on the NHP side.
- [ ] Cross-repo: once this is healthy in prod, unblock qurl-service #823 to drop
      the `resources` field from the `/internal/v1/resolve` response (keep the
      cookie/redirect/session/`nhp_resource_id` metadata intact).
