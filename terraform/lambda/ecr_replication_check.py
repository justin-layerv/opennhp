"""ECR Cross-Account Replication Status Checker.

Polls each replicated ECR repository, sums FAILED replication-status
entries across recent images (one entry per destination registry, so
an image failing replication to N destinations contributes N), and
publishes that count to CloudWatch as a per-repository metric. The
alarm fires on `> 0` over 2 evaluation periods — destination-as-units
counting matches alarm semantics either way (1 failed image = 1 failed
destination = > 0), and is the more useful number once a second
secondary account is added.

Triggered every 15 minutes by EventBridge. Worst-case detection latency is
up to ~15 min waiting for the next probe tick + 2 × 15-min eval window =
~45 min total, comfortably inside the 1-hour SLO from #1320 (the "~30 min"
figure cited elsewhere is the eval window only, assuming the failure
aligns with a tick). The pre-deploy preflight in promote-to-prod still
exists as a backstop, but this Lambda is what surfaces a silent failure
between deploys — see docs/incidents/2026-04-24-ecr-source-account-trap.md
for why we needed it.

Implementation notes
--------------------
* Only recent pushes (LOOKBACK_HOURS, default 25h) are checked. Replication
  status is set at push time and does not change after — checking the
  whole repo would scale linearly with image count for no extra signal,
  and the daily lifecycle policy keeps the recent set small. The 25h
  window assumes deploys happen at least daily; if cadence ever drops
  below daily (weekly release train, vendor-image-only churn) the
  override path is the LOOKBACK_HOURS env var on the Lambda.
* Failures from the AWS API are NOT swallowed, with one carved-out
  exception: `ImageNotFoundException` between the `describe_images`
  list and the per-digest `describe_image_replication_status` call is
  a benign race (lifecycle expiry or a manual delete mid-scan) and
  noisy-pages on the errors alarm if propagated. Anything else still
  raises so the companion `*-errors` alarm fires.
* `describe_images` has no server-side date filter, so the look-back
  is applied client-side after pagination. Today this is fine — daily
  lifecycle keeps each repo to ~tens of images — but if image volume
  ever grows (merge-train builds, retention bumped) revisit this
  before the per-invocation API count becomes a cost concern. The
  `describe_images` page count is bounded by the lifecycle policy's
  *tagged retention* (90 days) — not by `LOOKBACK_HOURS` — so a
  future bump of tagged retention amplifies the per-tick page walk
  even if look-back stays the same. ECR doesn't expose `imagePushedAt`
  as a server-side filter, so there's no early-exit hook today.
* Per-repo metrics are emitted (Environment, Repository) so the alarm
  name tells on-call which repository is affected without forcing a dig
  through Lambda logs.

Steady-state cost numerics
--------------------------
At today's deploy cadence (~5 deploys/repo/day) and 96 ticks/day:
~96 × 4 × ~5 ≈ 2k `describe_image_replication_status` calls/day. At
peak merge-train (~25 deploys/repo/day inside the 25h window) it'd
climb to ~10k. Either is well under ECR's published throttle. The
hard scaling cliff is #1474's `PutMetricData` chunking limit at ~500
repos (2 metrics/repo × 500 = 1000-entry batch limit).
"""

import datetime
import logging
import os
from typing import Iterable, TypedDict

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

# Lambda's runtime root logger emits to CloudWatch Logs; fetching a
# named child gives Logs Insights queries a usable `@level` field
# (`filter @level = "WARN"`) without grepping log substrings.
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class _ImageId(TypedDict):
    imageDigest: str


DEFAULT_LOOKBACK_HOURS = 25
# Inclusive [min, max] range mirrored from `var.ecr_replication_check_
# lookback_hours`'s validation block in terraform/variables.tf. Held
# as a constant so the test can assert the message against the same
# source — a future TF rename couldn't drift the runtime check from
# the test fence silently.
LOOKBACK_HOURS_MIN = 1
LOOKBACK_HOURS_MAX = 720
# Read-only fallback for non-Lambda imports (tests, REPL). The
# deployed probe always reads `METRIC_NAMESPACE` from the env var that
# Terraform plumbs from `local.ecr_replication_check_metric_namespace`.
DEFAULT_METRIC_NAMESPACE = "LayerV/NHP"

# Region resolution mirrors boto3's own chain:
#   1. AWS_REGION         — set by the Lambda runtime; always wins
#                           inside Lambda.
#   2. AWS_DEFAULT_REGION — boto3's standard CLI-tooling fallback;
#                           kept second so an ops-script env that
#                           sets only this value still works.
#   3. EXPECTED_REGION    — Terraform-plumbed last-resort for
#                           non-Lambda imports (tests, REPL) where
#                           neither boto3 var is set; the test
#                           fixture sets it explicitly.
# Raise if all three are missing so the cause is recognisable in the
# traceback rather than surfacing as an opaque downstream NoRegionError.
def _resolve_region() -> str:
    region = (
        os.environ.get("AWS_REGION")
        or os.environ.get("AWS_DEFAULT_REGION")
        or os.environ.get("EXPECTED_REGION")
    )
    if not region:
        raise RuntimeError(
            "None of AWS_REGION, AWS_DEFAULT_REGION, or EXPECTED_REGION is set. "
            "AWS_REGION is always set in the Lambda runtime; EXPECTED_REGION is "
            "plumbed by Terraform for non-Lambda imports. If you're running this "
            "module outside Lambda (tests, ops scripts), set EXPECTED_REGION (or "
            "the boto3-standard AWS_DEFAULT_REGION)."
        )
    return region


_REGION = _resolve_region()

# `max_attempts = 5` keeps a single retry chain comfortably inside
# the 120s Lambda timeout (standard mode caps backoff at ~20s, full-
# jitter); persistent throttling raises and the errors alarm fences it.
_BOTO3_CONFIG = Config(retries={"mode": "standard", "max_attempts": 5})
ecr = boto3.client("ecr", region_name=_REGION, config=_BOTO3_CONFIG)
cloudwatch = boto3.client("cloudwatch", region_name=_REGION, config=_BOTO3_CONFIG)


def _recent_image_ids(
    ecr_client,
    repository: str,
    cutoff: datetime.datetime,
) -> list[_ImageId]:
    """Return imageId dicts for images pushed at or after `cutoff`.

    Returns a materialised list rather than a generator: today's only
    caller (`handler`) needs the count for `results[repo]["checked"]`
    AND the iterable for `_failed_count`, so laziness buys nothing
    and a lazy interface invites a future caller to assume streaming
    semantics that don't exist (the dedup `set` is held regardless).
    """
    # Dedupe across pagination: an unlikely SDK contract violation would
    # otherwise inflate `_failed_count` silently rather than raising.
    seen_digests: set[str] = set()
    image_ids: list[_ImageId] = []
    paginator = ecr_client.get_paginator("describe_images")
    # `tagStatus: "TAGGED"` skips untagged transient layers — they're
    # build noise, not deploy artifacts that need replication
    # verification. Tag-rotation-within-lookback is a known coverage
    # gap; runbook "Bonus failure mode: tag rotation" owns the detail.
    for page in paginator.paginate(
        repositoryName=repository,
        filter={"tagStatus": "TAGGED"},
    ):
        # Bare-subscript surfaces SDK shape regressions as a KeyError
        # via the errors alarm; the tz-aware check is the only
        # carve-out (it gives a recognisable TypeError instead).
        for image in page["imageDetails"]:
            digest = image["imageDigest"]
            pushed_at = image["imagePushedAt"]
            if pushed_at.tzinfo is None:
                raise TypeError(
                    f"imagePushedAt for {digest} "
                    f"in {repository} is timezone-naive; the boto3 ECR client "
                    f"is expected to return tz-aware datetimes. SDK regression?"
                )
            if pushed_at < cutoff:
                continue
            if digest in seen_digests:
                logger.warning(
                    "duplicate imageDigest %s in %s (paginator returned "
                    "the same digest twice); skipping the duplicate",
                    digest,
                    repository,
                )
                continue
            seen_digests.add(digest)
            image_ids.append({"imageDigest": digest})
    return image_ids


def _failed_count(
    ecr_client, repository: str, image_ids: Iterable[_ImageId]
) -> int:
    """Return the number of FAILED replication-status entries across `image_ids` in `repository`.

    Each image can have multiple status entries (one per destination
    registry); this sums across destinations rather than collapsing to
    one-per-image. Alarm semantics (`> 0`) are unchanged either way,
    and per-destination counting becomes the more useful number when a
    second secondary account is added.
    """
    failed = 0
    for image_id in image_ids:
        try:
            resp = ecr_client.describe_image_replication_status(
                repositoryName=repository,
                imageId=image_id,
            )
        except ClientError as e:
            # An image that was listed by describe_images can be deleted
            # between that call and this one (lifecycle expiry, manual
            # cleanup); that's not a probe failure. The IAM policy is
            # repo-scoped to `module.ecr.repository_arns`, so the only
            # path that produces this error here is a digest that
            # vanished mid-scan — not a missing repo or a permissions
            # gap. Anything else raises, the errors alarm fires, and
            # on-call investigates.
            if e.response.get("Error", {}).get("Code") == "ImageNotFoundException":
                logger.info(
                    "image deleted mid-scan, skipping: repo=%s digest=%s",
                    repository,
                    image_id["imageDigest"],
                )
                continue
            raise
        # Counts FAILED entries per (image, destination) pair; AWS
        # owns destination dedup.
        for status in resp.get("replicationStatuses", []):
            # Bare-subscript `status` rather than `.get("status")` so
            # an SDK-shape regression that omits the field surfaces as
            # a KeyError → errors alarm, not a silent treat-as-not-
            # failed. The outer `replicationStatuses` field can
            # legitimately be absent (no destinations configured) —
            # that's the carve-out fenced by
            # `test_missing_replication_statuses_field_contributes_zero`
            # — but each entry within the list is documented as
            # always carrying `status`.
            if status["status"] == "FAILED":
                failed += 1
                # `warning` rather than `error` so Logs Insights queries
                # filtered on `@level = "ERROR"` stay reserved for
                # probe-side bugs; the failure-count metric drives the
                # alarm, not the log level. `failureCode` can be absent
                # (queued, mid-state) — render `<unset>` rather than
                # the literal string `None` so Logs Insights filters
                # like `failureCode != "<unset>"` partition cleanly.
                logger.warning(
                    "FAILED replication: repo=%s digest=%s region=%s "
                    "registry=%s failureCode=%s",
                    repository,
                    image_id["imageDigest"],
                    status.get("region", "<unset>"),
                    status.get("registryId", "<unset>"),
                    status.get("failureCode", "<unset>"),
                )
    return failed


def handler(event, context):
    """EventBridge entry point. Returns `{"environment", "results"}`
    where `results` maps each repository to `{"checked", "failed"}` —
    available for ad-hoc `aws lambda invoke` debugging; CloudWatch
    metrics are the production-facing surface."""
    # `.get(..., "")` rather than a bare subscript so both the unset
    # and empty-string paths funnel into the explicit RuntimeError
    # below with a clear message, instead of mixing bare-KeyError
    # (unset) with structured RuntimeError (empty) — the errors alarm
    # fires either way, but a recognisable message saves one log dive.
    # Order-preserving dedup against console-edit footguns; a duplicate
    # would double the per-repo API work and emit redundant MetricData.
    repositories = list(
        dict.fromkeys(
            r.strip()
            for r in os.environ.get("REPOSITORIES", "").split(",")
            if r.strip()
        )
    )
    # An empty REPOSITORIES list is unreachable under the current TF
    # gating (`module.ecr.is_replication_source` requires at least the
    # three core repos), so reaching this branch indicates a config
    # drift — most likely a console edit between applies, or the env
    # being unset entirely. Fail fast here rather than at the publish
    # site below so the error message names the actual cause; either
    # way the errors alarm fires.
    if not repositories:
        raise RuntimeError(
            f"REPOSITORIES env yielded an empty repo list "
            f"(env={os.environ.get('ENVIRONMENT', '<unset>')}); "
            f"this is structurally impossible under the TF wiring and indicates "
            f"a config drift — investigate the Lambda environment."
        )
    # ENVIRONMENT is a required metric dimension — there is no sensible
    # default ("sandbox" vs "prod" can't be inferred), so an unset
    # value is structurally a config error. Funnels into the same
    # RuntimeError shape as the REPOSITORIES path above so a future
    # reader doesn't trip on the asymmetry of bare-KeyError vs
    # structured-RuntimeError. Either way the errors alarm fires.
    environment = os.environ.get("ENVIRONMENT")
    if not environment:
        raise RuntimeError(
            f"ENVIRONMENT env not set on Lambda "
            f"(repositories={repositories}); this is required as a "
            f"CloudWatch dimension and the Terraform wiring sets it "
            f"exhaustively, so reaching this branch indicates a "
            f"config drift — investigate the Lambda environment."
        )
    # `METRIC_NAMESPACE` is plumbed from `local.ecr_replication_check_
    # metric_namespace` in TF so the IAM Condition, the alarm
    # namespace, and the publish call all stay in lockstep — a rename
    # in one place propagates to all three. The DEFAULT_METRIC_
    # NAMESPACE fallback is for non-Lambda imports (tests, REPL); the
    # deployed probe always reads the TF-plumbed value.
    # `os.environ.get(..., DEFAULT)` returns the default ONLY when the
    # key is missing, not when it's set to "". The check below covers
    # the env-set-to-empty-string case (a manual console edit that
    # cleared the value); REPOSITORIES/ENVIRONMENT use the same shape
    # but funnel both unset and empty into one path because there's
    # no sensible default for them.
    metric_namespace = os.environ.get("METRIC_NAMESPACE", DEFAULT_METRIC_NAMESPACE)
    if not metric_namespace:
        raise RuntimeError(
            "METRIC_NAMESPACE env was set but empty; this is required "
            "for the IAM Condition and alarm-namespace lockstep with "
            "Terraform — investigate the Lambda environment."
        )
    # LOOKBACK_HOURS validation. Terraform's variable validation already
    # constrains the value to [1, 720] — we re-check here so a console
    # edit that bypasses TF (or an unset env, falling through to the
    # DEFAULT) still gets caught with a recognisable error. Symmetric
    # with the empty-repos hard-raise above: an unparseable or non-
    # positive LOOKBACK is exactly the silent-failure mode the PR
    # closes (cutoff in the future, every image excluded, metric stays
    # at 0 forever), so a soft fall-back here would re-create that
    # regime under a manual misconfiguration. Errors alarm fires
    # either way; the structured message names the actual cause.
    # Wrap the default in str() so the !r formatting below renders
    # consistently regardless of whether the env var was set.
    raw_lookback = os.environ.get("LOOKBACK_HOURS", str(DEFAULT_LOOKBACK_HOURS))
    try:
        lookback_hours = int(raw_lookback)
    except ValueError as e:
        raise RuntimeError(
            f"LOOKBACK_HOURS={raw_lookback!r} is not parseable as int; "
            f"this is structurally impossible under the TF wiring "
            f"(`var.ecr_replication_check_lookback_hours` is `number`-typed "
            f"and validated [{LOOKBACK_HOURS_MIN}, {LOOKBACK_HOURS_MAX}]) "
            f"and indicates a config drift — investigate the Lambda environment."
        ) from e
    if not LOOKBACK_HOURS_MIN <= lookback_hours <= LOOKBACK_HOURS_MAX:
        raise RuntimeError(
            f"LOOKBACK_HOURS={lookback_hours} is outside "
            f"[{LOOKBACK_HOURS_MIN}, {LOOKBACK_HOURS_MAX}]; "
            f"this is structurally impossible under the TF wiring "
            f"(`var.ecr_replication_check_lookback_hours` is validated "
            f"[{LOOKBACK_HOURS_MIN}, {LOOKBACK_HOURS_MAX}]) and indicates a "
            f"config drift — investigate the Lambda environment. "
            f"Out-of-range values would either widen the look-back past the "
            f"untagged-lifecycle expiry (re-opening the silent-failure window "
            f"this PR closes) or zero it out (failure-count metric stuck at 0)."
        )

    cutoff = datetime.datetime.now(tz=datetime.timezone.utc) - datetime.timedelta(
        hours=lookback_hours
    )

    # Per-repo isolation: a non-ImageNotFoundException error on one
    # repo no longer blinds the others. We collect exceptions, let
    # surviving repos publish their datapoints, then raise at the end
    # so the errors alarm still fires. This preserves the "errors
    # alarm fires => probe is broken" contract while preventing the
    # masking regime where repo[0]'s transient throttle silenced
    # repo[1..N]'s failure-count alarms.
    results = {}
    metric_data = []
    per_repo_errors: list[tuple[str, Exception]] = []
    for repo in repositories:
        try:
            image_ids = _recent_image_ids(ecr, repo, cutoff)
            failed = _failed_count(ecr, repo, image_ids)
        except Exception as e:  # noqa: BLE001 — collected and re-raised post-loop
            # `exc_info=True` writes the full traceback into CloudWatch
            # Logs for this repo, which is what on-call grep'd for after
            # the errors alarm fires. Lambda's runtime emits its own
            # traceback on the post-loop raise, but that's the
            # *aggregate* error — the per-repo trace lives here.
            logger.error("error processing repo=%s: %s", repo, e, exc_info=True)
            per_repo_errors.append((repo, e))
            continue
        results[repo] = {"checked": len(image_ids), "failed": failed}
        # `Unit = "Count"` is in lockstep with the alarm's `unit` pin
        # (`terraform/ecr_replication_check.tf::aws_cloudwatch_metric_
        # alarm.ecr_replication_failure.unit`) — drift would let
        # CloudWatch evaluate the alarm against a unit-filter mismatch.
        dimensions = [
            {"Name": "Environment", "Value": environment},
            {"Name": "Repository", "Value": repo},
        ]
        # PER-TICK EMIT INVARIANT: every successful tick MUST publish
        # one ECRReplicationFailureCount datapoint per repo, even when
        # `failed == 0`. The alarm uses `treat_missing_data =
        # "notBreaching"` and `evaluation_periods = 2 / datapoints_to_
        # alarm = 2`, so a regression that short-circuits the publish
        # on quiet ticks would leave the metric stream sparse and the
        # alarm could mask a real failure between non-zero datapoints.
        # `test_skips_failed_count_when_no_recent_images` fences this.
        metric_data.append(
            {
                "MetricName": "ECRReplicationFailureCount",
                "Dimensions": dimensions,
                "Value": failed,
                "Unit": "Count",
            }
        )
        # Emit `ECRReplicationImagesCheckedCount` alongside so ops can
        # answer "is the look-back window actually covering deploys?"
        # without instrumenting the Lambda separately. If this drops to
        # zero on a repo for a sustained window, deploy cadence has
        # likely crossed below `LOOKBACK_HOURS` and the next replication
        # failure could fall into the persistence-window blind spot
        # tracked in #1476. No alarm wired today — surfacing the signal
        # so the dashboard can; a future alarm can pull from this
        # without a code change.
        metric_data.append(
            {
                "MetricName": "ECRReplicationImagesCheckedCount",
                "Dimensions": dimensions,
                "Value": len(image_ids),
                "Unit": "Count",
            }
        )

    # PutMetricData accepts up to 1000 MetricData entries and 40 KB
    # per request. We emit TWO entries per repo (FailureCount +
    # ImagesCheckedCount); the chunk cliff is ~500 repos (#1474).
    # Skip the call if every repo errored — `metric_data` would be
    # empty and PutMetricData rejects empty MetricData lists.
    if metric_data:
        cloudwatch.put_metric_data(Namespace=metric_namespace, MetricData=metric_data)

    if per_repo_errors:
        # Late-raise: surviving repos already published; this surfaces
        # the failure to the errors alarm without blinding them. The
        # message names every failed repo so on-call doesn't have to
        # cross-reference per-repo logs to see the breadth.
        failed_repos = ", ".join(repo for repo, _ in per_repo_errors)
        raise RuntimeError(
            f"per-repo errors during tick: {failed_repos}. Surviving "
            f"repos published; see per-repo tracebacks above. "
            f"docs/runbooks/ecr-replication-failure.md."
        )

    logger.info(
        "ECR replication check complete: env=%s lookback_hours=%s results=%s",
        environment,
        lookback_hours,
        results,
    )
    return {"environment": environment, "results": results}
