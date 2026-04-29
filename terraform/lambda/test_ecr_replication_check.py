"""
Unit tests for ECR replication-check Lambda.

Run with: pytest test_ecr_replication_check.py -v

Why these tests exist
---------------------
The whole point of #1320 is to close a *silent failure* gap. The Lambda
itself becoming a silent failure (e.g., catching exceptions and emitting
a clean zero) would recreate that gap. These tests fence the three
behaviours that matter for that property:

* recent-image filtering pulls in pushes inside the look-back window
  and excludes anything older;
* per-image FAILED counts are summed correctly and per-repo metrics
  are emitted;
* AWS errors propagate up so the companion `*-errors` alarm fires.
"""

import datetime
import re
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError


@pytest.fixture(autouse=True)
def lambda_env(monkeypatch):
    # 4-repo fixture matches today's prod env-var shape (the 3 core
    # repos + layerv/nhp-qurl when `deploy_qurl_ecr=true` in TF).
    # Tests that need a different-shaped repo set override
    # REPOSITORIES locally; this default keeps the assertion surface
    # aligned with the runtime config. Static fixture — does NOT
    # exercise the `deploy_qurl_ecr` conditional itself.
    monkeypatch.setenv(
        "REPOSITORIES",
        "layerv/nhp-server,layerv/nhp-ac,layerv/nhp-console,layerv/nhp-qurl",
    )
    monkeypatch.setenv("ENVIRONMENT", "sandbox")
    monkeypatch.setenv("AWS_REGION", "us-east-2")
    monkeypatch.setenv("EXPECTED_REGION", "us-east-2")


@pytest.fixture
def lambda_module(lambda_env):
    """Fresh per-test import. The explicit `lambda_env` parameter pins
    env-set-before-import ordering rather than relying on pytest's
    autouse-fixture resolution order; the `sys.modules.pop` keeps
    `test_module_imports_with_only_expected_region_set`'s mid-suite
    delete from leaking into other tests.

    Caveat: the module-level `_REGION` resolution + boto3 client
    instantiation makes this suite serial-only. If the suite ever
    moves to `pytest-xdist`, the per-test re-import races with
    parallel workers' env mutations and the module would need
    refactoring to lazify client construction first."""
    del lambda_env  # parameter name must match the fixture; the `del` enforces it as ordering-only
    import importlib
    import sys

    sys.modules.pop("ecr_replication_check", None)
    return importlib.import_module("ecr_replication_check")


def _image(*, digest: str, pushed_at: datetime.datetime) -> dict:
    """Keyword-only so a future test author can't transpose the args."""
    return {"imageDigest": digest, "imagePushedAt": pushed_at}


@pytest.fixture
def mocked_clients_no_images(lambda_module, monkeypatch):
    """Wires `ecr` + `cw` MagicMocks into the module with empty-paginator
    semantics — `describe_images` returns no images for any repo. Use
    when the test exercises handler logic that doesn't depend on which
    images exist (env-var passthrough, dimension shape, idle-tick
    zero-emit invariant). Returns the `(ecr, cw)` mocks so a test can
    assert on calls."""
    ecr = MagicMock()
    cw = MagicMock()
    paginator = MagicMock()
    paginator.paginate.return_value = [{"imageDetails": []}]
    ecr.get_paginator.return_value = paginator
    monkeypatch.setattr(lambda_module, "ecr", ecr)
    monkeypatch.setattr(lambda_module, "cloudwatch", cw)
    return ecr, cw


def _emitted_metrics(put_metric_data_call) -> dict:
    """Index a `put_metric_data` MagicMock call by `(MetricName, sorted-dim-tuple)` → value.

    Used by tests that need to assert per-(metric, dims) emit semantics
    independent of MetricData ordering — `put_metric_data` accepts the
    list in any order, so a positional-order assertion would couple the
    test to the publisher's iteration order over the repos dict.
    """
    return {
        (m["MetricName"], tuple(sorted((d["Name"], d["Value"]) for d in m["Dimensions"]))): m["Value"]
        for m in put_metric_data_call.kwargs["MetricData"]
    }


# ==================== module-level safety ====================


class TestModuleImport:
    """Properties that must hold even when the module is imported
    outside the Lambda runtime (CI runners, ops scripts, REPL).

    The previous CI regression (`Test Lambdas` failed with
    NoRegionError) was caused by dropping the `region_name=` fallback
    on the boto3 clients on the assumption that boto3 would auto-pick
    AWS_REGION. Boto3 only auto-picks it from the *Lambda runtime
    environment* — the GitHub Actions test runner has no AWS_REGION
    set, so the bare `boto3.client("ecr")` call raised at import
    time. This test fences against rediscovering that.
    """

    def test_module_imports_with_only_expected_region_set(self, monkeypatch):
        """Importing the module must succeed even when no AWS_REGION is
        in the environment — `EXPECTED_REGION` (Terraform-plumbed) is
        the fallback. The fixture above sets both, so this test only
        pops AWS_REGION/AWS_DEFAULT_REGION to fence the case where
        boto3's auto-pick fails."""
        import importlib
        import os
        import sys

        monkeypatch.delenv("AWS_REGION", raising=False)
        monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)
        # Force a fresh import so the module-level boto3.client calls
        # re-execute under the cleared env.
        sys.modules.pop("ecr_replication_check", None)

        ecr_replication_check = importlib.import_module("ecr_replication_check")

        assert ecr_replication_check.ecr is not None
        assert ecr_replication_check.cloudwatch is not None
        # Derive the expected value from the env that the fixture
        # actually set, rather than asserting a literal — a fixture-
        # value rename otherwise ghost-breaks the test.
        assert ecr_replication_check._REGION == os.environ["EXPECTED_REGION"]

    def test_module_imports_with_only_aws_default_region_set(self, monkeypatch):
        """Pin the middle-tier resolution path: when only the boto3-
        standard `AWS_DEFAULT_REGION` is set (the common case for ops
        scripts and CLI tooling), `_REGION` resolves to it before
        falling through to `EXPECTED_REGION`. A regression that
        consolidates the chain to two env vars would silently change
        behavior for those scripts."""
        import importlib
        import os
        import sys

        monkeypatch.delenv("AWS_REGION", raising=False)
        monkeypatch.delenv("EXPECTED_REGION", raising=False)
        monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-west-1")
        sys.modules.pop("ecr_replication_check", None)

        ecr_replication_check = importlib.import_module("ecr_replication_check")

        assert ecr_replication_check._REGION == os.environ["AWS_DEFAULT_REGION"]
        assert ecr_replication_check._REGION == "eu-west-1"

    def test_aws_region_takes_precedence_over_aws_default_region(self, monkeypatch):
        """Pin priority order: `AWS_REGION` wins over `AWS_DEFAULT_REGION`
        when both are set. A regression that swaps the chain order would
        pass every per-tier test (each fixture sets a single env) but
        break the contract here. `EXPECTED_REGION` is the third fallback;
        with `AWS_REGION` set, neither of the others should be consulted."""
        import importlib
        import sys

        monkeypatch.setenv("AWS_REGION", "us-east-2")
        monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-west-1")
        monkeypatch.setenv("EXPECTED_REGION", "ap-southeast-2")
        sys.modules.pop("ecr_replication_check", None)

        ecr_replication_check = importlib.import_module("ecr_replication_check")

        assert ecr_replication_check._REGION == "us-east-2"

    def test_module_import_raises_when_neither_region_env_set(self, monkeypatch):
        """If both `AWS_REGION` and `EXPECTED_REGION` are unset, module
        import must raise a structured `RuntimeError` with a message
        that names both env vars — symmetric with the
        REPOSITORIES/ENVIRONMENT/LOOKBACK_HOURS structured-raise stance
        in the handler. A bare `KeyError` would force the next
        operator to git-blame the line rather than reading the cause
        from the traceback."""
        import importlib
        import sys

        monkeypatch.delenv("AWS_REGION", raising=False)
        monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)
        monkeypatch.delenv("EXPECTED_REGION", raising=False)
        sys.modules.pop("ecr_replication_check", None)

        with pytest.raises(RuntimeError, match="EXPECTED_REGION"):
            importlib.import_module("ecr_replication_check")

    def test_boto3_retry_config_pins_max_attempts_and_standard_mode(
        self, lambda_module
    ):
        """Pin the boto3 retry config (`max_attempts=5`, `mode="standard"`)
        on the module-level clients. The retry budget is load-bearing for
        the "per-call retry chain can't kill the tick before any
        PutMetricData fires" reasoning in the surrounding comment block;
        a regression that drops the Config (e.g., a future refactor that
        constructs clients without it) would silently violate the budget
        and re-open the unrecoverable-throttle blind spot."""
        # boto3 normalises `max_attempts=N` (user-facing) to
        # `total_max_attempts=N+1` (initial attempt + retries) in
        # client.meta.config.retries, so assert the normalised form.
        for client in (lambda_module.ecr, lambda_module.cloudwatch):
            retries = client.meta.config.retries
            assert retries["mode"] == "standard"
            assert retries["total_max_attempts"] == 6


# ==================== _recent_image_ids ====================


class TestRecentImageIds:
    """Filters imageDetails by cutoff time."""

    def test_returns_only_images_pushed_at_or_after_cutoff(self, lambda_module):
        now = datetime.datetime(2026, 4, 28, 12, 0, tzinfo=datetime.timezone.utc)
        cutoff = now - datetime.timedelta(hours=25)

        ecr = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {
                "imageDetails": [
                    _image(digest="sha:fresh", pushed_at=now - datetime.timedelta(hours=1)),
                    _image(digest="sha:stale", pushed_at=now - datetime.timedelta(days=2)),
                    _image(digest="sha:edge", pushed_at=cutoff),
                ]
            }
        ]
        ecr.get_paginator.return_value = paginator

        result = lambda_module._recent_image_ids(ecr, "layerv/nhp-server", cutoff)

        # `>=` semantics: cutoff itself is included.
        assert {r["imageDigest"] for r in result} == {"sha:fresh", "sha:edge"}

        # `filter={"tagStatus": "TAGGED"}` is passed to the paginator
        # so untagged transient images aren't pulled into the per-tick
        # walk. Pins the contract that probe input is restricted to
        # deploy-artifact images, not intermediate Docker layers.
        paginate_kwargs = paginator.paginate.call_args.kwargs
        assert paginate_kwargs.get("filter") == {"tagStatus": "TAGGED"}

    def test_paginates(self, lambda_module):
        # Frozen `now` so the test is independent of wall-clock skew.
        now = datetime.datetime(2026, 4, 28, 12, 0, tzinfo=datetime.timezone.utc)
        cutoff = now - datetime.timedelta(hours=25)

        ecr = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {"imageDetails": [_image(digest="sha:a", pushed_at=now)]},
            {"imageDetails": [_image(digest="sha:b", pushed_at=now)]},
        ]
        ecr.get_paginator.return_value = paginator

        result = lambda_module._recent_image_ids(ecr, "layerv/nhp-server", cutoff)

        assert {r["imageDigest"] for r in result} == {"sha:a", "sha:b"}

    def test_aws_error_propagates_at_iteration_time(self, lambda_module):
        """Real boto3 raises while iterating pages, not when calling
        `paginate()` itself. Use an actual generator so `__next__` is
        what raises — that's the realistic propagation surface
        (botocore raises during retrieval of each page, not eagerly
        when paginate() is called). The errors alarm depends on this
        propagating up; a regression that swallows it would re-open the
        silent-failure regime."""
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        cutoff = now - datetime.timedelta(hours=25)

        def _raising_pages():
            yield {"imageDetails": [_image(digest="sha:first", pushed_at=now)]}
            raise RuntimeError("mid-iter boom")

        ecr = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = _raising_pages()
        ecr.get_paginator.return_value = paginator

        with pytest.raises(RuntimeError, match="mid-iter boom"):
            lambda_module._recent_image_ids(ecr, "layerv/nhp-server", cutoff)

    def test_describe_images_client_error_propagates(self, lambda_module):
        """Sibling fence to `test_other_client_errors_still_propagate` in
        TestFailedCount, but for the `DescribeImages` paginator path. If
        IAM drifts and the Lambda role loses `ecr:DescribeImages`, the
        paginator raises `AccessDeniedException` when consumers start
        iterating; the Lambda must propagate so the errors alarm fires
        instead of silently emitting zero failures."""
        cutoff = datetime.datetime.now(tz=datetime.timezone.utc) - datetime.timedelta(
            hours=25
        )

        class _RaisesOnIter:
            def __iter__(self):
                raise ClientError(
                    {"Error": {"Code": "AccessDeniedException", "Message": "nope"}},
                    "DescribeImages",
                )

        ecr = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = _RaisesOnIter()
        ecr.get_paginator.return_value = paginator

        with pytest.raises(ClientError):
            lambda_module._recent_image_ids(ecr, "layerv/nhp-server", cutoff)

    def test_naive_pushed_at_raises_with_clear_message(self, lambda_module):
        """boto3's ECR client returns tz-aware datetimes for
        imagePushedAt; if a future SDK regression returned naive ones,
        the `<` comparison against tz-aware `cutoff` would TypeError
        with an opaque stack trace. The explicit assertion surfaces
        the contract violation with a recognisable message instead."""
        now_naive = datetime.datetime.now()  # no tzinfo
        cutoff = datetime.datetime.now(tz=datetime.timezone.utc) - datetime.timedelta(
            hours=25
        )

        ecr = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {"imageDetails": [_image(digest="sha:naive", pushed_at=now_naive)]}
        ]
        ecr.get_paginator.return_value = paginator

        with pytest.raises(TypeError, match="timezone-naive"):
            lambda_module._recent_image_ids(ecr, "layerv/nhp-server", cutoff)

    def test_duplicate_digests_are_deduped_across_pages(self, lambda_module, caplog):
        """If the boto3 paginator ever returns the same digest twice
        (a contract violation today, but possible under a future SDK
        bug or paging-boundary glitch), `_failed_count` would
        otherwise multi-count the same image's destinations and
        inflate the metric. Alarm semantics (`> 0`) survive either
        way, but the runbook spot-check command would over-report
        and could mask a separate failure."""
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        cutoff = now - datetime.timedelta(hours=25)

        ecr = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {"imageDetails": [_image(digest="sha:dup", pushed_at=now), _image(digest="sha:other", pushed_at=now)]},
            {"imageDetails": [_image(digest="sha:dup", pushed_at=now)]},  # cross-page repeat
        ]
        ecr.get_paginator.return_value = paginator

        with caplog.at_level("WARNING", logger=lambda_module.logger.name):
            result = lambda_module._recent_image_ids(ecr, "layerv/nhp-server", cutoff)

        assert [r["imageDigest"] for r in result] == ["sha:dup", "sha:other"]
        assert "duplicate imageDigest" in caplog.text

# ==================== _failed_count ====================


class TestFailedCount:
    """Counts only FAILED replication statuses across all images."""

    def test_counts_failed_statuses(self, lambda_module):
        ecr = MagicMock()
        ecr.describe_image_replication_status.side_effect = [
            {"replicationStatuses": [{"status": "COMPLETE", "region": "us-east-2"}]},
            {
                "replicationStatuses": [
                    {"status": "FAILED", "region": "us-east-2", "failureCode": "PERM"}
                ]
            },
            {
                "replicationStatuses": [
                    {"status": "FAILED", "region": "us-east-2", "failureCode": "PERM"},
                    {"status": "COMPLETE", "region": "us-east-2"},
                ]
            },
        ]

        result = lambda_module._failed_count(
            ecr,
            "layerv/nhp-server",
            [
                {"imageDigest": "sha:a"},
                {"imageDigest": "sha:b"},
                {"imageDigest": "sha:c"},
            ],
        )

        assert result == 2

    def test_multiple_failed_destinations_on_one_image_count_separately(self, lambda_module):
        """Documented contract: an image failing replication to N
        destinations contributes N to the count. Matters once a second
        secondary account is added — alarm semantics (`> 0`) are
        unchanged either way, but per-destination is the more useful
        number to look at in the dashboard."""
        ecr = MagicMock()
        ecr.describe_image_replication_status.return_value = {
            "replicationStatuses": [
                {"status": "FAILED", "region": "us-east-2", "registryId": "111", "failureCode": "PERM"},
                {"status": "FAILED", "region": "us-east-2", "registryId": "222", "failureCode": "PERM"},
            ]
        }

        result = lambda_module._failed_count(
            ecr, "layerv/nhp-server", [{"imageDigest": "sha:a"}]
        )

        assert result == 2

    def test_missing_replication_statuses_field_contributes_zero(self, lambda_module):
        """Companion to `test_empty_replication_statuses_contributes_zero`:
        an API response that omits `replicationStatuses` entirely (vs.
        returning `[]`) must also contribute zero. The implementation
        uses `.get("replicationStatuses", [])`; this test pins that
        defense so a regression that switches to `[response["replicationStatuses"]]`
        fails loudly."""
        ecr = MagicMock()
        ecr.describe_image_replication_status.return_value = {}  # no field

        result = lambda_module._failed_count(
            ecr, "layerv/nhp-server", [{"imageDigest": "sha:a"}]
        )

        assert result == 0

    def test_missing_status_field_within_entry_raises(self, lambda_module):
        """Sibling fence to the previous test: the *outer*
        `replicationStatuses` field can legitimately be absent (no
        destinations configured), but each *entry* within the list
        is documented as always carrying `status`. A regression where
        the SDK starts returning entries without `status` (or where a
        future schema rename breaks the contract) must surface as a
        KeyError → errors alarm, not silently treat-as-not-failed.
        Bare-subscript on `status["status"]` enforces this; the
        previous `.get("status")` form would have masked it."""
        ecr = MagicMock()
        ecr.describe_image_replication_status.return_value = {
            "replicationStatuses": [
                {"region": "us-east-2"},  # missing the load-bearing `status` key
            ]
        }

        with pytest.raises(KeyError, match="status"):
            lambda_module._failed_count(
                ecr, "layerv/nhp-server", [{"imageDigest": "sha:a"}]
            )

    def test_repo_not_found_propagates_through_errors_alarm(self, lambda_module):
        """If a repo is renamed in the module but the Lambda env still
        references the old name (TF apply lag), the per-digest call
        will surface RepositoryNotFoundException. Like every other
        ClientError code that isn't ImageNotFoundException, this must
        propagate so the errors alarm fires — companion to
        `test_other_client_errors_still_propagate` covering the
        AccessDeniedException path."""

        ecr = MagicMock()
        ecr.describe_image_replication_status.side_effect = ClientError(
            {"Error": {"Code": "RepositoryNotFoundException", "Message": "gone"}},
            "DescribeImageReplicationStatus",
        )

        with pytest.raises(ClientError):
            lambda_module._failed_count(
                ecr, "layerv/nhp-server", [{"imageDigest": "sha:a"}]
            )

    def test_empty_replication_statuses_contributes_zero(self, lambda_module):
        """An image with no replication statuses (e.g., a tag that
        doesn't match a registry filter, or a future ECR API quirk)
        must contribute zero, not be interpreted as a failure. Fences
        against a "missing data == failure" misread regression."""
        ecr = MagicMock()
        ecr.describe_image_replication_status.return_value = {
            "replicationStatuses": []
        }

        result = lambda_module._failed_count(
            ecr, "layerv/nhp-server", [{"imageDigest": "sha:a"}]
        )

        assert result == 0

    def test_mixed_failed_and_in_progress_on_same_image(self, lambda_module):
        """Real-world transient state: replication to one destination
        completed-FAILED while replication to another is still
        IN_PROGRESS. Only the FAILED entry should count; the
        IN_PROGRESS one is the transient mid-flight state. Pins the
        invariant that mid-replication state never inflates the
        failure count."""
        ecr = MagicMock()
        ecr.describe_image_replication_status.return_value = {
            "replicationStatuses": [
                {"status": "FAILED", "region": "us-east-2", "registryId": "111", "failureCode": "PERM"},
                {"status": "IN_PROGRESS", "region": "us-east-2", "registryId": "222"},
            ]
        }

        result = lambda_module._failed_count(
            ecr, "layerv/nhp-server", [{"imageDigest": "sha:a"}]
        )

        assert result == 1

    def test_in_progress_is_not_failed(self, lambda_module):
        """IN_PROGRESS is the transient state mid-replication; not a failure."""
        ecr = MagicMock()
        ecr.describe_image_replication_status.return_value = {
            "replicationStatuses": [{"status": "IN_PROGRESS", "region": "us-east-2"}]
        }

        result = lambda_module._failed_count(
            ecr, "layerv/nhp-server", [{"imageDigest": "sha:a"}]
        )

        assert result == 0

    def test_aws_error_propagates(self, lambda_module):
        """Failed API calls must NOT be swallowed — that would recreate the
        observability gap this whole change exists to close. The errors
        alarm depends on the Lambda raising on AWS failures."""
        ecr = MagicMock()
        ecr.describe_image_replication_status.side_effect = RuntimeError("boom")

        with pytest.raises(RuntimeError, match="boom"):
            lambda_module._failed_count(
                ecr, "layerv/nhp-server", [{"imageDigest": "sha:a"}]
            )

    def test_image_not_found_is_skipped(self, lambda_module):
        """describe_image_replication_status can race a lifecycle expiry
        or manual delete. ImageNotFoundException is the one carved-out
        case where we keep going — anything else still propagates and
        pages on-call via the errors alarm."""

        ecr = MagicMock()
        ecr.describe_image_replication_status.side_effect = [
            ClientError(
                {"Error": {"Code": "ImageNotFoundException", "Message": "gone"}},
                "DescribeImageReplicationStatus",
            ),
            {
                "replicationStatuses": [
                    {"status": "FAILED", "region": "us-east-2", "failureCode": "PERM"}
                ]
            },
        ]

        result = lambda_module._failed_count(
            ecr,
            "layerv/nhp-server",
            [{"imageDigest": "sha:gone"}, {"imageDigest": "sha:still-here"}],
        )

        # The deleted image is skipped silently; the remaining image's
        # FAILED status still counts.
        assert result == 1

    def test_other_client_errors_still_propagate(self, lambda_module):
        """Carving out ImageNotFoundException must not swallow other
        ClientError codes — the errors alarm is the meta-gap fence."""

        ecr = MagicMock()
        ecr.describe_image_replication_status.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "nope"}},
            "DescribeImageReplicationStatus",
        )

        with pytest.raises(ClientError):
            lambda_module._failed_count(
                ecr, "layerv/nhp-server", [{"imageDigest": "sha:a"}]
            )

    def test_failed_log_renders_unset_for_missing_optional_fields(
        self, lambda_module, caplog
    ):
        """The FAILED-replication warning log uses `<unset>` rather than
        the literal `None` for missing `failureCode`/`region`/`registryId`
        so Logs Insights filters like `failureCode != "<unset>"` partition
        cleanly. AWS sometimes returns these entries without `failureCode`
        while replication is queued or in-progress; the log must stay
        useful in that state. Pin the contract so a future regression
        that drops the `<unset>` defaults doesn't silently render
        `None` strings instead."""
        ecr = MagicMock()
        # FAILED status entry with NO `failureCode`, `region`, or
        # `registryId` — only the load-bearing `status` key is present.
        ecr.describe_image_replication_status.return_value = {
            "replicationStatuses": [{"status": "FAILED"}]
        }

        with caplog.at_level("WARNING", logger=lambda_module.logger.name):
            failed = lambda_module._failed_count(
                ecr, "layerv/nhp-server", [{"imageDigest": "sha:a"}]
            )

        assert failed == 1
        assert "<unset>" in caplog.text
        # And specifically NOT the literal Python repr of None.
        assert "failureCode=None" not in caplog.text
        assert "region=None" not in caplog.text


# ==================== handler ====================


class TestHandler:
    """Top-level handler wiring."""

    def test_emits_one_metric_per_repository(self, lambda_module, monkeypatch):
        ecr = MagicMock()
        cw = MagicMock()

        # All repos return one fresh image, one of which has FAILED replication.
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {"imageDetails": [_image(digest="sha:fresh", pushed_at=now)]}
        ]
        ecr.get_paginator.return_value = paginator
        ecr.describe_image_replication_status.side_effect = (
            lambda **kwargs: {
                "replicationStatuses": [
                    {
                        "status": "FAILED" if kwargs["repositoryName"] == "layerv/nhp-ac" else "COMPLETE",
                        "region": "us-east-2",
                        "failureCode": "PERM",
                    }
                ]
            }
        )

        monkeypatch.setattr(lambda_module, "ecr", ecr)
        monkeypatch.setattr(lambda_module, "cloudwatch", cw)

        result = lambda_module.handler({}, None)

        assert result["environment"] == "sandbox"
        assert result["results"]["layerv/nhp-server"] == {"checked": 1, "failed": 0}
        assert result["results"]["layerv/nhp-ac"] == {"checked": 1, "failed": 1}
        assert result["results"]["layerv/nhp-console"] == {"checked": 1, "failed": 0}
        assert result["results"]["layerv/nhp-qurl"] == {"checked": 1, "failed": 0}

        # PutMetricData is called once with all four repos in one batch.
        cw.put_metric_data.assert_called_once()
        call = cw.put_metric_data.call_args
        assert call.kwargs["Namespace"] == "LayerV/NHP"

        # Each repo emits two metrics (FailureCount + ImagesCheckedCount)
        # with the same dimensions; key by (metric, dims) to assert.
        emitted = _emitted_metrics(call)
        for repo, expected_failed, expected_checked in [
            ("layerv/nhp-server", 0, 1),
            ("layerv/nhp-ac", 1, 1),
            ("layerv/nhp-console", 0, 1),
            ("layerv/nhp-qurl", 0, 1),
        ]:
            dims = (("Environment", "sandbox"), ("Repository", repo))
            assert emitted[("ECRReplicationFailureCount", dims)] == expected_failed
            assert emitted[("ECRReplicationImagesCheckedCount", dims)] == expected_checked

        # Explicit dimension-content assertion: the Repository values
        # carry the canonical `layerv/...` prefix and TWO entries exist
        # per env-var-listed repo (one per metric name). Belt-and-braces
        # vs. the (MetricName, dims) keys above so a regression that
        # drops a dimension or mis-spells a repo name surfaces obviously.
        repos_emitted = sorted({
            d["Value"]
            for m in call.kwargs["MetricData"]
            for d in m["Dimensions"]
            if d["Name"] == "Repository"
        })
        assert repos_emitted == [
            "layerv/nhp-ac",
            "layerv/nhp-console",
            "layerv/nhp-qurl",
            "layerv/nhp-server",
        ]

        # Unit pinned to "Count" on every entry — load-bearing for
        # alarm/publisher symmetry; without this, CloudWatch evaluates
        # the alarm against whichever sample matches its unit filter.
        assert all(m.get("Unit") == "Count" for m in call.kwargs["MetricData"])

        # Both metric names emitted exactly once per repo — pins that
        # the ImagesCheckedCount sibling stays in volume parity with
        # the primary FailureCount metric.
        metric_names = sorted(m["MetricName"] for m in call.kwargs["MetricData"])
        assert metric_names == sorted(
            ["ECRReplicationFailureCount"] * 4 + ["ECRReplicationImagesCheckedCount"] * 4
        )

    # `some-future-env` rather than a real third NHP environment name —
    # the test only verifies dimension passthrough, and listing
    # `staging` (which doesn't exist in NHP today) would give a future
    # reader the wrong impression that staging is supported.
    @pytest.mark.parametrize("env_value", ["sandbox", "prod", "some-future-env"])
    def test_environment_dimension_flows_through_handler(
        self, lambda_module, monkeypatch, mocked_clients_no_images, env_value
    ):
        """Environment dimension is set from the ENVIRONMENT env var
        and flows unchanged into every emitted MetricData entry. Cheap
        cross-environment fence — without it, a regression that hard-
        codes "sandbox" somewhere in the publish path (or a future
        refactor that drops the dimension) would only surface when the
        Lambda actually deployed to prod and routed alarms to the
        wrong cell.

        Note: this is a *passthrough* fence only. `prod` and `some-
        future-env` parametrize values do NOT imply the Lambda is
        deployed to prod or to any future environment today —
        `is_replication_source` only flips on sandbox under the
        current topology. The test asserts the publish path is
        environment-agnostic so a future deployment doesn't have
        to re-prove this contract."""
        monkeypatch.setenv("ENVIRONMENT", env_value)
        _ecr, cw = mocked_clients_no_images

        result = lambda_module.handler({}, None)
        assert result["environment"] == env_value

        cw.put_metric_data.assert_called_once()
        for m in cw.put_metric_data.call_args.kwargs["MetricData"]:
            env_dim = next(d for d in m["Dimensions"] if d["Name"] == "Environment")
            assert env_dim["Value"] == env_value

    def test_metric_namespace_flows_from_env(self, lambda_module, monkeypatch, mocked_clients_no_images):
        """`METRIC_NAMESPACE` env var must flow into the
        `put_metric_data` call's `Namespace` kwarg unmodified. The
        alarm's `namespace` attribute and the IAM Condition on
        `cloudwatch:PutMetricData` both read from
        `local.ecr_replication_check_metric_namespace` in TF; the
        Lambda reads the same value via this env. A regression that
        hard-codes `"LayerV/NHP"` in the publish call would silently
        break a future namespace rename — IAM denies, errors alarm
        fires, but the failure mode is non-obvious from the publish
        side. Standalone fence on the env→publish flow."""
        monkeypatch.setenv("METRIC_NAMESPACE", "LayerV/Test")
        _ecr, cw = mocked_clients_no_images

        lambda_module.handler({}, None)

        cw.put_metric_data.assert_called_once()
        assert cw.put_metric_data.call_args.kwargs["Namespace"] == "LayerV/Test"

    def test_repository_dimension_carries_layerv_prefix(self, lambda_module, mocked_clients_no_images):
        """The `Repository` dimension value must keep the canonical
        `layerv/...` prefix that `module.ecr.repository_names` emits.
        The runbook spot-check command in the "Stale-failure caveat"
        section relies on this prefix when querying ECR by name; a
        regression that strips it (e.g., a future refactor pulling the
        dimension from a normalised local) would silently break the
        runbook without breaking the alarm. Standalone fence so the
        regression surfaces obviously rather than mixed in with a
        broader emit-shape test."""
        _ecr, cw = mocked_clients_no_images

        lambda_module.handler({}, None)

        repos_emitted = sorted({
            d["Value"]
            for m in cw.put_metric_data.call_args.kwargs["MetricData"]
            for d in m["Dimensions"]
            if d["Name"] == "Repository"
        })
        assert all(r.startswith("layerv/") for r in repos_emitted), (
            f"Repository dimension dropped the `layerv/` prefix: {repos_emitted}"
        )

    def test_skips_failed_count_when_no_recent_images(self, lambda_module, mocked_clients_no_images):
        """A quiet repo (no recent pushes) should emit a `0` datapoint
        without calling describe_image_replication_status. The fresh-
        zero datapoint is load-bearing for `treat_missing_data =
        notBreaching` — without it, a repo that goes silent looks
        identical to a probe-side outage, and the alarm wouldn't
        distinguish "all-clear" from "blind." The companion
        not-invoking alarm catches the all-blind case, but only at the
        Lambda level, not per-repo."""
        ecr, cw = mocked_clients_no_images

        result = lambda_module.handler({}, None)

        for repo in ["layerv/nhp-server", "layerv/nhp-ac", "layerv/nhp-console", "layerv/nhp-qurl"]:
            assert result["results"][repo] == {"checked": 0, "failed": 0}
        ecr.describe_image_replication_status.assert_not_called()

        # Assert the per-repo zero datapoints are actually published, not
        # short-circuited away. A regression that elides PutMetricData
        # on a quiet tick would defeat the metric-stream-alive contract
        # the alarm depends on.
        cw.put_metric_data.assert_called_once()
        emitted = _emitted_metrics(cw.put_metric_data.call_args)
        for repo in ["layerv/nhp-server", "layerv/nhp-ac", "layerv/nhp-console", "layerv/nhp-qurl"]:
            dims = (("Environment", "sandbox"), ("Repository", repo))
            assert emitted[("ECRReplicationFailureCount", dims)] == 0
            # ImagesCheckedCount also published as 0 — load-bearing for
            # the "is the look-back window covering deploys?" signal.
            # If a repo goes dark for sustained ticks, this metric
            # reaching zero is the operational distress flag.
            assert emitted[("ECRReplicationImagesCheckedCount", dims)] == 0

    def test_lookback_hours_env_override(self, lambda_module, monkeypatch):
        """LOOKBACK_HOURS overrides the 25h default — fences the
        documented escape hatch for sub-daily deploy cadences."""
        monkeypatch.setenv("LOOKBACK_HOURS", "1")

        ecr = MagicMock()
        cw = MagicMock()

        # Two images: one 30 minutes old (within 1h window), one 2h old.
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {
                "imageDetails": [
                    _image(digest="sha:fresh", pushed_at=now - datetime.timedelta(minutes=30)),
                    _image(digest="sha:old", pushed_at=now - datetime.timedelta(hours=2)),
                ]
            }
        ]
        ecr.get_paginator.return_value = paginator
        ecr.describe_image_replication_status.return_value = {
            "replicationStatuses": [{"status": "COMPLETE", "region": "us-east-2"}]
        }

        monkeypatch.setattr(lambda_module, "ecr", ecr)
        monkeypatch.setattr(lambda_module, "cloudwatch", cw)

        result = lambda_module.handler({}, None)

        # Only the fresh image is within the 1h window; the 2h-old image
        # is excluded by the override.
        for repo in ["layerv/nhp-server", "layerv/nhp-ac", "layerv/nhp-console", "layerv/nhp-qurl"]:
            assert result["results"][repo]["checked"] == 1

    def test_lookback_hours_unset_falls_back_to_default(
        self, lambda_module, monkeypatch
    ):
        """If LOOKBACK_HOURS is unset, the handler falls back to
        `DEFAULT_LOOKBACK_HOURS` (25) without raising. The path is
        structurally unreachable under TF (the env var is always
        plumbed via `tostring(var.ecr_replication_check_lookback_hours)`),
        but a console edit that deletes the variable on the live
        Lambda env should produce a clean default rather than an
        opaque KeyError. Symmetric with `test_unset_repositories_env_
        raises_runtime_error` and `test_missing_environment_env_raises`
        — those hard-raise; this one falls back, because 25h is a
        sensible default and the structured message would mislead.

        Asserts the actual cutoff via boundary images: one inside
        the 25h window, one outside. A regression that silently set
        `DEFAULT_LOOKBACK_HOURS = 0` would exclude both and fail the
        in-window assertion."""
        monkeypatch.delenv("LOOKBACK_HOURS", raising=False)

        now = datetime.datetime.now(tz=datetime.timezone.utc)
        ecr = MagicMock()
        cw = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {
                "imageDetails": [
                    _image(digest="sha:in", pushed_at=now - datetime.timedelta(hours=24)),
                    _image(digest="sha:out", pushed_at=now - datetime.timedelta(hours=26)),
                ]
            }
        ]
        ecr.get_paginator.return_value = paginator
        ecr.describe_image_replication_status.return_value = {
            "replicationStatuses": [{"status": "COMPLETE", "region": "us-east-2"}]
        }

        monkeypatch.setattr(lambda_module, "ecr", ecr)
        monkeypatch.setattr(lambda_module, "cloudwatch", cw)

        result = lambda_module.handler({}, None)
        assert result["environment"] == "sandbox"
        # Default 25h window: the 24h-old image is in, the 26h-old
        # image is out — exactly one per repo.
        for repo in ["layerv/nhp-server", "layerv/nhp-ac", "layerv/nhp-console", "layerv/nhp-qurl"]:
            assert result["results"][repo]["checked"] == 1, (
                f"DEFAULT_LOOKBACK_HOURS regression: expected 1 image inside the "
                f"25h default window for {repo}, got {result['results'][repo]['checked']}"
            )
        cw.put_metric_data.assert_called_once()

    def test_missing_environment_env_raises(self, lambda_module, monkeypatch):
        """ENVIRONMENT is a required metric dimension; a missing value
        funnels into a structured RuntimeError that names the actual
        cause, matching the REPOSITORIES path's shape rather than
        bare-KeyError. Either way the errors alarm fires; the
        recognisable message saves a log dive."""
        monkeypatch.delenv("ENVIRONMENT", raising=False)

        ecr = MagicMock()
        cw = MagicMock()
        monkeypatch.setattr(lambda_module, "ecr", ecr)
        monkeypatch.setattr(lambda_module, "cloudwatch", cw)

        with pytest.raises(RuntimeError, match="ENVIRONMENT env not set"):
            lambda_module.handler({}, None)
        cw.put_metric_data.assert_not_called()

    def test_empty_metric_namespace_raises_runtime_error(
        self, lambda_module, monkeypatch
    ):
        """METRIC_NAMESPACE explicitly set to empty string (a console-edit
        clear) hard-raises. `os.environ.get(name, DEFAULT)` only returns
        the default for the *missing* key — env-set-to-empty falls through
        and would otherwise produce a publish to namespace="" (rejected
        by the IAM Condition + likely no-op in CloudWatch). The explicit
        guard at the top of `handler()` catches this before any API call;
        a future refactor that drops the guard ('os.environ.get already
        handles this' — which it doesn't) would slip through CI without
        this fence."""
        monkeypatch.setenv("METRIC_NAMESPACE", "")

        ecr = MagicMock()
        cw = MagicMock()
        monkeypatch.setattr(lambda_module, "ecr", ecr)
        monkeypatch.setattr(lambda_module, "cloudwatch", cw)

        with pytest.raises(RuntimeError, match="METRIC_NAMESPACE env was set but empty"):
            lambda_module.handler({}, None)
        cw.put_metric_data.assert_not_called()

    @pytest.mark.parametrize("bad_value", ["24h", ""])
    def test_misparsed_lookback_hours_raises_runtime_error(
        self, lambda_module, monkeypatch, bad_value
    ):
        """LOOKBACK_HOURS unparseable hard-raises rather than soft-
        falling-back to DEFAULT. Two cases parametrized:
        - `"24h"` (or any non-integer string): TF would never set this
          (the variable is `number`-typed) — only path is a console edit.
        - `""` (empty string): same console-edit footgun shape as
          METRIC_NAMESPACE='' (`os.environ.get` returns the default ONLY
          on missing key, not empty value), so the bare `int("")` would
          ValueError. Asymmetric with `os.environ.get(..., DEFAULT)`'s
          missing-key behaviour and the kind of thing a future reader
          trips on. Errors alarm fires either way; structured
          RuntimeError names the cause."""
        monkeypatch.setenv("LOOKBACK_HOURS", bad_value)

        ecr = MagicMock()
        cw = MagicMock()
        monkeypatch.setattr(lambda_module, "ecr", ecr)
        monkeypatch.setattr(lambda_module, "cloudwatch", cw)

        with pytest.raises(RuntimeError, match="not parseable as int"):
            lambda_module.handler({}, None)
        cw.put_metric_data.assert_not_called()

    @pytest.mark.parametrize("bad_value", ["-5", "0", "721", "10000"])
    def test_out_of_range_lookback_hours_raises_runtime_error(
        self, lambda_module, monkeypatch, bad_value
    ):
        """LOOKBACK_HOURS outside [1, 720] (the TF-validated range) must
        hard-raise. Below 1 pushes the cutoff into the future and
        silently publishes 0 forever — recreating the silent-failure
        regime this PR exists to close. Above 720 widens the look-back
        past the untagged-lifecycle expiry (168h) and re-opens the gap
        the lockstep comment fences. Terraform validates the variable,
        but a console edit on the Lambda env can bypass that. Symmetric
        with the misparsed path above and the empty-REPOSITORIES path:
        hard-raise rather than soft-fallback so a config drift surfaces
        clearly."""
        monkeypatch.setenv("LOOKBACK_HOURS", bad_value)

        ecr = MagicMock()
        cw = MagicMock()
        monkeypatch.setattr(lambda_module, "ecr", ecr)
        monkeypatch.setattr(lambda_module, "cloudwatch", cw)

        # Match against the constants rather than a literal regex, so a
        # future range bump in the Lambda module that forgets to update
        # the validation message can't accidentally match a stale test.
        expected_range = re.escape(
            f"[{lambda_module.LOOKBACK_HOURS_MIN}, {lambda_module.LOOKBACK_HOURS_MAX}]"
        )
        with pytest.raises(RuntimeError, match=expected_range):
            lambda_module.handler({}, None)
        cw.put_metric_data.assert_not_called()

    def test_repositories_env_tolerates_whitespace(self, lambda_module, monkeypatch, mocked_clients_no_images):
        """A future operator pasting `\" layerv/nhp-server, layerv/nhp-ac \"`
        from somewhere should not break the probe. The strip is
        defensive against env-injection footguns; locking it in keeps
        a future regression from silently dropping repos."""
        monkeypatch.setenv("REPOSITORIES", " layerv/nhp-server , layerv/nhp-ac ,, ")
        del mocked_clients_no_images  # only here to wire the empty-pagination mocks; not used directly

        result = lambda_module.handler({}, None)

        assert sorted(result["results"].keys()) == ["layerv/nhp-ac", "layerv/nhp-server"]

    def test_repositories_env_dedupes_duplicates(self, lambda_module, monkeypatch, mocked_clients_no_images):
        """A console edit putting `layerv/nhp-server,layerv/nhp-server`
        in the env would otherwise double the per-repo API work AND
        emit duplicate `(MetricName, dimensions)` MetricData entries
        for the same repo. CloudWatch accepts the duplicates but the
        wasted API calls are pure overhead. Dedup at parse time keeps
        the per-tick API budget aligned with the cost numerics in the
        module docstring."""
        monkeypatch.setenv(
            "REPOSITORIES",
            "layerv/nhp-server,layerv/nhp-server,layerv/nhp-ac,layerv/nhp-ac",
        )
        ecr, _cw = mocked_clients_no_images

        result = lambda_module.handler({}, None)

        assert sorted(result["results"].keys()) == ["layerv/nhp-ac", "layerv/nhp-server"]
        # `get_paginator` called once per UNIQUE repo, not per env entry.
        assert ecr.get_paginator.call_count == 2

    def test_all_repos_error_raises_aggregate_with_no_publish(
        self, lambda_module, monkeypatch, caplog
    ):
        """When EVERY repo errors (e.g., account-wide ECR throttle),
        no datapoints land — `metric_data` stays empty so the publish
        is skipped — and the aggregated RuntimeError names every
        failed repo. The errors alarm fires on the raise; no partial
        publish to mislead consumers. Per-repo tracebacks are logged
        at ERROR level so on-call can grep by repo name."""
        ecr = MagicMock()
        cw = MagicMock()

        # Every repo errors on `get_paginator` — simulates account-wide throttle.
        ecr.get_paginator.side_effect = RuntimeError("ECR throttled")

        monkeypatch.setattr(lambda_module, "ecr", ecr)
        monkeypatch.setattr(lambda_module, "cloudwatch", cw)

        with caplog.at_level("ERROR", logger=lambda_module.logger.name):
            with pytest.raises(RuntimeError, match="per-repo errors during tick:"):
                lambda_module.handler({}, None)

        # Every repo should be named in per-repo logs.
        for repo in ["layerv/nhp-server", "layerv/nhp-ac", "layerv/nhp-console", "layerv/nhp-qurl"]:
            assert f"error processing repo={repo}" in caplog.text
        # No publish — `metric_data` stays empty when every repo errors.
        cw.put_metric_data.assert_not_called()

    def test_partial_repo_failure_publishes_survivors_then_raises(
        self, lambda_module, monkeypatch, caplog
    ):
        """Per-repo isolation contract: a transient error on one repo
        must NOT silence the others. The failing repo's logs land at
        ERROR level, the surviving repos publish their datapoints,
        and the post-loop raise still fires the errors alarm — so
        on-call sees the broken probe AND the surviving per-repo
        failure-count alarms keep their fresh signal during the
        errors-alarm window."""
        # Pick the failing repo by NAME, not iteration position. A
        # future change that sorts the repo list (e.g., to make
        # CloudWatch dimension keys deterministic) would silently flip
        # which repo errors if we leaned on "the first one" semantics.
        FAILING_REPO = "layerv/nhp-ac"
        SURVIVING_REPOS = ["layerv/nhp-server", "layerv/nhp-console", "layerv/nhp-qurl"]

        ecr = MagicMock()
        cw = MagicMock()

        class _PaginatorSelector:
            def paginate(self, *, repositoryName, **_):
                if repositoryName == FAILING_REPO:
                    raise RuntimeError(f"ECR throttled on {FAILING_REPO}")
                return [{"imageDetails": []}]

        ecr.get_paginator.return_value = _PaginatorSelector()

        monkeypatch.setattr(lambda_module, "ecr", ecr)
        monkeypatch.setattr(lambda_module, "cloudwatch", cw)

        with caplog.at_level("ERROR", logger=lambda_module.logger.name):
            with pytest.raises(RuntimeError, match=re.escape(FAILING_REPO)):
                lambda_module.handler({}, None)

        # The failing repo is logged with full context.
        assert f"error processing repo={FAILING_REPO}" in caplog.text
        # Surviving repos still published — 3 × 2 metrics each.
        cw.put_metric_data.assert_called_once()
        emitted = _emitted_metrics(cw.put_metric_data.call_args)
        for repo in SURVIVING_REPOS:
            dims = (("Environment", "sandbox"), ("Repository", repo))
            assert emitted[("ECRReplicationFailureCount", dims)] == 0
            assert emitted[("ECRReplicationImagesCheckedCount", dims)] == 0
        # Failing repo MUST NOT have published partial state.
        failing_dims = (("Environment", "sandbox"), ("Repository", FAILING_REPO))
        assert ("ECRReplicationFailureCount", failing_dims) not in emitted
        assert ("ECRReplicationImagesCheckedCount", failing_dims) not in emitted

    def test_repository_not_found_exception_at_handler_aggregates_into_post_loop_raise(
        self, lambda_module, monkeypatch, caplog
    ):
        """Handler-level companion to `_failed_count`'s ClientError-
        propagation tests: a `RepositoryNotFoundException` raised by
        `describe_image_replication_status` on one repo flows through
        the per-repo `except Exception` block, gets aggregated into
        the post-loop `RuntimeError`, and the surviving repos still
        publish. The errors alarm fires on the aggregate raise — same
        contract as the unit-level fence, but exercised through the
        full handler path.

        Most likely real-world cause: a TF-managed repo was renamed
        but the Lambda env hasn't caught up yet (apply lag), or a
        manual console action deleted a repo between two ticks."""
        ecr = MagicMock()
        cw = MagicMock()

        # Pagination yields one image per repo; only the first repo's
        # describe_image_replication_status raises.
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {"imageDetails": [_image(digest="sha:fresh", pushed_at=now)]}
        ]
        ecr.get_paginator.return_value = paginator

        def _describe_status(*, repositoryName, **_):
            if repositoryName == "layerv/nhp-server":
                raise ClientError(
                    {"Error": {"Code": "RepositoryNotFoundException", "Message": "gone"}},
                    "DescribeImageReplicationStatus",
                )
            return {"replicationStatuses": [{"status": "COMPLETE", "region": "us-east-2"}]}

        ecr.describe_image_replication_status.side_effect = _describe_status

        monkeypatch.setattr(lambda_module, "ecr", ecr)
        monkeypatch.setattr(lambda_module, "cloudwatch", cw)

        with caplog.at_level("ERROR", logger=lambda_module.logger.name):
            with pytest.raises(RuntimeError, match="layerv/nhp-server"):
                lambda_module.handler({}, None)

        # Per-repo log line carries the failing repo + ClientError context.
        assert "error processing repo=layerv/nhp-server" in caplog.text
        # Surviving repos published; failing one did not.
        cw.put_metric_data.assert_called_once()
        emitted = _emitted_metrics(cw.put_metric_data.call_args)
        for repo in ["layerv/nhp-ac", "layerv/nhp-console", "layerv/nhp-qurl"]:
            dims = (("Environment", "sandbox"), ("Repository", repo))
            assert emitted[("ECRReplicationFailureCount", dims)] == 0
        failing_dims = (("Environment", "sandbox"), ("Repository", "layerv/nhp-server"))
        assert ("ECRReplicationFailureCount", failing_dims) not in emitted

    def test_put_metric_data_error_propagates(self, lambda_module, mocked_clients_no_images):
        """If CloudWatch PutMetricData itself fails (throttling, IAM
        change, etc.), the Lambda must raise so the errors alarm fires.
        Pins the contract that completes the silent-failure fence —
        emitting nothing is the same regression class as emitting wrong
        values."""
        _ecr, cw = mocked_clients_no_images
        cw.put_metric_data.side_effect = RuntimeError("PutMetricData boom")

        with pytest.raises(RuntimeError, match="PutMetricData boom"):
            lambda_module.handler({}, None)

    def test_empty_repository_list_raises(self, lambda_module, monkeypatch):
        """Empty REPOSITORIES is unreachable in practice (TF gates on
        is_replication_source) so reaching this branch indicates a
        config drift — most likely a console edit between applies. The
        Lambda raises so the errors alarm fires rather than running
        cleanly while emitting no signal, which would re-create the
        silent-failure regime this PR closes."""
        monkeypatch.setenv("REPOSITORIES", "")

        ecr = MagicMock()
        cw = MagicMock()
        monkeypatch.setattr(lambda_module, "ecr", ecr)
        monkeypatch.setattr(lambda_module, "cloudwatch", cw)

        with pytest.raises(RuntimeError, match="empty repo list"):
            lambda_module.handler({}, None)
        cw.put_metric_data.assert_not_called()

    def test_unset_repositories_env_raises_runtime_error(
        self, lambda_module, monkeypatch
    ):
        """Symmetry with test_empty_repository_list_raises: unset and
        empty-string both funnel into the same RuntimeError path with
        the same recognisable message, rather than mixing
        KeyError (unset) with RuntimeError (empty)."""
        monkeypatch.delenv("REPOSITORIES", raising=False)

        ecr = MagicMock()
        cw = MagicMock()
        monkeypatch.setattr(lambda_module, "ecr", ecr)
        monkeypatch.setattr(lambda_module, "cloudwatch", cw)

        with pytest.raises(RuntimeError, match="empty repo list"):
            lambda_module.handler({}, None)
        cw.put_metric_data.assert_not_called()
