#!/usr/bin/env python3
"""Validate `.golangci.yml` against a VENDORED golangci-lint JSON schema.

golangci-lint-action runs `golangci-lint config verify` by default, and
that command fetches its schema over the network every run:

    failing loading
    "https://golangci-lint.run/jsonschema/golangci.v2.11.jsonschema.json":
    context deadline exceeded (Client.Timeout exceeded while awaiting headers)

All four `lint (...)` matrix legs verify the same shared config, so one
timeout against golangci-lint.run reds the whole matrix in seconds — a
third-party host on the critical path of a required-adjacent check.

Dropping the verification instead of replacing it would lose real
coverage: `golangci-lint run` silently ignores unknown top-level AND
unknown nested config keys (only a misspelled *linter name* errors out).
A typo'd key therefore reads as an enabled setting that is doing
nothing. So the action's `verify` is disabled and this offline check
takes its place.

`config verify` cannot be pointed at a local schema — there is no
`--schema` flag, and a `$schema` key in the config is not honoured (it
is rejected as an unknown property). Hence a separate validator rather
than a flag.

A vendored copy is only as good as its coupling to the pinned linter,
so this checks more than the config:

1. The action's `verify:` is still `false`. If it is flipped back on,
   the network fetch — and the flake — return, and this script becomes
   dead weight that still passes.
2. The vendored schema matches the pinned golangci-lint version. The
   upstream URL is major.minor-scoped, so bumping to a new minor must
   land a new vendored file in the same change.
3. The vendored bytes match their sidecar `.sha256`, so a local
   hand-edit cannot masquerade as upstream's schema.
4. The schema is self-contained. jsonschema resolves `$ref`s lazily
   and will fetch an http(s) one, so a remote ref would put the
   network back on the path this replaced — as a flake, not an error.
5. The root config is still the only one — a per-module `.golangci.yml`
   would take precedence for that module and go unvalidated.
6. `.golangci.yml` validates against that schema, under the dialect the
   schema itself declares.

What this deliberately does NOT do is detect an upstream in-place
correction within the same major.minor. That is inherent to vendoring:
the point is a reproducible local artifact, and a floating one would
reintroduce the network dependency this replaced.

Exit codes:
  0 — config valid and the vendored schema is in lockstep with the pin
  1 — drift or an invalid config
  2 — malformed input (missing file, unparseable pin)

Usage:
  scripts/check-golangci-config-schema.py
  scripts/check-golangci-config-schema.py --workflow W --config C --schema-dir D

The override flags exist for the fixture suite
(tests/lints/golangci-config-schema/); the real run takes no arguments.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

try:
    import jsonschema
    import yaml
except ModuleNotFoundError as missing:
    # `make lint-workflows` is documented as mirroring CI, so a bare
    # ImportError traceback here reads as a broken repo rather than a missing
    # local dep. Both deps get the same treatment — guarding one and letting
    # the other traceback is the inconsistency, not the guard.
    print(
        f"check-golangci-config-schema: needs the `{missing.name or 'jsonschema/pyyaml'}` package\n"
        "  python3 -m pip install -r .github/scripts/validate-workflows-requirements.txt",
        file=sys.stderr,
    )
    raise SystemExit(2) from None

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = REPO_ROOT / ".github/workflows/ubuntu-build.yml"
CONFIG = REPO_ROOT / ".golangci.yml"
SCHEMA_DIR = REPO_ROOT / ".github/schemas"

EXIT_OK = 0
EXIT_DRIFT = 1
EXIT_BAD_INPUT = 2

# The action step this fence is coupled to. Steps are matched on this prefix
# after parsing, so `version:` and `verify:` are read off the same step by
# construction; a second such step makes "which pin?" ambiguous and is
# rejected rather than resolved by first-wins.
ACTION_PREFIX = "golangci/golangci-lint-action@"


def _rel(path: Path) -> str:
    """Repo-relative when possible; fixture runs pass paths from elsewhere."""
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def _fail(code: int, message: str) -> int:
    print(f"check-golangci-config-schema: {message}", file=sys.stderr)
    return code


# Parsed structurally rather than by regex. Three review rounds found three
# separate ways a text pattern got this wrong — a later step's `verify:`
# satisfying a step that had none, a blank line inside the mapping truncating
# it, a nested block sequence (`args:\n  - --foo`) truncating it — and each fix
# was a narrower pattern with a new edge behind it. YAML answers all three at
# once, and the file is already parsed for the config, so `yaml` costs nothing
# new here.
def _golangci_with_blocks(workflow_text: str) -> "list[dict]":
    """Every golangci-lint-action step's `with:` mapping, in document order.

    A list, not the first match: a second such step makes "which pin does the
    vendored schema track?" undecidable, and `verify: false` on one says
    nothing about the other. The caller rejects that rather than guessing.
    """
    parsed = yaml.safe_load(workflow_text)
    if not isinstance(parsed, dict):
        return []
    blocks = []
    for job in (parsed.get("jobs") or {}).values():
        for step in ((job or {}).get("steps") or []):
            if not isinstance(step, dict):
                continue
            if str(step.get("uses", "")).startswith(ACTION_PREFIX):
                blocks.append(step.get("with") or {})
    return blocks


def _pinned_version(block: dict) -> "str | None":
    """The step's `version:`, e.g. v2.11.4 — None if absent or malformed.

    Strict: a trailing-dot or otherwise garbage pin is rejected here rather
    than silently yielding a usable major.minor prefix.
    """
    raw = block.get("version")
    if not isinstance(raw, str):
        return None
    return raw if re.fullmatch(r"v\d+\.\d+(?:\.\d+)?", raw.strip()) else None


def _verify_disabled(block: dict) -> bool:
    """True only for a real false. YAML gives a bool; a quoted "false" is a str."""
    value = block.get("verify")
    if isinstance(value, bool):
        return value is False
    return isinstance(value, str) and value.strip().lower() == "false"


def _lint_matrix_modules(workflow_text: str) -> "list[str] | None":
    """The lint job's `matrix.module` list, e.g. [nhp, internalauth, …].

    None when the matrix cannot be read. The caller treats that as bad input
    rather than "no modules": returning an empty list would make the stray
    check silently examine nothing, so rewriting the matrix as a YAML block
    list would delete the guarantee without turning anything red — failing
    open, which is the one outcome a fence must never do.
    """
    match = re.search(r"^[ \t]+module:[ \t]*\[([^\]]+)\]", workflow_text, re.M)
    if not match:
        return None
    return [m.strip().strip("'\"") for m in match.group(1).split(",") if m.strip()]


def _stray_module_configs(workflow_text: str, root: Path) -> "list[str]":
    """Per-module configs that would take precedence over the root one.

    golangci-lint runs with `working-directory: <module>` and searches upward,
    so a config in a module root wins for that module and would go unvalidated.
    Scoped to the matrix modules rather than an `rglob` of the whole tree: a
    vendored dependency shipping its own `.golangci.yml` governs nothing here,
    and failing on it would couple this fence to unrelated additions.
    """
    strays = []
    for module in _lint_matrix_modules(workflow_text) or []:
        for name in (".golangci.yml", ".golangci.yaml"):
            candidate = root / module / name
            if candidate.is_file():
                strays.append(f"{module}/{name}")
    return sorted(strays)


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--workflow", type=Path, default=WORKFLOW)
    parser.add_argument("--config", type=Path, default=CONFIG)
    parser.add_argument("--schema-dir", type=Path, default=SCHEMA_DIR)
    args = parser.parse_args(argv)
    workflow, config_path, schema_dir = args.workflow, args.config, args.schema_dir

    # `.golangci.yaml` is an equally valid spelling and _stray_module_configs
    # already accepts both; fall back so the primary config is consistent.
    if not config_path.is_file() and config_path == CONFIG:
        alternate = CONFIG.with_suffix(".yaml")
        if alternate.is_file():
            config_path = alternate

    for path in (workflow, config_path):
        if not path.is_file():
            return _fail(EXIT_BAD_INPUT, f"missing {_rel(path)}")

    workflow_text = workflow.read_text()

    # "No such step" is bad input, not drift: reporting it as a `verify:`
    # problem would point the reader at a line that may be perfectly fine.
    blocks = _golangci_with_blocks(workflow_text)
    if not blocks:
        return _fail(
            EXIT_BAD_INPUT,
            f"no {ACTION_PREFIX}… step found in {_rel(workflow)}. This fence "
            "reads the version pin and `verify:` off that step, so it cannot "
            "check anything without it — if the lint job moved, point "
            "--workflow at its new home.",
        )
    if len(blocks) > 1:
        return _fail(
            EXIT_BAD_INPUT,
            f"{_rel(workflow)} has {len(blocks)} {ACTION_PREFIX}… steps. Which "
            "one's `version:` the vendored schema must match is then ambiguous, "
            "and `verify: false` on one says nothing about the others — decide "
            "explicitly rather than letting the first win.",
        )
    block = blocks[0]

    if not _verify_disabled(block):
        return _fail(
            EXIT_DRIFT,
            "golangci-lint-action must set `verify: false` — its built-in "
            "`config verify` fetches the schema over the network on every "
            "run and flakes all four lint legs at once. This script is the "
            "offline replacement; re-enabling `verify` restores the flake "
            "and makes this check redundant.",
        )

    # An unreadable matrix is bad input, not "no modules to check" — see
    # _lint_matrix_modules. Checked before use so a shape change is red rather
    # than a silently-empty scan.
    if _lint_matrix_modules(workflow_text) is None:
        return _fail(
            EXIT_BAD_INPUT,
            "could not read the lint job's `matrix.module` inline list from "
            f"{_rel(workflow)}; the stray per-module-config check needs it. "
            "If the matrix moved to a YAML block list, teach "
            "_lint_matrix_modules that shape — an empty module list would "
            "make this check silently pass.",
        )

    # Scoped to the config's own tree so fixtures can drive it, which the
    # earlier repo-wide rglob version could not.
    strays = _stray_module_configs(workflow_text, config_path.parent)
    if strays:
        return _fail(
            EXIT_DRIFT,
            f"only {_rel(config_path)} is validated, but these lint modules "
            f"carry their own config: {strays}. golangci-lint prefers the "
            "nearer config for that module, so it would go unvalidated — "
            "extend this check to cover each one.",
        )

    pinned = _pinned_version(block)
    if pinned is None:
        return _fail(
            EXIT_BAD_INPUT,
            "could not read the golangci-lint-action `version:` pin from "
            f"{_rel(workflow)}",
        )

    # Upstream publishes one schema per major.minor: v2.11.4 -> v2.11.
    # _pinned_version already rejected anything without at least MAJOR.MINOR,
    # so this split is total.
    major, minor = pinned.lstrip("v").split(".")[:2]
    series = f"v{major}.{minor}"
    schema_path = schema_dir / f"golangci.{series}.jsonschema.json"

    if not schema_path.is_file():
        vendored = sorted(p.name for p in schema_dir.glob("golangci.*.jsonschema.json"))
        return _fail(
            EXIT_DRIFT,
            f"golangci-lint is pinned to {pinned} but "
            f"{_rel(schema_path)} is not vendored "
            f"(found: {vendored or 'nothing'}). Refresh it in the same "
            f"change as the version bump:\n"
            f"  curl -sSfo {_rel(schema_path)} \\\n"
            f"    https://golangci-lint.run/jsonschema/golangci.{series}.jsonschema.json",
        )

    # A vendored artifact is upstream's bytes, not ours. The sidecar digest
    # records what was fetched and reviewed (same idea as the .sri beside
    # nhp-agent.min.js), so a local hand-edit to make a config "pass" cannot
    # masquerade as upstream's schema.
    digest_path = schema_path.with_suffix(schema_path.suffix + ".sha256")
    if not digest_path.is_file():
        return _fail(EXIT_DRIFT, f"{_rel(schema_path)} has no {digest_path.name} beside it")
    actual = hashlib.sha256(schema_path.read_bytes()).hexdigest()
    recorded = digest_path.read_text().split()
    if not recorded:
        return _fail(EXIT_BAD_INPUT, f"{_rel(digest_path)} is empty; expected a sha256 hex digest")
    expected = recorded[0].strip()
    if actual != expected:
        return _fail(
            EXIT_DRIFT,
            f"{_rel(schema_path)} does not match {digest_path.name}\n"
            f"  recorded: {expected}\n"
            f"  actual:   {actual}\n"
            "Vendored schemas are upstream bytes — do not hand-edit. Re-fetch "
            "and update the digest:\n"
            f"  shasum -a 256 {_rel(schema_path)} | awk '{{print $1}}' > {_rel(digest_path)}",
        )

    schema_text = schema_path.read_text()
    try:
        schema = json.loads(schema_text)
    except json.JSONDecodeError as e:
        return _fail(EXIT_BAD_INPUT, f"{_rel(schema_path)} is not valid JSON: {e}")

    # Offline-ness rests on the schema being self-contained. jsonschema
    # resolves $refs lazily and WILL fetch an http(s) one, so a future refresh
    # that introduces an external ref would quietly put a network fetch back on
    # the path this whole change exists to remove — and it would look like a
    # flake, not a regression. Today's copy is 107 refs, all `#/definitions/`.
    #
    # Anything not starting with `#` is external: that covers http(s) and
    # protocol-relative URLs AND a sibling-file ref like "other.json#/x", which
    # jsonschema would also resolve off the local filesystem or the network.
    external_refs = sorted(
        set(
            ref
            for ref in re.findall(r'"\$ref"\s*:\s*"([^"]*)"', schema_text)
            if not ref.startswith("#")
        )
    )
    if external_refs:
        return _fail(
            EXIT_DRIFT,
            f"{_rel(schema_path)} contains external $ref(s): {external_refs}. "
            "Validation would resolve them at check time, reintroducing the "
            "dependency this vendoring removed. Inline them, or pin a "
            "self-contained upstream revision.",
        )

    try:
        config = yaml.safe_load(config_path.read_text())
    except yaml.YAMLError as e:
        return _fail(EXIT_BAD_INPUT, f"{_rel(config_path)} is not valid YAML: {e}")

    # Pick the dialect from the schema's own `$schema` rather than hardcoding
    # Draft7: today's vendored copy is draft-07, but a future golangci minor
    # could publish a different dialect, and validating it under the wrong one
    # silently changes what passes.
    validator_cls = jsonschema.validators.validator_for(schema)
    try:
        validator_cls.check_schema(schema)
    except jsonschema.SchemaError as e:
        # Symmetry with the JSONDecodeError branch above: a refresh that lands
        # parseable JSON which is not a valid schema is bad input, not drift.
        return _fail(EXIT_BAD_INPUT, f"{_rel(schema_path)} is not a valid JSON Schema: {e.message}")
    validator = validator_cls(schema)
    errors = sorted(validator.iter_errors(config), key=lambda e: list(e.absolute_path))
    if errors:
        print(
            f"check-golangci-config-schema: {_rel(config_path)} does "
            f"not validate against {_rel(schema_path)} "
            f"(golangci-lint {pinned}):",
            file=sys.stderr,
        )
        for error in errors:
            location = ".".join(str(p) for p in error.absolute_path) or "(root)"
            print(f"  {location}: {error.message}", file=sys.stderr)
        return EXIT_DRIFT

    print(
        f"OK: {_rel(config_path)} validates against {schema_path.name} "
        f"(golangci-lint {pinned}, offline)"
    )
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
