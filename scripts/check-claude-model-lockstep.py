#!/usr/bin/env python3
"""Enforce the action and model pin across every Claude workflow.

Each workflow must contain exactly one Claude action invocation in a workflow
step and one single-line, single-quoted ``claude_args`` value. The model must be
supplied as ``--model`` inside ``claude_args``; the action's native ``model``
input is forbidden. Flow-style ``with`` mappings and alternate scalar forms are
rejected so the exact command remains visible on one reviewable line.

PyYAML's composed node tree supplies the workflow structure while preserving
scalar style. This avoids content or indentation heuristics without constructing
arbitrary tagged values. The workflows deliberately share one model so
interactive commands and automatic reviews use the same proven quality and
credential-compatibility baseline. Equality is intentional even though the
allowlist independently proves credential compatibility: changing quality tiers
between review entry points requires an explicit guard-design decision. A model
bump must update both workflows and ``PROVEN_MODELS`` here. At least two
workflows are intentional; consolidating the entry points also requires updating
this guard. The action SHA is equally load-bearing: the proven version fails
closed when the SDK reports ``subtype: success`` with ``is_error: true``.

The workflow-specific security and lifecycle assertions live beside the fixture
coverage in ``tests/scripts/test_check_claude_model_lockstep.py``; the canonical
``make lint-workflows`` target runs both.
"""

from __future__ import annotations

import argparse
import shlex
import sys
from collections.abc import Iterator
from pathlib import Path

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode


WORKFLOW_DIR = Path(".github/workflows")
ACTION_REPOSITORY = "anthropics/claude-code-action"
PROVEN_ACTION_REF = "c038e4dcdedfbbca18dfb17df35a17e40ded4ddc"
PROVEN_MODELS = frozenset({"claude-opus-4-8"})


class ContractError(ValueError):
    """Raised when a Claude workflow violates the guarded contract."""


def mapping_values(mapping: MappingNode, key: str) -> list[Node]:
    """Return every direct mapping value for a scalar key, preserving duplicates."""
    return [
        value_node
        for key_node, value_node in mapping.value
        if isinstance(key_node, ScalarNode) and key_node.value == key
    ]


def mapping_nodes(
    node: Node, ancestors: frozenset[int] = frozenset()
) -> Iterator[MappingNode]:
    """Yield mapping occurrences without looping through recursive aliases."""
    if id(node) in ancestors:
        return
    descendants = ancestors | {id(node)}
    if isinstance(node, MappingNode):
        yield node
        for key_node, value_node in node.value:
            yield from mapping_nodes(key_node, descendants)
            yield from mapping_nodes(value_node, descendants)
    elif isinstance(node, SequenceNode):
        for child in node.value:
            yield from mapping_nodes(child, descendants)


def is_claude_action(node: Node) -> bool:
    if not isinstance(node, ScalarNode):
        return False
    repository, separator, ref = node.value.partition("@")
    if separator != "@" or repository.casefold() != ACTION_REPOSITORY:
        return False
    return bool(ref) and not any(character.isspace() for character in ref)


def claude_action_invocations(document: Node) -> list[MappingNode]:
    invocations: list[MappingNode] = []
    for mapping in mapping_nodes(document):
        invocations.extend(
            mapping
            for uses_node in mapping_values(mapping, "uses")
            if is_claude_action(uses_node)
        )
    return invocations


def workflow_step_ids(document: Node) -> set[int]:
    """Return identities of mapping nodes that are direct ``jobs.*.steps`` items."""
    if not isinstance(document, MappingNode):
        return set()

    steps: set[int] = set()
    for jobs_node in mapping_values(document, "jobs"):
        if not isinstance(jobs_node, MappingNode):
            continue
        for _, job_node in jobs_node.value:
            if not isinstance(job_node, MappingNode):
                continue
            for steps_node in mapping_values(job_node, "steps"):
                if not isinstance(steps_node, SequenceNode):
                    continue
                steps.update(
                    id(step_node)
                    for step_node in steps_node.value
                    if isinstance(step_node, MappingNode)
                )
    return steps


def claude_args_from_step(path: Path, step: MappingNode) -> str:
    with_nodes = mapping_values(step, "with")
    if len(with_nodes) != 1:
        raise ContractError(
            f"{path}: expected exactly one block-style with mapping on the "
            f"Claude action step, found {len(with_nodes)}"
        )

    with_node = with_nodes[0]
    if isinstance(with_node, ScalarNode) and with_node.tag.endswith(":null"):
        inputs: MappingNode | None = None
    elif not isinstance(with_node, MappingNode) or with_node.flow_style:
        raise ContractError(
            f"{path}: Claude action with must be one block-style mapping"
        )
    else:
        inputs = with_node

    if inputs is not None and mapping_values(inputs, "model"):
        raise ContractError(
            f"{path}: native model input is forbidden; set the model only with "
            "claude_args --model"
        )

    args_nodes = [] if inputs is None else mapping_values(inputs, "claude_args")
    if len(args_nodes) != 1:
        raise ContractError(
            f"{path}: expected exactly one single-quoted claude_args value, "
            f"found {len(args_nodes)}"
        )

    args_node = args_nodes[0]
    if (
        not isinstance(args_node, ScalarNode)
        or args_node.style != "'"
        or args_node.start_mark.line != args_node.end_mark.line
        or "'" in args_node.value
    ):
        raise ContractError(
            f"{path}: expected exactly one single-quoted claude_args value on "
            "one line without embedded single quotes"
        )
    return args_node.value


def claude_action_step(path: Path, document: Node) -> tuple[MappingNode, ScalarNode]:
    """Return the sole Claude action workflow step and its ``uses`` value."""
    actions = claude_action_invocations(document)
    if len(actions) != 1:
        raise ContractError(
            f"{path}: expected exactly one Claude action invocation, "
            f"found {len(actions)}"
        )

    step = actions[0]
    if id(step) not in workflow_step_ids(document):
        raise ContractError(f"{path}: Claude action is not inside a workflow step")

    uses_nodes = [
        node for node in mapping_values(step, "uses") if is_claude_action(node)
    ]
    if len(uses_nodes) != 1:
        raise ContractError(
            f"{path}: expected exactly one Claude action uses value, "
            f"found {len(uses_nodes)}"
        )
    return step, uses_nodes[0]


def model_from_step(path: Path, step: MappingNode) -> str:
    """Return the explicit model from a validated Claude action step."""
    value = claude_args_from_step(path, step)
    try:
        args = shlex.split(value)
    except ValueError as exc:
        raise ContractError(f"{path}: invalid claude_args: {exc}") from exc

    model_args = [
        (index, arg)
        for index, arg in enumerate(args)
        if arg == "--model" or arg.startswith("--model=")
    ]
    if len(model_args) != 1:
        raise ContractError(
            f"{path}: expected exactly one --model argument, found {len(model_args)}"
        )

    model_index, model_arg = model_args[0]
    if model_arg.startswith("--model="):
        model = model_arg.removeprefix("--model=")
        if not model:
            raise ContractError(f"{path}: --model must have a value")
        return model

    if (
        model_index + 1 >= len(args)
        or not args[model_index + 1]
        or args[model_index + 1].startswith("-")
    ):
        raise ContractError(f"{path}: --model must have a value")
    return args[model_index + 1]


def workflow_contract(path: Path, document: Node) -> tuple[str, str]:
    """Return the model and immutable action ref after one structural walk."""
    step, uses_node = claude_action_step(path, document)
    _, _, action_ref = uses_node.value.partition("@")
    return model_from_step(path, step), action_ref


def claude_workflows(repo_root: Path) -> dict[Path, Node]:
    workflows: dict[Path, Node] = {}
    for path in sorted((repo_root / WORKFLOW_DIR).iterdir()):
        if not path.is_file() or path.suffix not in {".yml", ".yaml"}:
            continue
        relative_path = path.relative_to(repo_root)
        contents = path.read_text(encoding="utf-8")
        try:
            document = yaml.compose(contents)
        except yaml.YAMLError as exc:
            raise ContractError(f"{relative_path}: invalid YAML: {exc}") from exc
        if document is not None and claude_action_invocations(document):
            workflows[relative_path] = document

    if len(workflows) < 2:
        raise ContractError(
            f"expected at least two Claude action workflows, found {len(workflows)}"
        )
    return workflows


def check(repo_root: Path) -> str:
    workflows = claude_workflows(repo_root)
    contracts = {
        path: workflow_contract(path, document) for path, document in workflows.items()
    }
    pins = {path: contract[0] for path, contract in contracts.items()}
    models = set(pins.values())
    if len(models) != 1:
        detail = ", ".join(f"{path}={model}" for path, model in pins.items())
        raise ContractError(f"Claude workflow model pins differ: {detail}")
    model = next(iter(models))
    if model not in PROVEN_MODELS:
        allowed = ", ".join(sorted(PROVEN_MODELS))
        raise ContractError(
            f"Claude model {model!r} is not proven for this credential; "
            f"allowed: {allowed}; update PROVEN_MODELS in "
            "scripts/check-claude-model-lockstep.py after validation"
        )

    action_refs = {path: contract[1] for path, contract in contracts.items()}
    unproven_refs = {
        path: action_ref
        for path, action_ref in action_refs.items()
        if action_ref != PROVEN_ACTION_REF
    }
    if unproven_refs:
        detail = ", ".join(
            f"{path}={action_ref}" for path, action_ref in unproven_refs.items()
        )
        raise ContractError(
            f"Claude workflow action refs must use proven SHA "
            f"{PROVEN_ACTION_REF}: {detail}; the pin is a tamper fence, so a "
            "bump must re-prove the guarded action properties and update this "
            "constant plus tests/scripts/test_check_claude_model_lockstep.py "
            'in the same PR — see "Updating the Claude workflow contract" in '
            ".github/workflows/README.md"
        )

    return model


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="repository root containing .github/workflows",
    )
    args = parser.parse_args()

    try:
        model = check(args.repo_root)
    except (ContractError, OSError, UnicodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(
        "OK: Claude workflows pin the proven action and model "
        f"({PROVEN_ACTION_REF}, {model})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
