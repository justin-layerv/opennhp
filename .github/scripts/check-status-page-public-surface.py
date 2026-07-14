#!/usr/bin/env python3
"""Check status-page public-surface invariants."""

import base64
import hashlib
import re
import sys
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
INDEX_HTML = REPO / "terraform/modules/status-page/frontend/index.html"
MAIN_TF = REPO / "terraform/modules/status-page/main.tf"
TEMPLATE_INTERPOLATION_TOKENS = ("${", "%{")


def fail(message):
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def _single_inline_block(html, tag):
    matches = re.findall(rf"<{tag}(\s[^>]*)?>(.*?)</{tag}>", html, flags=re.S)
    inline_blocks = [
        block
        for attrs, block in matches
        if not re.search(r"\bsrc\s*=", attrs or "")
    ]
    if len(matches) != 1 or len(inline_blocks) != 1:
        fail(
            f"expected exactly one <{tag}> tag total, and it must be the hashed "
            f"inline block in {INDEX_HTML} for CSP pinning; found {len(matches)} "
            f"total <{tag}> tags and {len(inline_blocks)} inline blocks. "
            f"External or additional inline <{tag}> tags require extending the "
            "checker and Terraform CSP hashes together."
        )
    block = inline_blocks[0]
    for token in TEMPLATE_INTERPOLATION_TOKENS:
        if token in block:
            fail(
                f"inline <{tag}> in {INDEX_HTML} contains Terraform template "
                f"interpolation token {token!r}; keep template variables outside "
                "hashed blocks so raw-file CSP hashes match rendered output"
            )
    return block


def _hash_source(value):
    digest = base64.b64encode(hashlib.sha256(value.encode()).digest()).decode()
    return f"'sha256-{digest}'"


def _csp_directive(policy, name):
    directive_match = re.search(rf"(?:^|;)\s*{re.escape(name)}\s+([^;]+)", policy)
    if not directive_match:
        fail(f"status page CSP is missing {name}")
    directive = directive_match.group(1).split()
    if "'unsafe-inline'" in directive:
        fail(f"status page {name} must not allow unsafe-inline")
    return directive


def _inline_hashes(html):
    return {
        "script-src": _hash_source(_single_inline_block(html, "script")),
        "style-src": _hash_source(_single_inline_block(html, "style")),
    }


def print_hashes(html):
    for directive, value in _inline_hashes(html).items():
        print(f"{directive} {value}")


def check_csp_hashes(main_tf, html):
    if re.search(r"\sstyle\s*=", html):
        fail("status page inline style attributes are blocked by style-src")
    block = _terraform_resource_block(
        main_tf,
        "aws_cloudfront_response_headers_policy",
        "status",
    )
    policy_match = re.search(r'content_security_policy\s*=\s*"([^"]+)"', block)
    if not policy_match:
        fail("status page content_security_policy not found")
    policy = policy_match.group(1)
    hashes = _inline_hashes(html)

    script_hash = hashes["script-src"]
    if script_hash not in _csp_directive(policy, "script-src"):
        fail(
            "status page script-src hash is stale: "
            f"expected {script_hash} from frontend/index.html"
        )

    style_hash = hashes["style-src"]
    if style_hash not in _csp_directive(policy, "style-src"):
        fail(
            "status page style-src hash is stale: "
            f"expected {style_hash} from frontend/index.html"
        )


def check_no_html_sinks(html):
    """Ensure operator-controlled status text only reaches text nodes."""
    # Plain substring matching is intentional: comments or examples mentioning
    # these sinks should fail closed instead of normalizing unsafe vocabulary.
    forbidden = ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write")
    found = [name for name in forbidden if name in html]
    if found:
        fail(f"status page frontend must not use HTML sinks: {', '.join(found)}")


def _terraform_resource_block(main_tf, resource_type, name):
    """Return one Terraform resource body for narrow status-page CI checks.

    This is not a general HCL parser. It tracks quoted strings, comments, and
    braces for the known status-page resources, and fails closed on heredocs.
    """
    marker = f'resource "{resource_type}" "{name}"'
    start = main_tf.find(marker)
    if start == -1:
        fail(f"Terraform resource {resource_type}.{name} not found")
    open_brace = main_tf.find("{", start)
    if open_brace == -1:
        fail(f"Terraform resource {resource_type}.{name} has no body")

    depth = 0
    in_string = False
    in_line_comment = False
    in_block_comment = False
    escaped = False
    for idx in range(open_brace, len(main_tf)):
        ch = main_tf[idx]
        next_ch = main_tf[idx + 1] if idx + 1 < len(main_tf) else ""
        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
            continue
        if in_block_comment:
            if ch == "*" and next_ch == "/":
                in_block_comment = False
            continue
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "#":
            in_line_comment = True
        elif ch == "/" and next_ch == "/":
            in_line_comment = True
        elif ch == "/" and next_ch == "*":
            in_block_comment = True
        elif ch == "<" and next_ch == "<":
            fail(
                f"Terraform resource {resource_type}.{name} contains heredoc "
                "syntax; status-page public-surface scanner assumes heredoc-free "
                "guarded resource blocks"
            )
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return main_tf[start:idx + 1]
    fail(f"Terraform resource {resource_type}.{name} body was not closed")


def check_cloudfront_oac_scope(main_tf):
    block = _terraform_resource_block(main_tf, "aws_s3_bucket_policy", "status")
    forbidden = [
        '"${aws_s3_bucket.status.arn}/*"',
        "/incidents.json",
        "/history.json",
    ]
    for value in forbidden:
        if value in block:
            fail(f"status CloudFront OAC bucket policy exposes {value}")

    required = [
        "/index.html",
        "/status.json",
        "/favicon.svg",
        "/wordmark.svg",
        "/fonts/*",
    ]
    missing = [value for value in required if value not in block]
    if missing:
        fail(f"status CloudFront OAC bucket policy is missing {', '.join(missing)}")


def main():
    main_tf = MAIN_TF.read_text()
    html = INDEX_HTML.read_text()
    if len(sys.argv) > 1:
        if sys.argv[1:] == ["--print-hashes"]:
            print_hashes(html)
            return
        fail(f"unknown arguments: {' '.join(sys.argv[1:])}")

    check_csp_hashes(main_tf, html)
    check_no_html_sinks(html)
    check_cloudfront_oac_scope(main_tf)
    print("status page public-surface check passed")


if __name__ == "__main__":
    main()
