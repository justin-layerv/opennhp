# Security Policy

## Reporting Security Issues

This repository is a fork of [OpenNHP](https://github.com/OpenNHP/opennhp) maintained by layerv.ai. Route disclosures by scope:

### Fork-specific issues

Vulnerabilities in code that is unique to this fork — anything under `endpoints/`, `terraform/`, deploy workflows, plugin code, or console integration — disclose privately via the layerv GHSA tab: <https://github.com/layervai/nhp/security/advisories/new>. The layerv team can ship a patch directly to consumers of this fork.

### Upstream OpenNHP issues

Vulnerabilities in the core NHP protocol or upstream shared code disclose to the upstream OpenNHP maintainers: <https://github.com/OpenNHP/opennhp/security/advisories/new>. When in doubt (e.g., the vuln touches both layerv-specific and upstream code), file both — the layerv team will coordinate.

The respective security team (layerv or OpenNHP, based on routing above) will send a response indicating the next steps in handling your report and keep you informed of progress toward a fix and full announcement.

Report security bugs in third-party modules to the person or team maintaining the module.

## Known CodeQL False Positives

The following CodeQL alerts are **intentional patterns** that have been reviewed and determined to be safe:

### `go/missing-jwt-signature-check` in passcode plugin

**Locations:**
- `endpoints/server/staticplugins/passcode/main.go` (lines ~759 and ~846)

**Why `ParseUnverified` is used:**

1. **Sharing link detection** (line ~759): Parses JWT only to check if a passcode is a sharing link for routing purposes. No authentication decisions are made based on unverified claims. Actual validation occurs in `AuthWithHttpRefresh()`.

2. **Username extraction** (line ~846): Extracts username for informational/logging purposes only. The token is validated against the IAM service separately in `authAccessFromRaaS()`. The extracted name doesn't affect access control.

**Security guarantees:**
- No access is granted based on unverified JWT claims
- All authentication flows verify signatures through proper channels
- Unverified parsing is only used for routing and logging

These patterns are documented in code comments at each location. See PR #54 for the original security review.
