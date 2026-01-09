# Security Policy

## Reporting Security Issues

The OpenNHP team and community take security bugs in OpenNHP seriously. We appreciate your efforts to responsibly disclose your findings, and will make every effort to acknowledge your contributions.

To report a security issue, please use the GitHub Security Advisory ["Report a Vulnerability"](https://github.com/opennhp/opennhp/security/advisories/new) tab.

The OpenNHP team will send a response indicating the next steps in handling your report. After the initial reply to your report, the security team will keep you informed of the progress towards a fix and full announcement, and may ask for additional information or guidance.

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
