# redirect-url-drift lint fixtures

Regression fixtures for `scripts/check-redirect-url-drift.sh` (#1325).

The lint fences drift between the `redirectURLField` constant in the qurl
plugin handler (`endpoints/server/staticplugins/qurl/main.go`) and the
smoke test that verifies the wire contract
(`tests/smoke/15_resolve_accept_negotiation_test.go`). The two files
live in separate Go modules with no `replace` line, so the duplication
is enforced by this lint rather than the type system.

`run-fixtures.sh` invokes the lint against each fixture pair and
asserts the expected exit code, so a regex tightening that drops a
covered case is caught before it reaches the production paths.

## Fixtures

| Fixture           | Plugin literal       | Smoke literal        | Expected exit | Why                                                                |
| ----------------- | -------------------- | -------------------- | ------------- | ------------------------------------------------------------------ |
| `in-sync`         | `"redirect_url"`     | `"redirect_url"`     | 0             | Happy path — both sides agree.                                     |
| `backtick-raw`    | `` `redirect_url` `` | `` `redirect_url` `` | 0             | Both sides use Go raw-string (backtick) form; lint must accept it. |
| `lockstep-rename` | `"redirectUri"`      | `"redirectUri"`      | 0             | Deliberate rename in lockstep; the constant *name* is the anchor.  |
| `comment-line`    | `"redirect_url"`     | `"redirect_url"`     | 0             | A `//`-prefixed line above the real declaration must not match. Caught by the `^[[:space:]]*` start-of-line anchor (since `//` isn't whitespace, the anchor won't slide past it to find the identifier). |
| `block-comment-go-style` | `"redirect_url"` (real); `"old_name_pre_refactor"` (Go-convention `/* * */` doc block) | same | 0 | Go-convention block-comment continuation lines (` * ...`) must not match. Caught by the `grep -v '^[[:space:]]*\*'` pre-filter — separate defense from the `//` case (the start-of-line anchor would otherwise let the line through, since `*` is preceded by whitespace and the identifier follows). |
| `mixed-quote-in-sync` | `` `redirect_url` `` | `"redirect_url"` | 0 | Quote-style asymmetry (one side raw, the other double-quoted) must not register as drift. The strip logic normalizes either delimiter. |
| `value-drift`     | `"redirect_url"`     | `"redirectUrl"`      | 1             | Real drift: literals differ between sides.                         |
| `name-rename-smoke-only` | `redirectURLField` | `renamedField`  | 1             | One-sided rename on the smoke side. Today the script handles both files symmetrically, so this case is mechanically equivalent to the plugin-side rename below — but if a future refactor splits the regex per-file (e.g., a stricter pattern for the plugin's `const ( ... )` block), the implicit coverage evaporates. Both directions covered explicitly to lock the symmetry in. |
| `name-rename-plugin-only` | `renamedField` | `redirectURLField` | 1          | Sibling to `name-rename-smoke-only` — one-sided rename on the plugin side. |
| `empty-value-both` | `""` | `""` | 1 | Both sides extract to an empty string. The equality check would otherwise silently green; the explicit empty-value guard fails loud since an empty JSON field name would break the wire contract. |
| `typed-declaration` | `redirectURLField string = "redirect_url"` | `redirectURLField = "redirect_url"` | 1 | Locks in current rejection of typed const forms. Today the regex requires whitespace-then-equals after the identifier, so a typed declaration falls into the loud "could not find" error path rather than silently passing. Issue #1473 tracks the optional broadening to accept typed forms; if that lands, this fixture flips to exit 0. |
| `var-declaration` | `var redirectURLField = "redirect_url"` | `const redirectURLField = "redirect_url"` | 1 | Locks in current rejection of `var` forms. The regex matches an optional `const ` prefix or no keyword; `var ` is neither, so the line falls into the loud "could not find" path. Belt-and-suspenders against a future regex relaxation that silently starts accepting `var`. |
| `multiple-declarations` | two `redirectURLField = "..."` lines (different values) | one declaration | 1 | Two declarations on one side (build-tag-gated alternate, half-finished rename) would let `head -n1` silently mask the second. Lint now collects all matches and fails loud on >1, so a divergent value can't slip past. |

## Synthesized fixtures (generated at test time)

Two cases can't live as on-disk files in this directory:

| Synth case          | Setup                                                     | Expected exit | Why on-disk wouldn't work                                                                                                                                         |
| ------------------- | --------------------------------------------------------- | ------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `crlf-line-ending`  | Plugin file written with `\r\n`; smoke file with `\n`.    | 0             | Git's autocrlf handling and most editor normalization would silently re-normalize a checked-in CRLF file. Generated in a tempdir at test time so the bytes survive. |
| `missing-smoke`     | Smoke path points at a non-existent file.                 | 1             | A real "missing file" can't be a tracked artifact. Tested by passing a path that's reliably absent under the runner's tempdir.                                    |
| `missing-plugin`    | Plugin path points at a non-existent file.                | 1             | Symmetric coverage to `missing-smoke`. Today the script handles both files identically, but a future per-side regex split could silently lose one direction's coverage — same rationale as the `name-rename-{plugin,smoke}-only` pair. |
| `one-arg-rejected`  | Pass exactly one positional arg.                          | 2             | The CLI takes either zero (production paths) or two (override paths) — exactly one would silently mix a custom path with the default sibling. Exit 2 is the usage-error code. |

Both run in `run-fixtures.sh` after the on-disk array, sharing the same trapped tempdir.
