# Runbook: eBPF committed-object freshness

## What fired

One of:

- **`eBPF datapath and object freshness proof` failed** on a PR. The required
  load-relevant comparison failed.
- **Pinned apt snapshot/toolchain install failed** in the proof workflow.

PR #2860 introduced this proof so the native AC object at
`endpoints/ac/main/etc/nhp_ebpf_xdp.o` cannot silently lag the eBPF source used
by `make test-ebpf`. The committed object is DWARF-stripped while retaining BTF
sections; runtime loading uses the BTF-bearing object bytes, not DWARF.

## Triage order

1. If the required comparison failed on a PR that did not touch eBPF source,
   the committed native AC object, or the workflow toolchain pins,
   remember that clang builtin headers and transitive system headers are
   byte-sensitive. Check snapshot.ubuntu.com availability and the apt
   snapshot/package pins in `.github/workflows/ebpf-datapath-test.yml` plus
   `scripts/check-ebpf-committed-object-drift.sh`.
2. If those pins match, check whether an unpinned transitive header reached the
   compile through the clang or libbpf packages.
3. If the committed object contains DWARF/debug sections, regenerate it with
   `--update`; do not hand-commit full-DWARF objects.

## Rebaseline

A real clang/llvm/libbpf pin bump requires regenerating and committing the
DWARF-stripped native AC object with the canonical Linux eBPF toolchain:

```bash
CLANG=clang-18 LLVM_STRIP=llvm-strip-18 bash scripts/check-ebpf-committed-object-drift.sh --update
```

`--update` strips DWARF/debug sections before writing
`endpoints/ac/main/etc/nhp_ebpf_xdp.o`, and refuses to overwrite the committed
object when the local clang, llvm-strip, package, or apt snapshot provenance
does not match the pinned CI toolchain. `EBPF_ALLOW_NONCANONICAL_UPDATE=1`
exists only for an intentional emergency rebaseline; include the reason and
resulting object SHA in the PR if you use it.

## Snapshot outage

For a sustained snapshot.ubuntu.com outage, do not silently skip the freshness
check. The maintainer escape hatch is an explicit PR/workflow change that either
moves `EBPF_APT_SNAPSHOT` to a reachable snapshot plus object rebaseline, or
temporarily removes `--snapshot` with the resulting object SHA called out in the
PR and a follow-up issue to restore snapshot-pinned installs.

After a future Ubuntu or apt major-version bump, re-run
`tests/scripts/install-ebpf-toolchain_test.sh` and a clean-container
`scripts/install-ebpf-toolchain.sh` probe before trusting the terminal/retry
classifier; it intentionally matches `LC_ALL=C` apt/dpkg diagnostic text.

## Required-check rollout

Do not flip the branch ruleset or branch-protection requirement until PR #2860
lands on `qurl-v2` and the live proof workflow has passed there. Follow
`docs/runbooks/prod-rollout-ledger/2026-06-28-issue-2861-ebpf-required-check.md`
for the pre-rollout, rollout, post-rollout, and rollback checklist.
