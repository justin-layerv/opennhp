# 2026-08-10 · PR #3806 · Revoke the orphaned attended-UDP-proof App credentials

- **Owner:** prod rollout coordinator
- **Source:** [issue #3227](https://github.com/layervai/nhp/issues/3227) · #3799
  (attended proof removal) · #3804 (state-object cleanup)

The attended UDP proof is gone and so is its AWS footprint: the runner root was
destroyed, its emptied state object deleted in #3804, and no `udp-proof` IAM
role remains. Two GitHub environments and their App credentials outlived it,
with no workflow left that could use them. This is the manifest producer's own
rollback step, which was never taken — the entry is narrowed to it because every
other task it carried died with the proof.

- [x] Rollback — credentials: **DONE 2026-08-10.** Deleted all four App secrets
      and then both environments. The repository now exposes no `udp-proof`
      environment or secret; the remaining environments are
      `hub-publish-production`, `hub-publish-sandbox`, `production`,
      `production-scheduled`, `sandbox` and `staging`.

      | Environment | Secrets removed |
      |---|---|
      | `udp-proof-sandbox` | `UDP_PROOF_JIT_APP_ID`, `UDP_PROOF_JIT_APP_PRIVATE_KEY` |
      | `udp-proof-manifest-sandbox` | `UDP_PROOF_MANIFEST_APP_ID`, `UDP_PROOF_MANIFEST_APP_PRIVATE_KEY` |

      Only `udp-proof-manifest-sandbox` was ever ledgered; the JIT environment
      was not tracked anywhere.
- [ ] Rollback — installations: uninstall both GitHub Apps. Deleting the
      environment secret only stopped this repository from using the key; it did
      **not** revoke the installation or invalidate the private key, so this step
      is the one that actually ends the App's access. Rotate both keys if they
      may have been copied anywhere outside the environment. Org-settings work —
      it cannot be done from the repository.

      The manifest App held read-only Actions, Attestations, Contents, Packages
      and Pull requests on these eleven repositories. The in-repo list died with
      #3799; this is recovered from `REPOSITORIES` in the deleted
      `.github/scripts/udp_proof_deployment_contract.py` (`git show
      be7f2b5bd^:...`). Treat the App's own installation list in org settings as
      authoritative — installations may have drifted since — but start here:

      `layervai/frp` · `layervai/nhp` · `layervai/qurl-connector` ·
      `layervai/qurl-go` · `layervai/qurl-integrations` · `layervai/qurl-mcp` ·
      `layervai/qurl-python` · `layervai/qurl-reverse-tunnel-server` ·
      `layervai/qurl-service` · `layervai/qurl-typescript` · `layervai/website`

The entry's third rollback clause — remove the AWS reader role in a reviewed
standalone-root apply — is already satisfied: the runner root is destroyed and
`iam list-roles` returns no `udp-proof` role.

Delete this entry once both Apps are uninstalled.
