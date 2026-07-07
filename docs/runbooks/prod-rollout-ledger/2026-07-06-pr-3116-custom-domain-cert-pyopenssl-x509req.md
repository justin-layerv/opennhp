# 2026-07-06 · PR #3116 · Custom-domain cert issuance unbroken (pyOpenSSL X509Req)

- **Owner:** prod rollout coordinator
- **Source:** https://github.com/layervai/nhp/pull/3116

Bumps `acme`/`josepy` in the `custom-domain-cert` and `acme-cert` Lambda
requirements so cert provision/renewal stops crashing on the removed
`OpenSSL.crypto.X509Req`. Deploy redeploys both Lambdas (new source hash).
Domains already flipped to `failed` recover only on a subsequent renewal scan.

- [ ] Post-rollout: confirm `custom-domain-cert-manager` and `acme-cert-manager`
      Lambda logs no longer emit `module 'OpenSSL.crypto' has no attribute
      'X509Req'` on their next scheduled run (both envs).
- [ ] Post-rollout: confirm custom domains previously in `failed` recover to
      `active` after a renewal scan (sandbox: the customer domain from the
      #3116 investigation). To recover immediately instead of waiting for the
      schedule, invoke the cert-manager Lambda once after deploy.
- [ ] Rollback: reverting the `acme`/`josepy` bump re-breaks cert issuance —
      roll forward, do not revert. cryptography/pyOpenSSL pins are unchanged.
