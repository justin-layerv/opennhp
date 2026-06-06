# Runbook: Renew a LayerV-owned domain

Until this runbook landed, domain renewal was tribal knowledge — which is how
`layerv.xyz` and `layerv.org` came within weeks of expiry under nhp#1147. The
[Domain Expiry Watchdog](../../.github/workflows/domain-expiry-watchdog.yml) now
catches that failure mode automatically; this runbook is the human side of it:
what to do when the watchdog fires, and how renewal actually works.

## When this runs

- **Watchdog fired.** The weekly [Domain Expiry Watchdog](../../.github/workflows/domain-expiry-watchdog.yml)
  (Mondays 12:00 UTC) opened or updated a tracking issue because a domain is
  `critical` (expiry < 60 days) or `warn` (expiry < 90 days **and** flagged
  `clientRenewProhibited`). Start at [Renew](#renew).
- **Manual audit.** You want to confirm the fleet is healthy. Start at
  [Check current status](#check-current-status).

## Domain inventory

LayerV-owned domains are split across three registrars. There is no single
console; you need the right account for the right domain.

| Domain | Registrar | Renewal console |
|---|---|---|
| `layerv.ai` | Porkbun | <https://porkbun.com/account/domainsSpeedy> |
| `layerv.xyz` | GoDaddy | <https://dcc.godaddy.com/control/portfolio> |
| `layerv.org` | GoDaddy | <https://dcc.godaddy.com/control/portfolio> |
| `qurl.link` | Namecheap | <https://ap.www.namecheap.com/domains/list/> |
| `qurl.site` | Namecheap | <https://ap.www.namecheap.com/domains/list/> |

> Keep this table in lockstep with the `DOMAINS` array in
> [`domain-expiry-watchdog.yml`](../../.github/workflows/domain-expiry-watchdog.yml).
> If you add or retire a domain, update both in the same PR — otherwise the
> watchdog silently stops covering it.

The two GoDaddy domains (`layerv.xyz`, `layerv.org`) share a wall-clock expiry
date and the same registrar; **renew them in one sitting** so the follow-up
doesn't land on the same day two weeks later.

## Check current status

WHOIS is the source of truth — it reflects the registry, not a cached console
view. `Registry Expiry Date` is authoritative for modern gTLDs and `.ai`;
`autoRenewPeriod` in the status block means the registry has already
auto-renewed and a new expiry one year out is in effect.

```bash
# Per-domain expiry, registrar, and protective status flags.
for d in layerv.ai layerv.xyz layerv.org qurl.link qurl.site; do
  echo "=== $d ==="
  whois "$d" | grep -iE "registry expiry date|registrar:|domain status" | sort -u
done
```

`whois` is not preinstalled on macOS-from-Homebrew-only setups or on the
GitHub `ubuntu-24.04` runner image; install with `brew install whois` or
`sudo apt-get install -y whois`.

## Renew

Renewal is a registrar-console action — there is no CLI in this repo and no AWS
credential covers it. You need the login for the registrar holding the domain
(see the [inventory table](#domain-inventory)).

1. **Confirm ownership.** Log into the registrar account. If the domain isn't
   listed, it's under a different account — GoDaddy in particular has surfaced
   LayerV domains across more than one login. Check a second account before
   assuming the worst.
2. **Renew.** Renew for **multiple years** (5+ is the standing preference) to
   push the domain off the frequent-worry list. Cost is a spend decision; if
   you only have authority for a 1-year renewal, do that now to clear the
   acute risk and file a follow-up for the longer term.
3. **Verify.** Re-run the [WHOIS check](#check-current-status). The new
   `Registry Expiry Date` should be the years you renewed into the future.
   It can take minutes for the registry to reflect the change.
4. **Close the loop.** Comment the new expiry on the watchdog's tracking issue
   and close it. The next Monday sweep will confirm the domain is back to `ok`.

## Registrar protective flags

WHOIS status flags are easy to misread; they are **separate** from whether the
domain will renew:

| Flag | What it does | Want it? |
|---|---|---|
| `clientRenewProhibited` | Blocks the *EPP renew command*. GoDaddy sets this by default; it does **not** stop GoDaddy's billing auto-renew. | Harmless — see note below |
| `clientTransferProhibited` | Blocks transfer to another registrar (anti-hijack). | **Yes** |
| `clientUpdateProhibited` | Blocks changes to the domain record (anti-tamper). | **Yes** |
| `clientDeleteProhibited` | Blocks deletion (anti-accident / anti-malice). | **Yes** |

> **`clientRenewProhibited` is not the bug it looks like.** During nhp#1147 both
> GoDaddy domains auto-renewed *despite* this flag (`autoRenewPeriod` appeared
> and expiry advanced a year). The flag gates the manual EPP renew path, not
> GoDaddy's billing auto-renew. Clearing it is optional hygiene that makes the
> manual renew path available; it is **not** required to keep the domain alive,
> and it did not cause the near-miss. The near-miss was nobody watching the
> clock — which the watchdog now fixes.

As of this writing all three GoDaddy/`.xyz`/`.org` records carry
`clientTransferProhibited`, `clientUpdateProhibited`, and
`clientDeleteProhibited` — the protective set is in place.

## Automated detection

The [Domain Expiry Watchdog](../../.github/workflows/domain-expiry-watchdog.yml)
sweeps every domain in the [inventory](#domain-inventory) weekly and opens a
title-dedup'd tracking issue when any domain crosses a threshold, re-editing
that issue's status table on each subsequent fire. You should not have to
discover an expiry by hand again — but run the [WHOIS check](#check-current-status)
directly if you ever doubt the watchdog (e.g., after a runner-image bump that
could drop `whois`, as happened once already).

## Pending manual items (nhp#1147)

These are GoDaddy-console actions that cannot be done from this repo and remain
open on nhp#1147. None are urgent — both domains are renewed through 2027-05-15
— but they close out the issue:

- [ ] Renew `layerv.xyz` and `layerv.org` for 5+ years (currently 1-year,
      expiring 2027-05-15).
- [ ] *(Optional hygiene)* Clear `clientRenewProhibited` on both so the manual
      EPP renew path is available. Not required for auto-renewal — see
      [Registrar protective flags](#registrar-protective-flags).
- [ ] Consolidate registrars / accounts where practical so renewals don't span
      three consoles.
