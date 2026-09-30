# Security policy

## Report a vulnerability

Report privately through GitHub: https://github.com/viridis-security/maxwells-defense/security/advisories/new

Please don't open a public issue for a suspected vulnerability, leaked credential, signature or
verification bypass, or exposure of personal data. We acknowledge reports within 5 business days and
agree a fix and disclosure date with you.

## Scope

In scope: the code in this repository and packages published from it. Viridis-hosted services built on
it are in scope too; report them the same way and name the service. Out of scope: volume
denial-of-service testing, social engineering, and already-public issues in third-party dependencies
(report those upstream).

## Good-faith research

We won't pursue action against research that follows this policy, stays within your own accounts and
data, avoids privacy harm and service disruption, and gives us reasonable time to fix before disclosure.

## Trust boundary

- This repository never contains production credentials, private signing keys or customer data.
- Self-hosted deployments sign with their own keys and are self-rooted. Only Viridis's production trust
  root issues Viridis-signed receipts and certificates.
- If a credential is ever committed, treat it as compromised: revoke it, rotate it, and reissue anything
  it signed.
