# Sample audit: rotaskitchen.com (excerpt)

Real, passive run on 2026-10-02 against a domain owned by the author.
Command used:

```
python rssi.py rotaskitchen.com --no-history -o examples --json examples/rotaskitchen.com.json
```

Full outputs in this folder:

- [`rapport_rotaskitchen.com.html`](rapport_rotaskitchen.com.html): the self-contained HTML report (French, written for a non-technical business owner)
- [`rotaskitchen.com.json`](rotaskitchen.com.json): score and the 23 raw findings
- [`console-output.txt`](console-output.txt): console summary

## Result

**Score: 37 / 100, grade E.** 23 findings: 1 high, 4 medium, 6 low, 7 good points, 5 informational.

| Category | Finding | Severity / status |
|---|---|---|
| Email | DMARC present but in monitoring mode only (`v=DMARC1; p=none`) | eleve / warn |
| Email | SPF uses softfail (`v=spf1 include:_spf.mail.hostinger.com ~all`) | moyen / warn |
| Email | DKIM not found on the 5 common selectors (inconclusive, not penalized) | info |
| Headers | `Strict-Transport-Security` missing | moyen / fail |
| Headers | `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy` missing | faible / fail (x3) |
| Headers | `Content-Security-Policy` and `Permissions-Policy` present; HTTP to HTTPS redirect active | ok / pass |
| CVE | Versions exposed: `X-Powered-By: PHP/8.3.33`, generator tags for WordPress 6.8.10 and Elementor 4.1.4 | moyen / warn |
| CVE | Elementor 4.1.4: 1 CVE via keyword search (CVE-2026-8825, CVSS 4.9), flagged "approximate, to verify" | moyen / warn |
| CVE | PHP 8.3.33 and WordPress 6.8.10: no CVE returned by the CPE (version-exact) query | faible / warn |
| SSL | Let's Encrypt certificate, valid for 66 more days, name matches, TLS 1.3 negotiated | ok / pass |
| Breach | Domain not listed in any of the 1,039 public HIBP breaches | ok / pass |

## How to read this result

- The low grade comes from many small, cheap-to-fix items stacking up, not from a
  critical vulnerability. Adding HSTS and the three missing headers (about 27 points),
  enforcing DMARC (`p=quarantine`, then `p=reject`, 12 points) and hiding `X-Powered-By`
  and the generator tags (18 points) would take the score from 37 (E) to about 94 (A).
- The current scoring counts version exposure several times: once in Headers and
  once per detected product in CVE. See *Limitations* in the main README.
- The Elementor CVE comes from a keyword match. It has not been confirmed against the
  installed version, so the tool caps its severity at `moyen` and labels it.
- Before the certifi fix described in the README, the first run on this domain
  reported a false "broken certificate chain" (an expired root in the local Windows
  trust store). `openssl s_client` and curl both returned `Verify return code: 0 (ok)`.
  The SSL check now validates against the Mozilla root store (certifi) so results
  are the same on every machine.
