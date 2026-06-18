\# Lab 4 — Submission



\## Task 1: Syft SBOM Generation



\### SBOM stats

\- `juice-shop.cdx.json` component count: \*\*1846\*\*

\- `juice-shop.cdx.json` size: 1.5 MB (1,504,963 bytes)

\- `juice-shop.spdx.json` component count: \*\*911\*\*



\### Note on Grype

Grype was unable to download its vulnerability database due to network connectivity issues (timeout connecting to anchore.io servers). Therefore, vulnerability scanning was performed using Trivy as the primary SCA tool, which uses a different database infrastructure and worked successfully in this environment.



\---



\## Task 2: Trivy Vulnerability Scan



\### Trivy severity breakdown

```json

\[

&#x20; {

&#x20;   "severity": "CRITICAL",

&#x20;   "count": 5

&#x20; },

&#x20; {

&#x20;   "severity": "HIGH",

&#x20;   "count": 43

&#x20; },

&#x20; {

&#x20;   "severity": "LOW",

&#x20;   "count": 22

&#x20; },

&#x20; {

&#x20;   "severity": "MEDIUM",

&#x20;   "count": 39

&#x20; }

]

```



| Severity | Count |

|----------|------:|

| CRITICAL | 5 |

| HIGH | 43 |

| MEDIUM | 39 |

| LOW | 22 |

| \*\*Total\*\* | \*\*109\*\* |



\### Top 10 CVEs

```json

\[

&#x20; {

&#x20;   "cve": "CVE-2023-46233",

&#x20;   "severity": "CRITICAL",

&#x20;   "package": "crypto-js",

&#x20;   "version": "3.3.0",

&#x20;   "fix": "4.2.0"

&#x20; },

&#x20; {

&#x20;   "cve": "CVE-2015-9235",

&#x20;   "severity": "CRITICAL",

&#x20;   "package": "jsonwebtoken",

&#x20;   "version": "0.1.0",

&#x20;   "fix": "4.2.2"

&#x20; },

&#x20; {

&#x20;   "cve": "CVE-2015-9235",

&#x20;   "severity": "CRITICAL",

&#x20;   "package": "jsonwebtoken",

&#x20;   "version": "0.4.0",

&#x20;   "fix": "4.2.2"

&#x20; },

&#x20; {

&#x20;   "cve": "CVE-2019-10744",

&#x20;   "severity": "CRITICAL",

&#x20;   "package": "lodash",

&#x20;   "version": "2.4.2",

&#x20;   "fix": "4.17.12"

&#x20; },

&#x20; {

&#x20;   "cve": "GHSA-5mrr-rgp6-x4gr",

&#x20;   "severity": "CRITICAL",

&#x20;   "package": "marsdb",

&#x20;   "version": "0.6.11",

&#x20;   "fix": "none"

&#x20; },

&#x20; {

&#x20;   "cve": "CVE-2026-45447",

&#x20;   "severity": "HIGH",

&#x20;   "package": "libssl3t64",

&#x20;   "version": "3.5.5-1\~deb13u2",

&#x20;   "fix": "3.5.6-1\~deb13u2"

&#x20; },

&#x20; {

&#x20;   "cve": "NSWG-ECO-428",

&#x20;   "severity": "HIGH",

&#x20;   "package": "base64url",

&#x20;   "version": "0.0.6",

&#x20;   "fix": ">=3.0.0"

&#x20; },

&#x20; {

&#x20;   "cve": "CVE-2020-15084",

&#x20;   "severity": "HIGH",

&#x20;   "package": "express-jwt",

&#x20;   "version": "0.1.3",

&#x20;   "fix": "6.0.0"

&#x20; },

&#x20; {

&#x20;   "cve": "CVE-2022-25881",

&#x20;   "severity": "HIGH",

&#x20;   "package": "http-cache-semantics",

&#x20;   "version": "3.8.1",

&#x20;   "fix": "4.1.1"

&#x20; },

&#x20; {

&#x20;   "cve": "CVE-2022-23539",

&#x20;   "severity": "HIGH",

&#x20;   "package": "jsonwebtoken",

&#x20;   "version": "0.1.0",

&#x20;   "fix": "9.0.0"

&#x20; }

]

```



| CVE | Severity | Package | Installed | Fix |

|-----|----------|---------|-----------|-----|

| CVE-2023-46233 | CRITICAL | crypto-js | 3.3.0 | 4.2.0 |

| CVE-2015-9235 | CRITICAL | jsonwebtoken | 0.1.0 | 4.2.2 |

| CVE-2015-9235 | CRITICAL | jsonwebtoken | 0.4.0 | 4.2.2 |

| CVE-2019-10744 | CRITICAL | lodash | 2.4.2 | 4.17.12 |

| GHSA-5mrr-rgp6-x4gr | CRITICAL | marsdb | 0.6.11 | none |

| CVE-2026-45447 | HIGH | libssl3t64 | 3.5.5-1\~deb13u2 | 3.5.6-1\~deb13u2 |

| NSWG-ECO-428 | HIGH | base64url | 0.0.6 | >=3.0.0 |

| CVE-2020-15084 | HIGH | express-jwt | 0.1.3 | 6.0.0 |

| CVE-2022-25881 | HIGH | http-cache-semantics | 3.8.1 | 4.1.1 |

| CVE-2022-23539 | HIGH | jsonwebtoken | 0.1.0 | 9.0.0 |



\### Fix-available analysis

Out of the top 10 CVEs, 9 have fixes available (90%), with only marsdb (GHSA-5mrr-rgp6-x4gr) having no fix. Following Lecture 4's triage shortcut—sort by fix-available AND severity ≥ HIGH first—the immediate priorities are: (1) crypto-js 3.3.0 → 4.2.0 (CRITICAL, PBKDF2 weakness), (2) jsonwebtoken 0.1.0/0.4.0 → 4.2.2+ (CRITICAL, verification bypass), and (3) lodash 2.4.2 → 4.17.12 (CRITICAL, prototype pollution). These three CRITICAL vulnerabilities with available fixes represent the highest ROI for patching, as they address authentication bypass and cryptographic weaknesses that directly impact the application's security posture.



\---



\## Bonus Task: Sign-Ready SBOM for Lab 8



\### CycloneDX schema version

\- `specVersion`: \*\*1.6\*\*

\- `bomFormat`: \*\*CycloneDX\*\*



\### Image digest captured

\- `docker inspect ... RepoDigests`: `bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`



\### Attestation predicate (first 30 lines of juice-shop-attestation.json)

```json

{

&#x20;   "subject":  \[

&#x20;                   {

&#x20;                       "digest":  {

&#x20;                                      "sha256":  "fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0"

&#x20;                                  },

&#x20;                       "name":  "bkimminich/juice-shop:v20.0.0"

&#x20;                   }

&#x20;               ],

&#x20;   "\_type":  "https://in-toto.io/Statement/v1",

&#x20;   "predicate":  {

&#x20;                     "$schema":  "http://cyclonedx.org/schema/bom-1.6.schema.json",

&#x20;                     "bomFormat":  "CycloneDX",

&#x20;                     "specVersion":  "1.6",

&#x20;                     "serialNumber":  "urn:uuid:e64baadf-bb24-40dc-b73d-3186f9d2cb3b",

&#x20;                     "version":  1,

&#x20;                     "metadata":  {

&#x20;                                      "timestamp":  "2026-06-18T23:39:21+03:00",

&#x20;                                      "tools":  {

&#x20;                                                    "components":  \[

&#x20;                                                                       {

&#x20;                                                                           "type":  "application",

&#x20;                                                                           "author":  "anchore",

&#x20;                                                                           "name":  "syft",

&#x20;                                                                           "version":  "1.45.1"

&#x20;                                                                       }

&#x20;                                                                   ]

&#x20;                                                },

&#x20;                                      "component":  {

&#x20;                                                        "bom-ref":  "73ec537d8d158676",

```



\### What this enables in Lab 8

When Lab 8 runs `cosign attest --type cyclonedx --predicate juice-shop-attestation.json ...`, it creates a cryptographically signed in-toto attestation that binds the SBOM to the specific image digest. This proves: (1) \*\*Authenticity\*\* — the SBOM was generated by an authorized party holding the signing key, (2) \*\*Integrity\*\* — the SBOM has not been tampered with since signing, and (3) \*\*Provenance\*\* — the SBOM corresponds to the exact image with the specified digest. This enables supply chain security by allowing consumers to verify that the SBOM they're examining is the authoritative inventory for that specific image build, preventing attackers from substituting a malicious SBOM that hides vulnerable dependencies.

