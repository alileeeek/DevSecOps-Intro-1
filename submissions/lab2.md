# Lab 2 — Submission

## Task 1: Baseline Threat Model

### Risk count by severity
| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 0 |
| Elevated | 4 |
| Medium | 14 |
| Low | 5 |
| **Total** | 23 |

### Top 5 risks
1. **unencrypted-communication** — Direct to App (no proxy); severity elevated; affecting user-browser
2. **unencrypted-communication** — To App (via Reverse Proxy); severity elevated; affecting reverse-proxy
3. **missing-authentication** — To App (via Reverse Proxy); severity elevated; affecting juice-shop
4. **cross-site-scripting** — XSS risk at Juice Shop; severity elevated; affecting juice-shop
5. **unnecessary-data-transfer** — Tokens & Sessions; severity low; affecting user-browser

### STRIDE mapping
- Risk 1: **I (Information Disclosure)** — Unencrypted HTTP allows attackers to intercept authentication data in transit.
- Risk 2: **I (Information Disclosure)** — Internal traffic between proxy and app is unencrypted, risking data interception.
- Risk 3: **E (Elevation of Privilege)** — Missing authentication on internal links allows unauthorized access to the app.
- Risk 4: **T (Tampering)** — XSS allows attackers to modify page content and steal user data.
- Risk 5: **I (Information Disclosure)** — Sending unnecessary tokens increases the attack surface for data theft.

### Trust boundary observation
Arrow: User Browser (Internet) -> Juice Shop Application (Container).
Why attractive: It crosses the main trust boundary from the untrusted internet directly to the app without encryption (HTTP), making it the easiest target for Man-in-the-Middle attacks to steal credentials.
