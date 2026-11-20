# PrivacyCheck

**A Website Privacy & Security Audit Platform built in Plain Language (Software Testing Capstone Project - CSA3701).**

PrivacyCheck audits whether any website is safe for visitors to use. It examines transport encryption, HTTP security headers, cookie storage safety, and privacy policies, presenting plain-language verdicts (e.g. *"Looks good"*, *"Some concerns"*, *"Several concerns"*) with zero confusing technical jargon.

In accordance with strict Software Testing principles, if the app cannot verify a property (such as when a site blocks automated requests or injects banners dynamically via JavaScript), it explicitly states **"Couldn't check" (Inconclusive)** instead of inventing an unverified result.

---

## 🌟 Key Features

### For Everyday Users (Non-Technical)
1. **Plain-Language Safety Verdict & Score**: Instant traffic-light assessment with clear safety scores (80%+ Looks Good, 50-79% Some Concerns, <50% Several Concerns).
2. **Everyday Visitor Safety Checklist**:
   - 🔒 *Can I safely log in or enter passwords?*
   - 💳 *Can I safely make purchases or payments?*
   - 📶 *Am I protected on public or hotel Wi-Fi?*
   - 🛡️ *Is the site protected from malicious trickery (Clickjacking / XSS)?*
   - 📜 *Does the site provide a discoverable Privacy Policy?*
3. **Personalized Action Plan**: Plain-language tips telling visitors what they should do (e.g., *Always log out on shared computers*, *Enable HTTPS-Only mode*, *Avoid entering passwords on plain HTTP*).
4. **Website Comparison Tool (`#compare`)**: Compare two websites side-by-side (e.g. comparing two shopping stores or banking sites) with automatic winner detection and check-by-check diff.
5. **Privacy 101 Educational Guide (`#guide`)**: Easy-to-understand real-world analogies explaining HTTPS (wax-sealed envelope vs. postcard), cookies (coat check tickets), clickjacking, and trackers.
6. **Quick One-Click Test Presets**: Test popular sites (`Wikipedia`, `GitHub`, `BBC News`, `Example.com`) or test demo sites with one click.
7. **Export & Sharing**: One-click "Copy Summary to Clipboard", "Save HTML Report", and "Print / PDF Friendly Report".
8. **Dark / Light Mode**: Seamless theme toggle stored in `localStorage`.

### For Software Testing & Quality Evaluators (Capstone Core)
1. **Interactive Testing Lab (`#lab`)**:
   - Controlled test harness of 5 benchmark demo websites with known ground truth.
   - Hand-crafted Expected Results Oracle (5 sites × 11 test cases = 55 executions).
   - Configurable toggles (HSTS, CSP, nosniff, X-Frame-Options, Referrer-Policy, Cookie Secure, HttpOnly, SameSite, Privacy Link, Banner).
   - Automated Regression Engine: State diffing against previous executions, isolating newly broken defects vs resolved test cases.
   - Live Results Matrix and Defect Log with root-cause evidence.
2. **QA & Quality Engineering Hub (`#qa`)**:
   - **Automated Node Test Suite Runner**: Click-to-run official `node --test` suite directly in the browser, showing 35 passing unit, integration, and feature tests with millisecond execution timings!
   - **Formal Traceability Matrix**: Maps test cases TC01–TC11 to ISO/IEC 25010 Quality Characteristics, Black-Box Testing Techniques (Equivalence Partitioning, Boundary Value Analysis, Negative Testing), and Severity levels.
   - **Testing Methodology Documentation**: Academic write-up of Specification-based testing, the Test Oracle problem, Tri-State decision logic, and SSRF defensive testing.

---

## 🚀 Quick Start

Requires **Node.js 18 or newer**. There are **no external npm packages** to install (100% native Node.js).

```bash
# 1. Start the server
npm start
```

Open your browser to: **http://localhost:3000** (or set `PORT=4000` to customize).

---

## 🧪 Automated Testing Suite

To run the automated unit, security boundary, and integration test suite:

```bash
npm test
```

### Test Coverage (35 Passing Automated Tests)
- **11 Test Case Rules (`tests/checks.test.js`)**: Pure function verification of TC01–TC11, boundary conditions, and tri-state evaluation.
- **Controlled Lab Suite & Regression Scenarios (`tests/lab.test.js`)**: Real server boot, full 55-execution lab run matching the oracle, defect injection, and path traversal security.
- **SSRF Defensive Boundary Checks (`tests/ssrf.test.js`)**: Validates IPv4/IPv6 private ranges, loopback, link-local, cloud metadata IP (169.254.169.254), non-standard ports, and credential blocking.
- **Feature & Quality API Tests (`tests/features.test.js`)**: Tests plain checklist evaluation, actionable tips generation, dual-site comparison validation, and QA ISO 25010 endpoints.

---

## 📋 Test Cases & ISO/IEC 25010 Mapping

| ID | Test Case | Category | ISO/IEC 25010 Quality Metric | Black-Box Testing Technique | Severity |
|---|---|---|---|---|---|
| **TC01** | HTTPS is used | Transport | Confidentiality & Data Encryption | Equivalence Partitioning (http vs https) | High |
| **TC02** | HSTS header present | Transport | Integrity & Non-repudiation | Boundary Value Analysis (max-age > 0) | Medium |
| **TC03** | Content-Security-Policy present | Headers | Integrity & Code Injection Resistance | Negative Testing (Report-Only rejected) | High |
| **TC04** | MIME sniffing blocked (nosniff) | Headers | Fault Tolerance & Content Integrity | Equivalence Partitioning (nosniff) | Low |
| **TC05** | Clickjacking protection | Headers | Authenticity & Interface Security | Multi-condition Decision Coverage | Medium |
| **TC06** | Referrer-Policy present | Headers | Information Privacy & Leak Prevention | Negative Testing (unsafe-url rejected) | Low |
| **TC07** | Cookies use Secure | Cookies | Confidentiality & Session Protection | Invariant Checking (All cookies Secure) | High |
| **TC08** | Cookies use HttpOnly | Cookies | Session Hijacking & XSS Mitigation | Invariant Checking (All cookies HttpOnly) | Medium |
| **TC09** | Cookies declare SameSite | Cookies | Authenticity & CSRF Prevention | Equivalence Partitioning (SameSite set) | Medium |
| **TC10** | Privacy notice discoverable | Privacy | Regulatory Compliance & Transparency | HTML Anchor Pattern Matching | High |
| **TC11** | Cookie consent mechanism detected | Privacy | Regulatory Compliance (GDPR/ePrivacy) | Tri-state Pattern Matching (Pass/Inconclusive) | Medium |

---

## 🛡️ Security Design (SSRF Protection)

When testing live websites, users submit URLs that the server fetches. To prevent Server-Side Request Forgery (SSRF) and DNS-rebinding attacks, `lib/fetcher.js`:
- Restricts protocols strictly to `http:` and `https:`, and standard ports (`80` and `443`).
- Rejects credentials (`user:pass@host`), `localhost`, `.local`, `.internal`, and IP literals.
- Inspects resolved IP addresses **at connect time** (defeating time-of-check to time-of-use DNS rebinding).
- Validates every hop in redirect chains (max 5 hops).
- Enforces strict 10-second request timeouts and 512 KB response body limits.
- Enforces rate limiting per IP (30 scans per minute).

---

## 📂 Project Architecture

```
privacycheck/
├── server.js              # HTTP server, API endpoints, static file server
├── lib/
│   ├── checks.js          # Core 11 test case evaluation rules (pure functions)
│   ├── fetcher.js         # SSRF-defended HTTP/HTTPS page fetcher
│   ├── lab.js             # 5 benchmark demo sites and hand-crafted test oracle
│   ├── plain.js           # Plain-English checklist, actionable tips, ISO 25010 specs
│   └── store.js           # Local history persistence (data/history.json)
├── public/
│   ├── index.html         # Responsive, accessible application shell
│   ├── styles.css         # Modern design system (Dark & Light themes, mobile & print)
│   └── app.js             # Client SPA router, views, comparison engine, lab runner
├── tests/
│   ├── checks.test.js     # Unit tests for test case logic
│   ├── lab.test.js        # Integration tests and regression scenarios
│   ├── ssrf.test.js       # Security boundary & IP validation tests
│   └── features.test.js   # Plain checklist, tips, comparison, and QA endpoints
└── data/
    └── history.json       # Historical scan audit logs
```

---

## 🎓 Suggested Capstone Demonstration for Evaluators

1. **Everyday User Flow**:
   - Open `#live`. Click **Wikipedia** or type an address and click **Check Website**.
   - Show the **Overall Safety Score & Verdict**, the **Everyday Visitor Safety Checklist** (Logins, Payments, Wi-Fi safety), and **Recommended Steps**.
   - Click **"Copy Summary"** or **"Save HTML Report"**.
2. **Comparison Tool Flow**:
   - Open `#compare`. Click **"Wikipedia vs Example.com"** and click **Compare Websites**.
   - Show the comparative scores, the winner highlight, and check-by-check diff.
3. **Software Testing Lab Flow**:
   - Open `#lab`. Click **"Run Full Test Suite"**: 55 executions run against the oracle with 100% detection accuracy.
   - On **Secure Shop**, uncheck **Content-Security-Policy** and re-run: the **Regression Engine** immediately flags `secure-shop:TC03` as a newly broken defect!
   - Click **"Reset All to Baseline"** and re-run: the regression engine confirms TC03 is resolved.
4. **QA Engineering & Test Suite Flow**:
   - Open `#qa`. Click **"Run Test Suite (node --test)"**: watch all 35 unit, integration, and security tests execute live in the browser in ~600ms!
   - Review the **Test Case Specification & Traceability Matrix** demonstrating ISO/IEC 25010 compliance.
