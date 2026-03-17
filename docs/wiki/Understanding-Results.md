# Understanding Results

---

## Severity Levels

| Severity | Color | Description |
|---|---|---|
| **Critical** | Red | Immediate exploitation possible; direct impact on confidentiality, integrity, or availability |
| **High** | Orange | Significant risk; exploitable with moderate effort |
| **Medium** | Yellow | Exploitable under certain conditions; should be remediated |
| **Low** | Blue | Limited impact; best-practice violation |
| **Info** | Gray | Informational; no direct security risk |

---

## Finding Fields

Each finding includes:

| Field | Description |
|---|---|
| Rule ID | Which rule detected the issue (e.g. `BOLA-IDOR`) |
| OWASP Category | API1–API10 classification |
| Severity | Critical / High / Medium / Low / Info |
| Endpoint | The affected URL path |
| Method | HTTP method (GET, POST, etc.) |
| Description | Human-readable description of the finding |
| Impact | Business/technical impact statement |
| Remediation | Step-by-step fix guidance |
| Proof of Concept | Request/response evidence |
| CVSS Vector | CVSS 3.1 vector string |
| CVSS Score | Numeric score (0.0–10.0) |
| Status | Open / In Progress / Fixed / Accepted Risk |

---

## OWASP API Security Top 10 Mapping

| Category | Name | Rules |
|---|---|---|
| API1 | Broken Object Level Authorization | BOLA-IDOR |
| API2 | Broken Authentication | AUTH-MISSING, JWT-001 |
| API3 | Broken Object Property Level Auth | SENSITIVE-DATA, MASS-ASSIGN-001 |
| API4 | Unrestricted Resource Consumption | RATE-LIMIT, FUZZING |
| API5 | Broken Function Level Authorization | BFLA-001 |
| API6 | Unrestricted Access to Business Flows | BUSINESS-LOGIC |
| API7 | Server Side Request Forgery | SSRF-001 |
| API8 | Security Misconfiguration | SEC-HEADERS, CORS-001, HTML-INJ-001, PATH-TRAV-001 |
| API9 | Improper Inventory Management | OPENAPI-CONTRACT |
| API10 | Unsafe Consumption of APIs | INJECTION-BASIC, DESERIALIZATION |

---

## Risk Score

The dashboard **Risk Score** (0–100) is a weighted aggregate:

```
Score = (Critical×10 + High×7 + Medium×4 + Low×1) / max_possible × 100
```

Capped at 100. A score of 0 means no findings.

| Range | Interpretation |
|---|---|
| 0 | No findings |
| 1–30 | Low risk |
| 31–60 | Moderate risk |
| 61–80 | High risk |
| 81–100 | Critical risk |

---

## Triaging Findings

Change a finding's status directly from the scan detail page:

1. Click the status badge on a finding card
2. Select the new status from the dropdown:
   - **Open** — default; needs attention
   - **In Progress** — remediation underway
   - **Fixed** — vulnerability resolved
   - **Accepted Risk** — risk acknowledged and accepted

Status changes are saved immediately via API and reflected in subsequent reports.

---

## False Positives

Some rules (especially fuzzing, injection, BOLA) may produce false positives depending on the target API's response patterns. Use **Accepted Risk** status to acknowledge these. All findings are still included in exports so auditors have a complete record.
