# Reports

The scanner generates two report formats from the Scan Detail page.

---

## PDF Report

Client-side generated via **jsPDF + jspdf-autotable**. No server round-trip required.

### How to Export

1. Open a completed scan
2. Click **Export PDF**
3. The file downloads immediately as `scan-report-<id>.pdf`

### Report Structure

| Section | Content |
|---|---|
| Cover Page | Scan target, date, severity summary boxes, metadata table |
| Executive Summary | Findings count by severity, scan configuration |
| OWASP Coverage Map | Table showing findings per API1–API10 category |
| Finding Details | One section per finding: severity, OWASP badge, CVSS vector, description, impact, remediation, PoC |
| Methodology | Rules used, scanning approach, tool version |

---

## DOCX Report

Server-side generated via **python-docx 1.x**. Downloaded as a Word document.

### How to Export

1. Open a completed scan
2. Click **Download DOCX**
3. The file downloads as `scan-report-<id>.docx`

> The DOCX button is disabled for scans that are still `pending` or `running`.

### Report Structure

| Section | Content |
|---|---|
| Title Page | Scanner name, target, date |
| Executive Summary | Severity breakdown table |
| Findings | Per-finding tables with colored severity headers, full details |
| Appendix | CVSS vectors, scan configuration |

### Notes

- Temp files are cleaned up server-side automatically after download
- Maximum scan size for DOCX: no hard limit, but very large scans (500+ findings) may take a few seconds to generate

---

## Automating Report Generation

Use the API to download reports programmatically:

```bash
TOKEN="<your-jwt>"
SCAN_ID=42

# PDF is generated client-side — not available via API
# DOCX download:
curl -o "report-${SCAN_ID}.docx" \
  -H "Authorization: Bearer ${TOKEN}" \
  "http://localhost:8000/api/v1/scans/${SCAN_ID}/report/docx"
```
