# Security Policy

## Supported Versions

Only the latest commit on the `main` branch is actively supported with security updates and heuristic rule patches.

| Version | Supported          |
| ------- | ------------------ |
| `main`  | :white_check_mark: |
| < 1.0.0 | :x:                |

---

## Reporting a Vulnerability

The SajagQR Shield project takes the security of financial parsing logic, quishing heuristics, and underlying infrastructure seriously. We appreciate responsible, coordinated disclosure from researchers, engineers, and community members.

### 1. Where to Report
If you discover a security vulnerability, detection engine bypass, algorithmic denial-of-service (ReDoS), or unhandled edge case that could lead to financial fraud exposure:

* **Preferred Channel:** Use GitHub's [Private Vulnerability Reporting](https://github.com/Sangharsa-adk/QR-shield/security/advisories/new).
* **Direct Email:** Reach out privately to **hello@sangharsaadhikari.com.np** with the subject line:
  `[SECURITY VULNERABILITY] SajagQR - <Brief Summary>`

> **CRITICAL:** Do NOT file public GitHub Issues or post open Pull Requests containing unpatched bypasses, active zero-day attack payloads, or weaponized exploit samples.

---

## What to Include in Your Report

To help us investigate, triage, and patch the issue quickly, include:

1. **Description:** Clear explanation of the flaw, bypass mechanism, or false negative.
2. **Payload / Proof of Concept (PoC):** The sanitized QR string, raw URL, or image fixture demonstrating the issue.
3. **Impact:** How an attacker could exploit this (e.g., bypassing standee detection, spoofing a commercial bank, or crashing the parser).
4. **Environment:** Python version, OS (Arch Linux/Ubuntu/Windows), and browser if applicable.
5. **Remediation Suggestion:** (Optional) Code fix, regex patch, or logic recommendation if you have one.

---

## Our Commitment & Response Timeline

* **Acknowledgment:** Within 48 hours of your report.
* **Triage & Assessment:** Initial validation and severity scoring within 3 to 5 business days.
* **Coordinated Fix:** A patch will be developed, tested against regression fixtures, and released to `main`.
* **Public Credit:** With your consent, we will credit your contribution in the repository changelog and release notes.

---

## Scope & Guidelines

### In Scope
* Bypasses of EMVCo/NepalQR CRC-16 integrity verification.
* Heuristic evasion of licensed commercial bank and PSP typosquatting filters.
* Client-side injection (XSS/Markdown injection) via weaponized QR payloads.
* Catastrophic regex backtracking (ReDoS) crashing the parsing engine.

### Out of Scope
* Attacks requiring physical access to an unlocked developer workstation.
* Denial of service attacks against Streamlit Community Cloud hosting infrastructure.
* Social engineering or reports concerning third-party payment gateways themselves (please report directly to the affected bank or Nepal Police Cyber Bureau).

