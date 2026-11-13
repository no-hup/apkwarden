# Security Policy

## Supported Versions

APKwarden follows semantic versioning. Critical security patches and rule updates are provided for the current active minor release branch.

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

We take the security of APKwarden seriously. Because APKwarden parses untrusted APK and AAB archives, we prioritize hardening against archive anomalies, parser denial-of-service, and zip extraction vulnerabilities.

If you believe you have found a security vulnerability in APKwarden:

1. **Do not disclose publicly:** Please do not file a public GitHub issue.
2. **Submit via GitHub Private Vulnerability Reporting:**
   Use GitHub's built-in **"Report a vulnerability"** tab under the `Security` tab of this repository.
3. **What to include:**
   - Detailed description of the vulnerability.
   - Minimal proof-of-concept APK/AAB or reproduction steps.
   - Potential impact (e.g. infinite loop, memory exhaustion, incorrect reachability triage).

### Response SLA
- **Initial Response:** Within 48 hours acknowledging receipt.
- **Triage & Patch:** Within 7 business days for high/critical issues.
- **Coordination:** We will coordinate a public release notes credit and CVE identifier if appropriate.
