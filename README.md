# GitHub Security Audit

> **PowerShell-based automated security audit toolkit for GitHub repository vulnerability assessments.**

---

## Overview

A comprehensive PowerShell security audit runner designed for GitHub repositories. Automates the process of scanning repositories for common security issues, misconfigurations, and vulnerabilities.

---

## Contents

### `test-runner/run-all.ps1` (33KB)
The master security audit script — a comprehensive PowerShell script that runs multiple security checks against GitHub repositories.

---

## Features

- 🔐 **Repository Permission Audit** — Checks repository access controls
- 🔑 **Secret Detection** — Scans for exposed API keys, tokens, and credentials
- 📦 **Dependency Analysis** — Identifies vulnerable dependencies
- 🛡️ **Branch Protection Checks** — Validates branch protection rules
- 📋 **Compliance Reporting** — Generates detailed audit reports
- 🔍 **Code Scanning** — Basic static analysis for security issues

---

## Quick Start

### Prerequisites
- Windows PowerShell 5.1+ or PowerShell 7+
- GitHub token with repo access

### Run

```powershell
# Run the full audit suite
.\test-runner\run-all.ps1

# With specific GitHub token
$env:GITHUB_TOKEN = "your-token-here"
.\test-runner\run-all.ps1 -Repo "owner/repo"

# Generate report only
.\test-runner\run-all.ps1 -ReportOnly
```

---

## Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-Repo` | Target repository (owner/repo) | Current repo |
| `-Token` | GitHub personal access token | `$env:GITHUB_TOKEN` |
| `-OutputDir` | Report output directory | `./audit-results` |
| `-ReportOnly` | Skip fixes, only generate report | `false` |
| `-Verbose` | Detailed output | `false` |

---

## Audit Checks

- ✅ **Branch protection rules** — Are they enforced?
- ✅ **Require PR reviews** — Minimum reviewers set?
- ✅ **Secret scanning** — Enabled?
- ✅ **Dependabot** — Configured?
- ✅ **Code owners** — Defined?
- ✅ **Permission levels** — Appropriate access?
- ✅ **Deploy keys** — Reviewed and rotated?

---

## Use Cases

- 🔒 **Pre-Merge Security Gate** — Automated checks before merging
- 📊 **Quarterly Audits** — Scheduled security reviews
- 🚀 **Onboarding** — Security baseline for new repos
- 🔄 **CI/CD Integration** — Integrate with GitHub Actions

---

## Output

The script generates:
- HTML/JSON audit reports with findings
- Severity-ranked issue list (Critical/High/Medium/Low)
- Remediation recommendations
- Historical trend data for tracking improvements

---

## License

MIT
