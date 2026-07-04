# GitHub Security Audit — Automated Audit Runner

> **PowerShell-based GitHub security audit toolkit: runs 40+ security checks against your GitHub repositories, generates comprehensive Markdown reports with severity ratings and remediation steps.**

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?logo=powershell&logoColor=white)](https://learn.microsoft.com/en-us/powershell/)
[![GitHub API](https://img.shields.io/badge/GitHub-API-181717?logo=github&logoColor=white)](https://docs.github.com/en/rest)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## 🧠 Deep Analysis

A comprehensive PowerShell audit script that interacts with the **GitHub REST API v3** to assess repository security posture across 6 major categories.

### Architecture

```
┌────────────────────────────────────────────────────┐
│               run-all.ps1 (33KB)                   │
│                                                     │
│  .\run-all.ps1 -Token "ghp_xxx" -Username "myuser"  │
└────────────────────────┬───────────────────────────┘
                         │
              ┌──────────┴──────────┐
              ▼                     ▼
┌─────────────────────┐   ┌─────────────────────┐
│  GitHub API Calls   │   │  Report Generation   │
│                     │   │                      │
│  GET /users/{user}  │   │  ./reports/          │
│  GET /repos/{r}     │   │  report-{timestamp}  │
│  GET /repos/{r}/    │   │  .md                 │
│    branches          │   │                      │
│  GET /repos/{r}/    │   │  ✅ / ❌ / ⚠️        │
│    collaborators    │   │  Severity tags       │
│  GET /repos/{r}/    │   │  Remediation steps   │
│    secrets          │   │                      │
└─────────────────────┘   └─────────────────────┘
```

---

## 🛡️ Audit Categories (40+ Checks)

### 1. 🔐 Authentication & Access Control
| Check | Severity | What It Tests |
|-------|----------|---------------|
| Token validity | Critical | API responds with valid token |
| Token scopes | High | Verifies `repo`, `security_events`, `admin:org` scopes |
| 2FA enforcement | High | Checks if organization requires 2FA |
| Collaborator permissions | High | Identifies admin-level collaborators |
| Outside collaborators | High | Detects external collaborator access |

### 2. 📦 Repository Configuration
| Check | Severity | What It Tests |
|-------|----------|---------------|
| Visibility | Medium | Public vs private repos |
| Archived status | Low | Detects archived repositories |
| Template status | Low | Identifies template repos |
| Default branch | Info | Validates default branch name |
| Description | Low | Checks if repo has description |

### 3. 🛡️ Branch Protection
| Check | Severity | What It Tests |
|-------|----------|---------------|
| Protection enabled | High | Branch protection rules active |
| PR reviews required | High | Minimum number of reviewers |
| Dismiss stale reviews | Medium | Review dismissal on new pushes |
| Require code owners | High | Code owner review requirement |
| Status checks | Medium | CI status check requirements |
| Linear history | Low | Required linear commit history |

### 4. 🔑 Secrets & Scanning
| Check | Severity | What It Tests |
|-------|----------|---------------|
| Secret scanning | High | GitHub secret scanning enabled |
| Push protection | Critical | Secrets blocked from being pushed |
| Dependabot alerts | High | Vulnerability alert configuration |
| Dependabot security updates | High | Auto-merge for security patches |
| Code scanning | High | CodeQL or third-party SAST |

### 5. 📋 Compliance & Governance
| Check | Severity | What It Tests |
|-------|----------|---------------|
| CODEOWNERS file | Medium | .github/CODEOWNERS exists |
| CONTRIBUTING.md | Low | Contribution guidelines present |
| SECURITY.md | Low | Security policy document |
| LICENSE file | Low | Open source license detection |
| Issue templates | Low | Issue template configuration |
| PR templates | Low | Pull request template check |

### 6. 🔄 Activity & Hygiene
| Check | Severity | What It Tests |
|-------|----------|---------------|
| Stale branches | Medium | Branches without commits in 90 days |
| Recent commits | Low | Repository activity in last 30 days |
| Open issues | Low | Unresolved issue count |
| Open PRs | Low | Unmerged pull requests |
| Releases | Info | Latest release version and date |

---

## 🚀 Quick Start

### Prerequisites
- Windows PowerShell 5.1+ or PowerShell 7+
- GitHub Personal Access Token (classic) with `repo` and `security_events` scopes

### Run

```powershell
# Basic usage
.\test-runner\run-all.ps1 -Token "ghp_your_token_here" -Username "your-github-username"

# With custom report directory
.\test-runner\run-all.ps1 -Token "ghp_xxx" -Username "myuser" -ReportDir ".\my-reports"
```

### Output

```
========================================
  GitHub Security Audit — Test Runner
  By: Karan (Whitehat Security)
========================================

[Authentication] Token Validation
  [PASS] Token is valid
  [INFO] Token user: myuser
  [PASS] Token has required scopes

[Access Control] 2FA Enforcement
  [FAIL] 2FA not enforced for organization ⚠️ Critical

...

========================================
  Audit Complete
========================================
  Total Tests : 42
  Passed      : 35
  Failed      : 7
  Warnings    : 0
```

A full Markdown report is generated at `./reports/report-{timestamp}.md`.

---

## 📊 Report Format

Generated reports include:
- **Summary table** with pass/fail counts
- **Category breakdown** with severity indicators
- **Detailed findings** organized by category
- **Failure details** with severity and remediation recommendations
- **Timestamps** and tester attribution

```
# 🛡️ GitHub Security Audit Report
**Date:** 2026-07-04 12:00:00
**Tester:** Karan (Whitehat Security Research)

## Authentication — Token Validation
✅ **PASS:** Token is valid
✅ **PASS:** Required scopes present

## Access Control — 2FA Enforcement
❌ **FAIL:** 2FA not enforced | Severity: Critical
```

---

## 🔧 Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-Token` | ✅ | GitHub Personal Access Token |
| `-Username` | ✅ | GitHub username to audit |
| `-ReportDir` | ❌ | Output directory (default: `.\reports`) |

---

## 💡 Use Cases

- **🔒 Pre-Merge Security Gate** — Run before merging to main
- **📊 Quarterly Compliance Audits** — SOC2, ISO 27001 readiness
- **🚀 Repository Onboarding** — Security baseline for new repos
- **🔄 CI/CD Integration** — Add as GitHub Actions workflow step
- **👥 Organization Audits** — Bulk audit across all org repos (extend with `GET /orgs/{org}/repos`)

---

## 📄 License

MIT
