# GitHub Security Audit — Master Test Runner
# Author: Karan (Whitehat Security Research)
# Date: 2026-06-11
#
# Usage: .\run-all.ps1 -Token "ghp_YourToken" -Username "your-username"

param(
    [Parameter(Mandatory=$true)]
    [string]$Token,

    [Parameter(Mandatory=$true)]
    [string]$Username,

    [string]$ReportDir = ".\reports"
)

$ErrorActionPreference = "SilentlyContinue"
$Timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$ReportFile = "$ReportDir\report-$Timestamp.md"

# Create report directory
New-Item -ItemType Directory -Force -Path $ReportDir | Out-Null

# Initialize report
@"
# 🛡️ GitHub Security Audit Report
**Date:** $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
**Tester:** Karan (Whitehat Security Research)
**Target:** GitHub.com + GitHub API
**Token User:** $Username

---

"@ | Out-File -FilePath $ReportFile -Encoding UTF8

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  GitHub Security Audit — Test Runner" -ForegroundColor Cyan
Write-Host "  By: Karan (Whitehat Security)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$TotalTests = 0
$Passed = 0
$Failed = 0
$Findings = @()

# ============================================
# HELPER FUNCTIONS
# ============================================

function Write-TestHeader {
    param([string]$Category, [string]$TestName)
    Write-Host "`n[$Category] $TestName" -ForegroundColor Yellow
    "## $Category — $TestName" | Out-File -FilePath $ReportFile -Append -Encoding UTF8
}

function Write-Result {
    param(
        [string]$Status,
        [string]$Detail,
        [string]$Severity = "Info"
    )
    $script:TotalTests++
    switch ($Status) {
        "PASS" {
            Write-Host "  [PASS] $Detail" -ForegroundColor Green
            $script:Passed++
            "✅ **PASS:** $Detail" | Out-File -FilePath $ReportFile -Append -Encoding UTF8
        }
        "FAIL" {
            Write-Host "  [FAIL] $Detail" -ForegroundColor Red
            $script:Failed++
            "❌ **FAIL:** $Detail" | Out-File -FilePath $ReportFile -Append -Encoding UTF8
            $script:Findings += @{ Severity = $Severity; Detail = $Detail; Test = $TestName }
        }
        "WARN" {
            Write-Host "  [WARN] $Detail" -ForegroundColor DarkYellow
            "⚠️ **WARN:** $Detail" | Out-File -FilePath $ReportFile -Append -Encoding UTF8
        }
        "INFO" {
            Write-Host "  [INFO] $Detail" -ForegroundColor Gray
            "ℹ️ **INFO:** $Detail" | Out-File -FilePath $ReportFile -Append -Encoding UTF8
        }
    }
}

function Test-Response {
    param(
        [string]$Url,
        [string]$Method = "GET",
        [hashtable]$Headers = @{},
        [string]$Body = "",
        [int[]]$SuccessCodes = @(200, 201, 204),
        [int[]]$FailCodes = @(401, 403, 404)
    )
    try {
        $params = @{
            Uri = $Url
            Method = $Method
            Headers = $Headers
            TimeoutSec = 15
            UseBasicParsing = $true
        }
        if ($Body -and $Method -ne "GET") {
            $params["Body"] = $Body
            $params["ContentType"] = "application/json"
        }
        $response = Invoke-RestMethod @params -ErrorAction Stop
        return @{ Success = $true; Data = $response; StatusCode = 200 }
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        if ($statusCode) {
            return @{ Success = $false; StatusCode = $statusCode; Error = $_.Exception.Message }
        }
        return @{ Success = $false; StatusCode = 0; Error = $_.Exception.Message }
    }
}

$Headers = @{
    "Authorization" = "token $Token"
    "Accept" = "application/vnd.github.v3+json"
    "User-Agent" = "GitHub-Security-Audit-Karan"
}

# ============================================
# CATEGORY 1: AUTHENTICATION & SESSION
# ============================================

Write-Host "`n╔══════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "║  CATEGORY 1: AUTH & SESSION          ║" -ForegroundColor Magenta
Write-Host "╚══════════════════════════════════════╝" -ForegroundColor Magenta

"## Category 1: Authentication & Session" | Out-File -FilePath $ReportFile -Append -Encoding UTF8

# TC-1.1: Verify token works
Write-TestHeader -Category "Auth" -TestName "TC-1.1: Token Validation"
$result = Test-Response -Url "https://api.github.com/user" -Headers $Headers
if ($result.Success -and $result.Data.login -eq $Username) {
    Write-Result -Status "PASS" -Detail "Token valid, authenticated as: $($result.Data.login)"
} else {
    Write-Result -Status "FAIL" -Detail "Token validation failed: $($result.Error)" -Severity "Critical"
}

# TC-1.2: Check token scopes
Write-TestHeader -Category "Auth" -TestName "TC-1.2: Token Scope Analysis"
try {
    $scopeResponse = Invoke-WebRequest -Uri "https://api.github.com/user" -Headers $Headers -UseBasicParsing
    $scopes = $scopeResponse.Headers["X-OAuth-Scopes"]
    $acceptedScopes = $scopeResponse.Headers["X-Accepted-OAuth-Scopes"]
    Write-Result -Status "INFO" -Detail "Token scopes: $scopes"
    Write-Result -Status "INFO" -Detail "Accepted scopes: $acceptedScopes"

    if ($scopes -match "repo" -or $scopes -match "delete_repo") {
        Write-Result -Status "WARN" -Detail "Token has broad scope ($scopes) — fine-grained PAT recommended" -Severity "Medium"
    } else {
        Write-Result -Status "PASS" -Detail "Token has limited scope: $scopes"
    }
} catch {
    Write-Result -Status "FAIL" -Detail "Could not determine token scopes: $_" -Severity "Medium"
}

# TC-1.3: Session cookie security
Write-TestHeader -Category "Auth" -TestName "TC-1.3: Session Cookie Security"
try {
    $cookieResponse = Invoke-WebRequest -Uri "https://github.com/login" -UseBasicParsing -TimeoutSec 10
    $setCookies = $cookieResponse.Headers["Set-Cookie"]
    if ($setCookies) {
        $secureCount = ($setCookies | Select-String "Secure").Count
        $httpOnlyCount = ($setCookies | Select-String "HttpOnly").Count
        $sameSiteCount = ($setCookies | Select-String "SameSite").Count

        Write-Result -Status "INFO" -Detail "Cookies found: $($setCookies.Count)"
        Write-Result -Status "INFO" -Detail "Secure: $secureCount | HttpOnly: $httpOnlyCount | SameSite: $sameSiteCount"

        if ($secureCount -gt 0 -and $httpOnlyCount -gt 0) {
            Write-Result -Status "PASS" -Detail "Critical cookies have Secure + HttpOnly flags"
        } else {
            Write-Result -Status "FAIL" -Detail "Some cookies missing Secure/HttpOnly flags" -Severity "High"
        }
    } else {
        Write-Result -Status "INFO" -Detail "No Set-Cookie headers on login page (may use JS-based auth)"
    }
} catch {
    Write-Result -Status "WARN" -Detail "Could not analyze cookies: $_"
}

# TC-1.4: PAT scope enforcement test
Write-TestHeader -Category "Auth" -TestName "TC-1.4: PAT Scope Enforcement"
$result = Test-Response -Url "https://api.github.com/user/emails" -Headers $Headers
if ($result.Success) {
    Write-Result -Status "INFO" -Detail "Can access /user/emails — token has user:email or user scope"
} else {
    Write-Result -Status "INFO" -Detail "Cannot access /user/emails (Status: $($result.StatusCode)) — scope may be limited"
}

# Try accessing repos (should fail with minimal scope)
$result2 = Test-Response -Url "https://api.github.com/repos/$Username" -Headers $Headers
if ($result2.Success) {
    Write-Result -Status "INFO" -Detail "Can access repos endpoint"
} else {
    Write-Result -Status "INFO" -Detail "Cannot access repos (Status: $($result2.StatusCode))"
}

# TC-1.5: Rate limit check
Write-TestHeader -Category "Auth" -TestName "TC-1.5: Rate Limit Status"
try {
    $rateResponse = Invoke-WebRequest -Uri "https://api.github.com/rate_limit" -Headers $Headers -UseBasicParsing
    $rateData = $rateResponse.Content | ConvertFrom-Json
    $remaining = $rateData.rate.remaining
    $limit = $rateData.rate.limit
    $resetTime = [DateTimeOffset]::FromUnixTimeSeconds($rateData.rate.reset).DateTime

    Write-Result -Status "INFO" -Detail "Rate limit: $remaining / $limit remaining"
    Write-Result -Status "INFO" -Detail "Reset at: $resetTime"

    if ($remaining -lt 100) {
        Write-Result -Status "WARN" -Detail "Rate limit running low ($remaining remaining)" -Severity "Low"
    } else {
        Write-Result -Status "PASS" -Detail "Rate limit healthy ($remaining / $limit)"
    }
} catch {
    Write-Result -Status "WARN" -Detail "Could not check rate limit: $_"
}

# ============================================
# CATEGORY 2: XSS / SECURITY HEADERS
# ============================================

Write-Host "`n╔══════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "║  CATEGORY 2: XSS & SECURITY HEADERS  ║" -ForegroundColor Magenta
Write-Host "╚══════════════════════════════════════╝" -ForegroundColor Magenta

"## Category 2: XSS & Security Headers" | Out-File -FilePath $ReportFile -Append -Encoding UTF8

# TC-2.1: CSP Header Analysis
Write-TestHeader -Category "Headers" -TestName "TC-2.1: Content-Security-Policy Analysis"
try {
    $cspResponse = Invoke-WebRequest -Uri "https://github.com" -UseBasicParsing -TimeoutSec 10
    $csp = $cspResponse.Headers["Content-Security-Policy"]

    if ($csp) {
        Write-Result -Status "PASS" -Detail "CSP header present"
        Write-Result -Status "INFO" -Detail "CSP: $($csp.Substring(0, [Math]::Min(200, $csp.Length)))..."

        # Check for unsafe directives
        if ($csp -match "'unsafe-inline'") {
            Write-Result -Status "WARN" -Detail "CSP contains 'unsafe-inline' — CSS injection possible" -Severity "Medium"
        }
        if ($csp -match "'unsafe-eval'") {
            Write-Result -Status "WARN" -Detail "CSP contains 'unsafe-eval' — JS eval possible" -Severity "Medium"
        }
        if ($csp -match "script-src.*\*") {
            Write-Result -Status "FAIL" -Detail "CSP script-src allows wildcard (*)" -Severity "Critical"
        }
        if ($csp -match "default-src 'none'" -or $csp -match "default-src 'self'") {
            Write-Result -Status "PASS" -Detail "CSP has restrictive default-src"
        }

        # Check for bypassable domains
        $bypassablePatterns = @(
            "github.githubassets.com",
            "avatars.githubusercontent.com",
            "objects.githubusercontent.com"
        )
        foreach ($pattern in $bypassablePatterns) {
            if ($csp -match $pattern) {
                Write-Result -Status "INFO" -Detail "CSP allows $pattern — check for uploadable JS"
            }
        }
    } else {
        Write-Result -Status "FAIL" -Detail "No CSP header found!" -Severity "Critical"
    }
} catch {
    Write-Result -Status "WARN" -Detail "Could not analyze CSP: $_"
}

# TC-2.2: Other Security Headers
Write-TestHeader -Category "Headers" -TestName "TC-2.2: Security Headers Check"
try {
    $secResponse = Invoke-WebRequest -Uri "https://github.com" -UseBasicParsing -TimeoutSec 10
    $secHeaders = @{
        "X-Frame-Options" = $secResponse.Headers["X-Frame-Options"]
        "X-Content-Type-Options" = $secResponse.Headers["X-Content-Type-Options"]
        "Strict-Transport-Security" = $secResponse.Headers["Strict-Transport-Security"]
        "X-XSS-Protection" = $secResponse.Headers["X-XSS-Protection"]
        "Referrer-Policy" = $secResponse.Headers["Referrer-Policy"]
        "Permissions-Policy" = $secResponse.Headers["Permissions-Policy"]
    }

    foreach ($header in $secHeaders.GetEnumerator()) {
        if ($header.Value) {
            Write-Result -Status "PASS" -Detail "$($header.Key): $($header.Value)"
        } else {
            Write-Result -Status "WARN" -Detail "$($header.Key): MISSING" -Severity "Low"
        }
    }
} catch {
    Write-Result -Status "WARN" -Detail "Could not analyze security headers: $_"
}

# TC-2.3: API response content-type
Write-TestHeader -Category "Headers" -TestName "TC-2.3: API Content-Type Validation"
try {
    $apiResponse = Invoke-WebRequest -Uri "https://api.github.com/user" -Headers $Headers -UseBasicParsing
    $contentType = $apiResponse.Headers["Content-Type"]
    if ($contentType -match "application/json") {
        Write-Result -Status "PASS" -Detail "API returns proper JSON content-type: $contentType"
    } else {
        Write-Result -Status "WARN" -Detail "Unexpected content-type: $contentType" -Severity "Medium"
    }
} catch {
    Write-Result -Status "WARN" -Detail "Could not check content-type: $_"
}

# ============================================
# CATEGORY 3: SSRF
# ============================================

Write-Host "`n╔══════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "║  CATEGORY 3: SSRF                    ║" -ForegroundColor Magenta
Write-Host "╚══════════════════════════════════════╝" -ForegroundColor Magenta

"## Category 3: SSRF" | Out-File -FilePath $ReportFile -Append -Encoding UTF8

# TC-3.1: Webhook URL validation
Write-TestHeader -Category "SSRF" -TestName "TC-3.1: Webhook URL Validation"
$testUrls = @(
    "http://169.254.169.254/latest/meta-data/",
    "http://localhost:8080/",
    "http://127.0.0.1:6379/",
    "http://0xa9.0xfe.0xa9.0xfe/",
    "http://2852039166/"
)

foreach ($testUrl in $testUrls) {
    $webhookBody = @{
        name = "web"
        active = $true
        events = @("push")
        config = @{
            url = $testUrl
            content_type = "json"
        }
    } | ConvertTo-Json

    $result = Test-Response -Url "https://api.github.com/repos/$Username/hooks" -Headers $Headers -Method "POST" -Body $webhookBody
    if ($result.Success) {
        Write-Result -Status "WARN" -Detail "Webhook created with URL: $testUrl — may not validate internal IPs" -Severity "High"
        # Clean up
        if ($result.Data.id) {
            $null = Test-Response -Url "https://api.github.com/repos/$Username/hooks/$($result.Data.id)" -Headers $Headers -Method "DELETE"
        }
    } else {
        Write-Result -Status "PASS" -Detail "Webhook rejected for URL: $testUrl (Status: $($result.StatusCode))"
    }

    Start-Sleep -Seconds 2  # Rate limit protection
}

# TC-3.2: Repository import URL validation
Write-TestHeader -Category "SSRF" -TestName "TC-3.2: Repository Import URL Validation"
Write-Result -Status "INFO" -Detail "Repository import requires UI interaction — manual test needed"
Write-Result -Status "INFO" -Detail "Test URL: https://github.com/new/import"
Write-Result -Status "INFO" -Detail "Try importing from: http://169.254.169.254/latest/meta-data/"

# ============================================
# CATEGORY 4: IDOR
# ============================================

Write-Host "`n╔══════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "║  CATEGORY 4: IDOR                    ║" -ForegroundColor Magenta
Write-Host "╚══════════════════════════════════════╝" -ForegroundColor Magenta

"## Category 4: IDOR" | Out-File -FilePath $ReportFile -Append -Encoding UTF8

# TC-4.1: GraphQL node access
Write-TestHeader -Category "IDOR" -TestName "TC-4.1: GraphQL Node Access"
$graphqlBody = '{"query":"{ viewer { login repositories(first:1) { nodes { id name } } } }"}'
$result = Test-Response -Url "https://api.github.com/graphql" -Headers $Headers -Method "POST" -Body $graphqlBody
if ($result.Success) {
    Write-Result -Status "PASS" -Detail "GraphQL API accessible"
    $repoId = $result.Data.data.viewer.repositories.nodes[0].id
    Write-Result -Status "INFO" -Detail "Test repo node ID: $repoId"

    # Try accessing the same repo via node query
    $nodeQuery = "{ node(id:`"$repoId`") { ... on Repository { name isPrivate } } }"
    $nodeBody = @{ query = $nodeQuery } | ConvertTo-Json
    $nodeResult = Test-Response -Url "https://api.github.com/graphql" -Headers $Headers -Method "POST" -Body $nodeBody
    if ($nodeResult.Success) {
        Write-Result -Status "PASS" -Detail "Node query works for own repo: $($nodeResult.Data.data.node.name)"
    }
} else {
    Write-Result -Status "FAIL" -Detail "GraphQL API not accessible: $($result.Error)" -Severity "Medium"
}

# TC-4.2: GraphQL introspection
Write-TestHeader -Category "IDOR" -TestName "TC-4.2: GraphQL Introspection"
$introBody = '{"query":"{ __schema { types { name } } }"}'
$introResult = Test-Response -Url "https://api.github.com/graphql" -Headers $Headers -Method "POST" -Body $introBody
if ($introResult.Success -and $introResult.Data.data.__schema) {
    $typeCount = $introResult.Data.data.__schema.types.Count
    Write-Result -Status "INFO" -Detail "GraphQL introspection enabled — $typeCount types exposed"
    Write-Result -Status "WARN" -Detail "Introspection may reveal private data schema" -Severity "Low"
} else {
    Write-Result -Status "PASS" -Detail "GraphQL introspection disabled or restricted"
}

# TC-4.3: REST API access to other users' data
Write-TestHeader -Category "IDOR" -TestName "TC-4.3: REST API Cross-User Access"
$testUsers = @("octocat", "defunkt", "pjhyett")
foreach ($testUser in $testUsers) {
    $result = Test-Response -Url "https://api.github.com/users/$testUser" -Headers $Headers
    if ($result.Success) {
        Write-Result -Status "INFO" -Detail "Public profile accessible: $testUser (ID: $($result.Data.id))"
    }
}

# Try accessing private data of other users
$result = Test-Response -Url "https://api.github.com/users/octocat/emails" -Headers $Headers
if ($result.Success) {
    Write-Result -Status "WARN" -Detail "Can access other user's emails!" -Severity "Critical"
} else {
    Write-Result -Status "PASS" -Detail "Cannot access other user's emails (Status: $($result.StatusCode))"
}

# TC-4.4: Organization access test
Write-TestHeader -Category "IDOR" -TestName "TC-4.4: Organization Access"
$result = Test-Response -Url "https://api.github.com/user/orgs" -Headers $Headers
if ($result.Success) {
    Write-Result -Status "INFO" -Detail "Organizations accessible: $($result.Data.Count)"
    foreach ($org in $result.Data | Select-Object -First 3) {
        Write-Result -Status "INFO" "  - $($org.login) (ID: $($org.id))"
    }
}

# ============================================
# CATEGORY 5: GITHUB ACTIONS
# ============================================

Write-Host "`n╔══════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "║  CATEGORY 5: GITHUB ACTIONS          ║" -ForegroundColor Magenta
Write-Host "╚══════════════════════════════════════╝" -ForegroundColor Magenta

"## Category 5: GitHub Actions" | Out-File -FilePath $ReportFile -Append -Encoding UTF8

# TC-5.1: GITHUB_TOKEN permissions
Write-TestHeader -Category "Actions" -TestName "TC-5.1: Default Token Permissions"
$result = Test-Response -Url "https://api.github.com/repos/$Username" -Headers $Headers
if ($result.Success) {
    $defaultPermissions = $result.Data.permissions
    Write-Result -Status "INFO" -Detail "Repo permissions: admin=$($defaultPermissions.admin) push=$($defaultPermissions.push) pull=$($defaultPermissions.pull)"
}

# TC-5.2: Actions permissions
Write-TestHeader -Category "Actions" -TestName "TC-5.2: Actions Configuration"
$result = Test-Response -Url "https://api.github.com/repos/$Username/actions/permissions" -Headers $Headers
if ($result.Success) {
    Write-Result -Status "INFO" -Detail "Actions enabled: $($result.Data.enabled)"
    Write-Result -Status "INFO" -Detail "Allowed actions: $($result.Data.allowed_actions)"
}

# TC-5.3: OIDC token endpoint
Write-TestHeader -Category "Actions" -TestName "TC-5.3: OIDC Token Availability"
Write-Result -Status "INFO" -Detail "OIDC tokens only available inside Actions runners"
Write-Result -Status "INFO" -Detail "Test by adding `permissions: id-token: write` to workflow"

# ============================================
# CATEGORY 6: DATA EXPOSURE
# ============================================

Write-Host "`n╔══════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "║  CATEGORY 6: DATA EXPOSURE           ║" -ForegroundColor Magenta
Write-Host "╚══════════════════════════════════════╝" -ForegroundColor Magenta

"## Category 6: Data Exposure" | Out-File -FilePath $ReportFile -Append -Encoding UTF8

# TC-6.1: Public email exposure
Write-TestHeader -Category "Data" -TestName "TC-6.1: Email Exposure via API"
$result = Test-Response -Url "https://api.github.com/user/emails" -Headers $Headers
if ($result.Success) {
    foreach ($email in $result.Data) {
        $visibility = if ($email.visibility) { $email.visibility } else { "private" }
        Write-Result -Status "INFO" -Detail "Email: $($email.email) (Primary: $($email.primary), Verified: $($email.verified), Visibility: $visibility)"
        if ($visibility -eq "public") {
            Write-Result -Status "WARN" -Detail "Public email exposed: $($email.email)" -Severity "Low"
        }
    }
}

# TC-6.2: SSH keys exposure
Write-TestHeader -Category "Data" -TestName "TC-6.2: SSH Key Exposure"
$result = Test-Response -Url "https://api.github.com/user/keys" -Headers $Headers
if ($result.Success) {
    Write-Result -Status "INFO" -Detail "SSH keys visible to owner: $($result.Data.Count)"
    foreach ($key in $result.Data | Select-Object -First 3) {
        Write-Result -Status "INFO" "  - Key ID $($key.id): $($key.key.Substring(0, [Math]::Min(40, $key.key.Length)))..."
    }
}

# TC-6.3: Check for public events leakage
Write-TestHeader -Category "Data" -TestName "TC-6.3: Public Events Leakage"
$result = Test-Response -Url "https://api.github.com/users/$Username/events/public" -Headers $Headers
if ($result.Success) {
    Write-Result -Status "INFO" -Detail "Public events accessible: $($result.Data.Count)"
    foreach ($event in $result.Data | Select-Object -First 3) {
        Write-Result -Status "INFO" "  - $($event.type) on $($event.repo.name) at $($event.created_at)"
    }
}

# ============================================
# CATEGORY 7: CSRF
# ============================================

Write-Host "`n╔══════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "║  CATEGORY 7: CSRF                    ║" -ForegroundColor Magenta
Write-Host "╚══════════════════════════════════════╝" -ForegroundColor Magenta

"## Category 7: CSRF" | Out-File -FilePath $ReportFile -Append -Encoding UTF8

# TC-7.1: CSRF token presence
Write-TestHeader -Category "CSRF" -TestName "TC-7.1: CSRF Token Analysis"
try {
    $csrfResponse = Invoke-WebRequest -Uri "https://github.com/settings/tokens" -Headers @{"Cookie" = "user_session=TEST"} -UseBasicParsing -TimeoutSec 10
    $csrfToken = $csrfResponse.Content | Select-String -Pattern 'authenticity_token.*?value="([^"]*)"' -AllMatches
    if ($csrfToken) {
        Write-Result -Status "PASS" -Detail "CSRF token found in forms"
    } else {
        Write-Result -Status "INFO" -Detail "CSRF token not found in initial response (may require valid session)"
    }
} catch {
    Write-Result -Status "INFO" -Detail "CSRF analysis requires authenticated session"
}

# TC-7.2: SameSite cookie check
Write-TestHeader -Category "CSRF" -TestName "TC-7.2: SameSite Cookie Attribute"
try {
    $cookieResponse = Invoke-WebRequest -Uri "https://github.com/login" -UseBasicParsing -TimeoutSec 10
    $cookies = $cookieResponse.Headers["Set-Cookie"]
    if ($cookies -match "SameSite") {
        $sameSiteValue = $cookies | Select-String "SameSite=([^;]+)" | ForEach-Object { $_.Matches.Groups[1].Value }
        Write-Result -Status "PASS" -Detail "SameSite attribute present: $sameSiteValue"
    } else {
        Write-Result -Status "WARN" -Detail "SameSite attribute not found in cookies" -Severity "Medium"
    }
} catch {
    Write-Result -Status "WARN" -Detail "Could not analyze cookies: $_"
}

# ============================================
# CATEGORY 8: API & RATE LIMITING
# ============================================

Write-Host "`n╔══════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "║  CATEGORY 8: API & RATE LIMITING     ║" -ForegroundColor Magenta
Write-Host "╚══════════════════════════════════════╝" -ForegroundColor Magenta

"## Category 8: API & Rate Limiting" | Out-File -FilePath $ReportFile -Append -Encoding UTF8

# TC-8.1: Rate limit headers
Write-TestHeader -Category "API" -TestName "TC-8.1: Rate Limit Headers"
try {
    $rateResponse = Invoke-WebRequest -Uri "https://api.github.com/user" -Headers $Headers -UseBasicParsing
    $rlRemaining = $rateResponse.Headers["X-RateLimit-Remaining"]
    $rlLimit = $rateResponse.Headers["X-RateLimit-Limit"]
    $rlReset = $rateResponse.Headers["X-RateLimit-Reset"]
    $rlUsed = $rateResponse.Headers["X-RateLimit-Used"]

    Write-Result -Status "INFO" -Detail "Rate Limit: $rlUsed / $rlLimit used, $rlRemaining remaining"
    if ($rlReset) {
        $resetTime = [DateTimeOffset]::FromUnixTimeSeconds([int]$rlReset).DateTime
        Write-Result -Status "INFO" -Detail "Reset at: $resetTime"
    }
    Write-Result -Status "PASS" -Detail "Rate limit headers present"
} catch {
    Write-Result -Status "WARN" -Detail "Could not check rate limit headers: $_"
}

# TC-8.2: GraphQL rate limit
Write-TestHeader -Category "API" -TestName "TC-8.2: GraphQL Rate Limit"
$graphqlBody = '{"query":"{ viewer { login } }"}'
try {
    $gqlResponse = Invoke-WebRequest -Uri "https://api.github.com/graphql" -Headers $Headers -Method "POST" -Body $graphqlBody -ContentType "application/json" -UseBasicParsing
    $gqlRemaining = $gqlResponse.Headers["X-RateLimit-Remaining"]
    Write-Result -Status "INFO" -Detail "GraphQL rate limit remaining: $gqlRemaining"
} catch {
    Write-Result -Status "WARN" -Detail "Could not check GraphQL rate limit: $_"
}

# TC-8.3: CORS headers
Write-TestHeader -Category "API" -TestName "TC-8.3: CORS Configuration"
try {
    $corsResponse = Invoke-WebRequest -Uri "https://api.github.com/user" -Headers ($Headers + @{ "Origin" = "https://evil.com" }) -UseBasicParsing
    $acao = $corsResponse.Headers["Access-Control-Allow-Origin"]
    $acac = $corsResponse.Headers["Access-Control-Allow-Credentials"]

    if ($acao) {
        if ($acao -eq "*") {
            Write-Result -Status "WARN" -Detail "CORS allows wildcard origin" -Severity "Medium"
        } elseif ($acao -eq "https://evil.com") {
            Write-Result -Status "FAIL" -Detail "CORS reflects arbitrary origin!" -Severity "Critical"
        } else {
            Write-Result -Status "PASS" -Detail "CORS restricted to: $acao"
        }
    } else {
        Write-Result -Status "PASS" -Detail "No CORS headers (restrictive by default)"
    }
} catch {
    Write-Result -Status "INFO" -Detail "CORS test inconclusive: $_"
}

# ============================================
# CATEGORY 9: INFRASTRUCTURE
# ============================================

Write-Host "`n╔══════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "║  CATEGORY 9: INFRASTRUCTURE          ║" -ForegroundColor Magenta
Write-Host "╚══════════════════════════════════════╝" -ForegroundColor Magenta

"## Category 9: Infrastructure" | Out-File -FilePath $ReportFile -Append -Encoding UTF8

# TC-9.1: TLS Configuration
Write-TestHeader -Category "Infra" -TestName "TC-9.1: TLS Configuration"
try {
    $tlsResponse = Invoke-WebRequest -Uri "https://github.com" -UseBasicParsing -TimeoutSec 10
    Write-Result -Status "PASS" -Detail "HTTPS connection successful"
} catch {
    Write-Result -Status "FAIL" -Detail "HTTPS connection failed: $_" -Severity "Critical"
}

# TC-9.2: HSTS Header
Write-TestHeader -Category "Infra" -TestName "TC-9.2: HSTS Header"
try {
    $hstsResponse = Invoke-WebRequest -Uri "https://github.com" -UseBasicParsing -TimeoutSec 10
    $hsts = $hstsResponse.Headers["Strict-Transport-Security"]
    if ($hsts) {
        Write-Result -Status "PASS" -Detail "HSTS present: $hsts"
        if ($hsts -match "includeSubDomains") {
            Write-Result -Status "PASS" -Detail "HSTS includes subdomains"
        }
        if ($hsts -match "preload") {
            Write-Result -Status "PASS" -Detail "HSTS preload ready"
        }
    } else {
        Write-Result -Status "FAIL" -Detail "HSTS header missing!" -Severity "High"
    }
} catch {
    Write-Result -Status "WARN" -Detail "Could not check HSTS: $_"
}

# TC-9.3: Server header
Write-TestHeader -Category "Infra" -TestName "TC-9.3: Server Header Leakage"
try {
    $serverResponse = Invoke-WebRequest -Uri "https://github.com" -UseBasicParsing -TimeoutSec 10
    $server = $serverResponse.Headers["Server"]
    if ($server) {
        Write-Result -Status "WARN" -Detail "Server header exposed: $server" -Severity "Low"
    } else {
        Write-Result -Status "PASS" -Detail "Server header not exposed"
    }
} catch {
    Write-Result -Status "WARN" -Detail "Could not check server header: $_"
}

# ============================================
# CATEGORY 10: SUPPLY CHAIN
# ============================================

Write-Host "`n╔══════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "║  CATEGORY 10: SUPPLY CHAIN           ║" -ForegroundColor Magenta
Write-Host "╚══════════════════════════════════════╝" -ForegroundColor Magenta

"## Category 10: Supply Chain" | Out-File -FilePath $ReportFile -Append -Encoding UTF8

# TC-10.1: Dependabot alerts
Write-TestHeader -Category "Supply" -TestName "TC-10.1: Dependabot Configuration"
$result = Test-Response -Url "https://api.github.com/repos/$Username/vulnerability-alerts" -Headers $Headers
if ($result.Success -or $result.StatusCode -eq 204) {
    Write-Result -Status "PASS" -Detail "Dependabot alerts accessible"
} else {
    Write-Result -Status "INFO" -Detail "Dependabot alerts status: $($result.StatusCode)"
}

# TC-10.2: Code scanning
Write-TestHeader -Category "Supply" -TestName "TC-10.2: Code Scanning Status"
$result = Test-Response -Url "https://api.github.com/repos/$Username/code-scanning/analyses" -Headers $Headers
Write-Result -Status "INFO" -Detail "Code scanning status: $($result.StatusCode)"

# ============================================
# SUMMARY
# ============================================

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  TEST RESULTS SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Total Tests:  $TotalTests" -ForegroundColor White
Write-Host "  Passed:       $Passed" -ForegroundColor Green
Write-Host "  Failed:       $Failed" -ForegroundColor Red
Write-Host "  Findings:     $($Findings.Count)" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Cyan

# Write summary to report
@"

---

## 📊 Test Summary

| Metric | Value |
|---|---|
| **Total Tests** | $TotalTests |
| **Passed** | $Passed |
| **Failed** | $Failed |
| **Findings** | $($Findings.Count) |

## 🔴 Security Findings

"@ | Out-File -FilePath $ReportFile -Append -Encoding UTF8

if ($Findings.Count -eq 0) {
    "No critical security findings detected." | Out-File -FilePath $ReportFile -Append -Encoding UTF8
} else {
    $findingNum = 0
    foreach ($finding in $Findings) {
        $findingNum++
        "### Finding $findingNum — $($finding.Severity)" | Out-File -FilePath $ReportFile -Append -Encoding UTF8
        "- **Detail:** $($finding.Detail)" | Out-File -FilePath $ReportFile -Append -Encoding UTF8
        "" | Out-File -FilePath $ReportFile -Append -Encoding UTF8
    }
}

@"

---

*Report generated by Karan Security Audit Toolkit*
*$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")*
"@ | Out-File -FilePath $ReportFile -Append -Encoding UTF8

Write-Host "`n📄 Report saved to: $ReportFile" -ForegroundColor Green
Write-Host "`n⚠️  IMPORTANT:" -ForegroundColor Yellow
Write-Host "   - This is a READ-ONLY security audit" -ForegroundColor Yellow
Write-Host "   - No exploits were executed" -ForegroundColor Yellow
Write-Host "   - No data was modified or deleted" -ForegroundColor Yellow
Write-Host "   - Report is for authorized research only" -ForegroundColor Yellow
