<#
.SYNOPSIS
Global RC4 Kerberos detection script

.DESCRIPTION
This script orchestrates all RC4 detection checks:
- Tests whether the RC4 KB logs are installed
- If installed, searches the audit logs
- Always lists account keys and Kerberos encryption usage  
- Displays the size of the security logs

.PARAMETER Since
Search period since this date (default 30 days)

.PARAMETER SearchScope
Search scope: This (local machine) or AllKdcs (all KDCs in the domain)

.PARAMETER ShowDetails

Displays full details of results.

.EXAMPLE
.\Invoke-RC4DetectionGlobal.ps1


.EXAMPLE
.\Invoke-RC4DetectionGlobal.ps1 -Since (Get-Date).AddDays(-7) -SearchScope AllKdcs -ShowDetails

#>

[CmdletBinding()]
param(
    [DateTime]$Since = (Get-Date).AddDays(-30),
    [ValidateSet("This", "AllKdcs")]
    [string]$SearchScope = "This",
    [switch]$ShowDetails
)

# Import functions from existing scripts
. "$PSScriptRoot\Test-RC4LogsKBInstalled.ps1"
. "$PSScriptRoot\Get-RC4AuditSystemLog.ps1" 
. "$PSScriptRoot\List-AccountKeys.ps1"
. "$PSScriptRoot\Get-KerbEncryptionUsage.ps1"

function Get-SecurityLogSize {
    [CmdletBinding()]
    param()
    
    try {
        $securityLog = Get-WinEvent -ListLog 'Security' -ErrorAction SilentlyContinue
        if ($securityLog) {
            $logSizeMB = [math]::Round($securityLog.FileSize / 1MB, 2)
            $maxLogSizeMB = [math]::Round($securityLog.MaximumSizeInBytes / 1MB, 2)
            Write-Host "Security Log Size: $logSizeMB MB / $maxLogSizeMB MB (Maximum)" -ForegroundColor Cyan
        } else {
            Write-Host "Unable to access Security log information" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "Error retrieving Security log size: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Get-SystemLogSize {
    [CmdletBinding()]
    param()
    
    try {
        $systemLog = Get-WinEvent -ListLog 'System' -ErrorAction SilentlyContinue
        if ($systemLog) {
            $logSizeMB = [math]::Round($systemLog.FileSize / 1MB, 2)
            $maxLogSizeMB = [math]::Round($systemLog.MaximumSizeInBytes / 1MB, 2)
            Write-Host "System Log Size: $logSizeMB MB / $maxLogSizeMB MB (Maximum)" -ForegroundColor Cyan
        } else {
            Write-Host "Unable to access System log information" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "Error retrieving System log size: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Write-SectionHeader {
    param([string]$Title)
    Write-Host ""
    Write-Host "=" * 80 -ForegroundColor Blue
    Write-Host " $Title" -ForegroundColor White
    Write-Host "=" * 80 -ForegroundColor Blue
}

function Write-SubSectionHeader {
    param([string]$Title)
    Write-Host ""
    Write-Host "--- $Title ---" -ForegroundColor Yellow
}

# Main script execution
Write-Host "RC4 KERBEROS DETECTION - GLOBAL ANALYSIS" -ForegroundColor Green
Write-Host "Analysis Date: $(Get-Date -Format 'MM/dd/yyyy HH:mm:ss')" -ForegroundColor Green
Write-Host "Analysis Period: since $(Get-Date $Since -Format 'MM/dd/yyyy HH:mm:ss')" -ForegroundColor Green
Write-Host "Search Scope: $SearchScope" -ForegroundColor Green

# 1. Display log sizes
Write-SectionHeader "LOG SIZE INFORMATION"
Get-SecurityLogSize
Get-SystemLogSize

# 2. Test RC4 KB logs
Write-SectionHeader "RC4 KB LOGS VERIFICATION"
$isKBInstalled = Test-RC4LogsKBInstalled

# 3. Search audit logs (only if KB installed)
if ($isKBInstalled) {
    Write-SectionHeader "SYSTEM AUDIT LOGS SEARCH"
    Write-Host "KB installed - Searching for RC4 events in system logs..." -ForegroundColor Green
    try {
        Get-RC4AuditSystemLog -StartTime $Since
    }
    catch {
        Write-Host "Error searching audit logs: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-SectionHeader "SYSTEM AUDIT LOGS SEARCH"
    Write-Host "KB not installed - SKIPPING system audit logs search" -ForegroundColor Yellow
    Write-Host "RC4 detection events (201-209) are not available without the required KB." -ForegroundColor Yellow
}

# 4. Account keys list (always executed)
Write-SectionHeader "ACCOUNT KEYS LIST"
Write-Host "Analyzing account encryption keys..." -ForegroundColor Green
try {
    $accountKeys = List-AccountKeys -Since $Since -SearchScope $SearchScope
    
    if ($accountKeys) {
        Write-Host "Number of accounts found: $($accountKeys.Count)" -ForegroundColor Cyan
        
        if ($ShowDetails) {
            Write-SubSectionHeader "Account Key Details"
            $accountKeys | Select-Object Time, Name, Type, Keys | Format-Table -AutoSize
        }
        
        # Key type analysis
        Write-SubSectionHeader "Encryption Types Analysis"
        $rc4Accounts = $accountKeys | Where-Object { $_.Keys -match "RC4" }
        $desAccounts = $accountKeys | Where-Object { $_.Keys -match "DES" }
        $aesAccounts = $accountKeys | Where-Object { $_.Keys -match "AES" }
        
        Write-Host "Accounts using RC4: $($rc4Accounts.Count)" -ForegroundColor $(if ($rc4Accounts.Count -gt 0) { 'Red' } else { 'Green' })
        Write-Host "Accounts using DES: $($desAccounts.Count)" -ForegroundColor $(if ($desAccounts.Count -gt 0) { 'Red' } else { 'Green' })
        Write-Host "Accounts using AES: $($aesAccounts.Count)" -ForegroundColor Green
    } else {
        Write-Host "No account keys found for the specified period" -ForegroundColor Yellow
    }
}
catch {
    Write-Host "Error analyzing account keys: $($_.Exception.Message)" -ForegroundColor Red
}

# 5. Kerberos encryption usage (always executed)
Write-SectionHeader "KERBEROS ENCRYPTION USAGE"
Write-Host "Analyzing Kerberos encryption usage..." -ForegroundColor Green
try {
    $kerbUsage = Get-KerbEncryptionUsage -Since $Since -SearchScope $SearchScope
    
    if ($kerbUsage) {
        Write-Host "Number of Kerberos requests found: $($kerbUsage.Count)" -ForegroundColor Cyan
        
        # Encryption type analysis in requests
        Write-SubSectionHeader "Kerberos Request Encryption Analysis"
        $rc4Requests = $kerbUsage | Where-Object { $_.Ticket -eq "RC4" -or $_.SessionKey -eq "RC4" }
        $desRequests = $kerbUsage | Where-Object { $_.Ticket -match "DES" -or $_.SessionKey -match "DES" }
        $aesRequests = $kerbUsage | Where-Object { $_.Ticket -match "AES" -or $_.SessionKey -match "AES" }
        
        Write-Host "Requests using RC4: $($rc4Requests.Count)" -ForegroundColor $(if ($rc4Requests.Count -gt 0) { 'Red' } else { 'Green' })
        Write-Host "Requests using DES: $($desRequests.Count)" -ForegroundColor $(if ($desRequests.Count -gt 0) { 'Red' } else { 'Green' })
        Write-Host "Requests using AES: $($aesRequests.Count)" -ForegroundColor Green
        
        if ($ShowDetails) {
            Write-SubSectionHeader "Request Details by Encryption Type"
            $kerbUsage | Select-Object Time, Requestor, Target, Type, Ticket, SessionKey | Format-Table -AutoSize
        }
        
        if ($rc4Requests.Count -gt 0) {
            Write-SubSectionHeader "WARNING: RC4 Requests Detected"
            $rc4Requests | Select-Object Time, Requestor, Target, Type, Ticket, SessionKey | Format-Table -AutoSize
        }
    } else {
        Write-Host "No Kerberos requests found for the specified period" -ForegroundColor Yellow
    }
}
catch {
    Write-Host "Error analyzing Kerberos usage: $($_.Exception.Message)" -ForegroundColor Red
}

# 6. Final summary
Write-SectionHeader "ANALYSIS SUMMARY"
Write-Host "RC4 KB logs installed: $(if ($isKBInstalled) { 'YES' } else { 'NO' })" -ForegroundColor $(if ($isKBInstalled) { 'Green' } else { 'Red' })

if ($accountKeys) {
    $totalRC4Accounts = ($accountKeys | Where-Object { $_.Keys -match "RC4" }).Count
    Write-Host "Accounts with RC4 keys: $totalRC4Accounts out of $($accountKeys.Count)" -ForegroundColor $(if ($totalRC4Accounts -gt 0) { 'Red' } else { 'Green' })
}

if ($kerbUsage) {
    $totalRC4Requests = ($kerbUsage | Where-Object { $_.Ticket -eq "RC4" -or $_.SessionKey -eq "RC4" }).Count
    Write-Host "Kerberos RC4 requests: $totalRC4Requests out of $($kerbUsage.Count)" -ForegroundColor $(if ($totalRC4Requests -gt 0) { 'Red' } else { 'Green' })
}

Write-Host ""
if (($accountKeys | Where-Object { $_.Keys -match "RC4" }).Count -gt 0 -or ($kerbUsage | Where-Object { $_.Ticket -eq "RC4" -or $_.SessionKey -eq "RC4" }).Count -gt 0) {
    Write-Host "⚠️  ALERT: RC4 usage detected in your environment!" -ForegroundColor Red
    Write-Host "   Recommendation: Plan migration to AES" -ForegroundColor Yellow
} else {
    Write-Host "✅ No RC4 usage detected - Environment is secure" -ForegroundColor Green
}

Write-Host ""
Write-Host "Analysis completed on $(Get-Date -Format 'MM/dd/yyyy HH:mm:ss')" -ForegroundColor Green