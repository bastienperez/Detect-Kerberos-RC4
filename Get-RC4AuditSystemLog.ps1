function Get-RC4AuditSystemLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [DateTime]$StartTime = (Get-Date).AddDays(-30)
    )

    $eventIDs = 201, 202, 203, 204, 205, 206, 207, 208, 209

    if ($StartTime) {
        Write-Host "Searching for Event IDs 201-209 in System log since $StartTime..." -ForegroundColor Cyan
        
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            ID        = $eventIDs
            StartTime = $StartTime
        } -ErrorAction SilentlyContinue
    }
    else {
        Write-Host 'Searching for Event IDs 201-209 in System log...' -ForegroundColor Cyan
        
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'System'
            ID      = $eventIDs
        } -ErrorAction SilentlyContinue
    }

    if ($events) {
        Write-Host "Found $($events.Count) event(s)" -ForegroundColor Yellow
        $events | Select-Object TimeCreated, Id, Message | Format-Table -AutoSize
    }
    else {
        Write-Host 'No events found (201-209)' -ForegroundColor Green
    }
}