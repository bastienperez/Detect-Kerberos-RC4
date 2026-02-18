function Test-RC4LogsKBInstalled {
    [CmdletBinding()]
    param()

    $build = [System.Environment]::OSVersion.Version.Build

    switch ($build) {
        14393 { 
            $os = 'Windows Server 2016'
            $kb = 'KB5073722'
        }
        17763 { 
            $os = 'Windows Server 2019'
            $kb = 'KB5073723'
        }
        20348 { 
            $os = 'Windows Server 2022'
            $kb = 'KB5073724'
        }
        default { 
            Write-Host "Unknown OS - build: $build" -ForegroundColor Yellow
            return
        }
    }

    Write-Host "OS: $os (build $build)" -ForegroundColor Cyan

    $update = Get-HotFix -Id $kb -ErrorAction SilentlyContinue

    if ($update) {
        Write-Host "Status: $kb is INSTALLED" -ForegroundColor Green
        Write-Host "Install Date: $($update.InstalledOn)" -ForegroundColor Green
        return $true
    }
    else {
        Write-Host "Status: $kb is NOT INSTALLED" -ForegroundColor Red
        return $false
    }
}