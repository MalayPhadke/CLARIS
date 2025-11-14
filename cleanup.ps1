#!/usr/bin/env pwsh
# Cleanup script for Vigilink backend

Write-Host "`n=== Vigilink Backend Cleanup ===" -ForegroundColor Cyan

# 1. Kill all uvicorn/python processes related to the backend
Write-Host "`n[1/3] Stopping uvicorn/python processes..." -ForegroundColor Yellow

$pythonProcesses = Get-Process | Where-Object {
    ($_.ProcessName -like "*python*" -or $_.ProcessName -like "*uvicorn*") -and
    ($_.Path -like "*CLARIS*" -or $_.CommandLine -like "*backend*" -or $_.CommandLine -like "*uvicorn*")
}

if ($pythonProcesses) {
    foreach ($proc in $pythonProcesses) {
        Write-Host "  Killing process $($proc.Id) ($($proc.ProcessName))" -ForegroundColor Gray
        try {
            Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Host "    Could not kill $($proc.Id): $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    Write-Host "  Stopped $($pythonProcesses.Count) process(es)" -ForegroundColor Green
} else {
    Write-Host "  No uvicorn/python processes found" -ForegroundColor Green
}

# Wait a moment for processes to clean up
Start-Sleep -Seconds 2

# 2. Remove all vigilink Docker containers
Write-Host "`n[2/3] Removing vigilink Docker containers..." -ForegroundColor Yellow

$containers = docker ps -aq --filter "name=vigilink"
if ($containers) {
    $containerArray = $containers -split "`n" | Where-Object { $_ -ne "" }
    Write-Host "  Found $($containerArray.Count) container(s)" -ForegroundColor Gray
    docker rm -f $containers 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  Removed all vigilink containers" -ForegroundColor Green
    } else {
        Write-Host "  Warning: Some containers may not have been removed" -ForegroundColor Yellow
    }
} else {
    Write-Host "  No vigilink containers found" -ForegroundColor Green
}

# 3. Clean up connection state file
Write-Host "`n[3/3] Cleaning connection state..." -ForegroundColor Yellow

$stateFile = "backend\.vigilink_conns.json"
if (Test-Path $stateFile) {
    try {
        Remove-Item $stateFile -Force
        Write-Host "  Removed $stateFile" -ForegroundColor Green
    } catch {
        Write-Host "  Warning: Could not remove state file: $($_.Exception.Message)" -ForegroundColor Yellow
    }
} else {
    Write-Host "  No state file found" -ForegroundColor Green
}

# 4. Verify port 8000 is free
Write-Host "`n[4/4] Checking port 8000..." -ForegroundColor Yellow
Start-Sleep -Seconds 1

$port8000 = netstat -ano | Select-String "8000" | Select-String "LISTENING"
if ($port8000) {
    Write-Host "  Warning: Port 8000 is still in use:" -ForegroundColor Yellow
    Write-Host "  $port8000" -ForegroundColor Gray
    Write-Host "  You may need to manually kill these processes or wait a few seconds" -ForegroundColor Yellow
} else {
    Write-Host "  Port 8000 is free" -ForegroundColor Green
}

Write-Host "`n=== Cleanup Complete ===" -ForegroundColor Cyan
Write-Host "`nYou can now start the server with:" -ForegroundColor White
Write-Host "  cd backend" -ForegroundColor Gray
Write-Host "  uvicorn app:app --host 0.0.0.0 --port 8000 --reload" -ForegroundColor Gray
Write-Host ""
