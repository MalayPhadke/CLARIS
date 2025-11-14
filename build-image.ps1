#!/usr/bin/env pwsh
# Build script for vigilink-backend Docker image

Write-Host "Building vigilink-backend Docker image..." -ForegroundColor Cyan

$imageName = "vigilink-backend:latest"
$dockerfilePath = "backend/Dockerfile"

# Check if Docker is available
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host "Error: Docker is not installed or not in PATH" -ForegroundColor Red
    exit 1
}

# Check if Dockerfile exists
if (-not (Test-Path $dockerfilePath)) {
    Write-Host "Error: Dockerfile not found at $dockerfilePath" -ForegroundColor Red
    exit 1
}

# Build the image
Write-Host "Building image: $imageName" -ForegroundColor Yellow
docker build -t $imageName -f $dockerfilePath backend/

if ($LASTEXITCODE -eq 0) {
    Write-Host "`nSuccess! Image built: $imageName" -ForegroundColor Green
    Write-Host "`nVerify with: docker images | grep vigilink-backend" -ForegroundColor Cyan
} else {
    Write-Host "`nError: Docker build failed" -ForegroundColor Red
    exit 1
}
