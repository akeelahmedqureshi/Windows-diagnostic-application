# Builds, tests and publishes MeshScreenDiag as a single self-contained .exe (no .NET install needed on the client).
# Usage:  .\build.ps1                 (x64)
#         .\build.ps1 -Runtime win-arm64
param(
    [string]$Runtime = "win-x64",
    [string]$Configuration = "Release"
)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    Write-Host "The .NET 8 SDK is not installed (the 'dotnet' command was not found)." -ForegroundColor Red
    Write-Host "Install it with:  winget install Microsoft.DotNet.SDK.8"
    Write-Host "or download it from https://dotnet.microsoft.com/download/dotnet/8.0 (SDK, Windows x64 installer),"
    Write-Host "then CLOSE and REOPEN PowerShell and run this script again."
    exit 1
}

dotnet test tests/MeshScreenDiag.Core.Tests -c $Configuration
if ($LASTEXITCODE -ne 0) { throw "Tests failed" }

$out = Join-Path $PSScriptRoot "dist/$Runtime"
dotnet publish src/MeshScreenDiag/MeshScreenDiag.csproj -c $Configuration -r $Runtime --self-contained true `
    -p:PublishSingleFile=true -o $out
if ($LASTEXITCODE -ne 0) { throw "Publish failed" }

Write-Host ""
Write-Host "Published: $out\MeshScreenDiag.exe"
