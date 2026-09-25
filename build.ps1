# Builds, tests and publishes MeshScreenDiag as a single self-contained .exe (no .NET install needed on the client).
# Usage:  .\build.ps1                 (x64)
#         .\build.ps1 -Runtime win-arm64
param(
    [string]$Runtime = "win-x64",
    [string]$Configuration = "Release"
)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

dotnet test tests/MeshScreenDiag.Core.Tests -c $Configuration
if ($LASTEXITCODE -ne 0) { throw "Tests failed" }

$out = Join-Path $PSScriptRoot "dist/$Runtime"
dotnet publish src/MeshScreenDiag/MeshScreenDiag.csproj -c $Configuration -r $Runtime --self-contained true `
    -p:PublishSingleFile=true -o $out
if ($LASTEXITCODE -ne 0) { throw "Publish failed" }

Write-Host ""
Write-Host "Published: $out\MeshScreenDiag.exe"
