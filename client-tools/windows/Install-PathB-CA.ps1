<#
Path-B v5.12 — imports the Squid inspection CA.
Default: CurrentUser Root store, no administrator rights required for the signed-in test user.
With -Machine, the LocalMachine Root store is used and administrator rights are required.
#>
param(
    [string]$CAFile = "",
    [switch]$Machine
)

function Resolve-PathBCAFile {
    param([string]$RequestedPath)

    $candidates = @()
    if ($RequestedPath -and $RequestedPath.Trim().Length -gt 0) {
        $candidates += $RequestedPath
    }

    $candidates += @(
        (Join-Path $PSScriptRoot "myCA.crt"),
        (Join-Path (Get-Location) "myCA.crt"),
        (Join-Path $PSScriptRoot "..\myCA.crt"),
        (Join-Path $PSScriptRoot "..\..\certs\proxy\myCA.crt"),
        (Join-Path $PSScriptRoot "..\..\..\certs\proxy\myCA.crt"),
        (Join-Path (Get-Location) "..\certs\proxy\myCA.crt"),
        (Join-Path (Get-Location) "..\..\certs\proxy\myCA.crt")
    )

    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path $candidate)) {
            return (Resolve-Path $candidate).Path
        }
    }

    return $null
}

$resolved = Resolve-PathBCAFile -RequestedPath $CAFile
if (-not $resolved) {
    Write-Host "CA file myCA.crt was not found." -ForegroundColor Red
    Write-Host "Do NOT use only the source folder client-tools\windows." -ForegroundColor Yellow
    Write-Host "First copy the generated Windows kit from the proxy VM to the Windows client:" -ForegroundColor Yellow
    Write-Host "  <repo>/path-b-external-suricata-ips/certs/proxy/pathb-windows-client-kit.zip"
    Write-Host "or at least copy this file into this folder:" -ForegroundColor Yellow
    Write-Host "  <repo>/path-b-external-suricata-ips/certs/proxy/myCA.crt"
    Write-Host "Alternatively copy it directly from the proxy VM:" -ForegroundColor Yellow
    Write-Host "  /etc/squid/ssl_cert/myCA.crt"
    throw "CA file not found. Expected: myCA.crt in the current folder or in the generated windows-client-kit."
}

if ($Machine) {
    Write-Host "Importing CA into LocalMachine\Root: $resolved" -ForegroundColor Green
    & certutil.exe -addstore -f "Root" $resolved
}
else {
    Write-Host "Importing CA into CurrentUser\Root: $resolved" -ForegroundColor Green
    & certutil.exe -user -addstore -f "Root" $resolved
}

if ($LASTEXITCODE -ne 0) {
    throw "certutil failed with ExitCode $LASTEXITCODE"
}

$thumbprint = (& certutil.exe -hashfile $resolved SHA256 | Select-String -Pattern '^[0-9A-Fa-f ]+$' | Select-Object -First 1).ToString().Trim()
Write-Host "CA import completed." -ForegroundColor Green
Write-Host "CA file: $resolved"
if ($thumbprint) {
    Write-Host "SHA256: $thumbprint"
}
