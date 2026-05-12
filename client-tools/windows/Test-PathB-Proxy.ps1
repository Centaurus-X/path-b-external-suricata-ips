<#
Path-B v5.12 — Windows smoke test without changing system proxy settings.
#>
param(
    [string]$ProxyHost = "10.10.10.20",
    [int]$ProxyPort = 3128,
    [switch]$SkipHttps
)

function Import-PathBSettings {
    $settingsFile = Join-Path $PSScriptRoot "PathB-Client-Settings.txt"
    if (-not (Test-Path $settingsFile)) {
        return
    }
    $settings = @{}
    Get-Content $settingsFile | ForEach-Object {
        if ($_ -match '^([^=]+)=(.*)$') {
            $settings[$matches[1].Trim()] = $matches[2].Trim()
        }
    }
    if ($settings.ContainsKey("ProxyHost") -and $settings["ProxyHost"]) {
        Set-Variable -Name ProxyHost -Scope 1 -Value $settings["ProxyHost"]
    }
    if ($settings.ContainsKey("ProxyPort") -and $settings["ProxyPort"]) {
        Set-Variable -Name ProxyPort -Scope 1 -Value ([int]$settings["ProxyPort"])
    }
}

function Invoke-CurlTest {
    param(
        [string]$Title,
        [string[]]$CurlArgs
    )
    Write-Host "`n==> $Title" -ForegroundColor Cyan
    & curl.exe @CurlArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Host "curl ExitCode: $LASTEXITCODE" -ForegroundColor Yellow
    }
}

Import-PathBSettings

$proxyUrl = "http://{0}:{1}" -f $ProxyHost, $ProxyPort
Write-Host "Path-B proxy test via $proxyUrl" -ForegroundColor Green

Invoke-CurlTest -Title "HTTP baseline test" -CurlArgs @("-I", "-m", "20", "-x", $proxyUrl, "http://example.com/")
Invoke-CurlTest -Title "Suricata/ICAP block test" -CurlArgs @("-i", "-m", "20", "-x", $proxyUrl, "-H", "X-Proxylab-Test: icap-suricata-trigger", "http://example.com/")

if (-not $SkipHttps) {
    Invoke-CurlTest -Title "HTTPS SSL-Bump transport test without CA trust verification" -CurlArgs @("-k", "--ssl-no-revoke", "-I", "-m", "25", "-x", $proxyUrl, "https://example.com/")
    Invoke-CurlTest -Title "HTTPS SSL-Bump trust test with Windows Root store" -CurlArgs @("--ssl-no-revoke", "-I", "-m", "25", "-x", $proxyUrl, "https://example.com/")
}

Write-Host "`nExpected block test: HTTP 403 and header X-Blocked-By: Proxylab-PathB-ICAP-Suricata" -ForegroundColor Green
Write-Host "If only the trust test fails: run .\Install-PathB-CA.ps1 from the generated windows-client-kit. Windows curl uses --ssl-no-revoke because the local lab CA does not provide CRL/OCSP infrastructure." -ForegroundColor Yellow
