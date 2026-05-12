<#
Path-B v5.12 — starts Edge/Chrome with an isolated test profile and proxy.
Does NOT change global Windows proxy settings. RustDesk remains unaffected.
#>
param(
    [string]$ProxyHost = "10.10.10.20",
    [int]$ProxyPort = 3128,
    [string]$StartUrl = "https://example.com/",
    [string]$ProfileDir = "$env:TEMP\PathB-Browser-Test",
    [string]$Browser = "auto",
    [switch]$InstallCAFirst
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

function Get-BrowserPath {
    param([string]$RequestedBrowser)

    $programFiles = [Environment]::GetFolderPath("ProgramFiles")
    $programFilesX86 = [Environment]::GetFolderPath("ProgramFilesX86")
    $edgeCandidates = @(
        (Join-Path $programFilesX86 "Microsoft\Edge\Application\msedge.exe"),
        (Join-Path $programFiles "Microsoft\Edge\Application\msedge.exe")
    )
    $chromeCandidates = @(
        (Join-Path $programFiles "Google\Chrome\Application\chrome.exe"),
        (Join-Path $programFilesX86 "Google\Chrome\Application\chrome.exe")
    )

    if ($RequestedBrowser -eq "edge") {
        $candidates = $edgeCandidates
    }
    elseif ($RequestedBrowser -eq "chrome") {
        $candidates = $chromeCandidates
    }
    else {
        $candidates = $edgeCandidates + $chromeCandidates
    }

    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) {
            return $candidate
        }
    }

    throw "No Edge/Chrome browser found. Check -Browser edge or -Browser chrome."
}

Import-PathBSettings

if ($InstallCAFirst) {
    & powershell.exe -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "Install-PathB-CA.ps1")
    if ($LASTEXITCODE -ne 0) {
        throw "CA import failed. Browser test will not be started."
    }
}
elseif (-not (Test-Path (Join-Path $PSScriptRoot "myCA.crt"))) {
    Write-Host "Note: The current kit does not contain myCA.crt. HTTPS will then show certificate errors." -ForegroundColor Yellow
    Write-Host "Use the generated kit from the proxy VM: certs\proxy\pathb-windows-client-kit.zip" -ForegroundColor Yellow
}

$browserPath = Get-BrowserPath -RequestedBrowser $Browser
New-Item -ItemType Directory -Path $ProfileDir -Force | Out-Null

$proxyEndpoint = "{0}:{1}" -f $ProxyHost, $ProxyPort
$proxyServer = "http://{0}" -f $proxyEndpoint
$proxyBypass = "<-loopback>;localhost;127.0.0.1;192.168.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*"

$argsList = @(
    "--user-data-dir=$ProfileDir",
    "--no-first-run",
    "--disable-quic",
    "--disable-background-networking",
    "--disable-component-update",
    "--proxy-server=$proxyServer",
    "--proxy-bypass-list=$proxyBypass",
    $StartUrl
)

Write-Host "Starting isolated browser test..." -ForegroundColor Green
Write-Host "Browser: $browserPath"
Write-Host "Proxy:   $proxyServer"
Write-Host "Profile:  $ProfileDir"
Write-Host "Note: global Windows proxy settings remain unchanged."
Start-Process -FilePath $browserPath -ArgumentList $argsList
