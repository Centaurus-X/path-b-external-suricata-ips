<#
Path-B v5.12 — optional WinINET system proxy for the signed-in user.
For RustDesk tests, prefer not to use this script; use Start-PathB-Browser-Test.ps1 instead.
#>
param(
    [string]$ProxyHost = "10.10.10.20",
    [int]$ProxyPort = 3128,
    [switch]$Disable
)

$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
$backupPath = "$env:TEMP\PathB-WinINET-Proxy-Backup.reg"

if ($Disable) {
    Set-ItemProperty -Path $regPath -Name ProxyEnable -Value 0
    Write-Host "WinINET proxy disabled." -ForegroundColor Green
    Write-Host "Backup, if present: $backupPath"
    return
}

reg.exe export "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" $backupPath /y | Out-Null
$proxyServer = "{0}:{1}" -f $ProxyHost, $ProxyPort
$bypass = "<local>;localhost;127.0.0.1;192.168.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*"

Set-ItemProperty -Path $regPath -Name ProxyEnable -Value 1
Set-ItemProperty -Path $regPath -Name ProxyServer -Value $proxyServer
Set-ItemProperty -Path $regPath -Name ProxyOverride -Value $bypass

Write-Host "WinINET proxy enabled: $proxyServer" -ForegroundColor Green
Write-Host "Backup: $backupPath"
Write-Host "Disable: .\Set-PathB-SystemProxy.ps1 -Disable" -ForegroundColor Yellow
