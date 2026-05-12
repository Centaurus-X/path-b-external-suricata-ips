# Path-B v5.12 — Windows Client Test

Use the generated Windows client kit from the proxy VM. The source folder `client-tools\windows` intentionally does not contain `myCA.crt`.

Generated kit on the proxy VM:

```text
<repo>/path-b-external-suricata-ips/certs/proxy/pathb-windows-client-kit.zip
```

Recommended with RustDesk or any remote-control session:

```powershell
powershell -ExecutionPolicy Bypass -File .\Start-PathB-Browser-Test.ps1 -InstallCAFirst -StartUrl https://example.com/
```

The browser launcher starts Edge/Chrome with an isolated profile and proxy settings. Global Windows proxy settings remain unchanged.

`Set-PathB-SystemProxy.ps1` is optional. It changes the WinINET proxy for the signed-in user and should not be used during remote-control sessions unless you intentionally want a global proxy test.
