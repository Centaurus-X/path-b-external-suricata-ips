# Windows Client Test

Copy the generated kit from the proxy VM:

```text
certs/proxy/pathb-windows-client-kit.zip
```

Run on Windows:

```powershell
Expand-Archive .\pathb-windows-client-kit.zip -DestinationPath .\pathb-kit -Force
cd .\pathb-kit\windows-client-kit
powershell -ExecutionPolicy Bypass -File .\Start-PathB-Browser-Test.ps1 -InstallCAFirst -StartUrl https://example.com/
powershell -ExecutionPolicy Bypass -File .\Test-PathB-Proxy.ps1
```

The browser test uses an isolated profile and does not change global Windows proxy settings.
