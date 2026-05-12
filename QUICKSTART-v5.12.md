# Path-B v5.12 Quickstart

This quickstart deploys a non-production lab with one proxy VM and one ICAP/Suricata VM.

## 1. Prepare configuration

```bash
unzip path-b-external-suricata-ips_v5.12_public-edition.zip
cd path-b-external-suricata-ips

bash scripts/init-config.sh \
  --proxy-ip <PROXY_VM_IP> \
  --icap-ip <ICAP_SURICATA_VM_IP> \
  --gateway-ip <GATEWAY_IP> \
  --client-ip <TEST_CLIENT_IP> \
  --force

bash scripts/show-config.sh --config deployment.env
```

Example:

```bash
bash scripts/init-config.sh \
  --proxy-ip 10.10.10.20 \
  --icap-ip 10.10.10.30 \
  --gateway-ip 10.10.10.1 \
  --client-ip 10.10.10.40 \
  --force
```

## 2. Install ICAP/Suricata VM

Run on the ICAP/Suricata VM:

```bash
sudo bash scripts/install.sh --role icap --config deployment.env
sudo bash scripts/verify.sh --role icap --config deployment.env
```

Expected result:

```text
ICAP OPTIONS OK
REQMOD test header blocked
RESPMOD test body blocked
Healthcheck healthy=true
```

## 3. Install proxy VM

Run on the Squid proxy VM:

```bash
sudo bash scripts/install.sh --role proxy --config deployment.env
sudo bash scripts/verify.sh --role proxy --config deployment.env --curl-test
```

Expected result:

```text
Proxy verification: FAIL=0
HTTP baseline test OK
HTTP block test OK
HTTPS SSL-Bump test OK
```

## 4. Windows test client

Copy this generated file from the proxy VM to the Windows test client:

```text
certs/proxy/pathb-windows-client-kit.zip
```

Then run:

```powershell
Expand-Archive .\pathb-windows-client-kit.zip -DestinationPath .\pathb-kit -Force
cd .\pathb-kit\windows-client-kit
powershell -ExecutionPolicy Bypass -File .\Start-PathB-Browser-Test.ps1 -InstallCAFirst -StartUrl https://example.com/
powershell -ExecutionPolicy Bypass -File .\Test-PathB-Proxy.ps1
```

## 5. EICAR response blocking test

```powershell
curl.exe --ssl-no-revoke -i -x http://<PROXY_VM_IP>:3128 https://secure.eicar.org/eicar.com
curl.exe --ssl-no-revoke -i -x http://<PROXY_VM_IP>:3128 https://secure.eicar.org/eicar.com.txt
```

Expected result:

```text
HTTP/1.1 403 Forbidden
X-Blocked-By: Proxylab-PathB-ICAP-Suricata
```

## 6. Metrics

```bash
curl -s http://<ICAP_SURICATA_VM_IP>:2345/metrics | egrep 'requests_|blocked|bypass|pcap|queue|eve|errors|fail_open'
```
