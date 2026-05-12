# Path-B External Suricata IPS v5.12

**Community Lab Preview — source-available, not open source, not production-ready.**

Path-B is a lab-only SSL inspection research system for testing **Squid SSL-Bump**, an **external ICAP server**, and **Suricata-based allow/block decisions** on Squid-decrypted HTTP request and response data.

```text
Client -> Squid SSL-Bump -> ICAP REQMOD/RESPMOD -> Path-B ICAP Server -> Suricata -> Allow/Block -> Squid -> Client
```

## License and use limits

Path-B is released under the **Path-B Community Lab License v1.0**. Free private and non-commercial lab testing is allowed. Commercial, enterprise, production, managed-service, redistribution, sublicensing, publication of modified versions, and derivative works require prior written permission or a commercial license.

This is **not** an OSI-approved open-source license. See [`LICENSE.md`](LICENSE.md).

## Scope

Path-B v5.12 is designed for an isolated Ubuntu 24.04 LTS lab with:

- one Squid proxy VM,
- one ICAP/Suricata VM,
- one or more test clients,
- a trusted Squid inspection CA installed only on test clients.

It is not a turnkey production security product. Before any production-like use, perform legal review, privacy review, hardening, monitoring, backup planning, certificate lifecycle management, fail-closed testing, load testing, rollback planning, and a full change/risk assessment.

## How the detection path works

Squid decrypts HTTPS through SSL-Bump and forwards the resulting HTTP transaction to the external Path-B ICAP server. The ICAP server converts selected HTTP data into a synthetic TCP/HTTP PCAP, submits it to Suricata through the Unix-socket `pcap-file` interface, reads Suricata alerts from `eve.json`, and returns either:

- `ICAP 204 No Content` to allow Squid to continue with the original object, or
- `ICAP 200` with an HTTP `403 Forbidden` block page.

## v5.12 highlights

- Balanced browser-safe inspection mode.
- ICAP Preview support for lower latency.
- Conservative REQMOD static-asset bypass for trivial GET requests.
- RESPMOD scanning for text, small downloads, EICAR, and policy markers.
- EICAR `.com` and `.com.txt` response blocking.
- Lightweight Suricata EVE output focused on alerts.
- Metrics for PCAP build time, Suricata submit time, queue wait time, EVE wait time, static bypass ratio, and slow requests.
- Windows client kit for isolated browser testing without changing global Windows proxy settings.
- GitHub Actions static validation.

## Quick start

Create a deployment configuration:

```bash
unzip path-b-external-suricata-ips_v5.12_public-edition.zip
cd path-b-external-suricata-ips

bash scripts/init-config.sh \
  --proxy-ip 10.10.10.20 \
  --icap-ip 10.10.10.30 \
  --gateway-ip 10.10.10.1 \
  --client-ip 10.10.10.40 \
  --force

bash scripts/show-config.sh --config deployment.env
```

Install the ICAP/Suricata VM first:

```bash
sudo bash scripts/install.sh --role icap --config deployment.env
sudo bash scripts/verify.sh --role icap --config deployment.env
```

Install the proxy VM second:

```bash
sudo bash scripts/install.sh --role proxy --config deployment.env
sudo bash scripts/verify.sh --role proxy --config deployment.env --curl-test
```

Copy the generated Windows kit from the proxy VM to the Windows test client:

```text
certs/proxy/pathb-windows-client-kit.zip
```

On Windows:

```powershell
Expand-Archive .\pathb-windows-client-kit.zip -DestinationPath .\pathb-kit -Force
cd .\pathb-kit\windows-client-kit
powershell -ExecutionPolicy Bypass -File .\Start-PathB-Browser-Test.ps1 -InstallCAFirst -StartUrl https://example.com/
powershell -ExecutionPolicy Bypass -File .\Test-PathB-Proxy.ps1
```

## Repository layout

```text
path-b-external-suricata-ips/
├── LICENSE.md
├── README.md
├── deployment.env.example
├── examples/
├── scripts/
├── icap-vm/
├── proxy-vm/
├── client-tools/windows/
├── tests/
├── docs/
├── wiki/
└── .github/
```

## Documentation

Start here:

- [`QUICKSTART-v5.12.md`](QUICKSTART-v5.12.md)
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- [`docs/INSTALLATION.md`](docs/INSTALLATION.md)
- [`docs/OPERATIONS.md`](docs/OPERATIONS.md)
- [`docs/PERFORMANCE.md`](docs/PERFORMANCE.md)
- [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md)
- [`wiki/Home.md`](wiki/Home.md)

## Security reminder

Do not commit generated CAs, private keys, Windows client kits, runtime logs, production data, or personal data. See [`SECURITY.md`](SECURITY.md).
