# Installation Guide — Path-B v5.12

## Requirements

- Ubuntu Server 24.04 LTS on both Linux VMs.
- One Squid proxy VM.
- One ICAP/Suricata VM.
- One test client.
- Network reachability:
  - client to proxy TCP/3128,
  - proxy to ICAP TCP/1345,
  - proxy to Internet,
  - ICAP VM local health TCP/2345.

## Create deployment.env

```bash
bash scripts/init-config.sh \
  --proxy-ip <PROXY_VM_IP> \
  --icap-ip <ICAP_SURICATA_VM_IP> \
  --gateway-ip <GATEWAY_IP> \
  --client-ip <TEST_CLIENT_IP> \
  --force
```

Review:

```bash
bash scripts/show-config.sh --config deployment.env
```

## Install ICAP/Suricata VM

```bash
sudo bash scripts/install.sh --role icap --config deployment.env
sudo bash scripts/verify.sh --role icap --config deployment.env
```

## Install proxy VM

```bash
sudo bash scripts/install.sh --role proxy --config deployment.env
sudo bash scripts/verify.sh --role proxy --config deployment.env --curl-test
```

## Windows test client

Copy `certs/proxy/pathb-windows-client-kit.zip` from the proxy VM to the Windows test client and run the included PowerShell scripts.

## Fail-open and fail-closed

Lab default:

```text
ICAP_SURICATA_BYPASS=off
FAIL_CLOSED=0
```

After successful lab validation, `FAIL_CLOSED=1` can be tested intentionally.
