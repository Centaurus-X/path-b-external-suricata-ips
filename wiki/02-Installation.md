# Installation

## Create configuration

```bash
bash scripts/init-config.sh \
  --proxy-ip <PROXY_VM_IP> \
  --icap-ip <ICAP_VM_IP> \
  --gateway-ip <GATEWAY_IP> \
  --client-ip <CLIENT_IP> \
  --force
```

## ICAP/Suricata VM

```bash
sudo bash scripts/install.sh --role icap --config deployment.env
sudo bash scripts/verify.sh --role icap --config deployment.env
```

## Proxy VM

```bash
sudo bash scripts/install.sh --role proxy --config deployment.env
sudo bash scripts/verify.sh --role proxy --config deployment.env --curl-test
```
