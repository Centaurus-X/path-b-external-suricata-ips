# Contributing

Thank you for your interest in Path-B.

This project is source-available under the Path-B Community Lab License v1.0. It is not an open-source project. Pull requests and modifications are reviewed only by prior agreement. Do not publish modified versions or derivative works without written permission.

## Issue reports

Please include:

- Path-B version,
- Ubuntu version,
- Squid version,
- Suricata version,
- proxy role or ICAP role,
- sanitized `deployment.env`,
- relevant sanitized logs,
- exact verification command and output.

Do not upload private keys, generated CAs, production logs, credentials, personal data, or customer data.

## Static validation

```bash
bash -n scripts/*.sh icap-vm/scripts/*.sh proxy-vm/scripts/*.sh tests/*.sh
python3 -m py_compile icap-vm/src/*.py tests/simulate-v5.12-performance.py
python3 tests/simulate-v5.12-performance.py
```
