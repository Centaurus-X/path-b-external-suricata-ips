# Release v5.12

## Confirmed lab behavior

- SSL-Bump works with the generated CA.
- REQMOD blocking works.
- RESPMOD blocking works.
- EICAR `.com` and `.com.txt` are blocked.
- Normal browsing works in balanced mode.

## Known limits

- This is not production-ready.
- The Suricata `pcap-file` bridge is reliable for lab testing but not a native high-throughput streaming path.
- Some TLS test sites may require splice/bypass rules.
