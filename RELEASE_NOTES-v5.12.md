# Release Notes — Path-B v5.12 Community Lab Preview

## Status

Path-B v5.12 is a source-available, non-production lab release. It is intended for private, educational, and non-commercial testing only.

## Highlights

- External Path-B ICAP server for Squid REQMOD and RESPMOD.
- Suricata inspection of Squid-decrypted HTTP data through synthetic PCAP submission.
- EICAR `.com` and `.com.txt` response blocking.
- REQMOD test-header blocking.
- Browser-stable ICAP Preview implementation.
- Conservative REQMOD static-asset bypass.
- Alert-only Suricata EVE output profile.
- Metrics for PCAP build, Suricata submit, queue wait, EVE wait, static bypass, slow requests, and fail-open/fail-closed behavior.
- Windows isolated browser test kit.
- GitHub-ready documentation and static validation.

## Known limits

- This is not a production security product.
- Full-body inspection mode is available for lab testing but is slower.
- Suricata `pcap-file` submission is robust but not an ideal high-throughput synchronous streaming interface.
- Some TLS endpoints may need Squid splice/bypass rules.
- Malware detection depends on rules, policy, protocol visibility, and response handling.

## Recommended next research steps

- PCAP cleanup optimization.
- Suricata engine pool.
- Event-driven EVE correlation.
- Optional virtual live-flow bus research architecture.
- Suricata 8 compatibility profile.
