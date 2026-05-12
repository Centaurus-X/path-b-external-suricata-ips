# Architecture

```text
Client -> Squid SSL-Bump -> ICAP REQMOD/RESPMOD -> Path-B ICAP Server -> Suricata -> Verdict -> Squid -> Client
```

Squid decrypts HTTPS in the lab. The Path-B ICAP server receives the decrypted HTTP request or response, creates a synthetic TCP/HTTP PCAP, submits it to Suricata, reads alerts from EVE, and returns an ICAP allow/block verdict.

Suricata receives cleartext HTTP as synthetic PCAP, not encrypted TLS.
