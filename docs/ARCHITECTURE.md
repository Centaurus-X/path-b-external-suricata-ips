# Architecture — Path-B v5.12

Path-B v5.12 is a lab-only external ICAP and Suricata inspection path for Squid SSL-Bump.

## Data path

```text
Client
  -> Squid SSL-Bump
  -> ICAP REQMOD/RESPMOD
  -> Path-B Python ICAP server
  -> synthetic TCP/HTTP PCAP
  -> Suricata Unix socket pcap-file
  -> eve.json alert correlation
  -> ICAP allow/block verdict
  -> Squid
  -> Client
```

## Components

### Squid proxy VM

- Terminates or bumps HTTPS for lab clients.
- Sends decrypted HTTP transactions to the external ICAP service.
- Applies ICAP verdicts.
- Generates a lab inspection CA and a Windows client kit.

### Path-B ICAP/Suricata VM

- Runs the custom Path-B Python ICAP server.
- Converts selected HTTP data into synthetic PCAP files.
- Submits PCAP files to Suricata through the Unix-socket `pcap-file` interface.
- Reads Suricata alerts from `eve.json`.
- Returns `ICAP 204` for allowed traffic or an HTTP `403` block page.

### Suricata

- Runs as a dedicated ICAP-fed Suricata engine.
- Uses a reduced alert-focused EVE profile.
- Applies local lab rules in the `9100xxx` SID range.

## Why synthetic PCAP?

Suricata is optimized for packets and flows. Squid ICAP exposes HTTP objects, not packet streams. Path-B bridges that mismatch by building a synthetic TCP/HTTP PCAP from the ICAP cleartext transaction.

## v5.12 performance strategy

- ICAP Preview for early decisions.
- Fast allow when the Suricata queue drains without alerts.
- Conservative REQMOD static-asset bypass.
- RESPMOD scanning focused on text, small downloads, EICAR, and policy markers.
- Metrics for every major latency stage.

## Limits

The `pcap-file` path is reliable for lab testing, but it is not a native high-throughput streaming interface. Enterprise evolution should evaluate Suricata engine pools and a virtual live-flow bus.
