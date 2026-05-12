# Performance Notes — Path-B v5.12

## Current bottleneck model

The most expensive path is usually not Squid itself. The expensive path is:

```text
ICAP object -> synthetic PCAP -> Suricata pcap-file queue -> eve.json correlation -> ICAP verdict
```

Modern websites may create hundreds of small objects. Each object can become a separate ICAP transaction.

## v5.12 optimization levers

| Setting | Purpose |
|---|---|
| `ICAP_WORKERS` | Parallel ICAP request handling |
| `ICAP_SURICATA_MAX_CONN` | Squid-side ICAP connection limit |
| `SURICATA_PIPELINE_CONCURRENCY` | Parallel PCAP submission pipeline |
| `ICAP_PREVIEW_ENABLE` | Early decision support |
| `ICAP_PREVIEW_SIZE` | Preview body size |
| `REQMOD_STATIC_BYPASS_ENABLED` | Bypass trivial static GET requests |
| `RESPMOD_MAX_SCAN_BYTES` | Maximum synchronous response scan size |
| `RESPMOD_SCAN_SMALL_BODIES_BYTES` | Scan small downloads regardless of content type |
| `RESPMOD_SKIP_COMPRESSED` | Skip compressed responses for browser stability |

## Safe tuning order

1. Keep v5.12 balanced defaults.
2. Measure metrics after real browsing.
3. If `avg_pcap_build_ms` grows over time, optimize PCAP cleanup.
4. If `avg_suricata_queue_wait_ms` is high, evaluate a Suricata engine pool.
5. If `avg_eve_wait_ms` is high, improve event-driven alert correlation.
6. Only then consider full-body inspection.

## Full-body lab mode

Full-body mode is slower and should be used only for controlled lab tests:

```bash
sudo sed -i 's/^RESPMOD_MAX_SCAN_BYTES=.*/RESPMOD_MAX_SCAN_BYTES=0/' /etc/icap-suricata/icap-server.env
sudo sed -i 's/^RESPMOD_SKIP_COMPRESSED=.*/RESPMOD_SKIP_COMPRESSED=0/' /etc/icap-suricata/icap-server.env
sudo sed -i 's/^RESPMOD_SCAN_ALL_CONTENT_TYPES=.*/RESPMOD_SCAN_ALL_CONTENT_TYPES=1/' /etc/icap-suricata/icap-server.env
sudo systemctl restart icap-suricata-server
```
