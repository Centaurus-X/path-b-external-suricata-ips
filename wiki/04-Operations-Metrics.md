# Operations and Metrics

Health:

```bash
curl http://<ICAP_VM_IP>:2345/healthz
```

Metrics:

```bash
curl -s http://<ICAP_VM_IP>:2345/metrics | egrep 'requests_|blocked|bypass|pcap|queue|eve|errors|fail_open'
```

Key metrics:

- `requests_blocked_total`
- `reqmod_bypass_ratio`
- `avg_pcap_build_ms`
- `avg_suricata_queue_wait_ms`
- `avg_eve_wait_ms`
- `errors_total`
- `fail_open_total`
