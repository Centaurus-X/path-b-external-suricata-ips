# Operations and Metrics — Path-B v5.12

## Health

```bash
curl http://<ICAP_VM_IP>:2345/healthz
```

Expected:

```json
{"healthy":true}
```

## Metrics

```bash
curl -s http://<ICAP_VM_IP>:2345/metrics | \
  egrep 'requests_|blocked|bypass|pcap|queue|eve|errors|fail_open|timeouts|aborts'
```

Important metrics:

| Metric | Meaning |
|---|---|
| `requests_total` | Total ICAP requests handled |
| `requests_blocked_total` | Block decisions returned to Squid |
| `reqmod_bypass_ratio` | Static REQMOD bypass effectiveness |
| `avg_pcap_build_ms` | Average synthetic PCAP build time |
| `avg_suricata_submit_ms` | Average Suricata Unix-socket submit time |
| `avg_suricata_queue_wait_ms` | Average queue wait time |
| `avg_eve_wait_ms` | Average alert correlation wait |
| `errors_total` | Runtime errors |
| `fail_open_total` | Fail-open decisions |

## Logs

```bash
sudo journalctl -u icap-suricata-server -f
sudo journalctl -u icap-suricata-engine -f
sudo tail -F /var/log/icap-suricata/server.log
sudo tail -F /var/log/suricata-icap/eve.json
sudo tail -F /var/log/squid/access.log
sudo tail -F /var/log/squid/cache.log
```
