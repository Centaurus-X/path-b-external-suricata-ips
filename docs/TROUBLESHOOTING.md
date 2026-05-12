# Troubleshooting — Path-B v5.12

## ICAP protocol error in browser

Check the ICAP VM first:

```bash
sudo systemctl status icap-suricata-engine --no-pager -l
sudo systemctl status icap-suricata-server --no-pager -l
curl http://<ICAP_VM_IP>:2345/healthz
```

Then check proxy-to-ICAP connectivity:

```bash
sudo bash scripts/verify.sh --role proxy --config deployment.env --curl-test
```

## EICAR is not blocked

Check RESPMOD and EVE:

```bash
curl -s http://<ICAP_VM_IP>:2345/metrics | egrep 'blocked|respmod|force_scan|small_body'
sudo tail -n 200 /var/log/suricata-icap/eve.json
```

## TLS errors on selected test sites

Some legacy or security test sites may fail when actively bumped. Add them to Squid splice/bypass rules in `/etc/squid/ssl-bypass.regex` and reload Squid.

## Slow browsing

Check metrics:

```bash
curl -s http://<ICAP_VM_IP>:2345/metrics | egrep 'avg_pcap|avg_suricata|avg_eve|queue|bypass|errors|fail_open'
```

Interpretation:

```text
High avg_pcap_build_ms          PCAP build/cleanup bottleneck
High avg_suricata_queue_wait_ms Suricata pcap-file queue bottleneck
High avg_eve_wait_ms            Alert correlation bottleneck
Low reqmod_bypass_ratio         Too many trivial GETs hit Suricata
```
