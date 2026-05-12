# Troubleshooting

## Browser shows ICAP protocol error

```bash
sudo systemctl status icap-suricata-engine --no-pager -l
sudo systemctl status icap-suricata-server --no-pager -l
curl http://<ICAP_VM_IP>:2345/healthz
```

## EICAR is not blocked

```bash
curl -s http://<ICAP_VM_IP>:2345/metrics | egrep 'blocked|respmod|force_scan|small_body'
sudo tail -n 200 /var/log/suricata-icap/eve.json
```

## Selected TLS sites fail

Add the affected domain to Squid splice/bypass rules and reload Squid.
