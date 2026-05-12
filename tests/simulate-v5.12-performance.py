#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Path-B v5.12 local simulation without Suricata/systemd.
Checks ICAP preview detection, RESPMOD decisions, and PCAP segmentation.
"""
import os
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "icap-vm", "src")
sys.path.insert(0, SRC)

import icap_parser
import icap_suricata_server as server
import pcap_builder


def make_preview_message(preview_size, payload_size):
    request = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"
    response_header = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/html\r\n"
        b"Content-Length: " + str(payload_size).encode("ascii") + b"\r\n\r\n"
    )
    payload = b"A" * payload_size
    preview_payload = payload[:preview_size]
    body = request + response_header
    req_off = 0
    res_off = len(request)
    res_body_off = len(body)
    chunked = (b"%x\r\n" % len(preview_payload)) + preview_payload
    if payload_size <= preview_size:
        chunked += b"\r\n0; ieof\r\n\r\n"
    else:
        chunked += b"\r\n0\r\n"
    icap_head = (
        b"RESPMOD icap://127.0.0.1:1345/respmod ICAP/1.0\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Preview: " + str(preview_size).encode("ascii") + b"\r\n"
        b"X-Client-IP: 10.10.10.40\r\n"
        b"Encapsulated: req-hdr=" + str(req_off).encode("ascii") +
        b", res-hdr=" + str(res_off).encode("ascii") +
        b", res-body=" + str(res_body_off).encode("ascii") + b"\r\n\r\n"
    )
    return icap_head + body + chunked


def check_preview_cutoff():
    msg = make_preview_message(32768, 100000)
    if not server._icap_preview_cutoff_reached(msg):
        raise AssertionError("Preview cutoff was not detected")
    parsed = icap_parser.parse_icap_message(msg)
    response = icap_parser.extract_http_response_from_encapsulated(parsed["body"], parsed["encapsulated"])
    if len(response) < 32768:
        raise AssertionError("Preview response was not extracted")
    return len(msg)


def check_response_policy():
    body = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n\r\n" + body
    )
    should_scan, reason = server._response_should_scan(response, False, True)
    if not should_scan:
        raise AssertionError("EICAR response was not classified as scan-required: %s" % reason)
    return reason


def check_pcap_builder():
    request = b"GET /big HTTP/1.1\r\nHost: example.test\r\n\r\n"
    response = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" + (b"B" * (1024 * 1024))
    tmpdir = tempfile.mkdtemp(prefix="pathb-v512-")
    path = os.path.join(tmpdir, "big.pcap")
    start = time.perf_counter()
    pcap_builder.write_pcap(path, "10.10.10.40", "93.184.216.34", 41000, 80, request, response)
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    size = os.path.getsize(path)
    if size <= len(response):
        raise AssertionError("PCAP file is unexpectedly small")
    return int(elapsed_ms), size


def check_reqmod_static_bypass():
    request = (
        b"GET /assets/app.bundle.js?v=123 HTTP/1.1\r\n"
        b"Host: example.test\r\n"
        b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36\r\n"
        b"Accept: application/javascript\r\n\r\n"
    )
    should_bypass, reason = server._reqmod_should_bypass(request)
    if not should_bypass:
        raise AssertionError("static GET was not bypassed: %s" % reason)

    cobalt = (
        b"GET /assets/app.bundle.js HTTP/1.1\r\n"
        b"Host: example.test\r\n"
        b"User-Agent: Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1)\r\n\r\n"
    )
    should_bypass, _reason = server._reqmod_should_bypass(cobalt)
    if should_bypass:
        raise AssertionError("CobaltStrike UA must not be bypassed")

    marker = (
        b"GET /assets/logo.png HTTP/1.1\r\n"
        b"Host: example.test\r\n"
        b"User-Agent: Mozilla/5.0\r\n"
        b"X-Proxylab-Test: icap-suricata-trigger\r\n\r\n"
    )
    should_bypass, _reason = server._reqmod_should_bypass(marker)
    if should_bypass:
        raise AssertionError("X-Proxylab-Test must not be bypassed")
    return reason


def main():
    preview_len = check_preview_cutoff()
    bypass_reason = check_reqmod_static_bypass()
    reason = check_response_policy()
    elapsed_ms, pcap_size = check_pcap_builder()
    print("PASS preview_cutoff bytes=%d" % preview_len)
    print("PASS reqmod_static_bypass reason=%s" % bypass_reason)
    print("PASS response_policy reason=%s" % reason)
    print("PASS pcap_builder elapsed_ms=%d pcap_size=%d" % (elapsed_ms, pcap_size))


if __name__ == "__main__":
    main()
