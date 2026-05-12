#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
community_id.py — Bro/Zeek Community-ID v1.

Computes a canonical hash over the 5-tuple (saddr, daddr, sport,
dport, proto) that yields the same result when Suricata computes it as well.
We use it for correlation: the ICAP server precomputes the Community ID,
Suricata writes it to eve.json,
The ICAP server finds its verdict by matching this ID.

Spec: https://github.com/corelight/community-id-spec
"""
import base64
import hashlib
import socket
import struct

V1_PREFIX = "1:"


def _ip_to_bytes(addr):
    """IPv4 or IPv6 as bytes."""
    try:
        return socket.inet_pton(socket.AF_INET, addr)
    except (OSError, ValueError):
        return socket.inet_pton(socket.AF_INET6, addr)


def community_id_v1(saddr, daddr, sport, dport, proto=6, seed=0):
    """
    Compute Community ID v1 for the given 5-tuple.

    proto: 6=TCP, 17=UDP, 1=ICMP, etc.
    seed: optional salt. Default 0, identical to Suricata default.
    """
    a = _ip_to_bytes(saddr)
    b = _ip_to_bytes(daddr)

    # Sort endpoints — canonical independent of direction
    if (a, sport) > (b, dport):
        a, b = b, a
        sport, dport = dport, sport

    seed_bytes = struct.pack(">H", seed)
    proto_byte = struct.pack(">B", proto)
    pad = b"\x00"
    sport_bytes = struct.pack(">H", sport)
    dport_bytes = struct.pack(">H", dport)

    blob = seed_bytes + a + b + proto_byte + pad + sport_bytes + dport_bytes
    digest = hashlib.sha1(blob).digest()
    return V1_PREFIX + base64.b64encode(digest).decode("ascii")
