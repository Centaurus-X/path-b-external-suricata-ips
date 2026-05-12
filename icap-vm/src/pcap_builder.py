#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pcap_builder.py

Path-B v5.12: Pure-Python PCAP builder without external dependencies.

Baut aus HTTP-cleartext eine minimale TCP-Session, welche Suricata per
unix-socket `pcap-file` analysieren can.

Most important v5.12 fix:
- HTTP-Request-/Response-Payloads are in realistische TCP-Segmente zerlegt.
  Dadurch entstehen no IPv4/TCP-Segmente > 65535 Byte mehr.
- Large browser responses no longer create struct.error and the
  ICAP-Server liefert Squid weiterhin eine valide ICAP-Antwort.

Design: funktional, no OOP.
"""
import os
import socket
import struct
import time

PCAP_MAGIC = 0xA1B2C3D4
PCAP_VERSION = (2, 4)
LINKTYPE_ETHERNET = 1
ETHER_TYPE_IPV4 = 0x0800
PROTO_TCP = 6

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10

DEFAULT_TCP_MSS = 1400
MAX_IPV4_TOTAL_LENGTH = 65535
IPV4_HEADER_LENGTH = 20
TCP_HEADER_LENGTH = 20
MAX_TCP_PAYLOAD_BY_IPV4 = MAX_IPV4_TOTAL_LENGTH - IPV4_HEADER_LENGTH - TCP_HEADER_LENGTH


def _env_int(name, default):
    try:
        return int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default


def _tcp_mss():
    value = _env_int("PCAP_TCP_MSS", DEFAULT_TCP_MSS)
    if value < 256:
        return DEFAULT_TCP_MSS
    if value > MAX_TCP_PAYLOAD_BY_IPV4:
        return DEFAULT_TCP_MSS
    return value


def _ones_complement_sum(data):
    if len(data) % 2 == 1:
        data = data + b"\x00"
    total = 0
    for idx in range(0, len(data), 2):
        total += (data[idx] << 8) + data[idx + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _ipv4_checksum(header):
    return _ones_complement_sum(header)


def _tcp_checksum(saddr_b, daddr_b, tcp_segment):
    segment_len = len(tcp_segment)
    if segment_len > MAX_IPV4_TOTAL_LENGTH:
        raise ValueError("tcp segment too large for IPv4 pseudo-header: %d" % segment_len)
    pseudo = (
        saddr_b
        + daddr_b
        + b"\x00"
        + struct.pack(">B", PROTO_TCP)
        + struct.pack(">H", segment_len)
    )
    return _ones_complement_sum(pseudo + tcp_segment)


def pcap_global_header():
    return struct.pack(
        "<IHHiIII",
        PCAP_MAGIC,
        PCAP_VERSION[0],
        PCAP_VERSION[1],
        0,
        0,
        65535,
        LINKTYPE_ETHERNET,
    )


def pcap_record(ts_sec, ts_usec, packet_bytes):
    return (
        struct.pack(
            "<IIII",
            ts_sec,
            ts_usec,
            len(packet_bytes),
            len(packet_bytes),
        )
        + packet_bytes
    )


def build_ethernet(src_mac=b"\x02\x00\x00\x00\x00\x01",
                   dst_mac=b"\x02\x00\x00\x00\x00\x02"):
    return dst_mac + src_mac + struct.pack(">H", ETHER_TYPE_IPV4)


def build_ipv4(saddr_str, daddr_str, payload_len, ip_id=0x1234, ttl=64):
    saddr_b = socket.inet_aton(saddr_str)
    daddr_b = socket.inet_aton(daddr_str)
    total_len = IPV4_HEADER_LENGTH + payload_len
    if total_len > MAX_IPV4_TOTAL_LENGTH:
        raise ValueError("ipv4 packet too large: %d" % total_len)

    header_partial = struct.pack(
        ">BBHHHBBH4s4s",
        0x45,
        0x00,
        total_len,
        ip_id & 0xFFFF,
        0x4000,
        ttl,
        PROTO_TCP,
        0,
        saddr_b,
        daddr_b,
    )
    checksum = _ipv4_checksum(header_partial)
    header = struct.pack(
        ">BBHHHBBH4s4s",
        0x45,
        0x00,
        total_len,
        ip_id & 0xFFFF,
        0x4000,
        ttl,
        PROTO_TCP,
        checksum,
        saddr_b,
        daddr_b,
    )
    return header, saddr_b, daddr_b


def build_tcp(saddr_b, daddr_b, sport, dport, seq, ack, flags, payload=b"",
              window=0xFFFF):
    if len(payload) > MAX_TCP_PAYLOAD_BY_IPV4:
        raise ValueError("tcp payload too large: %d" % len(payload))
    data_offset_byte = 0x50
    seq = seq & 0xFFFFFFFF
    ack = ack & 0xFFFFFFFF
    header_partial = struct.pack(
        ">HHIIBBHHH",
        sport,
        dport,
        seq,
        ack,
        data_offset_byte,
        flags,
        window,
        0,
        0,
    )
    checksum = _tcp_checksum(saddr_b, daddr_b, header_partial + payload)
    header = struct.pack(
        ">HHIIBBHHH",
        sport,
        dport,
        seq,
        ack,
        data_offset_byte,
        flags,
        window,
        checksum,
        0,
    )
    return header + payload


def build_packet(saddr_str, daddr_str, sport, dport, seq, ack, flags,
                 payload=b""):
    tcp = build_tcp(
        socket.inet_aton(saddr_str),
        socket.inet_aton(daddr_str),
        sport,
        dport,
        seq,
        ack,
        flags,
        payload,
    )
    ip_header, _saddr_b, _daddr_b = build_ipv4(
        saddr_str,
        daddr_str,
        payload_len=len(tcp),
    )
    return build_ethernet() + ip_header + tcp


def iter_chunks(data, chunk_size):
    pos = 0
    size = len(data)
    while pos < size:
        end = pos + chunk_size
        yield data[pos:end]
        pos = end


def _add_payload_segments(add_func, saddr, daddr, sport, dport, seq, ack,
                          payload, micro_off):
    mss = _tcp_mss()
    if not payload:
        return seq, micro_off
    for chunk in iter_chunks(payload, mss):
        add_func(
            build_packet(
                saddr,
                daddr,
                sport,
                dport,
                seq,
                ack,
                TCP_PSH | TCP_ACK,
                chunk,
            ),
            micro_off,
        )
        seq += len(chunk)
        micro_off += 100
    return seq, micro_off


def build_http_session_pcap(saddr, daddr, sport, dport, request_bytes,
                            response_bytes=b""):
    out = bytearray(pcap_global_header())
    ts = int(time.time())
    seq_c = 1000
    seq_s = 2000
    micro = 0

    def add(packet, micro_off):
        # PCAP usec must remain in the range 0..999999. Large
        # HTTP responses may create many TCP segments, so normalize the value.
        ts_sec = ts + (micro_off // 1000000)
        ts_usec = micro_off % 1000000
        out.extend(pcap_record(ts_sec, ts_usec, packet))

    add(build_packet(saddr, daddr, sport, dport, seq_c, 0, TCP_SYN), micro)
    micro += 100

    add(build_packet(daddr, saddr, dport, sport, seq_s, seq_c + 1,
                     TCP_SYN | TCP_ACK), micro)
    micro += 100

    seq_c += 1
    seq_s += 1
    add(build_packet(saddr, daddr, sport, dport, seq_c, seq_s, TCP_ACK), micro)
    micro += 100

    seq_c, micro = _add_payload_segments(
        add,
        saddr,
        daddr,
        sport,
        dport,
        seq_c,
        seq_s,
        request_bytes,
        micro,
    )

    add(build_packet(daddr, saddr, dport, sport, seq_s, seq_c, TCP_ACK), micro)
    micro += 100

    if response_bytes:
        seq_s, micro = _add_payload_segments(
            add,
            daddr,
            saddr,
            dport,
            sport,
            seq_s,
            seq_c,
            response_bytes,
            micro,
        )
        add(build_packet(saddr, daddr, sport, dport, seq_c, seq_s, TCP_ACK), micro)
        micro += 100

    add(build_packet(saddr, daddr, sport, dport, seq_c, seq_s,
                     TCP_FIN | TCP_ACK), micro)
    micro += 100
    seq_c += 1

    add(build_packet(daddr, saddr, dport, sport, seq_s, seq_c,
                     TCP_FIN | TCP_ACK), micro)

    return bytes(out)


def write_pcap(out_path, saddr, daddr, sport, dport, request_bytes,
               response_bytes=b""):
    pcap_data = build_http_session_pcap(
        saddr,
        daddr,
        sport,
        dport,
        request_bytes,
        response_bytes,
    )
    tmp = out_path + ".tmp"
    with open(tmp, "wb") as handle:
        handle.write(pcap_data)
    os.rename(tmp, out_path)
    return out_path
