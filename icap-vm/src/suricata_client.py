#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Suricata-Unix-Socket-Client for Path-B v5.12.

Supports standard commands and pcap-file submission. The client intentionally
contains small retry/backoff logic because Suricata may answer EAGAIN on the
Unix socket during many short pcap-file submissions.
"""
import errno
import json
import socket
import time

RETRY_ERRNOS = set([
    errno.EAGAIN,
    errno.EWOULDBLOCK,
    errno.ECONNREFUSED,
    errno.EINTR,
])


def _recv_until_newline(sock, max_bytes=65536):
    buf = bytearray()
    while len(buf) < max_bytes:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf.extend(chunk)
        if b"\n" in chunk:
            break
    return bytes(buf).split(b"\n", 1)[0]


def _retryable_oserror(exc):
    return getattr(exc, "errno", None) in RETRY_ERRNOS


def call(socket_path, command, arguments=None, timeout_s=5.0):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout_s)
    try:
        sock.connect(socket_path)
        sock.sendall(json.dumps({"version": "0.2"}).encode("utf-8") + b"\n")
        handshake_raw = _recv_until_newline(sock)
        if not handshake_raw:
            raise RuntimeError("empty handshake response from suricata")
        handshake = json.loads(handshake_raw.decode("utf-8"))
        if handshake.get("return") != "OK":
            raise RuntimeError("suricata handshake failed: %r" % (handshake,))

        message = {"command": command}
        if arguments is not None:
            message["arguments"] = arguments
        sock.sendall(json.dumps(message).encode("utf-8") + b"\n")
        response_raw = _recv_until_newline(sock)
        if not response_raw:
            raise RuntimeError("empty response from suricata command %s" % command)
        return json.loads(response_raw.decode("utf-8"))
    finally:
        try:
            sock.close()
        except OSError:
            pass


def call_with_retry(socket_path, command, arguments=None, timeout_s=5.0,
                    max_attempts=6, base_sleep_s=0.04):
    deadline = time.monotonic() + timeout_s
    attempt = 0
    while True:
        attempt += 1
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            remaining = 0.2
        try:
            return call(socket_path, command, arguments, timeout_s=remaining)
        except OSError as exc:
            if attempt >= max_attempts or not _retryable_oserror(exc):
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(min(0.5, base_sleep_s * attempt))


def submit_pcap(socket_path, pcap_path, output_dir, timeout_s=5.0):
    return call_with_retry(
        socket_path,
        "pcap-file",
        {"filename": pcap_path, "output-dir": output_dir},
        timeout_s=timeout_s,
    )


def health(socket_path, timeout_s=2.0):
    try:
        response = call_with_retry(socket_path, "uptime", timeout_s=timeout_s, max_attempts=3)
        return response.get("return") == "OK"
    except (OSError, RuntimeError, json.JSONDecodeError):
        return False


def pcap_queue_number(socket_path, timeout_s=0.2):
    try:
        response = call_with_retry(
            socket_path,
            "pcap-file-number",
            timeout_s=timeout_s,
            max_attempts=1,
        )
    except (OSError, RuntimeError, json.JSONDecodeError):
        return None
    if response.get("return") != "OK":
        return None
    message = response.get("message")
    if isinstance(message, int):
        return message
    if isinstance(message, str):
        digits = "".join(ch for ch in message if ch.isdigit())
        if digits:
            return int(digits)
    return None


def wait_for_queue_drain(socket_path, deadline_monotonic, poll_s=0.025):
    unknown_count = 0
    while time.monotonic() < deadline_monotonic:
        number = pcap_queue_number(socket_path, timeout_s=0.2)
        if number == 0:
            return True
        if number is None:
            unknown_count += 1
            if unknown_count >= 2:
                # Command not available or temporarily not evaluable.
                # Do not wait until the full verdict timeout; retry with
                # kurzem Alert-Grace fortfahren.
                return None
        else:
            unknown_count = 0
        time.sleep(poll_s)
    return False
