#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EVE correlation for the ICAP/Suricata bridge.
"""
import functools
import json
import os
import time


def _read_new_lines(eve_path, last_pos):
    if not os.path.exists(eve_path):
        return [], last_pos
    size = os.path.getsize(eve_path)
    if size < last_pos:
        last_pos = 0
    if size == last_pos:
        return [], last_pos
    with open(eve_path, "r", encoding="utf-8", errors="replace") as handle:
        handle.seek(last_pos)
        data = handle.read()
    return data.splitlines(), size


def _json_or_none(line):
    try:
        return json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return None


def wait_for_match(eve_path, predicate, timeout_ms=1500, poll_ms=20, start_pos=None):
    deadline = time.monotonic() + timeout_ms / 1000.0
    last_pos = start_pos if start_pos is not None else (
        os.path.getsize(eve_path) if os.path.exists(eve_path) else 0
    )
    while time.monotonic() < deadline:
        lines, last_pos = _read_new_lines(eve_path, last_pos)
        for line in lines:
            if not line.strip():
                continue
            event = _json_or_none(line)
            if event is not None and predicate(event):
                return event
        time.sleep(poll_ms / 1000.0)
    return None


def _is_alert(obj):
    return obj.get("event_type") == "alert"


def _alert_sid(obj):
    alert = obj.get("alert", {}) if isinstance(obj, dict) else {}
    sid = alert.get("signature_id")
    if sid is None:
        sid = alert.get("sid")
    try:
        return int(sid)
    except (TypeError, ValueError):
        return None


def _int_or_none(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _is_alert_for_flow(community_id, src_port, obj):
    if not _is_alert(obj):
        return False
    if community_id and obj.get("community_id") == community_id:
        return True

    # REQMOD-Alerts laufen to_server: event.src_port == synthetischer Client-Port.
    # RESPMOD-Alerts laufen to_client: event.dest_port == synthetischer Client-Port.
    # Both directions must be accepted because not every Suricata/EVE
    # combination reliably emits community_id for pcap-file events.
    event_src_port = _int_or_none(obj.get("src_port"))
    event_dest_port = _int_or_none(obj.get("dest_port"))
    if src_port is None:
        return False
    return event_src_port == src_port or event_dest_port == src_port


def alert_predicate_combined(community_id, src_port):
    return functools.partial(_is_alert_for_flow, community_id, src_port)


def alert_is_in_sid_ranges(obj, ranges):
    sid = _alert_sid(obj)
    if sid is None:
        return False
    for start, end in ranges:
        if start <= sid <= end:
            return True
    return False


def parse_sid_ranges(text):
    ranges = []
    for token in text.split(","):
        item = token.strip()
        if not item:
            continue
        if "-" in item:
            left, right = item.split("-", 1)
        else:
            left, right = item, item
        try:
            ranges.append((int(left.strip()), int(right.strip())))
        except ValueError:
            continue
    return ranges



def wait_for_policy_match(eve_path, predicate, block_predicate, timeout_ms=1500,
                          poll_ms=20, start_pos=None):
    """
    Waits for alerts for an ICAP transaction and prioritizes blocking
    alerts. If only monitor/log alerts appear, the first matching alert is
    returned after the time window expires.
    """
    deadline = time.monotonic() + timeout_ms / 1000.0
    last_pos = start_pos if start_pos is not None else (
        os.path.getsize(eve_path) if os.path.exists(eve_path) else 0
    )
    first_match = None
    while time.monotonic() < deadline:
        lines, last_pos = _read_new_lines(eve_path, last_pos)
        for line in lines:
            if not line.strip():
                continue
            event = _json_or_none(line)
            if event is None or not predicate(event):
                continue
            if first_match is None:
                first_match = event
            if block_predicate(event):
                return event
        time.sleep(poll_ms / 1000.0)
    return first_match
