#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Path-B v5.12: ICAP server with Suricata backend.

Data flow:
  Squid SSL-Bump/Reverse-Proxy -> ICAP REQMOD/RESPMOD -> HTTP-cleartext
  -> synthetische PCAP -> Suricata unix-socket pcap-file -> eve.json
  -> ICAP 204 allow or ICAP 200 + HTTP 403 block.

v5.12 Fokus:
- Browser-stable operation through Fast-Allow and ICAP 204 for unchanged objects.
- No return of complete original responses to Squid for allow decisions.
- RESPMOD is klein/textbasiert gescannt; largee/binary Responses are schnell
  allowed unchanged.
"""
import functools
import ipaddress
import json
import logging
import os
import socket
import sys
import threading
import time
import traceback
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import community_id as cid_mod
import eve_correlator
import icap_parser
import pcap_builder
import suricata_client

ISTAG = "PROXYLAB-PATHB-ICAP-SURICATA-V5.12"
DEFAULT_RESPONSE_REQUEST = b"GET / HTTP/1.1\r\nHost: icap-response.local\r\n\r\n"
TEXT_RESPONSE_MARKERS = (
    "text/",
    "application/json",
    "application/javascript",
    "application/x-javascript",
    "application/ecmascript",
    "application/xml",
    "application/xhtml+xml",
    "application/rss+xml",
    "application/atom+xml",
    "image/svg+xml",
)
SKIP_ENCODINGS = ("gzip", "br", "zstd", "deflate")

DEFAULT_STATIC_BYPASS_EXTENSIONS = (
    ".css", ".js", ".mjs", ".map",
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".avif", ".bmp",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".mp4", ".webm", ".mp3", ".m4a", ".m4v", ".ogg", ".wav",
    ".wasm", ".json",
)

SUSPICIOUS_REQMOD_UA_SUBSTRINGS = (
    "XMRig/",
)

# CobaltStrike default UA fingerprint from the local block rule.
COBALTSTRIKE_UA_NEEDLES = ("MSIE 10.0", "Windows NT 6.1")

# These URIs must not be pre-bypassed even if the extension looks static.
DEFENSIVE_REQMOD_URI_NEEDLES = ("/cm/", "/admin/get.php")



def _env_int(name, default):
    try:
        return int(os.environ.get(name, str(default)))
    except ValueError:
        return default


def _env_float(name, default):
    try:
        return float(os.environ.get(name, str(default)))
    except ValueError:
        return default


def _env_bool(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _env_csv(name):
    raw = os.environ.get(name, "")
    return [item.strip() for item in raw.split(",") if item.strip()]


def _env_text_markers():
    raw = os.environ.get("RESPMOD_TEXT_CONTENT_TYPES", "")
    if not raw.strip():
        return TEXT_RESPONSE_MARKERS
    values = []
    for item in raw.split(","):
        value = item.strip().lower()
        if value:
            values.append(value)
    return tuple(values) if values else TEXT_RESPONSE_MARKERS


CFG = {
    "bind": os.environ.get("ICAP_BIND", "10.10.99.30"),
    "port": _env_int("ICAP_PORT", 1345),
    "health_bind": os.environ.get("HEALTH_BIND", os.environ.get("ICAP_BIND", "10.10.99.30")),
    "health_port": _env_int("HEALTH_PORT", 2345),
    "workers": _env_int("ICAP_WORKERS", 8),
    "max_request_bytes": _env_int("MAX_REQUEST_BYTES", 32 * 1024 * 1024),
    "socket_timeout_s": _env_float("SOCKET_TIMEOUT_S", 15.0),
    "icap_read_timeout_s": _env_float("ICAP_READ_TIMEOUT_S", 0.8),
    "suricata_sock": os.environ.get("SURICATA_SOCKET", "/run/suricata-icap/suricata-cmd.socket"),
    "eve_path": os.environ.get("EVE_PATH", "/var/log/suricata-icap/eve.json"),
    "suricata_output_dir": os.environ.get("SURICATA_OUTPUT_DIR", "/var/log/suricata-icap"),
    "pcap_tmpdir": os.environ.get("PCAP_TMPDIR", "/run/icap-suricata/pcaps"),
    "pcap_retention_seconds": _env_int("PCAP_RETENTION_SECONDS", 300),
    "wait_timeout_ms": _env_int("WAIT_TIMEOUT_MS", 1000),
    "reqmod_wait_timeout_ms": _env_int("REQMOD_WAIT_TIMEOUT_MS", _env_int("WAIT_TIMEOUT_MS", 1000)),
    "respmod_wait_timeout_ms": _env_int("RESPMOD_WAIT_TIMEOUT_MS", 300),
    "alert_post_drain_grace_ms": _env_int("ALERT_POST_DRAIN_GRACE_MS", _env_int("EVE_ALERT_GRACE_MS", 60)),
    "suricata_queue_poll_ms": _env_int("SURICATA_QUEUE_POLL_MS", 10),
    "suricata_pipeline_concurrency": _env_int("SURICATA_PIPELINE_CONCURRENCY", 4),
    "suricata_submit_retries": _env_int("SURICATA_SUBMIT_RETRIES", 3),
    "suricata_retry_sleep_ms": _env_int("SURICATA_RETRY_SLEEP_MS", _env_int("SURICATA_SUBMIT_RETRY_SLEEP_MS", 40)),
    "fail_closed": _env_bool("FAIL_CLOSED", False),
    "block_on_any_alert": _env_bool("BLOCK_ON_ANY_ALERT", False),
    "block_sid_ranges": eve_correlator.parse_sid_ranges(
        os.environ.get("BLOCK_SID_RANGES", "9100500-9100999")
    ),
    "allowed_clients": _env_csv("ALLOWED_CLIENTS"),
    "log_path": os.environ.get("LOG_PATH", "/var/log/icap-suricata/server.log"),
    "preview_enabled": _env_bool("ICAP_PREVIEW_ENABLE", True),
    "preview_size": _env_int("ICAP_PREVIEW_SIZE", 65536),
    "respmod_enabled": _env_bool("RESPMOD_ENABLED", True),
    "respmod_preview_scan": _env_bool("RESPMOD_PREVIEW_SCAN", True),
    "respmod_scan_all_content_types": _env_bool("RESPMOD_SCAN_ALL_CONTENT_TYPES", False),
    "respmod_skip_compressed": _env_bool("RESPMOD_SKIP_COMPRESSED", True),
    "respmod_max_scan_bytes": _env_int("RESPMOD_MAX_SCAN_BYTES", 262144),
    "respmod_scan_small_bodies_bytes": _env_int("RESPMOD_SCAN_SMALL_BODIES_BYTES", 131072),
    "respmod_force_scan_markers": _env_csv("RESPMOD_FORCE_SCAN_MARKERS"),
    "respmod_text_markers": _env_text_markers(),
    "reqmod_static_bypass_enabled": _env_bool("REQMOD_STATIC_BYPASS_ENABLED", True),
    "reqmod_static_bypass_extensions": _env_csv("REQMOD_STATIC_BYPASS_EXTENSIONS"),
    "reqmod_static_bypass_log_sample_rate": _env_int("REQMOD_STATIC_BYPASS_LOG_SAMPLE_RATE", 0),
    "latency_sample_every": _env_int("LATENCY_SAMPLE_EVERY", 0),
    "slow_request_log_ms": _env_float("SLOW_REQUEST_LOG_MS", 0.0),
    "log_monitor_alerts": _env_bool("LOG_MONITOR_ALERTS", False),
    "log_client_aborts": _env_bool("LOG_CLIENT_ABORTS", False),
    "log_incomplete_reads": _env_bool("LOG_INCOMPLETE_READS", False),
}

_SOURCE_PORT_COUNTER = [41000]
_PORT_LOCK = threading.Lock()
_WORKER_SEMAPHORE = threading.BoundedSemaphore(max(1, CFG["workers"]))
_SURICATA_PIPELINE_SEMAPHORE = threading.BoundedSemaphore(max(1, CFG["suricata_pipeline_concurrency"]))
_STATS = {
    "requests_total": 0,
    "requests_reqmod_total": 0,
    "requests_respmod_total": 0,
    "requests_blocked_total": 0,
    "requests_allowed_204_total": 0,
    "alerts_total": 0,
    "fail_open_total": 0,
    "errors_total": 0,
    "client_aborts_total": 0,
    "read_timeouts_total": 0,
    "incomplete_messages_total": 0,
    "bytes_in_total": 0,
    "respmod_skipped_total": 0,
    "respmod_preview_total": 0,
    "respmod_scanned_total": 0,
    "respmod_force_scan_total": 0,
    "respmod_small_body_scan_total": 0,
    "suricata_slowpath_total": 0,
    "preview_early_ready_total": 0,
    "reqmod_bypassed_total": 0,
    "reqmod_bypassed_static_total": 0,
    "reqmod_bypassed_safe_get_total": 0,
    "latency_samples_total": 0,
    "handle_total_ms_total": 0.0,
    "inspect_total_ms_total": 0.0,
    "inspect_reqmod_ms_total": 0.0,
    "inspect_respmod_ms_total": 0.0,
    "pcap_build_ms_total": 0.0,
    "suricata_pipeline_wait_ms_total": 0.0,
    "suricata_submit_ms_total": 0.0,
    "suricata_queue_wait_ms_total": 0.0,
    "eve_wait_ms_total": 0.0,
    "suricata_submit_total": 0,
    "suricata_submit_retry_total": 0,
    "suricata_queue_drained_total": 0,
    "suricata_queue_unknown_total": 0,
}
_STATS_LOCK = threading.Lock()
_LATENCY_SAMPLE_COUNTER = [0]
_LATENCY_SAMPLE_LOCK = threading.Lock()


def _latency_should_sample():
    every = CFG.get("latency_sample_every", 0)
    if every <= 0:
        return False
    with _LATENCY_SAMPLE_LOCK:
        _LATENCY_SAMPLE_COUNTER[0] += 1
        return _LATENCY_SAMPLE_COUNTER[0] % every == 0


def _ms_since(start):
    return (time.monotonic() - start) * 1000.0


def _latency_log(request_id, method, stages_ms):
    _bump("latency_samples_total")
    parts = ", ".join("%s=%.1fms" % (name, value) for name, value in stages_ms)
    logging.info("LATENCY rid=%s method=%s %s", request_id, method, parts)


def _resolve_static_bypass_extensions():
    raw = CFG.get("reqmod_static_bypass_extensions") or ()
    if not raw:
        return DEFAULT_STATIC_BYPASS_EXTENSIONS
    cleaned = []
    for item in raw:
        value = str(item).strip().lower()
        if not value:
            continue
        if not value.startswith("."):
            value = "." + value
        cleaned.append(value)
    return tuple(cleaned) if cleaned else DEFAULT_STATIC_BYPASS_EXTENSIONS


_STATIC_BYPASS_EXTENSIONS_CACHE = _resolve_static_bypass_extensions()



def _bump(key, n=1):
    with _STATS_LOCK:
        _STATS[key] = _STATS.get(key, 0) + n


def _next_src_port():
    with _PORT_LOCK:
        value = _SOURCE_PORT_COUNTER[0]
        _SOURCE_PORT_COUNTER[0] += 1
        if _SOURCE_PORT_COUNTER[0] > 60999:
            _SOURCE_PORT_COUNTER[0] = 41000
        return value


def setup_logging():
    handlers = []
    fmt = "%(asctime)s [%(levelname)s] %(message)s"
    try:
        os.makedirs(os.path.dirname(CFG["log_path"]), exist_ok=True)
        handlers.append(logging.FileHandler(CFG["log_path"]))
    except OSError:
        pass
    handlers.append(logging.StreamHandler(sys.stderr))
    logging.basicConfig(level=logging.INFO, format=fmt, handlers=handlers)


def _safe_ipv4(value, default="10.255.0.10"):
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return default
    if ip.version != 4:
        return default
    return str(ip)


def _client_is_allowed(addr):
    if not CFG["allowed_clients"]:
        return True
    client_ip = addr[0]
    for item in CFG["allowed_clients"]:
        try:
            if "/" in item:
                if ipaddress.ip_address(client_ip) in ipaddress.ip_network(item, strict=False):
                    return True
            elif client_ip == item:
                return True
        except ValueError:
            continue
    return False


def _cleanup_old_pcaps():
    now = time.time()
    try:
        names = os.listdir(CFG["pcap_tmpdir"])
    except OSError:
        return
    for name in names:
        if not (name.endswith(".pcap") or name.endswith(".tmp")):
            continue
        path = os.path.join(CFG["pcap_tmpdir"], name)
        try:
            if now - os.path.getmtime(path) > CFG["pcap_retention_seconds"]:
                os.remove(path)
        except OSError:
            pass


def _split_http_hdr_body(http_bytes):
    idx = http_bytes.find(b"\r\n\r\n")
    if idx < 0:
        return len(http_bytes)
    return idx + 4


def _http_headers(http_bytes):
    line_end = http_bytes.find(b"\r\n")
    if line_end < 0:
        return {}
    hdr_end = http_bytes.find(b"\r\n\r\n")
    if hdr_end < 0:
        hdr_end = len(http_bytes)
    return icap_parser.parse_headers(http_bytes[line_end + 2:hdr_end])


def _http_body_len(http_bytes):
    return max(0, len(http_bytes) - _split_http_hdr_body(http_bytes))


def _content_type_is_text(headers):
    content_type = headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if not content_type:
        return False
    for marker in CFG["respmod_text_markers"]:
        if marker.endswith("/"):
            if content_type.startswith(marker):
                return True
        elif content_type == marker or marker in content_type:
            return True
    return False




def _content_type_is_download_or_unknown(headers):
    content_type = headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if not content_type:
        return True
    if content_type in (
        "application/octet-stream",
        "binary/octet-stream",
        "application/x-msdownload",
        "application/x-dosexec",
        "application/download",
        "application/x-download",
    ):
        return True
    if "executable" in content_type or "download" in content_type:
        return True
    return False

def _content_is_compressed(headers):
    encoding = headers.get("content-encoding", "").strip().lower()
    if not encoding or encoding == "identity":
        return False
    for marker in SKIP_ENCODINGS:
        if marker in encoding:
            return True
    return True


def _force_scan_marker_present(response_bytes):
    markers = CFG["respmod_force_scan_markers"]
    if not markers:
        return False
    haystack = response_bytes
    for marker in markers:
        if not marker:
            continue
        if marker.encode("utf-8", errors="ignore") in haystack:
            return True
    return False


def _response_should_scan(response_bytes, is_preview, preview_has_ieof):
    if not CFG["respmod_enabled"]:
        return False, "respmod-disabled"
    if not response_bytes:
        return False, "empty-response"

    headers = _http_headers(response_bytes)
    body_len = _http_body_len(response_bytes)
    if body_len <= 0:
        return False, "response-without-body"

    if _force_scan_marker_present(response_bytes):
        _bump("respmod_force_scan_total")
        return True, "force-marker-scan"

    small_body_limit = CFG["respmod_scan_small_bodies_bytes"]
    is_small_body = small_body_limit > 0 and body_len <= small_body_limit

    if is_preview and not preview_has_ieof:
        if not CFG["respmod_preview_scan"]:
            return False, "preview-fast-allow"
        if CFG["respmod_skip_compressed"] and _content_is_compressed(headers):
            return False, "preview-compressed-skip"
        if CFG["respmod_scan_all_content_types"] or _content_type_is_text(headers):
            return True, "preview-text-scan"
        if is_small_body and _content_type_is_download_or_unknown(headers):
            _bump("respmod_small_body_scan_total")
            return True, "preview-small-download-scan"
        return False, "preview-nontext-skip"

    max_scan_bytes = CFG["respmod_max_scan_bytes"]
    if max_scan_bytes > 0 and body_len > max_scan_bytes:
        return False, "body-too-large"
    if CFG["respmod_skip_compressed"] and _content_is_compressed(headers):
        return False, "compressed-skip"
    if CFG["respmod_scan_all_content_types"] or _content_type_is_text(headers):
        return True, "text-scan"
    if is_small_body and _content_type_is_download_or_unknown(headers):
        _bump("respmod_small_body_scan_total")
        return True, "small-download-scan"
    return False, "nontext-skip"


def _to_chunked(body_bytes):
    if not body_bytes:
        return b"0\r\n\r\n"
    out = bytearray()
    chunk_size = 16384
    pos = 0
    size = len(body_bytes)
    while pos < size:
        end = min(size, pos + chunk_size)
        chunk = body_bytes[pos:end]
        out.extend(("%x\r\n" % len(chunk)).encode("ascii"))
        out.extend(chunk)
        out.extend(b"\r\n")
        pos = end
    out.extend(b"0\r\n\r\n")
    return bytes(out)


def _icap_reason(value, default):
    text = str(value or default)
    text = text.replace("\r", " ").replace("\n", " ").strip()
    return text if text else default


def icap_204(reason="No Content"):
    response = (
        "ICAP/1.0 204 %s\r\n"
        "ISTag: \"%s\"\r\n"
        "Server: proxylab-pathb-icap-suricata\r\n"
        "Connection: close\r\n\r\n" % (_icap_reason(reason, "No Content"), ISTAG)
    ).encode("ascii", errors="replace")
    _bump("requests_allowed_204_total")
    return response


def icap_500(reason="Internal Server Error"):
    return (
        "ICAP/1.0 500 %s\r\n"
        "ISTag: \"%s\"\r\n"
        "Server: proxylab-pathb-icap-suricata\r\n"
        "Connection: close\r\n\r\n" % (_icap_reason(reason, "Internal Server Error"), ISTAG)
    ).encode("ascii", errors="replace")


def icap_options_response():
    # v5.12: Preview is advertised only when explicitly enabled.
    # The runtime handles Squid Preview robustly, even if after the
    # 64-KiB-Probe no complete Chunk-Endemarkierung ankommt.
    preview_block = ""
    if CFG["preview_enabled"] and CFG["preview_size"] > 0:
        preview_block = (
            "Preview: %d\r\n"
            "Transfer-Preview: *\r\n" % CFG["preview_size"]
        )
    response = (
        "ICAP/1.0 200 OK\r\n"
        "ISTag: \"%s\"\r\n"
        "Server: proxylab-pathb-icap-suricata\r\n"
        "Methods: REQMOD, RESPMOD\r\n"
        "Service: Proxylab Path-B Suricata ICAP IPS\r\n"
        "Max-Connections: %d\r\n"
        "Options-TTL: 60\r\n"
        "Allow: 204\r\n"
        "%s"
        "X-Include: X-Client-IP, X-Server-IP, X-Authenticated-User\r\n"
        "Encapsulated: null-body=0\r\n"
        "Connection: close\r\n\r\n"
    ) % (ISTAG, CFG["workers"], preview_block)
    return response.encode("ascii")

def build_block_html(signature, severity, request_id):
    safe_sig = str(signature).replace("<", "&lt;").replace(">", "&gt;")
    safe_sev = str(severity).replace("<", "&lt;").replace(">", "&gt;")
    html = (
        "<!doctype html>\r\n"
        "<html><head><meta charset='utf-8'>"
        "<title>Blocked by Proxylab Path-B</title>"
        "<style>body{font-family:sans-serif;max-width:760px;margin:48px auto;"
        "padding:24px;background:#fafafa;color:#222}h1{color:#a40000}"
        "code{background:#eee;padding:2px 5px}</style></head>"
        "<body><h1>Access blocked</h1>"
        "<p>This HTTP transaction was blocked by the external "
        "<strong>ICAP server with Suricata backend</strong>.</p>"
        "<p>Signature: <code>%s</code><br>Severity: <code>%s</code><br>"
        "Request-ID: <code>%s</code></p>"
        "<p>Please report this request ID to IT if this access is business-"
        "required.</p></body></html>\r\n" % (safe_sig, safe_sev, request_id)
    )
    return html.encode("utf-8")


def make_block_response(signature, severity, request_id):
    body = build_block_html(signature, severity, request_id)
    headers = (
        "HTTP/1.1 403 Forbidden\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Content-Length: %d\r\n"
        "X-Blocked-By: Proxylab-PathB-ICAP-Suricata\r\n"
        "X-ICAP-Request-ID: %s\r\n"
        "Connection: close\r\n\r\n" % (len(body), request_id)
    ).encode("ascii")
    return headers + body


def icap_200_with_http_response(http_response_bytes):
    body_offset = _split_http_hdr_body(http_response_bytes)
    head = (
        "ICAP/1.0 200 OK\r\n"
        "ISTag: \"%s\"\r\n"
        "Server: proxylab-pathb-icap-suricata\r\n"
        "Connection: close\r\n"
        "Encapsulated: res-hdr=0, res-body=%d\r\n\r\n" % (ISTAG, body_offset)
    ).encode("ascii")
    return head + http_response_bytes[:body_offset] + _to_chunked(http_response_bytes[body_offset:])


def _event_should_block(event):
    alert = event.get("alert", {}) if isinstance(event, dict) else {}
    action = str(alert.get("action", "")).lower()
    verdict = event.get("verdict", {}) if isinstance(event, dict) else {}
    verdict_action = str(verdict.get("action", "")).lower()
    if action == "blocked" or verdict_action in ("drop", "reject"):
        return True
    if eve_correlator.alert_is_in_sid_ranges(event, CFG["block_sid_ranges"]):
        return True
    return CFG["block_on_any_alert"]


def _synthetic_response_request(http_response_bytes):
    return DEFAULT_RESPONSE_REQUEST


def _wait_timeout_for_method(method):
    if method == "RESPMOD":
        return CFG["respmod_wait_timeout_ms"]
    if method == "REQMOD":
        return CFG["reqmod_wait_timeout_ms"]
    return CFG["wait_timeout_ms"]


def inspect_http(method, request_bytes, response_bytes, src_ip, dst_ip, src_port, dst_port):
    cid = cid_mod.community_id_v1(src_ip, dst_ip, src_port, dst_port, proto=6, seed=0)
    pcap_name = "icap-%d-%d.pcap" % (int(time.time() * 1000), src_port)
    pcap_path = os.path.join(CFG["pcap_tmpdir"], pcap_name)

    if method == "REQMOD":
        pcap_request = request_bytes
        pcap_response = b""
    else:
        pcap_request = request_bytes if request_bytes else _synthetic_response_request(response_bytes)
        pcap_response = response_bytes

    inspect_start = time.monotonic()
    pcap_start = time.monotonic()
    try:
        os.makedirs(CFG["pcap_tmpdir"], exist_ok=True)
        os.makedirs(CFG["suricata_output_dir"], exist_ok=True)
        _cleanup_old_pcaps()
        pcap_builder.write_pcap(
            pcap_path,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            pcap_request,
            response_bytes=pcap_response,
        )
        _bump("pcap_build_ms_total", _ms_since(pcap_start))
    except Exception as exc:
        logging.error("pcap build/write failed: %s\n%s", exc, traceback.format_exc())
        _bump("errors_total")
        _bump("fail_open_total")
        return "fail-open"

    pipeline_wait_start = time.monotonic()
    pipeline_acquired = _SURICATA_PIPELINE_SEMAPHORE.acquire(timeout=CFG["socket_timeout_s"])
    _bump("suricata_pipeline_wait_ms_total", _ms_since(pipeline_wait_start))
    if not pipeline_acquired:
        logging.error("suricata pipeline busy")
        _bump("errors_total")
        _bump("fail_open_total")
        return "fail-open"

    try:
        pre_pos = os.path.getsize(CFG["eve_path"]) if os.path.exists(CFG["eve_path"]) else 0
        wait_timeout_ms = max(1, _wait_timeout_for_method(method))
        deadline = time.monotonic() + wait_timeout_ms / 1000.0

        response = None
        last_error = None
        attempts = max(1, CFG["suricata_submit_retries"])
        for attempt in range(attempts):
            try:
                _bump("suricata_submit_total")
                submit_start = time.monotonic()
                response = suricata_client.submit_pcap(
                    CFG["suricata_sock"],
                    pcap_path,
                    CFG["suricata_output_dir"],
                    timeout_s=5.0,
                )
                _bump("suricata_submit_ms_total", _ms_since(submit_start))
                last_error = None
                break
            except (OSError, RuntimeError, json.JSONDecodeError) as exc:
                last_error = exc
                if attempt + 1 >= attempts:
                    break
                _bump("suricata_submit_retry_total")
                time.sleep(max(1, CFG["suricata_retry_sleep_ms"]) / 1000.0)

        if last_error is not None:
            logging.error("suricata submit failed after retries: %s", last_error)
            _bump("errors_total")
            _bump("fail_open_total")
            return "fail-open"

        if not isinstance(response, dict) or response.get("return") != "OK":
            logging.warning("suricata pcap-file returned %r", response)
            _bump("errors_total")
            _bump("fail_open_total")
            return "fail-open"

        predicate = eve_correlator.alert_predicate_combined(cid, src_port)

        # v5.12 Fast-Allow-Pfad:
        # Do not wait for an alert first. Clean traffic produces no
        # alert; the previous version therefore waited until timeout per object.
        # Now we wait for queue drain and then read EVE only briefly.
        queue_wait_start = time.monotonic()
        drained = suricata_client.wait_for_queue_drain(
            CFG["suricata_sock"],
            deadline,
            poll_s=max(0.005, CFG["suricata_queue_poll_ms"] / 1000.0),
        )
        _bump("suricata_queue_wait_ms_total", _ms_since(queue_wait_start))
        if drained is True:
            _bump("suricata_queue_drained_total")
        elif drained is False:
            logging.warning("suricata queue did not drain within %d ms", wait_timeout_ms)
            _bump("suricata_slowpath_total")
            if CFG["fail_closed"]:
                return "fail-open"
        else:
            _bump("suricata_queue_unknown_total")

        grace_ms = max(0, CFG["alert_post_drain_grace_ms"])
        if drained is False:
            grace_ms = max(grace_ms, min(500, wait_timeout_ms))
        if drained is None:
            grace_ms = max(grace_ms, 250)

        eve_wait_start = time.monotonic()
        match = eve_correlator.wait_for_policy_match(
            CFG["eve_path"],
            predicate,
            _event_should_block,
            timeout_ms=grace_ms,
            start_pos=pre_pos,
        )
        _bump("eve_wait_ms_total", _ms_since(eve_wait_start))
        total_inspect_ms = _ms_since(inspect_start)
        _bump("inspect_total_ms_total", total_inspect_ms)
        if method == "REQMOD":
            _bump("inspect_reqmod_ms_total", total_inspect_ms)
        elif method == "RESPMOD":
            _bump("inspect_respmod_ms_total", total_inspect_ms)
        return match
    finally:
        _SURICATA_PIPELINE_SEMAPHORE.release()



def _reqmod_extract_request_summary(request_bytes):
    """Extrahiert Method/URI/Headers for ein konservatives REQMOD-Prescreening."""
    if not request_bytes:
        return None
    request_line = icap_parser.parse_http_request_line(request_bytes)
    if request_line is None:
        return None
    method_token, uri_token, _version = request_line
    method_upper = str(method_token).upper()
    head, _sep, _body = request_bytes.partition(b"\r\n\r\n")
    if b"\r\n" in head:
        header_block = head.split(b"\r\n", 1)[1]
    else:
        header_block = b""
    headers = icap_parser.parse_headers(header_block)
    return {
        "method": method_upper,
        "uri": uri_token,
        "headers": headers,
    }


def _reqmod_uri_path_lower(uri_token):
    if not uri_token:
        return ""
    uri_text = str(uri_token)
    without_fragment = uri_text.split("#", 1)[0]
    without_query = without_fragment.split("?", 1)[0]
    return without_query.lower()


def _reqmod_user_agent_is_safe(user_agent):
    if not user_agent:
        # Empty or missing UA is not bypassed because bots/tools often send without UA.
        return False
    ua_text = str(user_agent)
    for needle in SUSPICIOUS_REQMOD_UA_SUBSTRINGS:
        if needle in ua_text:
            return False
    if all(needle in ua_text for needle in COBALTSTRIKE_UA_NEEDLES):
        return False
    return True


def _reqmod_headers_have_proxylab_marker(headers):
    for key in headers.keys():
        if str(key).lower().startswith("x-proxylab-"):
            return True
    return False


def _reqmod_should_bypass(request_bytes):
    """Returns (True, reason) if REQMOD can be safely allowed without the Suricata slow path."""
    if not CFG["reqmod_static_bypass_enabled"]:
        return False, ""
    summary = _reqmod_extract_request_summary(request_bytes)
    if summary is None:
        return False, ""
    method = summary["method"]
    if method != "GET":
        return False, ""
    uri = summary["uri"]
    path_lower = _reqmod_uri_path_lower(uri)
    if not path_lower:
        return False, ""
    for needle in DEFENSIVE_REQMOD_URI_NEEDLES:
        if needle in path_lower:
            return False, ""
    if not path_lower.endswith(_STATIC_BYPASS_EXTENSIONS_CACHE):
        return False, ""
    headers = summary["headers"]
    if _reqmod_headers_have_proxylab_marker(headers):
        return False, ""
    content_length_raw = headers.get("content-length", "0")
    try:
        content_length_value = int(str(content_length_raw).strip())
    except (TypeError, ValueError):
        content_length_value = 0
    if content_length_value > 0:
        return False, ""
    user_agent = headers.get("user-agent", "")
    if not _reqmod_user_agent_is_safe(user_agent):
        return False, ""
    return True, "static-asset-bypass"


def _reqmod_maybe_log_bypass(request_id, path_reason):
    sample_rate = CFG.get("reqmod_static_bypass_log_sample_rate", 0)
    if sample_rate <= 0:
        return
    with _STATS_LOCK:
        count = _STATS.get("reqmod_bypassed_total", 0)
    if count > 0 and count % sample_rate == 0:
        logging.info("REQMOD_BYPASS rid=%s reason=%s count=%s", request_id, path_reason, count)


def _safe_int_text(value, default):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _chunked_available_payload_len(data, limit):
    pos = 0
    total = 0
    n = len(data)
    safe_limit = max(0, int(limit))
    while pos < n and total < safe_limit:
        eol = data.find(b"\r\n", pos)
        if eol < 0:
            break
        size_line = data[pos:eol].decode("ascii", errors="replace").strip()
        size_text = size_line.split(";", 1)[0].strip()
        try:
            size = int(size_text, 16)
        except ValueError:
            # Unexpected raw data. For Preview, the
            # available data volume as a conservative estimate.
            return min(n, safe_limit)
        pos = eol + 2
        if size == 0:
            return total
        available = max(0, n - pos)
        take = min(size, available)
        total += take
        if available < size:
            return total
        pos += size
        if data[pos:pos + 2] == b"\r\n":
            pos += 2
        else:
            return total
    return total


def _icap_preview_cutoff_reached(buf):
    if not CFG["preview_enabled"] or CFG["preview_size"] <= 0:
        return False
    parsed = icap_parser.parse_icap_message(buf)
    if parsed is None:
        return False
    method = parsed.get("method", "")
    if method not in ("REQMOD", "RESPMOD"):
        return False
    headers = parsed.get("headers", {})
    if "preview" not in headers:
        return False
    encap = parsed.get("encapsulated", {})
    body = parsed.get("body", b"")
    body_offsets = []
    for key in ("req-body", "res-body"):
        if key in encap:
            body_offsets.append(encap[key])
    if not body_offsets:
        return False
    body_offset = min(body_offsets)
    if len(body) < body_offset:
        return False
    requested_preview = _safe_int_text(headers.get("preview"), CFG["preview_size"])
    preview_limit = min(max(0, requested_preview), max(0, CFG["preview_size"]))
    if preview_limit <= 0:
        return True
    chunked = body[body_offset:]
    available = _chunked_available_payload_len(chunked, preview_limit)
    return available >= preview_limit

def _recv_full_message(conn):
    buf = bytearray()
    conn.settimeout(CFG["icap_read_timeout_s"])
    while len(buf) < CFG["max_request_bytes"]:
        try:
            chunk = conn.recv(8192)
        except socket.timeout:
            if not buf:
                raise TimeoutError("no ICAP bytes received before timeout")
            _bump("incomplete_messages_total")
            raise TimeoutError("incomplete ICAP message after %d bytes" % len(buf))
        if not chunk:
            break
        buf.extend(chunk)
        current = bytes(buf)
        if icap_parser.icap_message_is_complete(current):
            return current
        if _icap_preview_cutoff_reached(current):
            _bump("preview_early_ready_total")
            return current
    if len(buf) >= CFG["max_request_bytes"]:
        raise ValueError("ICAP message exceeds MAX_REQUEST_BYTES")
    return bytes(buf)


def _send_fail_policy(conn, request_id, reason):
    if CFG["fail_closed"]:
        conn.sendall(icap_200_with_http_response(make_block_response(reason, 3, request_id)))
        _bump("requests_blocked_total")
    else:
        conn.sendall(icap_204("fail-open"))
        _bump("fail_open_total")


def _extract_message_parts(method, body, encap):
    if method == "REQMOD":
        request_bytes = icap_parser.extract_http_request_from_encapsulated(body, encap)
        return request_bytes, b"", request_bytes
    if method == "RESPMOD":
        request_bytes = icap_parser.extract_http_request_from_encapsulated(body, encap)
        response_bytes = icap_parser.extract_http_response_from_encapsulated(body, encap)
        return request_bytes, response_bytes, response_bytes
    return b"", b"", b""


def _send_allow(conn, reason="No Content"):
    conn.sendall(icap_204(reason))


def _handle_scan_result(conn, request_id, method, client_ip, result):
    if result == "fail-open":
        _send_fail_policy(conn, request_id, "Suricata backend unavailable")
        return

    if result is None:
        _send_allow(conn, "No Content")
        return

    _bump("alerts_total")
    alert = result.get("alert", {}) if isinstance(result, dict) else {}
    signature = alert.get("signature", "suricata alert")
    severity = alert.get("severity", 1)

    if _event_should_block(result):
        response = make_block_response(signature, severity, request_id)
        conn.sendall(icap_200_with_http_response(response))
        _bump("requests_blocked_total")
        logging.info("BLOCK rid=%s method=%s client=%s sig=%r", request_id, method, client_ip, signature)
        return

    _send_allow(conn, "alert log-only")
    if CFG["log_monitor_alerts"]:
        logging.info("ALERT rid=%s method=%s client=%s sig=%r", request_id, method, client_ip, signature)
    else:
        logging.debug("ALERT rid=%s method=%s client=%s sig=%r", request_id, method, client_ip, signature)


def handle_connection(conn, addr):
    request_id = uuid.uuid4().hex[:12]
    handle_start = time.monotonic()
    sample_active = _latency_should_sample()
    latency_stages = []
    method = "REQMOD"
    acquired = _WORKER_SEMAPHORE.acquire(timeout=CFG["socket_timeout_s"])
    if not acquired:
        try:
            conn.sendall(icap_500("server busy"))
        except OSError:
            pass
        return
    try:
        if not _client_is_allowed(addr):
            logging.warning("reject unauthorized ICAP client %s", addr[0])
            conn.sendall(icap_500("unauthorized client"))
            return

        raw = _recv_full_message(conn)
        if sample_active:
            latency_stages.append(("recv", _ms_since(handle_start)))
        if not raw:
            return
        _bump("requests_total")
        _bump("bytes_in_total", len(raw))

        msg = icap_parser.parse_icap_message(raw)
        if msg is None:
            conn.sendall(icap_500("bad request"))
            return

        method = msg["method"]
        if method == "OPTIONS":
            conn.sendall(icap_options_response())
            return

        encap = msg["encapsulated"]
        body = msg["body"]
        headers = msg["headers"]
        is_preview = "preview" in headers
        preview_has_ieof = icap_parser.encapsulated_body_has_ieof(body, encap)

        if method == "REQMOD":
            _bump("requests_reqmod_total")
        elif method == "RESPMOD":
            _bump("requests_respmod_total")
            if is_preview:
                _bump("respmod_preview_total")
        else:
            conn.sendall(icap_500("method not supported"))
            return

        request_bytes, response_bytes, inspect_payload = _extract_message_parts(method, body, encap)
        if not inspect_payload:
            _send_allow(conn, "empty")
            return

        if method == "REQMOD":
            should_bypass, bypass_reason = _reqmod_should_bypass(request_bytes)
            if should_bypass:
                _bump("reqmod_bypassed_total")
                _bump("reqmod_bypassed_static_total")
                _bump("reqmod_bypassed_safe_get_total")
                _reqmod_maybe_log_bypass(request_id, bypass_reason)
                _send_allow(conn, bypass_reason)
                if sample_active:
                    total_ms = _ms_since(handle_start)
                    _bump("handle_total_ms_total", total_ms)
                    latency_stages.append(("bypass", total_ms))
                    _latency_log(request_id, method, latency_stages)
                return

        if method == "RESPMOD":
            should_scan, scan_reason = _response_should_scan(response_bytes, is_preview, preview_has_ieof)
            if not should_scan:
                _bump("respmod_skipped_total")
                logging.debug("RESPMOD skip rid=%s reason=%s bytes=%d preview=%s ieof=%s", request_id, scan_reason, len(response_bytes), is_preview, preview_has_ieof)
                _send_allow(conn, scan_reason)
                return
            _bump("respmod_scanned_total")

        client_ip = _safe_ipv4(headers.get("x-client-ip", "10.255.0.10"))
        target_ip = _safe_ipv4(headers.get("x-server-ip", "198.51.100.10"), default="198.51.100.10")
        source_port = _next_src_port()
        target_port = 80

        inspect_call_start = time.monotonic()
        result = inspect_http(
            method,
            request_bytes,
            response_bytes,
            client_ip,
            target_ip,
            source_port,
            target_port,
        )
        if sample_active:
            latency_stages.append(("inspect", _ms_since(inspect_call_start)))
        _handle_scan_result(conn, request_id, method, client_ip, result)
        total_ms = _ms_since(handle_start)
        _bump("handle_total_ms_total", total_ms)
        slow_ms = CFG.get("slow_request_log_ms", 0.0)
        if sample_active:
            latency_stages.append(("total", total_ms))
            _latency_log(request_id, method, latency_stages)
        elif slow_ms > 0.0 and total_ms >= slow_ms:
            logging.info("SLOW rid=%s method=%s total=%.1fms bytes=%d", request_id, method, total_ms, len(raw))
    except TimeoutError as exc:
        _bump("read_timeouts_total")
        if CFG["log_incomplete_reads"]:
            logging.info("client/incomplete ICAP read rid=%s peer=%s reason=%s; sending fail-open/fail-closed policy once", request_id, addr, exc)
        else:
            logging.debug("client/incomplete ICAP read rid=%s peer=%s reason=%s", request_id, addr, exc)
        try:
            _send_fail_policy(conn, request_id, "incomplete ICAP preview/read timeout")
        except OSError:
            pass
    except (ConnectionResetError, BrokenPipeError) as exc:
        _bump("client_aborts_total")
        if CFG["log_client_aborts"]:
            logging.info("client aborted ICAP connection rid=%s peer=%s reason=%s", request_id, addr, exc)
        else:
            logging.debug("client aborted ICAP connection rid=%s peer=%s reason=%s", request_id, addr, exc)
    except Exception:
        logging.error("connection error rid=%s peer=%s; using fail policy:\n%s", request_id, addr, traceback.format_exc())
        _bump("errors_total")
        try:
            _send_fail_policy(conn, request_id, "internal ICAP bridge error")
        except OSError:
            pass
    finally:
        _WORKER_SEMAPHORE.release()
        try:
            conn.close()
        except OSError:
            pass


def _http_response(status, content_type, body):
    return (b"HTTP/1.1 " + status + b"\r\nContent-Type: " + content_type +
            b"\r\nContent-Length: " + str(len(body)).encode("ascii") +
            b"\r\n\r\n" + body)


def _metrics_avg(snapshot, total_key, count_key):
    count = float(snapshot.get(count_key, 0) or 0)
    if count <= 0.0:
        return 0.0
    return float(snapshot.get(total_key, 0.0) or 0.0) / count


def _metrics_body():
    with _STATS_LOCK:
        snapshot = dict(_STATS)
    lines = []
    for key in sorted(snapshot):
        lines.append("# TYPE icap_suricata_%s counter" % key)
        lines.append("icap_suricata_%s %s" % (key, snapshot[key]))
    lines.append("icap_suricata_workers %d" % CFG["workers"])
    lines.append("icap_suricata_fail_closed %d" % (1 if CFG["fail_closed"] else 0))
    lines.append("icap_suricata_respmod_max_scan_bytes %d" % CFG["respmod_max_scan_bytes"])
    lines.append("icap_suricata_respmod_scan_small_bodies_bytes %d" % CFG["respmod_scan_small_bodies_bytes"])
    lines.append("icap_suricata_icap_read_timeout_s %.3f" % CFG["icap_read_timeout_s"])
    lines.append("icap_suricata_preview_enabled %d" % (1 if CFG["preview_enabled"] else 0))
    lines.append("icap_suricata_preview_size %d" % CFG["preview_size"])
    lines.append("icap_suricata_suricata_pipeline_concurrency %d" % CFG["suricata_pipeline_concurrency"])
    lines.append("icap_suricata_suricata_submit_retries %d" % CFG["suricata_submit_retries"])
    lines.append("icap_suricata_suricata_queue_poll_ms %d" % CFG["suricata_queue_poll_ms"])
    lines.append("icap_suricata_alert_post_drain_grace_ms %d" % CFG["alert_post_drain_grace_ms"])
    lines.append("icap_suricata_log_client_aborts %d" % (1 if CFG["log_client_aborts"] else 0))
    submit_count = max(1, int(snapshot.get("suricata_submit_total", 0) or 0))
    req_count = max(1, int(snapshot.get("requests_reqmod_total", 0) or 0))
    lines.append("# TYPE icap_suricata_avg_pcap_build_ms gauge")
    lines.append("icap_suricata_avg_pcap_build_ms %.3f" % _metrics_avg(snapshot, "pcap_build_ms_total", "suricata_submit_total"))
    lines.append("# TYPE icap_suricata_avg_suricata_submit_ms gauge")
    lines.append("icap_suricata_avg_suricata_submit_ms %.3f" % _metrics_avg(snapshot, "suricata_submit_ms_total", "suricata_submit_total"))
    lines.append("# TYPE icap_suricata_avg_suricata_queue_wait_ms gauge")
    lines.append("icap_suricata_avg_suricata_queue_wait_ms %.3f" % _metrics_avg(snapshot, "suricata_queue_wait_ms_total", "suricata_submit_total"))
    lines.append("# TYPE icap_suricata_avg_eve_wait_ms gauge")
    lines.append("icap_suricata_avg_eve_wait_ms %.3f" % _metrics_avg(snapshot, "eve_wait_ms_total", "suricata_submit_total"))
    lines.append("# TYPE icap_suricata_reqmod_bypass_ratio gauge")
    lines.append("icap_suricata_reqmod_bypass_ratio %.6f" % (float(snapshot.get("reqmod_bypassed_total", 0) or 0) / float(req_count)))
    lines.append("icap_suricata_log_incomplete_reads %d" % (1 if CFG["log_incomplete_reads"] else 0))
    lines.append("icap_suricata_log_monitor_alerts %d" % (1 if CFG["log_monitor_alerts"] else 0))
    lines.append("icap_suricata_reqmod_static_bypass_enabled %d" % (1 if CFG["reqmod_static_bypass_enabled"] else 0))
    lines.append("icap_suricata_reqmod_static_bypass_extensions %d" % len(_STATIC_BYPASS_EXTENSIONS_CACHE))
    lines.append("icap_suricata_latency_sample_every %d" % CFG["latency_sample_every"])
    lines.append("icap_suricata_slow_request_log_ms %.1f" % CFG["slow_request_log_ms"])
    return ("\n".join(lines) + "\n").encode("utf-8")


def _serve_metrics(host, port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(16)
    logging.info("health/metrics endpoint on %s:%d", host, port)
    while True:
        conn, _addr = server.accept()
        try:
            data = conn.recv(4096)
            path = b"/"
            if b" " in data:
                path = data.split(b" ", 2)[1]
            if path == b"/healthz":
                healthy = suricata_client.health(CFG["suricata_sock"])
                body = (b'{"healthy":' + (b"true" if healthy else b"false") + b"}")
                status = b"200 OK" if healthy else b"503 Service Unavailable"
                conn.sendall(_http_response(status, b"application/json", body))
            elif path == b"/metrics":
                conn.sendall(_http_response(b"200 OK", b"text/plain; version=0.0.4", _metrics_body()))
            else:
                conn.sendall(_http_response(b"404 Not Found", b"text/plain", b"not found\n"))
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass


def main():
    setup_logging()
    logging.info(
        "starting Path-B ICAP/Suricata v5.12 bind=%s:%d health=%s:%d workers=%d preview_enabled=%s preview=%d read_timeout=%.3fs respmod_enabled=%s respmod_max=%d small_body=%d suricata_pipeline=%d reqmod_static_bypass=%s latency_sample_every=%d fail_closed=%s sid_ranges=%s",
        CFG["bind"], CFG["port"], CFG["health_bind"], CFG["health_port"],
        CFG["workers"], CFG["preview_enabled"], CFG["preview_size"], CFG["icap_read_timeout_s"], CFG["respmod_enabled"],
        CFG["respmod_max_scan_bytes"], CFG["respmod_scan_small_bodies_bytes"],
        CFG["suricata_pipeline_concurrency"], CFG["reqmod_static_bypass_enabled"],
        CFG["latency_sample_every"], CFG["fail_closed"], CFG["block_sid_ranges"],
    )
    os.makedirs(CFG["pcap_tmpdir"], exist_ok=True)
    os.makedirs(CFG["suricata_output_dir"], exist_ok=True)

    metrics_thread = threading.Thread(
        target=functools.partial(_serve_metrics, CFG["health_bind"], CFG["health_port"]),
        daemon=True,
    )
    metrics_thread.start()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((CFG["bind"], CFG["port"]))
    server.listen(max(16, CFG["workers"] * 4))
    logging.info("ICAP listener ready")

    while True:
        try:
            conn, addr = server.accept()
        except KeyboardInterrupt:
            break
        thread = threading.Thread(
            target=functools.partial(handle_connection, conn, addr),
            daemon=True,
        )
        thread.start()


if __name__ == "__main__":
    main()
