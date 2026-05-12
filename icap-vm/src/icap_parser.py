#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ICAP/1.0 Minimalparser for Squid REQMOD/RESPMOD.

Ziel for v5.12:
- no external Python dependencies
- robust reading of complete ICAP messages including ICAP Preview early decision
- extraction of HTTP request/response including dechunked body
"""

CRLF = b"\r\n"
CRLF_CRLF = b"\r\n\r\n"


def parse_icap_request_line(line_bytes):
    parts = line_bytes.decode("ascii", errors="replace").strip().split(" ", 2)
    if len(parts) != 3:
        raise ValueError("malformed ICAP request line: %r" % (line_bytes,))
    method, uri, version = parts
    if not version.startswith("ICAP/"):
        raise ValueError("not an ICAP request: %r" % (line_bytes,))
    return method.upper(), uri, version


def parse_headers(header_block_bytes):
    out = {}
    text = header_block_bytes.decode("ascii", errors="replace")
    current_key = None
    for raw_line in text.split("\r\n"):
        if not raw_line:
            continue
        if raw_line[:1] in (" ", "\t") and current_key:
            out[current_key] = out[current_key] + " " + raw_line.strip()
            continue
        if ":" not in raw_line:
            continue
        key, value = raw_line.split(":", 1)
        current_key = key.strip().lower()
        out[current_key] = value.strip()
    return out


def parse_encapsulated(value_str):
    out = {}
    for token in value_str.split(","):
        item = token.strip()
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        try:
            out[key.strip().lower()] = int(value.strip())
        except ValueError:
            continue
    return out


def split_icap_message(buf):
    sep_idx = buf.find(CRLF_CRLF)
    if sep_idx < 0:
        return None, None, None
    head = buf[:sep_idx]
    rest = buf[sep_idx + len(CRLF_CRLF):]
    line_end = head.find(CRLF)
    if line_end < 0:
        request_line = head
        headers_block = b""
    else:
        request_line = head[:line_end]
        headers_block = head[line_end + len(CRLF):]
    return request_line, headers_block, rest


def parse_icap_message(buf):
    request_line, headers_block, rest = split_icap_message(buf)
    if request_line is None:
        return None
    method, uri, version = parse_icap_request_line(request_line)
    headers = parse_headers(headers_block)
    encap = parse_encapsulated(headers.get("encapsulated", ""))
    return {
        "method": method,
        "uri": uri,
        "version": version,
        "headers": headers,
        "encapsulated": encap,
        "body": rest,
    }


def icap_message_is_complete(buf):
    """Best-effort check whether a complete ICAP message is present.

    Important for Squid Preview: after exactly ``Preview`` bytes, Squid can
    stop and wait for an ICAP decision. In this state, the
    message is already decidable for the balanced policy, even if
    no finaler 0-Chunk for den kompletten HTTP-Body vorliegt.
    """
    parsed = parse_icap_message(buf)
    if parsed is None:
        return False
    method = parsed["method"]
    if method == "OPTIONS":
        return True
    encap = parsed["encapsulated"]
    body = parsed["body"]
    headers = parsed["headers"]
    body_keys = ["req-body", "res-body"]
    chunk_offsets = [encap[k] for k in body_keys if k in encap]
    if chunk_offsets:
        offset = min(chunk_offsets)
        if len(body) < offset:
            return False
        chunked = body[offset:]
        if find_chunked_end(chunked) is not None:
            return True
        preview_size = _parse_non_negative_int(headers.get("preview"))
        if preview_size is not None:
            return chunked_preview_is_complete(chunked, preview_size)
        return False
    null_offsets = [encap[k] for k in ("null-body",) if k in encap]
    if null_offsets:
        return len(body) >= min(null_offsets)
    # Header-only encapsulation, for example req-hdr=0 without a body key.
    header_offsets = [encap[k] for k in ("req-hdr", "res-hdr") if k in encap]
    if header_offsets:
        return len(body) >= max(header_offsets)
    return True


def _parse_non_negative_int(value):
    try:
        out = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    if out < 0:
        return None
    return out


def chunked_preview_is_complete(data, preview_size):
    """True if Squid has sent enough chunk data for the Preview stop.

    Some Squid/ICAP flows do not immediately send a final
    0-chunk during Preview. They stop at the preview boundary and wait
    for 204/100-Continue. Therefore the server must not read until timeout.
    """
    pos = 0
    decoded = 0
    n = len(data)
    if preview_size == 0:
        return True
    while pos < n:
        eol = data.find(CRLF, pos)
        if eol < 0:
            return False
        size_line = data[pos:eol].decode("ascii", errors="replace").strip()
        size_text = size_line.split(";", 1)[0].strip()
        try:
            size = int(size_text, 16)
        except ValueError:
            return False
        pos = eol + len(CRLF)
        if size == 0:
            return True
        available = max(0, n - pos)
        if available < size:
            decoded += available
            return decoded >= preview_size
        decoded += size
        pos += size
        if decoded >= preview_size:
            return True
        if data[pos:pos + len(CRLF)] != CRLF:
            return False
        pos += len(CRLF)
    return False

def find_chunked_end(data):
    """Return the end position of the ICAP/HTTP chunked body section or None."""
    pos = 0
    n = len(data)
    while pos < n:
        eol = data.find(CRLF, pos)
        if eol < 0:
            return None
        size_line = data[pos:eol].decode("ascii", errors="replace").strip()
        size_text = size_line.split(";", 1)[0].strip()
        try:
            size = int(size_text, 16)
        except ValueError:
            return None
        pos = eol + len(CRLF)
        if size == 0:
            # Optional trailer up to CRLFCRLF, direct CRLF, or Squid Preview end with only "0\r\n".
            trailer_end = data.find(CRLF_CRLF, pos)
            if trailer_end >= 0:
                return trailer_end + len(CRLF_CRLF)
            if data[pos:pos + len(CRLF)] == CRLF:
                return pos + len(CRLF)
            if pos == n:
                return pos
            return None
        if pos + size > n:
            return None
        pos += size
        if data[pos:pos + len(CRLF)] != CRLF:
            return None
        pos += len(CRLF)
    return None



def chunked_body_has_ieof(data):
    """True if an ICAP Preview body was completed with 0;ieof."""
    pos = 0
    n = len(data)
    while pos < n:
        eol = data.find(CRLF, pos)
        if eol < 0:
            return False
        size_line_raw = data[pos:eol].decode("ascii", errors="replace").strip()
        size_text = size_line_raw.split(";", 1)[0].strip()
        try:
            size = int(size_text, 16)
        except ValueError:
            return False
        pos = eol + len(CRLF)
        if size == 0:
            return any(part.strip().lower() == "ieof" for part in size_line_raw.split(";")[1:])
        if pos + size > n:
            return False
        pos += size
        if data[pos:pos + len(CRLF)] != CRLF:
            return False
        pos += len(CRLF)
    return False


def encapsulated_body_has_ieof(body, encap):
    offsets = [encap[k] for k in ("req-body", "res-body") if k in encap]
    if not offsets:
        return True
    offset = min(offsets)
    if len(body) < offset:
        return False
    return chunked_body_has_ieof(body[offset:])

def extract_http_request_from_encapsulated(body, encap):
    return _extract_encapsulated(body, encap, "req-hdr", "req-body", "null-body")


def extract_http_response_from_encapsulated(body, encap):
    return _extract_encapsulated(body, encap, "res-hdr", "res-body", "null-body")


def _next_encapsulated_offset(encap, start_offset):
    candidates = []
    for value in encap.values():
        if value > start_offset:
            candidates.append(value)
    if not candidates:
        return None
    return min(candidates)


def _extract_encapsulated(body, encap, hdr_key, body_key, null_key):
    if hdr_key not in encap:
        return b""
    hdr_off = encap[hdr_key]
    body_off = encap.get(body_key)
    null_off = encap.get(null_key)
    if body_off is not None:
        headers_part = body[hdr_off:body_off]
        chunked = body[body_off:]
        end = find_chunked_end(chunked)
        decoded = _decode_chunked(chunked[:end] if end else chunked)
        return headers_part + decoded
    if null_off is not None:
        return body[hdr_off:null_off]
    next_off = _next_encapsulated_offset(encap, hdr_off)
    if next_off is not None:
        return body[hdr_off:next_off]
    return body[hdr_off:]


def _decode_chunked(data):
    out = bytearray()
    pos = 0
    n = len(data)
    while pos < n:
        eol = data.find(CRLF, pos)
        if eol < 0:
            break
        size_line = data[pos:eol].decode("ascii", errors="replace").strip()
        size_text = size_line.split(";", 1)[0].strip()
        try:
            size = int(size_text, 16)
        except ValueError:
            break
        pos = eol + len(CRLF)
        if size == 0:
            break
        if pos + size > n:
            out.extend(data[pos:n])
            break
        out.extend(data[pos:pos + size])
        pos += size
        if data[pos:pos + len(CRLF)] == CRLF:
            pos += len(CRLF)
    return bytes(out)


def parse_http_request_line(http_bytes):
    if CRLF not in http_bytes:
        return None
    line = http_bytes.split(CRLF, 1)[0].decode("ascii", errors="replace").strip()
    parts = line.split(" ", 2)
    if len(parts) != 3:
        return None
    return tuple(parts)


def parse_http_status_line(http_bytes):
    if CRLF not in http_bytes:
        return None
    line = http_bytes.split(CRLF, 1)[0].decode("ascii", errors="replace").strip()
    parts = line.split(" ", 2)
    if len(parts) < 2:
        return None
    try:
        return parts[0], int(parts[1]), parts[2] if len(parts) > 2 else ""
    except ValueError:
        return None


def host_from_http_request(http_bytes, default="icap.local"):
    _, sep, rest = http_bytes.partition(CRLF)
    if not sep:
        return default
    header_block, _sep2, _body = rest.partition(CRLF_CRLF)
    headers = parse_headers(header_block)
    return headers.get("host", default)
