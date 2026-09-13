#!/usr/bin/env python3
"""
Daily config filter.

1. Downloads every subscription URL in sources.txt
2. Keeps only entries that are:  port 443 + WebSocket (ws) + TLS
   (trojan:// is TLS by definition, so it only needs port 443 + ws)
   and that carry a host= or sni= parameter (needed when the address
   is replaced by a CDN IP).
3. Replaces ONLY the server address (the part right after @) with TARGET_IP.
   Everything else - uuid, port, sni, host, path, fragment name - stays
   byte-for-byte identical to the original line.
4. Saves the result into output/ as plain text + base64 + per-protocol files.

Set the TARGET_IP environment variable to override the default IP.
"""

import base64
import json
import os
import re
import ssl
import urllib.error
import urllib.request
from urllib.parse import parse_qsl

# --------------------------- settings ---------------------------------
TARGET_IP = os.environ.get("TARGET_IP", "104.18.37.127")

# Only these protocols are kept.
ALLOWED_SCHEMES = {"ss", "vmess", "vless", "trojan"}

# After the rewrite the client connects to TARGET_IP, so the config must
# carry the real backend in host= or sni= - otherwise it can never work.
REQUIRE_HOST_OR_SNI = True

TIMEOUT = 25          # seconds per download
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SOURCES_FILE = os.path.join(BASE_DIR, "sources.txt")
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) config-filter/1.0"
# -----------------------------------------------------------------------

URI_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*)://(.*)$")
HOSTPORT_RE = re.compile(r"^(?P<host>.+):(?P<port>\d+)(?P<path>/.*)?$")


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return resp.read().decode("utf-8", "ignore")
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", exc)
        if "CERTIFICATE_VERIFY_FAILED" not in str(reason):
            raise
    # some machines (e.g. macOS without python certs) - retry unverified
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as resp:
        return resp.read().decode("utf-8", "ignore")


def fetch_with_retry(url: str) -> str:
    for attempt in (1, 2):
        try:
            return fetch(url)
        except Exception as exc:
            if attempt == 2:
                print(f"[FAIL] {url}: {exc}")
                raise
    raise RuntimeError("unreachable")


def b64flex(data: str) -> bytes:
    """base64 decode tolerant to missing padding and urlsafe alphabets."""
    data = data.strip().replace("-", "+").replace("_", "/")
    data += "=" * (-len(data) % 4)
    return base64.b64decode(data)


def decode_payload(text: str) -> list:
    """Return config lines from a payload that may be plain or base64."""
    text = text.strip()
    if not text:
        return []
    if "://" in text:
        return text.splitlines()
    # whole payload is base64
    try:
        decoded = b64flex(text).decode("utf-8", "ignore")
        if "://" in decoded:
            return decoded.splitlines()
    except Exception:
        pass
    # payload is one base64 line per config
    out = []
    for line in text.splitlines():
        line = line.strip()
        if "://" in line:
            out.append(line)
            continue
        try:
            decoded = b64flex(line).decode("utf-8", "ignore")
            if "://" in decoded:
                out.append(decoded.strip())
        except Exception:
            continue
    return out


def rewrite_uri(line: str) -> str | None:
    """vless:// / trojan:// / ss:// style lines (scheme://info@host:port?query#frag)."""
    m = URI_RE.match(line)
    if not m:
        return None
    scheme, rest = m.group(1).lower(), m.group(2)
    if scheme not in ALLOWED_SCHEMES:
        return None

    frag = ""
    i = rest.find("#")
    if i != -1:
        frag, rest = rest[i:], rest[:i]
    query = ""
    i = rest.find("?")
    if i != -1:
        query, rest = rest[i + 1:], rest[:i]

    if "@" not in rest:          # old ss://base64(host:pass) style - cannot rewrite safely
        return None
    userinfo, hostport = rest.rsplit("@", 1)
    if "/" in hostport:
        hostport = hostport.split("/", 1)[0]
    hm = HOSTPORT_RE.match(hostport)
    if not hm:
        return None
    port = hm.group("port")
    if port != "443":
        return None

    params = {}
    for key, value in parse_qsl(query, keep_blank_values=True):
        params.setdefault(key.lower(), value)

    transport = params.get("type") or params.get("net") or params.get("network") or ""
    if transport.lower() != "ws":
        return None

    security = params.get("security", "")
    if scheme == "trojan":
        if security and security.lower() != "tls":
            return None
    elif security.lower() != "tls":
        return None

    if REQUIRE_HOST_OR_SNI and not (params.get("host") or params.get("sni")):
        return None

    # rebuild keeping everything except the host byte-identical
    rebuilt = f"{scheme}://{userinfo}@{TARGET_IP}:{port}"
    if query:
        rebuilt += f"?{query}"
    rebuilt += frag
    return rebuilt


def load_vmess_obj(line: str):
    payload = line[len("vmess://"):]
    try:
        if payload.lstrip().startswith("{"):
            return json.loads(payload)
        return json.loads(b64flex(payload).decode("utf-8", "ignore"))
    except Exception:
        return None


def rewrite_vmess(line: str) -> str | None:
    """vmess://<base64 JSON> lines."""
    obj = load_vmess_obj(line)
    if not isinstance(obj, dict):
        return None
    if str(obj.get("port")) != "443":
        return None
    if str(obj.get("net", "")).lower() != "ws":
        return None
    if str(obj.get("tls", "")).lower() != "tls":
        return None
    ws_opts = obj.get("ws-opts") or {}
    host = obj.get("host") or obj.get("sni") or (ws_opts.get("headers") or {}).get("Host")
    if REQUIRE_HOST_OR_SNI and not host:
        return None
    obj["add"] = TARGET_IP
    out = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    return "vmess://" + base64.b64encode(out.encode()).decode()


def dedup_key(line: str) -> str:
    """
    Identity of a config: everything that changes the real connection
    (scheme, uuid/password, sni, host, path, every query parameter value).

    Deliberately IGNORES:
      - the display name (#fragment at the end)
      - the order of query parameters (?a=1&b=2 == ?b=2&a=1)
      - url-encoding differences (%2F == /)

    So two links that are the same server with a different label collapse
    into one, but ANY real difference (uuid, path, sni, host, port...)
    keeps both links - unique links are never removed.
    """
    if line.lower().startswith("vmess://"):
        obj = load_vmess_obj(line)
        if isinstance(obj, dict):
            core = {k: v for k, v in obj.items() if k != "ps"}
            return "vmess|" + json.dumps(core, sort_keys=True,
                                         ensure_ascii=False, default=str)
        return line
    m = URI_RE.match(line)
    if not m:
        return line
    scheme, rest = m.group(1).lower(), m.group(2)
    i = rest.find("#")
    if i != -1:
        rest = rest[:i]
    i = rest.find("?")
    query = rest[i + 1:] if i != -1 else ""
    head = rest[:i] if i != -1 else rest
    userinfo = head.rsplit("@", 1)[0] if "@" in head else head
    params = sorted(parse_qsl(query, keep_blank_values=True))
    return f"{scheme}|{userinfo}|" + repr(params)


def collect(lines: list, exact_seen: set) -> list:
    """Filter + rewrite raw lines; drop exact duplicates. Returns rewritten lines."""
    kept = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith(("#", "//")):
            continue
        if line.lower().startswith("vmess://"):
            result = rewrite_vmess(line)
        else:
            result = rewrite_uri(line)
        if not result or result in exact_seen:
            continue
        exact_seen.add(result)
        kept.append(result)
    return kept


def write_outputs(groups: dict) -> list:
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    base64_names = {"all", "unique", "vless", "vmess", "trojan", "ss"}
    paths = []
    for name, lines in groups.items():
        plain = os.path.join(OUTPUT_DIR, f"{name}.txt")
        with open(plain, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + ("\n" if lines else ""))
        paths.append(plain)
        if name in base64_names and lines:
            b64 = os.path.join(OUTPUT_DIR, f"{name}_base64.txt")
            with open(b64, "w", encoding="utf-8") as fh:
                fh.write(base64.b64encode(("\n".join(lines) + "\n").encode()).decode())
            paths.append(b64)
    return paths


def main():
    with open(SOURCES_FILE, encoding="utf-8") as fh:
        sources = [ln.strip() for ln in fh
                   if ln.strip() and not ln.strip().startswith("#")]
    print(f"Target IP : {TARGET_IP}")
    print(f"Sources   : {len(sources)}")

    exact_seen, entries, failures = set(), [], 0
    for url in sources:
        try:
            lines = decode_payload(fetch_with_retry(url))
        except Exception:
            failures += 1
            continue
        got = collect(lines, exact_seen)
        entries.extend(got)
        print(f"[ok] {url}  fetched={len(lines)}  kept={len(got)}")

    # "all" keeps every exactly-unique line (same as before).
    # "unique" additionally collapses lines that are the same config
    # written twice with a different #name or a different parameter order.
    groups = {"all": [], "unique": [], "duplicates_removed": [],
              "vless": [], "vmess": [], "trojan": [], "ss": []}
    key_seen = set()
    for line in entries:
        scheme = line.split("://", 1)[0]
        groups["all"].append(line)
        if scheme in groups:
            groups[scheme].append(line)
        key = dedup_key(line)
        if key in key_seen:
            groups["duplicates_removed"].append(line)
        else:
            key_seen.add(key)
            groups["unique"].append(line)

    paths = write_outputs(groups)
    print("-" * 60)
    print(f"Exact-unique lines : {len(groups['all'])}")
    print(f"Unique configs     : {len(groups['unique'])}")
    print(f"Removed as same-config-different-name/order: {len(groups['duplicates_removed'])}")
    for name in ("vless", "vmess", "trojan", "ss"):
        print(f"  {name:8s}: {len(groups[name])}")
    print(f"Failed sources: {failures}")
    for p in paths:
        print(f"  wrote {p}")


if __name__ == "__main__":
    main()
