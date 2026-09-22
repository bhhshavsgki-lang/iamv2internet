#!/usr/bin/env python3
"""
Original-address filter (second pipeline - no IP rewriting).

1. Downloads every subscription URL in sources.txt
2. Keeps ONLY vless:// vmess:// trojan:// configs - ANY port, ANY
   transport (ws, grpc, tcp, reality...). The server address is kept
   EXACTLY as it appears in the source list.
3. Deduplicates: two links are the same config when protocol + secret +
   server address + port + all parameter values are identical
   (ignores only the #name and parameter order).
4. Saves to output_original/ (separate from the CDN pipeline in output/).

Set TARGET nothing here - nothing is rewritten.
"""

import base64
import hashlib
import json
import os
import re
import ssl
import time
import urllib.error
import urllib.request
from urllib.parse import parse_qsl

ALLOWED_SCHEMES = {"vless", "vmess", "trojan"}

# The unique list is also split into N deterministic shards for the
# parallel test jobs (shards_tmp/, uploaded as artifacts, not committed).
N_SHARDS = int(os.environ.get("N_SHARDS", "8"))
SHARD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "shards_tmp")

# Caps for files committed to the repo (git stays healthy; the shards
# carry the FULL list to the testers).
CAP_UNIQUE = 150000
CAP_ALL = 30000
CAP_PROTO = 10000
CAP_DUPS = 20000

TIMEOUT = 30
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SOURCES_FILE = os.path.join(BASE_DIR, "sources.txt")
OUTPUT_DIR = os.path.join(BASE_DIR, "output_original")
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) config-filter/1.0"

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
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as resp:
        return resp.read().decode("utf-8", "ignore")


def fetch_with_retry(url: str) -> str:
    last = None
    for attempt in range(1, 5):
        try:
            text = fetch(url)
            time.sleep(0.5)              # be gentle with raw.githubusercontent
            return text
        except Exception as exc:
            last = exc
            time.sleep(2 * attempt)      # backoff: 2s, 4s, 6s
    print(f"[FAIL] {url}: {last}")
    raise last


def b64flex(data: str) -> bytes:
    data = data.strip().replace("-", "+").replace("_", "/")
    data += "=" * (-len(data) % 4)
    return base64.b64decode(data)


def decode_payload(text: str) -> list:
    text = text.strip()
    if not text:
        return []
    if "://" in text:
        return text.splitlines()
    try:
        decoded = b64flex(text).decode("utf-8", "ignore")
        if "://" in decoded:
            return decoded.splitlines()
    except Exception:
        pass
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


def load_vmess_obj(line: str):
    payload = line[len("vmess://"):]
    try:
        if payload.lstrip().startswith("{"):
            return json.loads(payload)
        return json.loads(b64flex(payload).decode("utf-8", "ignore"))
    except Exception:
        return None


def normalize(line: str):
    """Parse one config line. Returns (scheme, host, port) or None if unusable."""
    m = URI_RE.match(line)
    if not m:
        return None
    scheme, rest = m.group(1).lower(), m.group(2)
    if scheme not in ALLOWED_SCHEMES:
        return None

    if scheme == "vmess":
        obj = load_vmess_obj(line)
        if not isinstance(obj, dict):
            return None
        host = str(obj.get("add", "")).strip()
        port = str(obj.get("port", "")).strip()
        if not host or not port.isdigit():
            return None
        return scheme, host, port

    i = rest.find("#")
    if i != -1:
        rest = rest[:i]
    i = rest.find("?")
    head = rest[:i] if i != -1 else rest
    if "@" not in head:
        return None                      # ss-style payload, not testable
    hostport = head.rsplit("@", 1)[1]
    if "/" in hostport:
        hostport = hostport.split("/", 1)[0]
    hm = HOSTPORT_RE.match(hostport)
    if not hm or len(hm.group("host")) < 3:
        return None
    return scheme, hm.group("host"), hm.group("port")


def dedup_key(line: str) -> str:
    """
    Identity: protocol + secret + SERVER ADDRESS + port + every parameter
    value. Ignores only the #name, parameter order and url-encoding.
    """
    parsed = normalize(line)
    if parsed is None:
        return line
    scheme, host, port = parsed
    m = URI_RE.match(line)
    scheme_l, rest = m.group(1).lower(), m.group(2)
    if scheme_l == "vmess":
        obj = load_vmess_obj(line)
        if isinstance(obj, dict):
            core = {k: v for k, v in obj.items() if k != "ps"}
            return "vmess|" + json.dumps(core, sort_keys=True,
                                         ensure_ascii=False, default=str)
        return line
    i = rest.find("#")
    if i != -1:
        rest = rest[:i]
    i = rest.find("?")
    query = rest[i + 1:] if i != -1 else ""
    head = rest[:i] if i != -1 else rest
    userinfo = head.rsplit("@", 1)[0] if "@" in head else head
    params = sorted(parse_qsl(query, keep_blank_values=True))
    return f"{scheme_l}|{userinfo}|{host}:{port}|" + repr(params)


def main():
    with open(SOURCES_FILE, encoding="utf-8") as fh:
        sources = [ln.strip() for ln in fh
                   if ln.strip() and not ln.strip().startswith("#")]
    print(f"Sources: {len(sources)} (original addresses, vless/vmess/trojan, any port)")

    exact_seen, entries, failures = set(), [], 0
    for url in sources:
        try:
            lines = decode_payload(fetch_with_retry(url))
        except Exception:
            failures += 1
            continue
        kept = 0
        for raw in lines:
            line = raw.strip()
            if not line or line.startswith(("#", "//")):
                continue
            if normalize(line) is None:
                continue
            if line in exact_seen:
                continue
            exact_seen.add(line)
            entries.append(line)
            kept += 1
        print(f"[ok] {url}  fetched={len(lines)}  kept={kept}")

    groups = {"all": list(entries), "unique": [], "duplicates_removed": [],
              "vless": [], "vmess": [], "trojan": []}
    key_seen = set()
    for line in entries:
        scheme = line.split("://", 1)[0].lower()
        if scheme in groups:
            groups[scheme].append(line)
        key = dedup_key(line)
        if key in key_seen:
            groups["duplicates_removed"].append(line)
        else:
            key_seen.add(key)
            groups["unique"].append(line)

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # full unique list -> deterministic shards for the parallel testers
    os.makedirs(SHARD_DIR, exist_ok=True)
    shard_counts = [0] * N_SHARDS
    handles = [open(os.path.join(SHARD_DIR, f"shard_{i}.txt"), "w",
                    encoding="utf-8") for i in range(N_SHARDS)]
    for line in groups["unique"]:
        key = dedup_key(line)
        idx = int(hashlib.md5(key.encode()).hexdigest(), 16) % N_SHARDS
        handles[idx].write(line + "\n")
        shard_counts[idx] += 1
    for fh in handles:
        fh.close()
    print(f"Shards written to {SHARD_DIR}: {shard_counts}")

    caps = {"all": CAP_ALL, "unique": CAP_UNIQUE,
            "duplicates_removed": CAP_DUPS,
            "vless": CAP_PROTO, "vmess": CAP_PROTO, "trojan": CAP_PROTO}
    for name, lines in groups.items():
        cap = caps.get(name, 20000)
        cut = lines[:cap]
        if len(lines) > cap:
            print(f"[cap] {name}.txt truncated to {cap} of {len(lines)} lines")
        with open(os.path.join(OUTPUT_DIR, f"{name}.txt"), "w", encoding="utf-8") as fh:
            fh.write("\n".join(cut) + ("\n" if cut else ""))

    print("-" * 60)
    print(f"Parsed lines        : {len(groups['all'])}")
    print(f"Unique configs      : {len(groups['unique'])}")
    print(f"Removed as duplicates: {len(groups['duplicates_removed'])}")
    for name in ("vless", "vmess", "trojan"):
        print(f"  {name:8s}: {len(groups[name])}")
    print(f"Failed sources: {failures}")


if __name__ == "__main__":
    main()
