#!/usr/bin/env python3
"""
Connectivity + ping tester for ORIGINAL configs (no IP rewriting).

Reads output_original/unique.txt (vless/vmess/trojan, any port, any
transport), dials every config through a real xray-core instance and
requests https://www.gstatic.com/generate_204 through it.

Supports: ws, grpc, tcp (incl. http header), httpupgrade, xhttp,
security tls / reality / none.

For every working config:
  - ping (request time through the tunnel, ms)
  - country: flag emoji from the original name, otherwise geo-IP lookup
    of the actual server address
  - name rewritten to:  #FLAG CC 87ms | original-name
output_original/working.txt is sorted by ping - fastest at the top.

Env vars: XRAY_PATH, WORKERS (40), MAX_TEST (0=all), TEST_TIMEOUT (8).
"""

import base64
import json
import os
import queue
import re
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import parse_qsl

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "output_original")
INPUT_FILE = os.path.join(OUTPUT_DIR, "unique.txt")
XRAY = os.environ.get("XRAY_PATH", os.path.join(BASE_DIR, "xray", "xray"))
WORKERS = int(os.environ.get("WORKERS", "40"))
MAX_TEST = int(os.environ.get("MAX_TEST", "0"))
TEST_TIMEOUT = int(os.environ.get("TEST_TIMEOUT", "8"))
TEST_URL = os.environ.get("TEST_URL", "https://www.gstatic.com/generate_204")
GEO_API = os.environ.get("GEO_API", "http://ip-api.com/batch?fields=query,countryCode")
GEO_FALLBACKS = ("https://freeipapi.com/api/json/",
                 "https://ipwho.is/",
                 "https://api.ip.sb/geoip/")
PORT_BASE = 30000
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) config-tester/1.0"

URI_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*)://(.*)$")
HOSTPORT_RE = re.compile(r"^(?P<host>.+):(?P<port>\d+)(?P<path>/.*)?$")


def b64flex(data: str) -> bytes:
    data = data.strip().replace("-", "+").replace("_", "/")
    data += "=" * (-len(data) % 4)
    return base64.b64decode(data)


def split_uri(line: str):
    m = URI_RE.match(line)
    if not m:
        return None
    scheme, rest = m.group(1).lower(), m.group(2)
    i = rest.find("#")
    if i != -1:
        rest = rest[:i]
    i = rest.find("?")
    query = rest[i + 1:] if i != -1 else ""
    head = rest[:i] if i != -1 else rest
    if "@" not in head:
        return None
    userinfo, hostport = head.rsplit("@", 1)
    if "/" in hostport:
        hostport = hostport.split("/", 1)[0]
    hm = HOSTPORT_RE.match(hostport)
    if not hm:
        return None
    params = {}
    for key, value in parse_qsl(query, keep_blank_values=True):
        params.setdefault(key.lower(), value)
    return scheme, userinfo, hm.group("host"), int(hm.group("port")), params


def norm_stream(params: dict, address: str, scheme: str) -> dict:
    """Build xray streamSettings from URI params / vmess fields."""
    net = (params.get("type") or params.get("net") or params.get("network")
           or "tcp").lower()
    if net in ("h2", "http"):
        net = "http"
    if net in ("splithttp",):
        net = "xhttp"

    security = (params.get("security") or "").lower()
    if scheme == "trojan" and security not in ("tls", "reality"):
        security = "tls"
    if net in ("tcp",) and not security and scheme in ("vless",):
        security = "none"

    stream = {"network": net, "security": security or "none"}
    sni = params.get("sni") or params.get("host") or address
    fp = params.get("fp")
    alpn = params.get("alpn")

    if security == "tls":
        tls = {"serverName": sni,
               "allowInsecure": params.get("allowinsecure") in ("1", "true")
                                or params.get("insecure") in ("1", "true")}
        if fp:
            tls["fingerprint"] = fp
        if alpn:
            tls["alpn"] = alpn.split(",")
        stream["tlsSettings"] = tls
    elif security == "reality":
        rl = {"serverName": sni, "show": False,
              # uTLS fingerprint is required for reality to handshake
              "fingerprint": fp or "chrome"}
        pubkey = params.get("pbk") or params.get("pb") or params.get("publickey")
        if pubkey:
            rl["publicKey"] = pubkey
        if params.get("sid") or params.get("shortid"):
            rl["shortId"] = params.get("sid") or params.get("shortid")
        if params.get("spx"):
            rl["spiderX"] = params["spx"]
        stream["realitySettings"] = rl

    path = params.get("path") or "/"
    host = params.get("host") or params.get("sni") or ""
    if net == "ws":
        ws = {"path": path}
        if host:
            ws["headers"] = {"Host": host}
        stream["wsSettings"] = ws
    elif net == "grpc":
        g = {"serviceName": params.get("servicename") or params.get("path") or ""}
        if params.get("mode") == "multi":
            g["multiMode"] = True
        stream["grpcSettings"] = g
    elif net == "httpupgrade":
        h = {"path": path}
        if host:
            h["host"] = host
        stream["httpupgradeSettings"] = h
    elif net == "xhttp":
        h = {"path": path}
        if host:
            h["host"] = host
        if params.get("mode"):
            h["mode"] = params["mode"]
        stream["xhttpSettings"] = h
    elif net == "http":
        h = {"path": path}
        if host:
            h["host"] = [host]
        stream["httpSettings"] = h
    else:                                     # tcp
        if (params.get("header") or "").lower() == "http":
            stream["tcpSettings"] = {"header": {"type": "http",
                                                "request": {"headers": {"Host": [host]} if host else {}}}}
    return stream


def build_outbound(line: str):
    """Convert one config line into an xray outbound dict + connect address."""
    if line.lower().startswith("vmess://"):
        try:
            obj = json.loads(b64flex(line[len("vmess://"):]).decode("utf-8", "ignore"))
        except Exception:
            return None, None, ""
        if not isinstance(obj, dict):
            return None, None, ""
        address = str(obj.get("add", "")).strip()
        try:
            port = int(str(obj.get("port", "0")).strip())
        except ValueError:
            return None, None, ""
        net = str(obj.get("net", "tcp")).lower()
        tls_field = str(obj.get("tls", "")).lower()
        params = {"type": net, "security": tls_field,
                  "sni": str(obj.get("sni", "")),
                  "host": str(obj.get("host", "")),
                  "path": str(obj.get("path", "")),
                  "alpn": str(obj.get("alpn", "")),
                  "fp": str(obj.get("fp", "")),
                  "insecure": str(obj.get("allowinsecure", ""))}
        if net == "tcp" and str(obj.get("type", "")).lower() == "http":
            params["header"] = "http"
        scheme, userinfo = "vmess", str(obj.get("id", ""))
        user = {"id": userinfo, "security": str(obj.get("scy", "auto")),
                "alterId": int(obj.get("aid", 0) or 0)}
        network = "tcp" if net not in ("ws", "grpc", "httpupgrade", "xhttp", "http") else net
    else:
        parsed = split_uri(line)
        if not parsed:
            return None, None, ""
        scheme, userinfo, address, port, params = parsed
        user = {"id": userinfo, "encryption": "none"}
        if params.get("flow"):
            # flow is only valid on raw tcp (tls/reality); drop it otherwise
            if params.get("type", "tcp").lower() in ("tcp", ""):
                user["flow"] = params["flow"]
        network = None

    if scheme == "vless":
        outbound = {"protocol": "vless",
                    "settings": {"vnext": [{"address": address, "port": port,
                                            "users": [user]}]}}
    elif scheme == "trojan":
        outbound = {"protocol": "trojan",
                    "settings": {"servers": [{"address": address, "port": port,
                                              "password": userinfo}]}}
    elif scheme == "vmess":
        outbound = {"protocol": "vmess",
                    "settings": {"vnext": [{"address": address, "port": port,
                                            "users": [user]}]}}
    else:
        return None, None, ""

    stream = norm_stream(params, address, scheme)
    if network:
        stream["network"] = network
    outbound["streamSettings"] = stream
    return outbound, scheme, address


# ------------------------- country detection ---------------------------

def first_flag(name: str):
    ind = [ord(c) for c in name if 0x1F1E6 <= ord(c) <= 0x1F1FF]
    if len(ind) >= 2:
        return "".join(chr(65 + v - 0x1F1E6) for v in ind[:2])
    return None


def cc_to_flag(cc: str) -> str:
    if cc and len(cc) == 2 and cc.isalpha():
        return "".join(chr(0x1F1E6 + ord(c) - 65) for c in cc.upper())
    return "🌍"


def _resolve_ip(address: str):
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", address):
        return address
    try:
        return socket.gethostbyname(address)
    except Exception:
        return None


def _geo_ipapi_batch(ips: list) -> dict:
    req = urllib.request.Request(GEO_API, data=json.dumps(ips).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        out = {}
        for row in json.load(resp):
            if row.get("query") and row.get("countryCode"):
                out[row["query"]] = row["countryCode"]
        return out


def _geo_one(ip: str):
    """Country code for one IP, trying every fallback provider."""
    for attempt in range(2):
        # freeipapi: https://freeipapi.com/api/json/<ip> -> {"countryCode": "CA"}
        try:
            with urllib.request.urlopen(GEO_FALLBACKS[0] + ip, timeout=10) as resp:
                cc = json.load(resp).get("countryCode")
                if cc:
                    return cc
        except Exception:
            pass
        # ipwho.is: https://ipwho.is/<ip> -> {"country_code": "CA"}
        try:
            with urllib.request.urlopen(GEO_FALLBACKS[1] + ip, timeout=10) as resp:
                cc = json.load(resp).get("country_code")
                if cc:
                    return cc
        except Exception:
            pass
        # api.ip.sb: https://api.ip.sb/geoip/<ip> -> {"country_code": "CA"}
        try:
            req = urllib.request.Request(GEO_FALLBACKS[2] + ip,
                                         headers={"User-Agent": "curl/8.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                cc = json.load(resp).get("country_code")
                if cc:
                    return cc
        except Exception:
            pass
        time.sleep(1 + attempt)
    return ""


def geo_lookup(addresses: list) -> dict:
    """address (IP or domain) -> ISO country code. DNS-resolves domains,
    tries a batch API first, falls back to per-IP lookups."""
    result, ip_of = {}, {}
    for a in set(addresses):
        ip = _resolve_ip(a)
        if ip:
            ip_of.setdefault(ip, a)
    ips = list(ip_of.keys())
    if not ips:
        return result
    socket.setdefaulttimeout(5)

    # 1) batch API - one request per 100 IPs
    for i in range(0, len(ips), 100):
        chunk = ips[i:i + 100]
        try:
            result.update(_geo_ipapi_batch(chunk))
        except Exception:
            break
    remaining = [ip for ip in ips if ip not in result]
    # 2) fallback: per-IP provider chain, polite concurrency
    if remaining:
        with ThreadPoolExecutor(max_workers=10) as ex:
            for ip, cc in zip(remaining, ex.map(_geo_one, remaining)):
                if cc:
                    result[ip] = cc
    return {ip_of[ip]: cc for ip, cc in result.items() if ip in ip_of}


def rename_line(line: str, cc: str, ms: int) -> str:
    base = line.split("#", 1)[0]
    orig = line.split("#", 1)[1] if "#" in line else ""
    orig = orig[:50]
    name = f"{cc_to_flag(cc)} {cc or '??'} {ms}ms"
    if orig:
        name += f" | {orig}"
    return f"{base}#{name}"


# ------------------------------ testing --------------------------------

class Tester:
    def __init__(self):
        self.tmpdir = tempfile.mkdtemp(prefix="xrtest-")
        self.ports = queue.Queue()
        for k in range(WORKERS):
            self.ports.put(PORT_BASE + k)

    def test(self, line: str):
        outbound, scheme, address = build_outbound(line)
        if outbound is None:
            return line, scheme, address, False, "unparseable", 0
        port = self.ports.get()
        cfg_path = os.path.join(self.tmpdir, f"c{port}.json")
        cfg = {"log": {"loglevel": "error"},
               "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "socks",
                             "settings": {"udp": False}}],
               "outbounds": [outbound]}
        with open(cfg_path, "w") as fh:
            json.dump(cfg, fh)
        proc = subprocess.Popen([XRAY, "run", "-c", cfg_path],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        code, ms = "000", 0
        try:
            time.sleep(0.35)
            r = subprocess.run(
                ["curl", "-s", "-o", "/dev/null",
                 "-w", "%{http_code} %{time_total}",
                 "--max-time", str(TEST_TIMEOUT), "-x", f"socks5h://127.0.0.1:{port}",
                 "-A", USER_AGENT, TEST_URL],
                capture_output=True, text=True, timeout=TEST_TIMEOUT + 5)
            parts = (r.stdout.strip() or "000 0").split()
            code = parts[0]
            if code in ("200", "204"):
                ms = max(1, round(float(parts[1]) * 1000))
        except Exception:
            code = "000"
        finally:
            proc.kill()
            proc.wait()
            try:
                os.unlink(cfg_path)
            except OSError:
                pass
            self.ports.put(port)
        return line, scheme, address, code in ("200", "204"), code, ms


def main():
    if not os.path.exists(XRAY):
        print(f"[warn] xray binary not found at {XRAY} - skipping test.")
        return 0
    if not os.path.exists(INPUT_FILE):
        print(f"[warn] {INPUT_FILE} not found - run filter_original.py first.")
        return 0

    with open(INPUT_FILE, encoding="utf-8") as fh:
        lines = [ln.strip() for ln in fh if ln.strip()]
    if MAX_TEST and len(lines) > MAX_TEST:
        lines = lines[:MAX_TEST]
    total = len(lines)
    print(f"Testing {total} ORIGINAL configs via {XRAY} "
          f"(workers={WORKERS}, timeout={TEST_TIMEOUT}s)")

    tester = Tester()
    alive, per_proto = [], {}
    done = ok_count = 0
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futures = [ex.submit(tester.test, ln) for ln in lines]
        for fut in as_completed(futures):
            line, scheme, address, ok, code, ms = fut.result()
            done += 1
            per_proto.setdefault(scheme, [0, 0])
            per_proto[scheme][1] += 1
            if ok:
                ok_count += 1
                alive.append((ms, line, scheme, address))
                per_proto[scheme][0] += 1
            if done % 100 == 0 or done == total:
                print(f"  {done}/{total} tested, {ok_count} alive", flush=True)

    # --- country detection ---
    cc_of, need_geo = {}, []
    for i, (ms, line, scheme, address) in enumerate(alive):
        cc = first_flag(line.split("#", 1)[1]) if "#" in line else None
        if cc:
            cc_of[i] = cc
        else:
            need_geo.append((i, address))
    geo = geo_lookup([a for _, a in need_geo])
    for i, address in need_geo:
        if i not in cc_of:
            cc_of[i] = geo.get(address, "")

    # --- rename + sort fastest first ---
    named = []
    for i, (ms, line, scheme, address) in enumerate(alive):
        named.append((ms, rename_line(line, cc_of.get(i, ""), ms), scheme))
    named.sort(key=lambda t: t[0])

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    ordered = [ln for _, ln, _ in named]
    with open(os.path.join(OUTPUT_DIR, "working.txt"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(ordered) + ("\n" if ordered else ""))
    with open(os.path.join(OUTPUT_DIR, "working_base64.txt"), "w", encoding="utf-8") as fh:
        fh.write(base64.b64encode(("\n".join(ordered) + "\n").encode()).decode())
    for name in ("vless", "vmess", "trojan"):
        subset = [ln for _, ln, sch in named if sch == name]
        with open(os.path.join(OUTPUT_DIR, f"working_{name}.txt"), "w", encoding="utf-8") as fh:
            fh.write("\n".join(subset) + ("\n" if subset else ""))

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    pct = (100.0 * ok_count / total) if total else 0.0
    pings = [ms for ms, _, _ in named]
    report = ["Original-config connectivity report", f"Date   : {now}",
              f"Tested : {total}", f"Working: {ok_count} ({pct:.1f}%)",
              f"Fastest ping: {pings[0] if pings else '-'} ms"
              + (f" | median: {int(statistics.median(pings))} ms" if pings else ""), "",
              "working.txt is sorted by ping - fastest at the top.", ""]
    for name in ("vless", "vmess", "trojan"):
        ok, tot = per_proto.get(name, [0, 0])
        report.append(f"  {name:7s}: {ok}/{tot} alive")
    with open(os.path.join(OUTPUT_DIR, "test_report.txt"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(report) + "\n")
    print("\n".join(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
