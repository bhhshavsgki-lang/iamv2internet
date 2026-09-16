#!/usr/bin/env python3
"""
Connectivity + ping tester.

Reads output/unique.txt, dials every config through a real xray-core
instance (local socks5 inbound -> the config's outbound), and requests
https://www.gstatic.com/generate_204 through it.

For every config that returns HTTP 200/204:
  - the ping (full request time through the tunnel, in ms) is measured
  - the country is detected: first from the flag emoji in the original
    name, otherwise via DNS + geo-IP lookup (ip-api.com) of the host=
    domain
  - the display name is rewritten to:  #FLAG CC 123ms | original-name

output/working.txt is sorted by ping - fastest at the top.

Outputs:
  output/working.txt            (+ _base64)  sorted by ping
  output/working_vless.txt / working_vmess.txt / working_trojan.txt / working_ss.txt
  output/test_report.txt        (summary committed to the repo)

If the xray binary is not found, the test is skipped with a warning and
the filtered lists are left untouched (exit 0).

Env vars: XRAY_PATH, WORKERS (default 30), MAX_TEST (0=all), TEST_TIMEOUT (10).
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
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
INPUT_FILE = os.path.join(OUTPUT_DIR, "unique.txt")
XRAY = os.environ.get("XRAY_PATH", os.path.join(BASE_DIR, "xray", "xray"))
WORKERS = int(os.environ.get("WORKERS", "30"))
MAX_TEST = int(os.environ.get("MAX_TEST", "0"))     # 0 = test everything
TEST_TIMEOUT = int(os.environ.get("TEST_TIMEOUT", "10"))
TEST_URL = os.environ.get("TEST_URL", "https://www.gstatic.com/generate_204")
GEO_API = os.environ.get("GEO_API", "http://ip-api.com/batch?fields=query,countryCode")
PORT_BASE = 20000
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


def build_outbound(line: str):
    """Convert one config line into an xray outbound dict."""
    if line.lower().startswith("vmess://"):
        try:
            obj = json.loads(b64flex(line[len("vmess://"):]).decode("utf-8", "ignore"))
        except Exception:
            return None, None, {}
        if not isinstance(obj, dict):
            return None, None, {}
        address, port = str(obj.get("add", "")), int(obj.get("port", 0))
        scheme, userinfo = "vmess", str(obj.get("id", ""))
        params = {"path": str(obj.get("path", "")),
                  "host": str(obj.get("host", "")),
                  "sni": str(obj.get("sni", ""))}
    else:
        parsed = split_uri(line)
        if not parsed:
            return None, None, {}
        scheme, userinfo, address, port, params = parsed

    sni = params.get("sni") or params.get("host") or address
    ws_host = params.get("host") or params.get("sni") or ""
    tls = {
        "serverName": sni,
        "allowInsecure": params.get("allowInsecure") in ("1", "true")
                         or params.get("insecure") in ("1", "true"),
    }
    if params.get("fp"):
        tls["fingerprint"] = params["fp"]
    if params.get("alpn"):
        tls["alpn"] = params["alpn"].split(",")

    stream = {
        "network": "ws",
        "security": "tls",
        "tlsSettings": tls,
        "wsSettings": {"path": params.get("path") or "/",
                       "headers": {"Host": ws_host} if ws_host else {}},
    }

    if scheme == "vless":
        outbound = {"protocol": "vless",
                    "settings": {"vnext": [{"address": address, "port": port,
                                            "users": [{"id": userinfo, "encryption": "none",
                                                       "flow": params.get("flow", "")}]}]},
                    "streamSettings": stream}
    elif scheme == "trojan":
        outbound = {"protocol": "trojan",
                    "settings": {"servers": [{"address": address, "port": port,
                                              "password": userinfo}]},
                    "streamSettings": stream}
    elif scheme == "vmess":
        outbound = {"protocol": "vmess",
                    "settings": {"vnext": [{"address": address, "port": port,
                                            "users": [{"id": userinfo, "security": "auto"}]}]},
                    "streamSettings": stream}
    elif scheme == "ss":
        method, password = params.get("encryption", "none"), userinfo
        try:
            decoded = b64flex(userinfo).decode("utf-8", "ignore")
            if ":" in decoded:
                method, password = decoded.split(":", 1)
        except Exception:
            pass
        outbound = {"protocol": "shadowsocks",
                    "settings": {"servers": [{"address": address, "port": port,
                                              "method": method, "password": password}]},
                    "streamSettings": stream}
    else:
        return None, None, {}
    return outbound, scheme, params


# ------------------------- country detection ---------------------------

def first_flag(name: str):
    """Country code from a flag emoji at the start of the name, e.g. 🇩🇪 -> DE."""
    ind = [ord(c) for c in name if 0x1F1E6 <= ord(c) <= 0x1F1FF]
    if len(ind) >= 2:
        return "".join(chr(65 + v - 0x1F1E6) for v in ind[:2])
    return None


def cc_to_flag(cc: str) -> str:
    if cc and len(cc) == 2 and cc.isalpha():
        return "".join(chr(0x1F1E6 + ord(c) - 65) for c in cc.upper())
    return "🌍"


def host_domain_of(line: str, params: dict):
    """The real backend domain of the config (host= or sni=)."""
    dom = params.get("host") or params.get("sni") or ""
    return dom.split("#", 1)[0].strip() if dom else ""


def geo_lookup(domains: list) -> dict:
    """domain -> ISO country code, via DNS + ip-api.com batch (free)."""
    result = {}
    if not domains:
        return result
    socket.setdefaulttimeout(3)
    ip_of = {}
    for d in set(domains):
        try:
            ip_of.setdefault(socket.gethostbyname(d), d)
        except Exception:
            continue
    ips = list(ip_of.keys())
    for i in range(0, len(ips), 100):
        chunk = ips[i:i + 100]
        try:
            req = urllib.request.Request(GEO_API, data=json.dumps(chunk).encode(),
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=20) as resp:
                for row in json.load(resp):
                    dom = ip_of.get(row.get("query"))
                    cc = row.get("countryCode")
                    if dom and cc:
                        result[dom] = cc
        except Exception:
            break
    return result


def rename_line(line: str, cc: str, ms: int) -> str:
    """Replace the display name with:  #FLAG CC 123ms | original-name"""
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
        outbound, scheme, params = build_outbound(line)
        if outbound is None:
            return line, scheme, params, False, "unparseable", 0
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
            time.sleep(0.35)                      # let xray bind the port
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
        return line, scheme, params, code in ("200", "204"), code, ms


def main():
    if not os.path.exists(XRAY):
        print(f"[warn] xray binary not found at {XRAY} - skipping test.")
        print("[warn] Filtered lists are untouched. Install xray to enable testing.")
        return 0
    if not os.path.exists(INPUT_FILE):
        print(f"[warn] {INPUT_FILE} not found - run filter.py first.")
        return 0

    with open(INPUT_FILE, encoding="utf-8") as fh:
        lines = [ln.strip() for ln in fh if ln.strip()]
    if MAX_TEST and len(lines) > MAX_TEST:
        lines = lines[:MAX_TEST]
    total = len(lines)
    print(f"Testing {total} configs via {XRAY} (workers={WORKERS}, timeout={TEST_TIMEOUT}s)")

    tester = Tester()
    alive = []            # (ms, line, scheme, params)
    per_proto = {}
    done = ok_count = 0
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futures = [ex.submit(tester.test, ln) for ln in lines]
        for fut in as_completed(futures):
            line, scheme, params, ok, code, ms = fut.result()
            done += 1
            per_proto.setdefault(scheme, [0, 0])
            per_proto[scheme][1] += 1
            if ok:
                ok_count += 1
                alive.append((ms, line, scheme, params))
                per_proto[scheme][0] += 1
            if done % 50 == 0 or done == total:
                print(f"  {done}/{total} tested, {ok_count} alive", flush=True)

    # --- country detection for the working configs ---
    cc_of, need_geo = {}, []     # cc_of: index into alive -> country code
    for i, (ms, line, scheme, params) in enumerate(alive):
        cc = first_flag(line.split("#", 1)[1]) if "#" in line else None
        if cc:
            cc_of[i] = cc
        else:
            need_geo.append((i, host_domain_of(line, params)))
    geo = geo_lookup([d for _, d in need_geo if d])
    for i, dom in need_geo:
        if i not in cc_of:
            cc_of[i] = geo.get(dom, "")

    # --- rename with country + ping, sort fastest first ---
    named = []
    for i, (ms, line, scheme, params) in enumerate(alive):
        named.append((ms, rename_line(line, cc_of.get(i, ""), ms), scheme))
    named.sort(key=lambda t: t[0])

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    ordered_lines = [ln for _, ln, _ in named]
    with open(os.path.join(OUTPUT_DIR, "working.txt"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(ordered_lines) + ("\n" if ordered_lines else ""))
    with open(os.path.join(OUTPUT_DIR, "working_base64.txt"), "w", encoding="utf-8") as fh:
        fh.write(base64.b64encode(("\n".join(ordered_lines) + "\n").encode()).decode())
    for name in ("vless", "vmess", "trojan", "ss"):
        subset = [ln for _, ln, sch in named if sch == name]
        with open(os.path.join(OUTPUT_DIR, f"working_{name}.txt"), "w", encoding="utf-8") as fh:
            fh.write("\n".join(subset) + ("\n" if subset else ""))

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    pct = (100.0 * ok_count / total) if total else 0.0
    pings = [ms for ms, _, _ in named]
    report = ["Connectivity test report", f"Date   : {now}",
              f"Tested : {total}", f"Working: {ok_count} ({pct:.1f}%)",
              f"Fastest ping: {pings[0] if pings else '-'} ms"
              + (f" | median: {int(statistics.median(pings))} ms" if pings else ""), "",
              "working.txt is sorted by ping - fastest at the top.", ""]
    for name in ("vless", "vmess", "trojan", "ss"):
        ok, tot = per_proto.get(name, [0, 0])
        report.append(f"  {name:7s}: {ok}/{tot} alive")
    with open(os.path.join(OUTPUT_DIR, "test_report.txt"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(report) + "\n")
    print("\n".join(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
