#!/usr/bin/env python3
"""
Connectivity tester.

Reads output/unique.txt, dials every config through a real xray-core
instance (local socks5 inbound -> the config's outbound), and requests
https://www.gstatic.com/generate_204 through it.

Configs that return HTTP 200/204 are alive -> saved to:
  output/working.txt            (+ _base64)
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
import subprocess
import sys
import tempfile
import threading
import time
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
            return None, None
        if not isinstance(obj, dict):
            return None, None
        address, port = str(obj.get("add", "")), int(obj.get("port", 0))
        scheme, userinfo = "vmess", str(obj.get("id", ""))
        params = {"path": str(obj.get("path", "")),
                  "host": str(obj.get("host", "")),
                  "sni": str(obj.get("sni", ""))}
    else:
        parsed = split_uri(line)
        if not parsed:
            return None, None
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
        return None, None
    return outbound, scheme


class Tester:
    def __init__(self):
        self.tmpdir = tempfile.mkdtemp(prefix="xrtest-")
        self.ports = queue.Queue()
        for k in range(WORKERS):
            self.ports.put(PORT_BASE + k)
        self.lock = threading.Lock()

    def test(self, line: str):
        outbound, scheme = build_outbound(line)
        if outbound is None:
            return line, scheme, False, "unparseable"
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
        code = "000"
        try:
            time.sleep(0.35)                      # let xray bind the port
            r = subprocess.run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                 "--max-time", str(TEST_TIMEOUT), "-x", f"socks5h://127.0.0.1:{port}",
                 "-A", USER_AGENT, TEST_URL],
                capture_output=True, text=True, timeout=TEST_TIMEOUT + 5)
            code = r.stdout.strip() or "000"
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
        return line, scheme, code in ("200", "204"), code


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
    alive, per_proto = [], {}
    done = ok_count = 0
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futures = [ex.submit(tester.test, ln) for ln in lines]
        for fut in as_completed(futures):
            line, scheme, ok, code = fut.result()
            done += 1
            if ok:
                ok_count += 1
                alive.append(line)
                per_proto.setdefault(scheme, [0, 0])
                per_proto[scheme][0] += 1
            per_proto.setdefault(scheme, [0, 0])
            per_proto[scheme][1] += 1
            if done % 50 == 0 or done == total:
                print(f"  {done}/{total} tested, {ok_count} alive", flush=True)

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "working.txt"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(alive) + ("\n" if alive else ""))
    with open(os.path.join(OUTPUT_DIR, "working_base64.txt"), "w", encoding="utf-8") as fh:
        fh.write(base64.b64encode(("\n".join(alive) + "\n").encode()).decode())
    for name in ("vless", "vmess", "trojan", "ss"):
        subset = [ln for ln in alive if ln.startswith(name + "://")]
        with open(os.path.join(OUTPUT_DIR, f"working_{name}.txt"), "w", encoding="utf-8") as fh:
            fh.write("\n".join(subset) + ("\n" if subset else ""))

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    pct = (100.0 * ok_count / total) if total else 0.0
    report = ["Connectivity test report", f"Date   : {now}",
              f"Tested : {total}", f"Working: {ok_count} ({pct:.1f}%)", ""]
    for name in ("vless", "vmess", "trojan", "ss"):
        ok, tot = per_proto.get(name, [0, 0])
        report.append(f"  {name:7s}: {ok}/{tot} alive")
    with open(os.path.join(OUTPUT_DIR, "test_report.txt"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(report) + "\n")
    print("\n".join(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
