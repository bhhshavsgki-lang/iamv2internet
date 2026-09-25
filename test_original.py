#!/usr/bin/env python3
"""
Connectivity + ping tester for ORIGINAL configs (no IP rewriting).

THREE MODES (env SHARD):
  (unset)      single mode  - local runs: test output_original/unique.txt
  SHARD=k      shard mode   - GitHub parallel jobs: test shards_tmp/shard_k.txt
                              (the k-th deterministic slice of ALL unique
                              configs) + the pool lines belonging to shard k
  SHARD=merge  merge mode   - collect all shard results, deep-check every
                              working server, build the final files

Runs in shard mode test EVERY candidate in their shard (no cap) so the
whole unique list is covered in one workflow run - 8 runners in parallel.
"""

import base64
import hashlib
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

import filter_original as fo

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "output_original")
INPUT_FILE = os.path.join(OUTPUT_DIR, "unique.txt")
STATE_FILE = os.path.join(OUTPUT_DIR, "state.json")   # persistent pool
LEGACY_WORKING = os.path.join(OUTPUT_DIR, "working.txt")  # pre-pool runs
SHARD_DIR = fo.SHARD_DIR                              # input shards
SHARD_OUT_DIR = os.path.join(BASE_DIR, "shard_out_tmp")  # shard results
N_SHARDS = fo.N_SHARDS
SHARD = os.environ.get("SHARD", "")
GRACE = 2
TARGET_IP = os.environ.get("TARGET_IP", "104.18.37.127")
PER_COUNTRY_LIMIT = int(os.environ.get("PER_COUNTRY_LIMIT", "50"))
DEEP_SAMPLES = int(os.environ.get("DEEP_SAMPLES", "3"))
XRAY = os.environ.get("XRAY_PATH", os.path.join(BASE_DIR, "xray", "xray"))
WORKERS = int(os.environ.get("WORKERS", "40"))
MAX_TEST = int(os.environ.get("MAX_TEST", "0"))     # single mode cap
MAX_TEST_SHARD = int(os.environ.get("MAX_TEST_SHARD", "0"))  # shard mode, 0=all
TEST_TIMEOUT = int(os.environ.get("TEST_TIMEOUT", "8"))
TEST_URL = os.environ.get("TEST_URL", "https://www.gstatic.com/generate_204")
GEO_API = os.environ.get("GEO_API", "http://ip-api.com/batch?fields=query,countryCode,city")
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
        if (params.get("header") or params.get("type") or "").lower() == "http":
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
        try:
            alter_id = int(obj.get("aid", 0) or 0)
        except (TypeError, ValueError):
            alter_id = 0
        user = {"id": userinfo, "security": str(obj.get("scy", "auto")),
                "alterId": alter_id}
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
                out[row["query"]] = (row["countryCode"], row.get("city") or "")
        return out


def _geo_one(ip: str):
    """(country_code, city) for one IP - tries every provider, twice."""
    for attempt in range(2):
        # freeipapi: -> {"countryCode": "CA", "cityName": "Toronto"}
        try:
            with urllib.request.urlopen(GEO_FALLBACKS[0] + ip, timeout=10) as resp:
                d = json.load(resp)
                if d.get("countryCode"):
                    return d["countryCode"], d.get("cityName") or ""
        except Exception:
            pass
        # ipwho.is: -> {"country_code": "CA", "city": "Toronto"}
        try:
            with urllib.request.urlopen(GEO_FALLBACKS[1] + ip, timeout=10) as resp:
                d = json.load(resp)
                if d.get("country_code"):
                    return d["country_code"], d.get("city") or ""
        except Exception:
            pass
        # api.ip.sb: -> {"country_code": "CA", "city": "Toronto"}
        try:
            req = urllib.request.Request(GEO_FALLBACKS[2] + ip,
                                         headers={"User-Agent": "curl/8.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                d = json.load(resp)
                if d.get("country_code"):
                    return d["country_code"], d.get("city") or ""
        except Exception:
            pass
        time.sleep(1 + attempt)
    return "", ""


def geo_lookup(addresses: list) -> dict:
    """address (IP or domain) -> (country_code, city). DNS-resolves domains,
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
            for ip, loc in zip(remaining, ex.map(_geo_one, remaining)):
                if loc[0]:
                    result[ip] = loc
    return {ip_of[ip]: loc for ip, loc in result.items() if ip in ip_of}


def rename_line(line: str, cc: str, city: str, ms: int) -> str:
    base = line.split("#", 1)[0]
    orig = line.split("#", 1)[1] if "#" in line else ""
    orig = orig[:50]
    name = f"{cc_to_flag(cc)} {cc or '??'}"
    if city:
        city = city.replace(",", "").replace("#", "").strip()[:18]
        if city:
            name += f" {city}"
    name += f" {ms}ms"
    if orig:
        name += f" | {orig}"
    return f"{base}#{name}"


def swap_address(line: str, new_ip: str) -> str:
    """Replace ONLY the server address with new_ip; port, params and name stay."""
    if line.lower().startswith("vmess://"):
        try:
            payload = line[len("vmess://"):]
            if payload.lstrip().startswith("{"):
                obj = json.loads(payload)
            else:
                obj = json.loads(fo.b64flex(payload).decode("utf-8", "ignore"))
        except Exception:
            return line
        if isinstance(obj, dict):
            obj["add"] = new_ip
            out = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
            return "vmess://" + base64.b64encode(out.encode()).decode()
        return line
    m = fo.URI_RE.match(line)
    if not m:
        return line
    scheme, rest = m.group(1), m.group(2)
    i = rest.find("#")
    frag = rest[i:] if i != -1 else ""
    if i != -1:
        rest = rest[:i]
    j = rest.find("?")
    query = rest[j:] if j != -1 else ""
    head = rest[:j] if j != -1 else rest
    if "@" not in head:
        return line
    userinfo, hostport = head.rsplit("@", 1)
    path_part = ""
    if "/" in hostport:
        hostport, path_part = hostport.split("/", 1)
        path_part = "/" + path_part
    port = ":443"
    k = hostport.find(":")
    if k != -1:
        port = hostport[k:]
    return f"{scheme}://{userinfo}@{new_ip}{port}{path_part}{query}{frag}"


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
               # same DNS the app forces (vpn_engine.buildFullConfiguration)
               "dns": {"queryStrategy": "UseIPv4",
                       "servers": ["https://1.1.1.1/dns-query", "8.8.8.8", "1.1.1.1"]},
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

    def deep_test(self, line: str):
        """Stability probe: DEEP_SAMPLES requests through ONE tunnel.
        Returns (successes, median_ms) - a server that keeps answering
        with steady times is the one that will hold up under traffic."""
        outbound, scheme, address = build_outbound(line)
        if outbound is None:
            return line, 0, 0
        port = self.ports.get()
        cfg_path = os.path.join(self.tmpdir, f"d{port}.json")
        cfg = {"log": {"loglevel": "error"},
               # same DNS the app forces (vpn_engine.buildFullConfiguration)
               "dns": {"queryStrategy": "UseIPv4",
                       "servers": ["https://1.1.1.1/dns-query", "8.8.8.8", "1.1.1.1"]},
               "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "socks",
                             "settings": {"udp": False}}],
               "outbounds": [outbound]}
        with open(cfg_path, "w") as fh:
            json.dump(cfg, fh)
        proc = subprocess.Popen([XRAY, "run", "-c", cfg_path],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        times, ok = [], 0
        try:
            time.sleep(0.35)
            for _ in range(DEEP_SAMPLES):
                try:
                    r = subprocess.run(
                        ["curl", "-s", "-o", "/dev/null",
                         "-w", "%{http_code} %{time_total}",
                         "--max-time", str(TEST_TIMEOUT),
                         "-x", f"socks5h://127.0.0.1:{port}",
                         "-A", USER_AGENT, TEST_URL],
                        capture_output=True, text=True, timeout=TEST_TIMEOUT + 5)
                    parts = (r.stdout.strip() or "000 0").split()
                    if parts[0] in ("200", "204"):
                        ok += 1
                        times.append(float(parts[1]) * 1000)
                except Exception:
                    pass
        finally:
            proc.kill()
            proc.wait()
            try:
                os.unlink(cfg_path)
            except OSError:
                pass
            self.ports.put(port)
        med = int(statistics.median(times)) if times else 99999
        return line, ok, med


def shard_of(line: str) -> int:
    """Deterministic shard routing - MUST match filter_original.py."""
    key = fo.dedup_key(line)
    return int(hashlib.md5(key.encode()).hexdigest(), 16) % N_SHARDS


def run_tests(candidates: list):
    """Test every candidate. Returns (alive, per_proto, ok_count, total)."""
    tester = Tester()
    alive, per_proto = [], {}
    done = ok_count = 0
    total = len(candidates)
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futures = [ex.submit(tester.test, ln) for ln in candidates]
        for fut in as_completed(futures):
            try:
                line, scheme, address, ok, code, ms = fut.result()
            except Exception as exc:
                done += 1
                print(f"  [skip] unparseable line: {type(exc).__name__}: {exc}")
                continue
            done += 1
            per_proto.setdefault(scheme, [0, 0])
            per_proto[scheme][1] += 1
            if ok:
                ok_count += 1
                alive.append((ms, line, scheme, address))
                per_proto[scheme][0] += 1
            if done % 100 == 0 or done == total:
                print(f"  {done}/{total} tested, {ok_count} alive", flush=True)
    return alive, per_proto, ok_count, total


def grace_update(candidates: list, alive_lines: set, pool: dict):
    """alive -> trusted; dead -> one grace retry; dead twice -> dropped.
    Returns (new_pool, grace_retry, dropped_grace)."""
    new_pool, dropped_grace, grace_retry = {}, 0, 0
    for cand in candidates:
        if cand in alive_lines:
            new_pool[cand] = 0
        else:
            fails = pool.get(cand, 0) + 1
            if fails < GRACE:
                new_pool[cand] = fails
                grace_retry += 1
            else:
                dropped_grace += 1
    return new_pool, grace_retry, dropped_grace


def locate(alive: list):
    """Country + city for every alive config, from its real server address.
    Country: flag in the name wins, else geo-IP. City: always geo-IP.
    Returns loc_of: index -> (cc, city)."""
    loc_of, need_geo = {}, []
    for i, (ms, line, scheme, address) in enumerate(alive):
        cc = first_flag(line.split("#", 1)[1]) if "#" in line else None
        if cc:
            loc_of[i] = (cc, "")
        need_geo.append((i, address))
    geo = geo_lookup([a for _, a in need_geo])
    for i, dom in need_geo:
        cc, city = geo.get(dom, ("", ""))
        if i in loc_of:
            loc_of[i] = (loc_of[i][0], city)
        else:
            loc_of[i] = (cc, city)
    return loc_of


def finalize_outputs(named: list, tester: 'Tester'):
    """Deep quality pass + all final files + report. `named` is a list of
    (first_ms, renamed_line, scheme, cc, city, orig_line) sorted or not."""
    named.sort(key=lambda t: t[0])
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # ---- working files ----
    ordered = [ln for _, ln, _, _, _, _ in named]
    with open(os.path.join(OUTPUT_DIR, "working.txt"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(ordered) + ("\n" if ordered else ""))
    with open(os.path.join(OUTPUT_DIR, "working_base64.txt"), "w", encoding="utf-8") as fh:
        fh.write(base64.b64encode(("\n".join(ordered) + "\n").encode()).decode())
    for name in ("vless", "vmess", "trojan", "ss"):
        subset = [ln for _, ln, sch, _, _, _ in named if sch == name]
        with open(os.path.join(OUTPUT_DIR, f"working_{name}.txt"), "w", encoding="utf-8") as fh:
            fh.write("\n".join(subset) + ("\n" if subset else ""))

    # ---- working_ip_changed.txt: same tested servers, address -> TARGET_IP ----
    ip_changed = [swap_address(ln, TARGET_IP) for _, ln, _, _, _, _ in named]
    with open(os.path.join(OUTPUT_DIR, "working_ip_changed.txt"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(ip_changed) + ("\n" if ip_changed else ""))
    with open(os.path.join(OUTPUT_DIR, "working_ip_changed_base64.txt"), "w", encoding="utf-8") as fh:
        fh.write(base64.b64encode(("\n".join(ip_changed) + "\n").encode()).decode())

    # ---- deep quality pass on EVERY working server ----
    print(f"Deep-checking all {len(named)} working servers "
          f"({DEEP_SAMPLES} requests each)...")
    deep = {}
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futures = {ex.submit(tester.deep_test, orig): rn
                   for _, rn, _, _, _, orig in named}
        for n, fut in enumerate(as_completed(futures), 1):
            rn = futures[fut]
            try:
                line, ok, med = fut.result()
            except Exception:
                ok, med = 0, 99999
            deep[rn] = (ok, med)
            if n % 100 == 0 or n == len(futures):
                print(f"  {n}/{len(futures)} deep-checked", flush=True)

    by_country = {}
    for _, rn, _, cc, _, _ in named:
        by_country.setdefault(cc, []).append(rn)
    keep_clean, vip_flags, dropped_cap = set(), {}, 0
    country_stats = []
    for cc, lines in by_country.items():
        ranked = sorted(lines, key=lambda l: (-deep[l][0], deep[l][1]))
        vip_flags.update({l: deep[l][0] == DEEP_SAMPLES for l in ranked})
        if len(ranked) > PER_COUNTRY_LIMIT:
            dropped_cap += len(ranked) - PER_COUNTRY_LIMIT
            ranked = ranked[:PER_COUNTRY_LIMIT]
        keep_clean.update(ranked)
        country_stats.append((cc, len(lines), len(ranked),
                              sum(1 for l in ranked if vip_flags[l])))
    country_stats.sort(key=lambda t: -t[1])

    clean_entries = []
    for first_ms, rn, _, cc, city, orig in named:
        if rn not in keep_clean:
            continue
        ok, med = deep[rn]
        ms = med if 0 < med < 99999 else first_ms
        line = rename_line(orig, cc, city, ms)
        if vip_flags[rn]:
            base, _, rest = line.partition("#")
            line = f"{base}#⭐VIP {rest}"
        clean_entries.append((0 if vip_flags[rn] else 1, ms, line))
    clean_entries.sort(key=lambda t: (t[0], t[1]))
    clean = [ln for _, _, ln in clean_entries]
    with open(os.path.join(OUTPUT_DIR, "working_clean.txt"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(clean) + ("\n" if clean else ""))
    with open(os.path.join(OUTPUT_DIR, "working_clean_base64.txt"), "w", encoding="utf-8") as fh:
        fh.write(base64.b64encode(("\n".join(clean) + "\n").encode()).decode())
    clean_ip = [swap_address(ln, TARGET_IP) for ln in clean]
    with open(os.path.join(OUTPUT_DIR, "working_clean_ip_changed.txt"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(clean_ip) + ("\n" if clean_ip else ""))

    # ---- 443 + WS + TLS subset (CDN-ready) ----
    # From ALL tested-working servers keep only those a CDN front can
    # serve: port 443 + websocket + TLS (trojan is TLS by definition).
    # Same quality treatment: VIP tag, per-country top-50, fastest first.
    def cdn_ok(orig_line: str) -> bool:
        if orig_line.lower().startswith("vmess://"):
            try:
                obj = json.loads(b64flex(orig_line[8:]).decode("utf-8", "ignore"))
            except Exception:
                return False
            if not isinstance(obj, dict):
                return False
            return (str(obj.get("port")) == "443"
                    and str(obj.get("net", "")).lower() == "ws"
                    and str(obj.get("tls", "")).lower() == "tls")
        parsed = split_uri(orig_line)
        if not parsed:
            return False
        scheme, _, _, port, params = parsed
        if port != 443:
            return False
        net = (params.get("type") or params.get("net")
               or params.get("network") or "").lower()
        if net != "ws":
            return False
        sec = (params.get("security") or "").lower()
        return sec == "tls" if scheme != "trojan" else sec in ("", "tls")

    sub = [(ms, rn, sch, cc, city, orig) for
           (ms, rn, sch, cc, city, orig) in named if cdn_ok(orig)]
    sub_by_cc = {}
    for _, rn, _, cc, _, _ in sub:
        sub_by_cc.setdefault(cc, []).append(rn)
    sub_keep = set()
    sub_dropped = 0
    for cc, lines in sub_by_cc.items():
        ranked = sorted(lines, key=lambda l: (-deep[l][0], deep[l][1]))
        if len(ranked) > PER_COUNTRY_LIMIT:
            sub_dropped += len(ranked) - PER_COUNTRY_LIMIT
            ranked = ranked[:PER_COUNTRY_LIMIT]
        sub_keep.update(ranked)
    sub_entries = []
    for first_ms, rn, _, cc, city, orig in sub:
        if rn not in sub_keep:
            continue
        ok, med = deep[rn]
        ms = med if 0 < med < 99999 else first_ms
        line = rename_line(orig, cc, city, ms)
        if vip_flags[rn]:
            base, _, rest = line.partition("#")
            line = f"{base}#⭐VIP {rest}"
        sub_entries.append((0 if vip_flags[rn] else 1, ms, line))
    sub_entries.sort(key=lambda t: (t[0], t[1]))
    sub_lines = [ln for _, _, ln in sub_entries]
    with open(os.path.join(OUTPUT_DIR, "working_443tls.txt"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(sub_lines) + ("\n" if sub_lines else ""))
    with open(os.path.join(OUTPUT_DIR, "working_443tls_base64.txt"), "w", encoding="utf-8") as fh:
        fh.write(base64.b64encode(("\n".join(sub_lines) + "\n").encode()).decode())
    sub_ip = [swap_address(ln, TARGET_IP) for ln in sub_lines]
    with open(os.path.join(OUTPUT_DIR, "working_443tls_ip_changed.txt"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(sub_ip) + ("\n" if sub_ip else ""))

    pings = [ms for ms, _, _, _, _, _ in named]
    vip_total = sum(1 for v in vip_flags.values() if v)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    report = [f"Date   : {now}",
              f"Working: {len(named)}",
              f"Deep check: {vip_total} marked VIP ({DEEP_SAMPLES}/{DEEP_SAMPLES} stable)",
              f"Per-country cap {PER_COUNTRY_LIMIT}: {dropped_cap} removed "
              f"from working_clean.txt",
              f"443+WS+TLS subset: {len(sub_lines)} servers "
              f"({sub_dropped} removed by cap) -> working_443tls.txt",
              f"Fastest ping: {pings[0] if pings else '-'} ms"
              + (f" | median: {int(statistics.median(pings))} ms" if pings else ""), "",
              "Top countries (servers -> kept/VIP):"]
    for cc, total_c, kept, vips in country_stats[:12]:
        report.append(f"  {cc}: {total_c} -> {kept} kept, {vips} VIP")
    return report


def load_pool() -> dict:
    pool = {}
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, encoding="utf-8") as fh:
                pool = json.load(fh)
        except Exception:
            pool = {}
    if not pool and os.path.exists(LEGACY_WORKING):
        with open(LEGACY_WORKING, encoding="utf-8") as fh:
            pool = {ln.strip(): 0 for ln in fh if ln.strip()}
        print(f"[pool] seeded with {len(pool)} servers from previous working.txt")
    return pool


def build_candidates(pool: dict, new_lines: list, shard: int = None):
    """Proven pool servers FIRST, then new ones, deduped by identity.
    With a shard set, only lines routed to that shard are included."""
    candidates, seen, carried = [], set(), 0
    for line in pool.keys():
        if shard is not None and shard_of(line) != shard:
            continue
        key = fo.dedup_key(line)
        if key in seen:
            continue
        seen.add(key)
        candidates.append(line)
        carried += 1
    fresh = 0
    for line in new_lines:
        if shard is not None and shard_of(line) != shard:
            continue
        key = fo.dedup_key(line)
        if key in seen:
            continue
        seen.add(key)
        candidates.append(line)
        fresh += 1
    return candidates, carried, fresh


def single_main():
    if not os.path.exists(XRAY):
        print(f"[warn] xray binary not found at {XRAY} - skipping test.")
        return 0
    if not os.path.exists(INPUT_FILE):
        print(f"[warn] {INPUT_FILE} not found - run filter_original.py first.")
        return 0

    with open(INPUT_FILE, encoding="utf-8") as fh:
        new_lines = [ln.strip() for ln in fh if ln.strip()]
    pool = load_pool()
    candidates, carried, fresh = build_candidates(pool, new_lines)
    if MAX_TEST and len(candidates) > MAX_TEST:
        candidates = candidates[:MAX_TEST]
    print(f"Proven pool carried : {carried} (tested first, always)")
    print(f"New unique available: {fresh}")
    print(f"Testing today       : {len(candidates)} of {carried + fresh} "
          f"(MAX_TEST={MAX_TEST or 'off'} - untested new ones rotate in "
          f"on the following days)")
    print(f"workers={WORKERS}, timeout={TEST_TIMEOUT}s")

    alive, per_proto, ok_count, total = run_tests(candidates)

    alive_lines = {t[1] for t in alive}
    new_pool, grace_retry, dropped_grace = grace_update(candidates, alive_lines, pool)
    with open(STATE_FILE, "w", encoding="utf-8") as fh:
        json.dump(new_pool, fh, ensure_ascii=False)

    loc_of = locate(alive)
    named = []
    for i, (ms, line, scheme, address) in enumerate(alive):
        cc, city = loc_of.get(i, ("", ""))
        named.append((ms, rename_line(line, cc, city, ms), scheme, cc or "??",
                      city, line))

    report = [f"Tested : {total} ({carried} carried from previous run)",
              f"Working: {ok_count}",
              f"Pool   : {len(new_pool)} servers kept "
              f"({grace_retry} on grace retry, {dropped_grace} dropped after "
              f"{GRACE} failed runs)"]
    report += finalize_outputs(named, Tester())
    print("\n".join(report))
    with open(os.path.join(OUTPUT_DIR, "test_report.txt"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(report) + "\n")
    return 0


def shard_main(shard: int):
    if not os.path.exists(XRAY):
        print(f"[warn] xray binary not found at {XRAY} - skipping test.")
        return 0
    shard_file = os.path.join(SHARD_DIR, f"shard_{shard}.txt")
    if not os.path.exists(shard_file):
        print(f"[warn] {shard_file} not found - run filter_original.py first.")
        return 0
    os.makedirs(SHARD_OUT_DIR, exist_ok=True)

    with open(shard_file, encoding="utf-8") as fh:
        new_lines = [ln.strip() for ln in fh if ln.strip()]
    pool = load_pool()
    candidates, carried, fresh = build_candidates(pool, new_lines, shard=shard)
    if MAX_TEST_SHARD and len(candidates) > MAX_TEST_SHARD:
        candidates = candidates[:MAX_TEST_SHARD]
    print(f"[shard {shard}/{N_SHARDS}] pool lines: {carried}, new: {fresh}, "
          f"testing ALL {len(candidates)} (workers={WORKERS}, "
          f"timeout={TEST_TIMEOUT}s)")

    alive, per_proto, ok_count, total = run_tests(candidates)

    alive_lines = {t[1] for t in alive}
    new_pool, grace_retry, dropped_grace = grace_update(candidates, alive_lines, pool)
    with open(os.path.join(SHARD_OUT_DIR, f"shard_state_{shard}.json"), "w",
              encoding="utf-8") as fh:
        json.dump(new_pool, fh, ensure_ascii=False)

    loc_of = locate(alive)
    metas = []
    for i, (ms, line, scheme, address) in enumerate(alive):
        cc, city = loc_of.get(i, ("", ""))
        renamed = rename_line(line, cc, city, ms)
        metas.append({"ms": ms, "line": renamed, "scheme": scheme,
                      "cc": cc or "??", "city": city, "orig": line})
    metas.sort(key=lambda m: m["ms"])
    with open(os.path.join(SHARD_OUT_DIR, f"shard_meta_{shard}.json"), "w",
              encoding="utf-8") as fh:
        json.dump(metas, fh, ensure_ascii=False)
    with open(os.path.join(SHARD_OUT_DIR, f"shard_result_{shard}.txt"), "w",
              encoding="utf-8") as fh:
        fh.write("\n".join(m["line"] for m in metas) + ("\n" if metas else ""))

    print(f"[shard {shard}] done: {len(metas)} alive "
          f"({grace_retry} grace, {dropped_grace} dropped)")
    return 0


def merge_main():
    metas = []
    for k in range(N_SHARDS):
        path = os.path.join(SHARD_OUT_DIR, f"shard_meta_{k}.json")
        if not os.path.exists(path):
            print(f"[merge] missing shard_meta_{k}.json - skipped")
            continue
        with open(path, encoding="utf-8") as fh:
            metas.extend(json.load(fh))
    if not metas:
        print("[merge] no shard results found - nothing to do.")
        return 0
    named = [(m["ms"], m["line"], m["scheme"], m["cc"], m["city"], m["orig"])
             for m in metas]

    # merge the per-shard pools back into the single persistent pool
    merged_pool = {}
    for k in range(N_SHARDS):
        path = os.path.join(SHARD_OUT_DIR, f"shard_state_{k}.json")
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                merged_pool.update(json.load(fh))
    with open(STATE_FILE, "w", encoding="utf-8") as fh:
        json.dump(merged_pool, fh, ensure_ascii=False)

    print(f"[merge] {len(named)} working servers from shards; "
          f"pool: {len(merged_pool)}")
    report = [f"Shards merged: {len(named)} working servers",
              f"Pool   : {len(merged_pool)} servers kept"]
    report += finalize_outputs(named, Tester())
    print("\n".join(report))
    with open(os.path.join(OUTPUT_DIR, "test_report.txt"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(report) + "\n")
    return 0


def main():
    if SHARD == "merge":
        return merge_main()
    if SHARD != "":
        return shard_main(int(SHARD))
    return single_main()


if __name__ == "__main__":
    sys.exit(main())
