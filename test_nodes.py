#!/usr/bin/env python3
"""
Connectivity + ping tester for the CDN pipeline (443-family + ws + tls,
address already rewritten to TARGET_IP by filter.py).

THREE MODES (env SHARD):
  (unset)      single mode  - local runs: test output/unique.txt
  SHARD=k      shard mode   - GitHub parallel jobs: test shards_tmp/shard_k.txt
  SHARD=merge  merge mode   - collect shard results, deep-check, final files

App-alignment (vip_vpn / flutter_vless):
  - TEST_TIMEOUT must stay <= 5: the app's ping gives up at ~4.8s, so a
    server that only answers after 6s would pass here but time out in the
    app. The workflow sets TEST_TIMEOUT=5.
  - tester configs use the same DNS the app forces (UseIPv4 + DoH 1.1.1.1)
    so domain resolution behaves the same way.
  - country/city come from the BACKEND domain (host=/sni=), never from the
    shared CDN IP.

Outputs in output/: working.txt (+_base64, per-protocol), working_clean.txt
(VIP + per-country cap), state.json (persistent pool).
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

import filter as fmod            # CDN dedup key + shard routing source

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
INPUT_FILE = os.path.join(OUTPUT_DIR, "unique.txt")
STATE_FILE = os.path.join(OUTPUT_DIR, "state.json")
LEGACY_WORKING = os.path.join(OUTPUT_DIR, "working.txt")
SHARD_DIR = fmod.SHARD_DIR
SHARD_OUT_DIR = os.path.join(BASE_DIR, "shard_out_nodes_tmp")
N_SHARDS = fmod.N_SHARDS
SHARD = os.environ.get("SHARD", "")
GRACE = 2
PER_COUNTRY_LIMIT = int(os.environ.get("PER_COUNTRY_LIMIT", "50"))
DEEP_SAMPLES = int(os.environ.get("DEEP_SAMPLES", "3"))
XRAY = os.environ.get("XRAY_PATH", os.path.join(BASE_DIR, "xray", "xray"))
WORKERS = int(os.environ.get("WORKERS", "30"))
MAX_TEST = int(os.environ.get("MAX_TEST", "0"))
TEST_TIMEOUT = int(os.environ.get("TEST_TIMEOUT", "5"))
TEST_URL = os.environ.get("TEST_URL", "https://www.gstatic.com/generate_204")
GEO_API = os.environ.get("GEO_API", "http://ip-api.com/batch?fields=query,countryCode,city")
GEO_FALLBACKS = ("https://freeipapi.com/api/json/",
                 "https://ipwho.is/",
                 "https://api.ip.sb/geoip/")
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


def parse_line(line: str):
    """-> (scheme, address, port, params, userinfo) or None, all schemes."""
    if line.lower().startswith("vmess://"):
        try:
            obj = json.loads(b64flex(line[len("vmess://"):]).decode("utf-8", "ignore"))
        except Exception:
            return None
        if not isinstance(obj, dict):
            return None
        try:
            port = int(str(obj.get("port", "0")))
        except (TypeError, ValueError):
            return None
        params = {"host": str(obj.get("host", "")), "sni": str(obj.get("sni", "")),
                  "path": str(obj.get("path", "")), "type": str(obj.get("net", "ws")),
                  "security": str(obj.get("tls", "")), "fp": str(obj.get("fp", "")),
                  "alpn": str(obj.get("alpn", "")), "aid": obj.get("aid", 0)}
        return "vmess", str(obj.get("add", "")), port, params, str(obj.get("id", ""))
    parsed = split_uri(line)
    if not parsed:
        return None
    scheme, userinfo, address, port, params = parsed
    return scheme, address, port, params, userinfo


def build_outbound(line: str):
    """xray outbound for a 443+ws+tls config (the pipeline guarantees ws+tls)."""
    p = parse_line(line)
    if p is None:
        return None, None, ""
    scheme, address, port, params, userinfo = p
    sni = params.get("sni") or params.get("host") or address
    ws_host = params.get("host") or params.get("sni") or ""
    tls = {"serverName": sni,
           "allowInsecure": params.get("allowinsecure") in ("1", "true")
                            or params.get("insecure") in ("1", "true")}
    if params.get("fp"):
        tls["fingerprint"] = params["fp"]
    if params.get("alpn"):
        tls["alpn"] = params["alpn"].split(",")
    stream = {"network": "ws", "security": "tls", "tlsSettings": tls,
              "wsSettings": {"path": params.get("path") or "/",
                             "headers": {"Host": ws_host} if ws_host else {}}}

    if scheme == "vless":
        outbound = {"protocol": "vless",
                    "settings": {"vnext": [{"address": address, "port": port,
                                            "users": [{"id": userinfo,
                                                       "encryption": "none"}]}]},
                    "streamSettings": stream}
    elif scheme == "trojan":
        outbound = {"protocol": "trojan",
                    "settings": {"servers": [{"address": address, "port": port,
                                              "password": userinfo}]},
                    "streamSettings": stream}
    elif scheme == "vmess":
        try:
            alter_id = int(str(params.get("aid", 0) or 0))
        except (TypeError, ValueError):
            alter_id = 0
        outbound = {"protocol": "vmess",
                    "settings": {"vnext": [{"address": address, "port": port,
                                            "users": [{"id": userinfo,
                                                       "security": "auto",
                                                       "alterId": alter_id}]}]},
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
        return None, None, ""
    return outbound, scheme, address


def backend_domain(line: str) -> str:
    """The real backend domain (host= / sni=) - the connect address is the
    shared CDN IP, so location MUST come from here instead."""
    if line.lower().startswith("vmess://"):
        try:
            obj = json.loads(b64flex(line[len("vmess://"):]).decode("utf-8", "ignore"))
            return str(obj.get("host") or obj.get("sni") or "")
        except Exception:
            return ""
    p = split_uri(line)
    if not p:
        return ""
    return p[4].get("host") or p[4].get("sni") or ""


# ------------------------- location detection --------------------------

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
    for attempt in range(2):
        try:
            with urllib.request.urlopen(GEO_FALLBACKS[0] + ip, timeout=10) as resp:
                d = json.load(resp)
                if d.get("countryCode"):
                    return d["countryCode"], d.get("cityName") or ""
        except Exception:
            pass
        try:
            with urllib.request.urlopen(GEO_FALLBACKS[1] + ip, timeout=10) as resp:
                d = json.load(resp)
                if d.get("country_code"):
                    return d["country_code"], d.get("city") or ""
        except Exception:
            pass
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
    """address (IP or domain) -> (country_code, city)."""
    result, ip_of = {}, {}
    for a in set(addresses):
        ip = _resolve_ip(a)
        if ip:
            ip_of.setdefault(ip, a)
    ips = list(ip_of.keys())
    if not ips:
        return result
    socket.setdefaulttimeout(5)
    for i in range(0, len(ips), 100):
        try:
            result.update(_geo_ipapi_batch(ips[i:i + 100]))
        except Exception:
            break
    remaining = [ip for ip in ips if ip not in result]
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


# ------------------------------ testing --------------------------------

class Tester:
    def __init__(self):
        self.tmpdir = tempfile.mkdtemp(prefix="xrtest-")
        self.ports = queue.Queue()
        for k in range(WORKERS):
            self.ports.put(PORT_BASE + k)

    def _run_cfg(self, line, tag, requests):
        outbound, scheme, address = build_outbound(line)
        if outbound is None:
            return line, scheme, address, 0, 0, []
        port = self.ports.get()
        cfg_path = os.path.join(self.tmpdir, f"{tag}{port}.json")
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
        code, ms, times, ok = "000", 0, [], 0
        try:
            time.sleep(0.35)
            for _ in range(requests):
                parts = ["000", "0"]
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
                        t = float(parts[1]) * 1000
                        times.append(t)
                        if requests == 1:
                            ms = max(1, round(t))
                except Exception:
                    pass
                if requests == 1 and parts[0] not in ("200", "204"):
                    code = parts[0]
        finally:
            proc.kill()
            proc.wait()
            try:
                os.unlink(cfg_path)
            except OSError:
                pass
            self.ports.put(port)
        return line, scheme, address, ok, ms, times

    def test(self, line: str):
        line, scheme, address, ok, ms, _ = self._run_cfg(line, "c", 1)
        return line, scheme, address, ok == 1, ms

    def deep_test(self, line: str):
        line, scheme, address, ok, _, times = self._run_cfg(line, "d", DEEP_SAMPLES)
        med = int(statistics.median(times)) if times else 99999
        return line, ok, med


def shard_of(line: str) -> int:
    """Deterministic shard routing - MUST match filter.py."""
    key = fmod.dedup_key(line)
    return int(hashlib.md5(key.encode()).hexdigest(), 16) % N_SHARDS


def run_tests(candidates: list):
    tester = Tester()
    alive, per_proto = [], {}
    done = ok_count = 0
    total = len(candidates)
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futures = [ex.submit(tester.test, ln) for ln in candidates]
        for fut in as_completed(futures):
            try:
                line, scheme, address, ok, ms = fut.result()
            except Exception as exc:
                done += 1
                print(f"  [skip] unparseable line: {type(exc).__name__}: {exc}")
                continue
            done += 1
            per_proto.setdefault(scheme, [0, 0])
            per_proto[scheme][1] += 1
            if ok:
                ok_count += 1
                alive.append((ms, line, scheme))
                per_proto[scheme][0] += 1
            if done % 100 == 0 or done == total:
                print(f"  {done}/{total} tested, {ok_count} alive", flush=True)
    return alive, per_proto, ok_count, total


def grace_update(candidates: list, alive_lines: set, pool: dict):
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
    """Country + city from the BACKEND domain (host=/sni=) - the connect
    address is the shared CDN IP and would report the CDN's location."""
    loc_of, need_geo = {}, []
    for i, (ms, line, scheme) in enumerate(alive):
        cc = first_flag(line.split("#", 1)[1]) if "#" in line else None
        if cc:
            loc_of[i] = (cc, "")
        need_geo.append((i, backend_domain(line)))
    geo = geo_lookup([d for _, d in need_geo if d])
    for i, dom in need_geo:
        cc, city = geo.get(dom, ("", ""))
        if i in loc_of:
            loc_of[i] = (loc_of[i][0], city)
        else:
            loc_of[i] = (cc, city)
    return loc_of


def finalize_outputs(named: list, tester: 'Tester'):
    """Deep quality pass + final files + report."""
    named.sort(key=lambda t: t[0])
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    ordered = [ln for _, ln, _, _, _, _ in named]
    with open(os.path.join(OUTPUT_DIR, "working.txt"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(ordered) + ("\n" if ordered else ""))
    with open(os.path.join(OUTPUT_DIR, "working_base64.txt"), "w", encoding="utf-8") as fh:
        fh.write(base64.b64encode(("\n".join(ordered) + "\n").encode()).decode())
    for name in ("vless", "vmess", "trojan", "ss"):
        subset = [ln for _, ln, sch, _, _, _ in named if sch == name]
        with open(os.path.join(OUTPUT_DIR, f"working_{name}.txt"), "w", encoding="utf-8") as fh:
            fh.write("\n".join(subset) + ("\n" if subset else ""))

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

    pings = [ms for ms, _, _, _, _, _ in named]
    vip_total = sum(1 for v in vip_flags.values() if v)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    report = [f"Date   : {now}",
              f"Working: {len(named)}",
              f"Deep check: {vip_total} marked VIP ({DEEP_SAMPLES}/{DEEP_SAMPLES} stable)",
              f"Per-country cap {PER_COUNTRY_LIMIT}: {dropped_cap} removed "
              f"from working_clean.txt",
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
    candidates, seen, carried = [], set(), 0
    for line in pool.keys():
        if shard is not None and shard_of(line) != shard:
            continue
        key = fmod.dedup_key(line)
        if key in seen:
            continue
        seen.add(key)
        candidates.append(line)
        carried += 1
    fresh = 0
    for line in new_lines:
        if shard is not None and shard_of(line) != shard:
            continue
        key = fmod.dedup_key(line)
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
        print(f"[warn] {INPUT_FILE} not found - run filter.py first.")
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
          f"(MAX_TEST={MAX_TEST or 'off'})")
    print(f"workers={WORKERS}, timeout={TEST_TIMEOUT}s")

    alive, per_proto, ok_count, total = run_tests(candidates)

    alive_lines = {t[1] for t in alive}
    new_pool, grace_retry, dropped_grace = grace_update(candidates, alive_lines, pool)
    with open(STATE_FILE, "w", encoding="utf-8") as fh:
        json.dump(new_pool, fh, ensure_ascii=False)

    loc_of = locate(alive)
    named = []
    for i, (ms, line, scheme) in enumerate(alive):
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
        print(f"[warn] {shard_file} not found - run filter.py first.")
        return 0
    os.makedirs(SHARD_OUT_DIR, exist_ok=True)

    with open(shard_file, encoding="utf-8") as fh:
        new_lines = [ln.strip() for ln in fh if ln.strip()]
    pool = load_pool()
    candidates, carried, fresh = build_candidates(pool, new_lines, shard=shard)
    if MAX_TEST and len(candidates) > MAX_TEST:
        candidates = candidates[:MAX_TEST]
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
    for i, (ms, line, scheme) in enumerate(alive):
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
