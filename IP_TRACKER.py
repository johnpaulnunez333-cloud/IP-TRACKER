import os
import re
import ssl
import sys
import shutil
import json
import math
import time
import socket
import struct
import ipaddress
import statistics
import http.client
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from colorama import Fore, Style, init

init(autoreset=True)

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

R = Fore.RED
G = Fore.GREEN
Y = Fore.YELLOW
C = Fore.CYAN
W = Fore.WHITE
BR = Fore.RED + Style.BRIGHT

VERSION = "3.0"
USER_AGENT = "Mozilla/5.0 (IPTracker/3.0)"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
STUN_SERVERS = [("stun.l.google.com", 19302), ("stun.cloudflare.com", 3478)]
STUN_MAGIC = 0x2112A442
HOSTING_HINTS = (
    "amazon", "aws", "microsoft", "azure", "digitalocean", "ovh", "hetzner", "linode", "akamai",
    "vultr", "cloudflare", "oracle cloud", "alibaba", "tencent", "hosting", "datacenter",
    "data center", "cloud", "vpn", "proxy", "colo",
)
SESSION = {"ips": 0, "domains": 0, "bulk": 0, "saved": 0}

SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
    135: "RPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS",
    995: "POP3S", 3306: "MySQL", 3389: "RDP", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
}


def clear():
    os.system("cls" if os.name == "nt" else "clear")


LOGO_FONT = {
    "I": ["██╗", "██║", "██║", "██║", "██║", "╚═╝"],
    "P": ["██████╗ ", "██╔══██╗", "██████╔╝", "██╔═══╝ ", "██║     ", "╚═╝     "],
    "T": ["████████╗", "╚══██╔══╝", "   ██║   ", "   ██║   ", "   ██║   ", "   ╚═╝   "],
    "R": ["██████╗ ", "██╔══██╗", "██████╔╝", "██╔══██╗", "██║  ██║", "╚═╝  ╚═╝"],
    "A": [" █████╗ ", "██╔══██╗", "███████║", "██╔══██║", "██║  ██║", "╚═╝  ╚═╝"],
    "C": [" ██████╗", "██╔════╝", "██║     ", "██║     ", "╚██████╗", " ╚═════╝"],
    "K": ["██╗  ██╗", "██║ ██╔╝", "█████╔╝ ", "██╔═██╗ ", "██║  ██╗", "╚═╝  ╚═╝"],
    "E": ["███████╗", "██╔════╝", "█████╗  ", "██╔══╝  ", "███████╗", "╚══════╝"],
    " ": ["    "] * 6,
}
LOGO_BRIGHT = [199, 198, 197, 196, 202, 208, 214, 220]
LOGO_DARK = [125, 125, 124, 88, 130, 130, 136, 142]
CREATOR = "Created by John Paul Nuñez"


def render_logo(text):
    rows = [""] * 6
    for ch in text:
        for i, part in enumerate(LOGO_FONT[ch]):
            rows[i] += part
    return rows


def logo_color(x, width, bright):
    palette = LOGO_BRIGHT if bright else LOGO_DARK
    return palette[min(len(palette) - 1, int(x * len(palette) / max(width, 1)))]


def paint_logo(rows, width):
    out = []
    for row in rows:
        parts = []
        for x, ch in enumerate(row):
            if ch == " ":
                parts.append(" ")
            else:
                parts.append(f"\033[38;5;{logo_color(x, width, ch == '█')}m{ch}")
        out.append("".join(parts) + "\033[0m")
    return out


def credit_line(width):
    text = f"  {CREATOR}  "
    left = max((width - len(text)) // 2, 0)
    right = max(width - len(text) - left, 0)
    parts = []
    for x in range(left):
        parts.append(f"\033[38;5;{logo_color(x, width, True)}m━")
    parts.append(f"\033[1;38;5;255m{text}")
    for x in range(left + len(text), left + len(text) + right):
        parts.append(f"\033[38;5;{logo_color(x, width, True)}m━")
    return "".join(parts) + "\033[0m"


def banner():
    clear()
    cols = shutil.get_terminal_size((80, 24)).columns
    full = render_logo("IP TRACKER")
    full_w = len(full[0])
    if cols > full_w:
        groups = ["IP TRACKER"]
    elif cols > len(render_logo("TRACKER")[0]):
        groups = ["IP", "TRACKER"]
    else:
        groups = ["IP", "TRAC", "KER"]
    width = 0
    print()
    for n, group in enumerate(groups):
        rows = render_logo(group)
        w = len(rows[0])
        width = max(width, w)
        for line in paint_logo(rows, w):
            print(line)
        if n < len(groups) - 1:
            print()
    width = min(max(width, len(CREATOR) + 8), max(cols - 1, 20))
    print()
    print(credit_line(width))
    subtitle = f"v{VERSION}  ·  offline consensus"
    print(f"\033[2;38;5;250m{subtitle.center(width)}\033[0m")
    print()


def pause():
    input(f"\n{C}[PRESS ENTER TO CONTINUE]")


def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_public(ip):
    return ipaddress.ip_address(ip).is_global


def to_float(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def norm(v):
    return v.strip().lower() if isinstance(v, str) and v.strip() else None


def fmt(v):
    return v if v not in (None, "", []) else "N/A"


def names_en(obj):
    return ((obj or {}).get("names") or {}).get("en")


def parse_mmdb_record(rec):
    if not isinstance(rec, dict):
        return None
    country = rec.get("country") or rec.get("registered_country") or {}
    subs = rec.get("subdivisions") or []
    loc = rec.get("location") or {}
    out = {
        "country": names_en(country),
        "cc": country.get("iso_code"),
        "region": names_en(subs[0]) if subs else None,
        "city": names_en(rec.get("city")),
        "zip": (rec.get("postal") or {}).get("code"),
        "lat": to_float(loc.get("latitude")),
        "lon": to_float(loc.get("longitude")),
        "timezone": loc.get("time_zone"),
    }
    if rec.get("autonomous_system_number"):
        out["as"] = f"AS{rec['autonomous_system_number']}"
    if rec.get("autonomous_system_organization"):
        out["org"] = rec["autonomous_system_organization"]
    return out if any(v is not None for v in out.values()) else None


def make_geoip2fast_provider():
    try:
        from geoip2fast import GeoIP2Fast
    except Exception:
        return None
    try:
        engine = GeoIP2Fast(verbose=False)
    except TypeError:
        try:
            engine = GeoIP2Fast()
        except Exception:
            return None
    except Exception:
        return None

    def lookup(ip):
        try:
            r = engine.lookup(ip)
        except Exception:
            return None
        cc = getattr(r, "country_code", None)
        if not cc or cc == "--" or getattr(r, "is_private", False):
            return None
        out = {"country": getattr(r, "country_name", None) or None, "cc": cc}
        org = getattr(r, "asn_name", None)
        if org:
            out["org"] = org
        return out

    return lookup


def make_mmdb_provider(path):
    try:
        import maxminddb
        reader = maxminddb.open_database(path)
    except Exception:
        return None

    def lookup(ip):
        try:
            return parse_mmdb_record(reader.get(ip))
        except Exception:
            return None

    return lookup


def make_bundled_provider():
    try:
        from geolite2 import geolite2
        reader = geolite2.reader()
    except Exception:
        return None

    def lookup(ip):
        try:
            return parse_mmdb_record(reader.get(ip))
        except Exception:
            return None

    return lookup


def find_mmdb_files():
    dirs = [
        os.environ.get("IPTRACKER_DB_DIR"),
        SCRIPT_DIR,
        os.path.join(SCRIPT_DIR, "data"),
        os.getcwd(),
        os.path.expanduser("~/.ip_tracker"),
    ]
    files, seen = [], set()
    for d in dirs:
        if not d or not os.path.isdir(d):
            continue
        for name in sorted(os.listdir(d)):
            if name.lower().endswith(".mmdb"):
                path = os.path.join(d, name)
                real = os.path.realpath(path)
                if real not in seen:
                    seen.add(real)
                    files.append(path)
    return files


def load_providers():
    providers = {}
    fast = make_geoip2fast_provider()
    if fast:
        providers["geoip2fast"] = fast
    for path in find_mmdb_files():
        p = make_mmdb_provider(path)
        if p:
            providers[os.path.basename(path)] = p
    if not any(name.lower().endswith(".mmdb") for name in providers):
        bundled = make_bundled_provider()
        if bundled:
            providers["geolite2-bundled"] = bundled
    return providers


PROVIDERS = load_providers()


def query_provider(args):
    name, func, ip = args
    try:
        return name, func(ip)
    except Exception:
        return name, None


def haversine(lat1, lon1, lat2, lon2):
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = p2 - p1
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def vote(pool, key):
    counts = Counter()
    original = {}
    for r in pool.values():
        n = norm(r.get(key))
        if n:
            counts[n] += 1
            original.setdefault(n, r.get(key))
    if not counts:
        return None, 0
    top, total = counts.most_common(1)[0]
    return original[top], total


def pick_first(pool, key):
    for r in pool.values():
        if r.get(key):
            return r[key]
    return None


def build_consensus(results):
    if not results:
        return {}
    geo = {k: v for k, v in results.items() if v.get("cc")}
    base = geo or results
    cc, cc_votes = vote(base, "cc")
    in_cc = {k: v for k, v in base.items() if norm(v.get("cc")) == norm(cc)} or base
    region, region_votes = vote(in_cc, "region")
    in_region = {k: v for k, v in in_cc.items() if norm(v.get("region")) == norm(region)} or in_cc
    city, city_votes = vote(in_region, "city")
    in_city = {k: v for k, v in in_region.items() if norm(v.get("city")) == norm(city)} or in_region

    points = [(v["lat"], v["lon"]) for v in in_city.values() if v.get("lat") is not None and v.get("lon") is not None]
    lat = lon = None
    spread = None
    if points:
        lat = statistics.median(p[0] for p in points)
        lon = statistics.median(p[1] for p in points)
        spread = max(haversine(lat, lon, p[0], p[1]) for p in points) if len(points) > 1 else 0.0

    all_points = [(v["lat"], v["lon"]) for v in base.values() if v.get("lat") is not None and v.get("lon") is not None]
    wide_spread = None
    if lat is not None and len(all_points) > 1:
        wide_spread = max(haversine(lat, lon, p[0], p[1]) for p in all_points)

    geo_total = len(base)
    score = 40 * (cc_votes / geo_total)
    score += 25 * (region_votes / geo_total if region else 0)
    score += 25 * (city_votes / geo_total if city else 0)
    if wide_spread is not None:
        if wide_spread < 25:
            score += 10
        elif wide_spread < 100:
            score += 5
    if geo_total < 2:
        score = min(score, 50)

    if score >= 80:
        label = "HIGH"
    elif score >= 55:
        label = "MEDIUM"
    else:
        label = "LOW"

    precision = "CITY" if city else ("REGION" if region else "COUNTRY")

    return {
        "country": pick_first(in_cc, "country") or cc,
        "cc": cc,
        "region": region,
        "city": city,
        "zip": vote(in_city, "zip")[0],
        "lat": lat,
        "lon": lon,
        "timezone": vote(in_cc, "timezone")[0],
        "isp": vote(results, "isp")[0] or pick_first(results, "isp"),
        "org": vote(results, "org")[0] or pick_first(results, "org"),
        "as": vote(results, "as")[0] or pick_first(results, "as"),
        "providers_used": len(results),
        "geo_sources": geo_total,
        "country_agree": cc_votes,
        "region_agree": region_votes,
        "city_agree": city_votes,
        "city_spread_km": spread,
        "overall_spread_km": wide_spread,
        "precision": precision,
        "confidence_score": round(score),
        "confidence": label,
    }


def get_ip_info(ip):
    if not PROVIDERS:
        return {}, {}
    jobs = [(name, func, ip) for name, func in PROVIDERS.items()]
    with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        out = list(pool.map(query_provider, jobs))
    results = {name: data for name, data in out if data}
    return build_consensus(results), results


def get_reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "N/A"


def resolve_domain(text):
    host = re.sub(r"^[A-Za-z][A-Za-z0-9+.\-]*://", "", text.strip())
    host = host.split("/")[0].split("?")[0].rsplit("@", 1)[-1]
    if host.count(":") == 1:
        host = host.split(":")[0]
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError):
        return host, []
    ips = []
    for info in infos:
        addr = info[4][0]
        if addr not in ips:
            ips.append(addr)
    ips.sort(key=lambda a: ":" in a)
    return host, ips


def whois_query(server, query, timeout=6):
    with socket.create_connection((server, 43), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall((query + "\r\n").encode())
        chunks = []
        while True:
            data = s.recv(4096)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks).decode("utf-8", errors="replace")


def parse_whois(text):
    fields = {}
    for line in text.splitlines():
        if line.startswith(("%", "#")) or ":" not in line:
            continue
        key, _, value = line.partition(":")
        key, value = key.strip().lower(), value.strip()
        if value and key not in fields:
            fields[key] = value
    return fields


def get_whois(ip):
    info = {"abuse": "N/A"}
    try:
        iana = whois_query("whois.iana.org", ip)
        m = re.search(r"^(?:refer|whois):\s*(\S+)", iana, re.M | re.I)
        server = m.group(1) if m else "whois.arin.net"
        text = whois_query(server, ip)
        ref = re.search(r"ReferralServer:\s*(?:r?whois://)?([A-Za-z0-9.\-]+)", text, re.I)
        if ref and ref.group(1).lower() != server:
            text = whois_query(ref.group(1), ip)
        f = parse_whois(text)
        rng = f.get("netrange") or f.get("inetnum") or f.get("inet6num")
        if rng and "-" in rng:
            start, _, end = rng.partition("-")
            info["start_address"], info["end_address"] = start.strip(), end.strip()
        elif rng:
            info["start_address"] = rng
        mapping = (
            ("network_name", f.get("netname")),
            ("handle", f.get("nethandle")),
            ("cidr", f.get("cidr") or f.get("route") or f.get("route6")),
            ("country", f.get("country")),
            ("org_name", f.get("orgname") or f.get("org-name") or f.get("owner") or f.get("descr")),
        )
        for key, value in mapping:
            if value:
                info[key] = value
        abuse = f.get("orgabuseemail") or f.get("abuse-mailbox")
        if abuse:
            info["abuse"] = abuse
    except Exception:
        pass
    return info


def parse_stun(data, tid):
    if len(data) < 20:
        return None
    mtype, mlen, cookie = struct.unpack("!HHI", data[:8])
    if mtype != 0x0101 or cookie != STUN_MAGIC or data[8:20] != tid:
        return None
    pos, end = 20, min(20 + mlen, len(data))
    fallback = None
    while pos + 4 <= end:
        atype, alen = struct.unpack("!HH", data[pos:pos + 4])
        val = data[pos + 4:pos + 4 + alen]
        if atype == 0x0020 and len(val) >= 8 and val[1] == 0x01:
            raw = struct.unpack("!I", val[4:8])[0] ^ STUN_MAGIC
            return socket.inet_ntoa(struct.pack("!I", raw))
        if atype == 0x0001 and len(val) >= 8 and val[1] == 0x01 and not fallback:
            fallback = socket.inet_ntoa(val[4:8])
        pos += 4 + alen + (-alen % 4)
    return fallback


def stun_public_ip(servers=None, timeout=3.0):
    for host, port in servers or STUN_SERVERS:
        tid = os.urandom(12)
        request = struct.pack("!HHI", 0x0001, 0, STUN_MAGIC) + tid
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(request, (host, port))
                data, _ = s.recvfrom(2048)
            ip = parse_stun(data, tid)
            if ip:
                return ip
        except OSError:
            continue
    return None


def local_ips():
    found = []
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))
            found.append(s.getsockname()[0])
    except OSError:
        pass
    try:
        for addr in socket.gethostbyname_ex(socket.gethostname())[2]:
            if addr not in found and not addr.startswith("127."):
                found.append(addr)
    except OSError:
        pass
    return found


def check_port(args):
    ip, port = args
    try:
        with socket.create_connection((ip, port), timeout=1.0):
            return port
    except OSError:
        return None


def get_ports(ip):
    with ThreadPoolExecutor(max_workers=20) as pool:
        found = pool.map(check_port, [(ip, p) for p in SERVICES])
    return sorted(p for p in found if p)


def get_device_info(ip, ports=(80, 443)):
    host = f"[{ip}]" if ":" in ip else ip
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    for port in ports:
        try:
            if port == 443:
                conn = http.client.HTTPSConnection(host, port, timeout=3, context=ctx)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=3)
            conn.request("HEAD", "/", headers={"User-Agent": USER_AGENT})
            server = conn.getresponse().getheader("Server") or ""
            conn.close()
        except Exception:
            continue
        low = server.lower()
        if "nginx" in low:
            kind = "Web Server (Nginx)"
        elif "apache" in low:
            kind = "Web Server (Apache)"
        elif "iis" in low:
            kind = "Web Server (IIS)"
        else:
            kind = "Web Server"
        return {"device_type": kind, "server_header": server or "N/A"}
    return {}


def guess_hosting(info, whois):
    text = " ".join(str(x).lower() for x in (
        info.get("org"), info.get("isp"), whois.get("org_name"), whois.get("network_name")) if x)
    if not text:
        return None
    return any(h in text for h in HOSTING_HINTS)


def gather(ip):
    with ThreadPoolExecutor(max_workers=3) as pool:
        f_geo = pool.submit(get_ip_info, ip)
        f_dns = pool.submit(get_reverse_dns, ip)
        f_who = pool.submit(get_whois, ip)
        info, raw = f_geo.result()
        return info, raw, f_dns.result(), f_who.result()


def box(title, rows):
    print(f"\n{C}[ {title} ]")
    print(f"{W}┌─────────────────────────────────────────────")
    for label, value in rows:
        print(f"{W}│ {Y}{label}: {G}{fmt(value)}")
    print(f"{W}└─────────────────────────────────────────────")


def no_sources_help():
    print(f"\n{R}[!] NO OFFLINE GEOLOCATION SOURCE IS INSTALLED.")
    print(f"{Y}[!] INSTALL AT LEAST ONE:")
    print(f"{Y}    pip install geoip2fast                  (country + ASN, bundled)")
    print(f"{Y}    pip install maxminddb maxminddb-geolite2 (city level, bundled, older data)")
    print(f"{Y}    OR put GeoLite2-City.mmdb / dbip-city-lite.mmdb next to this script")


def save_json(prefix, data):
    filename = f"{prefix}_{int(time.time())}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    SESSION["saved"] += 1
    print(f"{G}[+] Results saved to: {filename}")


LABEL = Fore.YELLOW + Style.BRIGHT
VALUE = Fore.GREEN + Style.BRIGHT
LINK = Fore.LIGHTBLUE_EX
RESULT_MENU = (
    ("01", "Return To Main Menu"),
    ("02", "Exit"),
    ("03", "More Details"),
    ("04", "Scan Ports"),
    ("05", "Save Results"),
)
COUNTRY_CACHE = {}


def country_extras(cc):
    if not cc:
        return {}
    cc = cc.upper()
    if cc in COUNTRY_CACHE:
        return COUNTRY_CACHE[cc]
    extras = {}
    try:
        from babel.numbers import get_territory_currencies
        codes = get_territory_currencies(cc)
        if codes:
            extras["currency"] = codes[0]
    except Exception:
        pass
    try:
        from babel.languages import get_official_languages
        langs = get_official_languages(cc)
        if langs:
            extras["languages"] = ", ".join(f"{lang}-{cc}" for lang in langs)
    except Exception:
        pass
    try:
        import phonenumbers
        code = phonenumbers.country_code_for_region(cc)
        if code:
            extras["calling_code"] = f"+{code}"
    except Exception:
        pass
    COUNTRY_CACHE[cc] = extras
    return extras


def result_groups(ip, info, whois):
    extras = country_extras(info.get("cc"))
    isp = info.get("isp") or info.get("org") or whois.get("org_name")
    return [
        [("Ip Address", ip), ("City", info.get("city")), ("Region", info.get("region")),
         ("Country", info.get("country"))],
        [("Latitude", info.get("lat")), ("Longitude", info.get("lon")),
         ("Time Zone", info.get("timezone")), ("Postal Code", info.get("zip"))],
        [("ISP", isp), ("ASN", info.get("as"))],
        [("Country Code", info.get("cc")), ("Currency", extras.get("currency")),
         ("Languages", extras.get("languages")), ("Calling Code", extras.get("calling_code"))],
    ]


def show_result(ip, info, whois):
    banner()
    for group in result_groups(ip, info, whois):
        for label, value in group:
            print(f"  {LABEL}{label:<13}{VALUE}:   {fmt(value)}")
        print()
    if info.get("lat") is not None and info.get("lon") is not None:
        print(f"  {LABEL}{'GOOGLE Maps':<13}{VALUE}:   {LINK}https://maps.google.com/?q={info['lat']},{info['lon']}")
        print()
    if not info:
        if not PROVIDERS:
            no_sources_help()
        else:
            print(f"{R}[!] NO OFFLINE SOURCE HAS A RECORD FOR THIS IP.")
        print()
    for number, text in RESULT_MENU:
        print(f"{R}[{number}] {LABEL}{text}")
    return input(f"\n{R}>> {W}").strip()


def show_details(ip, info, raw, reverse_dns, whois, open_ports, device):
    banner()
    box("BASIC INFORMATION", [
        ("IP Address", ip),
        ("Reverse DNS", reverse_dns),
        ("Device Type", device.get("device_type")),
    ])

    if info:
        spread = info.get("overall_spread_km")
        box("ACCURACY CHECK", [
            ("Sources Responded", f"{info['providers_used']}/{len(PROVIDERS)}"),
            ("Precision Level", info.get("precision")),
            ("Country Agreement", f"{info['country_agree']}/{info['geo_sources']}"),
            ("Region Agreement", f"{info['region_agree']}/{info['geo_sources']}"),
            ("City Agreement", f"{info['city_agree']}/{info['geo_sources']}"),
            ("Max Coordinate Spread", f"{spread:.1f} km" if spread is not None else None),
            ("Confidence", f"{info['confidence']} ({info['confidence_score']}/100)"),
        ])
        hosting = guess_hosting(info, whois)
        box("CONNECTION HINTS", [
            ("Hosting/VPN (Likely)", "N/A" if hosting is None else ("YES" if hosting else "NO")),
        ])

    box("NETWORK INFORMATION", [
        ("Organization", info.get("org") or whois.get("org_name")),
        ("Network Name", whois.get("network_name")),
        ("Handle", whois.get("handle")),
        ("CIDR", whois.get("cidr")),
        ("Start Address", whois.get("start_address")),
        ("End Address", whois.get("end_address")),
        ("Registered Country", whois.get("country")),
        ("Abuse Contact", whois.get("abuse")),
    ])

    if open_ports:
        box("OPEN PORTS & SERVICES", [(f"Port {p}", SERVICES.get(p, "Unknown")) for p in open_ports])

    if raw:
        print(f"\n{C}[ SOURCE BREAKDOWN ]")
        print(f"{W}┌─────────────────────────────────────────────")
        for name, data in raw.items():
            loc = ", ".join(x for x in (data.get("city"), data.get("region"), data.get("cc")) if x) or fmt(data.get("org"))
            print(f"{W}│ {Y}{name}: {G}{loc}")
        print(f"{W}└─────────────────────────────────────────────")

    print(f"\n{Y}[!] NOTE: IP GEOLOCATION IS APPROXIMATE (USUALLY CITY LEVEL) AND OFTEN POINTS TO THE ISP'S")
    print(f"{Y}[!] NETWORK HUB, NOT THE EXACT USER. VPN/PROXY/MOBILE IPs CAN BE FAR FROM THE REAL LOCATION.")


def scan_host(ip):
    answer = input(f"\n{Y}[SCAN PORTS? ONLY ON HOSTS YOU OWN OR HAVE PERMISSION FOR (y/n)] {W}").strip().lower()
    if answer != "y":
        return None
    print(f"{Y}[*] SCANNING PORTS...")
    open_ports = get_ports(ip)
    print(f"{Y}[*] DETECTING DEVICE TYPE...")
    device = get_device_info(ip)
    rows = [(f"Port {p}", SERVICES.get(p, "Unknown")) for p in open_ports] or [("Result", "No open ports detected")]
    box("OPEN PORTS & SERVICES", rows)
    if device:
        box("DEVICE", [("Device Type", device.get("device_type")), ("Server Header", device.get("server_header"))])
    return open_ports, device


def trace_ip(ip):
    banner()
    print(f"\n{R}[!] TRACING: {ip}")

    if not validate_ip(ip):
        print(f"{R}[!] INVALID IP ADDRESS FORMAT!")
        pause()
        return

    if not is_public(ip):
        print(f"{R}[!] PRIVATE / RESERVED ADDRESS - NO PUBLIC GEOLOCATION EXISTS FOR THIS IP.")
        pause()
        return

    SESSION["ips"] += 1
    print(f"\n{Y}[*] QUERYING {len(PROVIDERS)} OFFLINE GEO SOURCES, WHOIS AND REVERSE DNS...")
    info, raw, reverse_dns, whois = gather(ip)
    open_ports, device = [], {}

    while True:
        choice = show_result(ip, info, whois)
        if choice in ("1", "01"):
            return
        if choice in ("2", "02"):
            print(f"\n{R}[!] EXITING IP TRACKER...")
            sys.exit(0)
        if choice in ("3", "03"):
            show_details(ip, info, raw, reverse_dns, whois, open_ports, device)
            pause()
        elif choice in ("4", "04"):
            scanned = scan_host(ip)
            if scanned:
                open_ports, device = scanned
            pause()
        elif choice in ("5", "05"):
            save_json(f"ip_tracker_{ip.replace(':', '-')}", {
                "ip": ip,
                "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "reverse_dns": reverse_dns,
                "consensus": info,
                "sources": raw,
                "whois": whois,
                "ports": {str(p): SERVICES.get(p, "Unknown") for p in open_ports},
                "device_info": device,
            })
            pause()
        else:
            print(f"{R}[!] INVALID CHOICE!")
            time.sleep(1)


def show_menu():
    banner()
    print(f"\n{R}{'=' * 60}")
    print(f"{R}[ IP TRACKER - MAIN MENU ]")
    print(f"{R}{'=' * 60}")
    print(f"\n{Y}[1] TRACE IP ADDRESS")
    print(f"{Y}[2] TRACE DOMAIN")
    print(f"{Y}[3] TRACE MY IP")
    print(f"{Y}[4] BULK IP TRACING")
    print(f"{Y}[5] SHOW STATISTICS")
    print(f"{R}[0] EXIT")
    print(f"\n{R}{'=' * 60}")
    color = G if PROVIDERS else R
    print(f"{color}[*] OFFLINE GEO SOURCES LOADED: {len(PROVIDERS)}")


def trace_domain():
    banner()
    text = input(f"\n{Y}[ENTER DOMAIN] > {W}").strip()
    if not text:
        print(f"{R}[!] NO DOMAIN ENTERED!")
        pause()
        return
    host, ips = resolve_domain(text)
    if not ips:
        print(f"{R}[!] COULD NOT RESOLVE DOMAIN!")
        pause()
        return
    SESSION["domains"] += 1
    print(f"{G}[+] Domain: {host}")
    print(f"{G}[+] Resolved IPs: {', '.join(ips)}")
    target = next((i for i in ips if is_public(i)), ips[0])
    if len(ips) > 1:
        print(f"{Y}[*] Tracing: {target}")
    time.sleep(1)
    trace_ip(target)


def trace_my_ip():
    banner()
    locals_found = local_ips()
    if locals_found:
        print(f"{G}[+] Local IP(s): {', '.join(locals_found)}")
    print(f"{Y}[*] Detecting public IP via STUN...")
    ip = stun_public_ip()
    if not ip:
        print(f"{R}[!] COULD NOT DETECT YOUR PUBLIC IP (STUN BLOCKED OR NO INTERNET).")
        print(f"{Y}[!] Use option 1 and enter your public IP manually.")
        pause()
        return
    print(f"{G}[+] Your Public IP: {ip}")
    time.sleep(1)
    trace_ip(ip)


def bulk_trace():
    banner()
    print(f"\n{Y}[!] Enter IP addresses (one per line)")
    print(f"{Y}[!] Type 'DONE' when finished")
    ips = []
    while True:
        ip = input(f"{C}[IP] > {W}").strip()
        if ip.upper() == "DONE":
            break
        if ip and ip not in ips:
            ips.append(ip)
    if not ips:
        print(f"{R}[!] NO IP ADDRESSES ENTERED!")
        pause()
        return
    if not PROVIDERS:
        no_sources_help()

    report = []
    for i, ip in enumerate(ips, 1):
        print(f"\n{G}[{i}/{len(ips)}] TRACING: {ip}")
        if not validate_ip(ip):
            print(f"{R}    INVALID IP ADDRESS")
            continue
        if not is_public(ip):
            print(f"{R}    PRIVATE / RESERVED ADDRESS")
            continue
        info, raw, reverse_dns, whois = gather(ip)
        SESSION["ips"] += 1
        place = ", ".join(x for x in (info.get("city"), info.get("region"), info.get("cc")) if x)
        network = " ".join(x for x in (info.get("org") or whois.get("org_name"), info.get("as")) if x)
        print(f"{Y}    LOCATION   : {G}{fmt(place)}")
        print(f"{Y}    NETWORK    : {G}{fmt(network)}")
        print(f"{Y}    REVERSE DNS: {G}{reverse_dns}")
        print(f"{Y}    CONFIDENCE : {G}{info.get('confidence', 'N/A')}")
        report.append({"ip": ip, "reverse_dns": reverse_dns, "consensus": info, "sources": raw, "whois": whois})

    SESSION["bulk"] += 1
    if report and input(f"\n{Y}[SAVE ALL RESULTS? (y/n)] {W}").strip().lower() == "y":
        save_json("ip_tracker_bulk", {"date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "results": report})
    pause()


def show_stats():
    banner()
    print(f"\n{Y}[*] Version: {VERSION}")
    print(f"{Y}[*] Created by: John Paul Nuñez")
    print(f"{Y}[*] Offline geo sources: {', '.join(PROVIDERS) if PROVIDERS else 'NONE'}")
    print(f"{Y}[*] Session: {SESSION['ips']} IPs traced, {SESSION['domains']} domains, "
          f"{SESSION['bulk']} bulk runs, {SESSION['saved']} files saved")
    print(f"{Y}[*] Features:")
    for f in ("Offline multi-source consensus voting (no web APIs)", "Coordinate median and spread check",
              "Confidence score and precision level", "Reverse DNS (socket)",
              "WHOIS and abuse contact (port 43, socket)", "Public IP via STUN (socket)",
              "Optional threaded port scan", "Map link", "Bulk tracing", "JSON export"):
        print(f"    - {f}")
    pause()


def main():
    while True:
        show_menu()
        choice = input(f"\n{R}[CHOICE] > {W}").strip()
        if choice == "1":
            banner()
            ip = input(f"\n{Y}[ENTER IP ADDRESS] > {W}").strip()
            if ip:
                trace_ip(ip)
        elif choice == "2":
            trace_domain()
        elif choice == "3":
            trace_my_ip()
        elif choice == "4":
            bulk_trace()
        elif choice == "5":
            show_stats()
        elif choice == "0":
            print(f"\n{R}[!] EXITING IP TRACKER...")
            sys.exit(0)
        else:
            print(f"{R}[!] INVALID CHOICE!")
            time.sleep(1)


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print(f"\n\n{R}[!] INTERRUPTED BY USER")
        sys.exit(0)
    except Exception as e:
        print(f"\n{R}[!] ERROR: {e}")
        sys.exit(1)
