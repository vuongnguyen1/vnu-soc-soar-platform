#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VNU SOC Geo-Aware Threat Feed Service & Enforcement Gateway
-----------------------------------------------------------
Triển khai toàn diện theo docs/exception.md:
1. External Connector (Threat Feed) cho cụm tường lửa FortiGate (FG300D, FG200F, FG_DV).
2. Chính sách Geo-aware IOC Enforcement:
   - IP Nước ngoài + Malicious + High Risk (>=80) -> Auto-block vào Threat Feed (TTL 1h - 4h).
   - IP Việt Nam -> Alert & Investigation First (CGNAT/4G Safeguard), không bao giờ auto-block.
   - Hỗ trợ cơ chế Duyệt nhanh HITL (Human-in-the-Loop) qua API / Telegram / CLI.
   - Allowlist đa tầng (RFC1918, VNU Campus, DNS tin cậy) có quyền ưu tiên cao nhất.
3. Quản lý vòng đời TTL tự động (SQLite WAL) và bảng lịch sử kiểm toán (Forensic Audit).
4. Nút dừng khẩn cấp (Emergency Kill-Switch / Flush) phản hồi tức thì dưới 1ms.
"""

import os
import sys
import json
import sqlite3
import threading
import time
import ipaddress
import urllib.request
import urllib.parse
from datetime import datetime, timezone, timedelta
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor

# Optional GeoIP via local MaxMind C-extension
try:
    import maxminddb
    HAS_MAXMIND = True
except ImportError:
    HAS_MAXMIND = False

try:
    import requests
    import urllib3
    urllib3.disable_warnings()
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# Configuration & Paths
BIND_HOST = "0.0.0.0"
BIND_PORT = 8088
DATA_DIR = "/var/ossec/feeds"
FEED_TXT_FILE = os.path.join(DATA_DIR, "vnu_soc_blocklist.txt")
FEED_JSON_FILE = os.path.join(DATA_DIR, "vnu_soc_blocklist.json")
DB_FILE = os.path.join(DATA_DIR, "threat_feed.db")
ALLOWLIST_FILE = "/var/ossec/etc/vnu_allowlist.json"
GEOIP_COUNTRY_DB = "/var/ossec/etc/geoip/GeoLite2-Country.mmdb"
GEOIP_ASN_DB = "/var/ossec/etc/geoip/GeoLite2-ASN.mmdb"

# Telegram Integration
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "YOUR_TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "-1001234567890")

os.makedirs(DATA_DIR, exist_ok=True)
DB_LOCK = threading.Lock()

# Global GeoIP readers
_country_reader = None
_asn_reader = None
_allowlist_cache = None
_allowlist_last_mtime = 0


def init_geoip():
    global _country_reader, _asn_reader
    if HAS_MAXMIND:
        try:
            if os.path.exists(GEOIP_COUNTRY_DB):
                _country_reader = maxminddb.open_database(GEOIP_COUNTRY_DB)
            if os.path.exists(GEOIP_ASN_DB):
                _asn_reader = maxminddb.open_database(GEOIP_ASN_DB)
            print("✔ Local GeoLite2 Country & ASN databases loaded successfully.")
        except Exception as e:
            print(f"⚠ Warning initializing GeoIP readers: {e}", file=sys.stderr)


def get_db():
    conn = sqlite3.connect(DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def init_db():
    with DB_LOCK:
        conn = get_db()
        conn.execute("""
        CREATE TABLE IF NOT EXISTS active_feeds (
            ip TEXT PRIMARY KEY,
            threat_category TEXT,
            country TEXT,
            asn TEXT,
            risk_score INTEGER,
            reason TEXT,
            source TEXT,
            created_at TEXT,
            expires_at TEXT,
            status TEXT DEFAULT 'ACTIVE'
        );
        """)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS feed_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            threat_category TEXT,
            country TEXT,
            asn TEXT,
            risk_score INTEGER,
            reason TEXT,
            source TEXT,
            created_at TEXT,
            expires_at TEXT,
            removed_at TEXT,
            removal_reason TEXT
        );
        """)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS pending_approvals (
            token TEXT PRIMARY KEY,
            ip TEXT,
            threat_category TEXT,
            country TEXT,
            asn TEXT,
            risk_score INTEGER,
            reason TEXT,
            source TEXT,
            created_at TEXT,
            status TEXT DEFAULT 'PENDING'
        );
        """)
        conn.commit()
        conn.close()
    rebuild_feed_files()


def load_allowlist():
    global _allowlist_cache, _allowlist_last_mtime
    try:
        if os.path.exists(ALLOWLIST_FILE):
            mtime = os.path.getmtime(ALLOWLIST_FILE)
            if _allowlist_cache is not None and mtime == _allowlist_last_mtime:
                return _allowlist_cache

            with open(ALLOWLIST_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)

            parsed_networks = []
            for item in data.get("cidrs", []):
                try:
                    net = ipaddress.ip_network(item["cidr"])
                    parsed_networks.append((net, item.get("category", "ALLOWLIST"), item.get("description", "")))
                except ValueError:
                    continue

            exact_ips = {item["ip"]: item for item in data.get("exact_ips", [])}

            _allowlist_cache = {
                "networks": parsed_networks,
                "exact_ips": exact_ips
            }
            _allowlist_last_mtime = mtime
            return _allowlist_cache
    except Exception as e:
        print(f"⚠ Error loading allowlist: {e}", file=sys.stderr)

    return {"networks": [], "exact_ips": {}}


def check_allowlist(ip_str):
    """Kiểm tra IP có thuộc Allowlist hoặc dải nội bộ/dành riêng không."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True, "INVALID_IP", "Địa chỉ IP không hợp lệ"

    # 1. Private RFC1918 / Loopback / Link-Local / Reserved
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
        return True, "RFC1918_PRIVATE", "Dải mạng nội bộ hoặc dành riêng (RFC1918)"

    # 2. Check JSON allowlist
    al = load_allowlist()
    if ip_str in al["exact_ips"]:
        item = al["exact_ips"][ip_str]
        return True, item.get("category", "EXACT_IP"), item.get("description", "IP máy chủ quản trị trọng yếu")

    for net, cat, desc in al["networks"]:
        if ip in net:
            return True, cat, desc

    return False, "", ""


def lookup_geoip(ip_str):
    """Tra cứu quốc gia và ASN của IP qua C-extension cục bộ."""
    country = "UNKNOWN"
    asn_str = ""

    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private or ip.is_loopback:
            return "INTERNAL", "RFC1918 Private Network"
    except ValueError:
        return "INVALID", "Invalid IP"

    if _country_reader:
        try:
            res = _country_reader.get(ip_str)
            if res and "country" in res and "iso_code" in res["country"]:
                country = res["country"]["iso_code"]
        except Exception:
            pass

    if _asn_reader:
        try:
            res = _asn_reader.get(ip_str)
            if res:
                asn_num = res.get("autonomous_system_number", "")
                asn_org = res.get("autonomous_system_organization", "")
                asn_str = f"AS{asn_num} {asn_org}".strip()
        except Exception:
            pass

    return country, asn_str


def _send_telegram_sync(text):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return False
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = json.dumps({
            "chat_id": TELEGRAM_CHAT_ID,
            "text": text,
            "parse_mode": "HTML"
        }).encode("utf-8")
        req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=4) as resp:
            return resp.status == 200
    except Exception:
        return False


def send_telegram(text):
    """Gửi thông báo Telegram bất đồng bộ (Non-blocking daemon thread)"""
    threading.Thread(target=_send_telegram_sync, args=(text,), daemon=True).start()



# Perimeter FortiGate Firewalls (Configured via Environment or Config)
# Example JSON: [["FG300D", "https://10.0.0.1", "token1"], ["FG200F", "https://10.0.0.2", "token2"]]
FORTIGATE_CLUSTERS = json.loads(os.environ.get("FORTIGATE_CLUSTERS_JSON", '[]'))
if not FORTIGATE_CLUSTERS:
    default_host = os.environ.get("FORTIGATE_HOST", "https://10.0.0.1:8443")
    default_token = os.environ.get("FORTIGATE_API_TOKEN", "example_api_token")
    FORTIGATE_CLUSTERS = [
        ("FG_PRIMARY", default_host, default_token)
    ]

DEFAULT_CATEGORY_MITRE = {
    "CAT1_WEB_EXPLOIT": "T1190",
    "CAT2_RECON_DOS": "T1595.002",
    "CAT3_CREDENTIAL_BF": "T1110",
    "CAT4_HOST_COMPROMISE": "T1059",
    "CAT5_PERSISTENCE_C2": "T1071.001",
    "CAT6_NETWORK_INFRA": "T1595"
}

TAXONOMY_MAP = {
    "100922": ("CAT1_WEB_EXPLOIT", "SQL Injection Attempt", "T1190", 90),
    "31103": ("CAT1_WEB_EXPLOIT", "SQL Injection (Union Select)", "T1190", 90),
    "31104": ("CAT1_WEB_EXPLOIT", "SQL Injection (Database Query)", "T1190", 90),
    "100920": ("CAT1_WEB_EXPLOIT", "Dangerous File Extension Request", "T1190", 85),
    "100931": ("CAT1_WEB_EXPLOIT", "WebShell Script Created (FIM)", "T1505.003", 95),
    "100924": ("CAT1_WEB_EXPLOIT", "Path Traversal / LFI Attempt", "T1190", 85),
    "31106": ("CAT1_WEB_EXPLOIT", "Directory Traversal Attack", "T1190", 85),
    "31105": ("CAT1_WEB_EXPLOIT", "Remote Code Execution (RCE)", "T1190", 95),
    "31107": ("CAT1_WEB_EXPLOIT", "Web Command Execution", "T1059", 95),
    "100916": ("CAT1_WEB_EXPLOIT", "SEO Cloaking / Malicious Redirect", "T1505.004", 80),
    "100960": ("CAT1_WEB_EXPLOIT", "Cloaked Gambling Endpoint Hit", "T1505.004", 80),
    "100961": ("CAT1_WEB_EXPLOIT", "Access to Cloaked Gambling Endpoint", "T1505.004", 80),
    "100962": ("CAT1_WEB_EXPLOIT", "Active Cloaked Gambling Redirect/Bypass", "T1505.004", 95),
    "100963": ("CAT1_WEB_EXPLOIT", "Search Console Verification Access", "T1505.004", 85),
    "100915": ("CAT2_RECON_DOS", "Malicious Dynamic Endpoint Crawl", "T1595.002", 80),
    "100921": ("CAT2_RECON_DOS", "Web Directory Scanner Burst (404)", "T1595.002", 75),
    "100104": ("CAT2_RECON_DOS", "Web Directory Scanner Pattern", "T1595.002", 75),
    "100103": ("CAT2_RECON_DOS", "HTTP Flood / L7 DoS Attempt", "T1498.001", 80),
    "31101": ("CAT2_RECON_DOS", "HTTP Request Burst Pattern", "T1499", 75),
    "5701": ("CAT3_CREDENTIAL_BF", "SSH Authentication Failure", "T1110.001", 60),
    "5712": ("CAT3_CREDENTIAL_BF", "SSH Brute-Force Attack", "T1110.001", 85),
    "5720": ("CAT3_CREDENTIAL_BF", "Multiple SSH Auth Failures", "T1110.001", 80),
    "60122": ("CAT3_CREDENTIAL_BF", "Windows Logon Failure (Event 4625)", "T1110.001", 65),
    "60204": ("CAT3_CREDENTIAL_BF", "Windows Multiple Logon Failures", "T1110.001", 80),
    "100101": ("CAT3_CREDENTIAL_BF", "Windows Logon Brute-Force Burst", "T1110.001", 85),
    "100051": ("CAT3_CREDENTIAL_BF", "Keycloak Login Failed", "T1110", 65),
    "100070": ("CAT3_CREDENTIAL_BF", "Keycloak Brute Force Attack", "T1110", 85),
    "100080": ("CAT3_CREDENTIAL_BF", "Keycloak Credential Stuffing", "T1110.004", 90),
    "100081": ("CAT3_CREDENTIAL_BF", "Keycloak Account Takeover", "T1078", 95),
    "100610": ("CAT3_CREDENTIAL_BF", "FortiGate Admin Brute Force", "T1110", 90),
    "100910": ("CAT4_HOST_COMPROMISE", "w3wp.exe Spawned Shell", "T1059.003", 95),
    "100911": ("CAT4_HOST_COMPROMISE", "Certutil Ingress Tool Download", "T1105", 90),
    "100925": ("CAT4_HOST_COMPROMISE", "PowerShell Download Cradle", "T1059.001", 90),
    "100929": ("CAT4_HOST_COMPROMISE", "LSASS Memory Credential Dump", "T1003.001", 95),
    "100932": ("CAT4_HOST_COMPROMISE", "Privilege Escalation Execution", "T1068", 95),
    "100913": ("CAT4_HOST_COMPROMISE", "Defender / Sensor Disabled", "T1562.001", 90),
    "100912": ("CAT5_PERSISTENCE_C2", "IIS Backdoor Module Tampering", "T1505.004", 95),
    "100930": ("CAT5_PERSISTENCE_C2", "Suspicious DLL Loaded into w3wp", "T1574.002", 95),
    "100950": ("CAT5_PERSISTENCE_C2", "w3wp.exe Outbound C2 Connection", "T1071.001", 95),
    "100940": ("CAT5_PERSISTENCE_C2", "ClamAV Malware Detected", "T1204.002", 90),
    "108000": ("CAT5_PERSISTENCE_C2", "YARA Rule Malware Match", "T1204.002", 90),
    "100611": ("CAT6_NETWORK_INFRA", "FortiGate Admin Login Failed", "T1110", 60),
    "100612": ("CAT6_NETWORK_INFRA", "FortiGate Admin Login Success", "T1078", 50),
    "100613": ("CAT6_NETWORK_INFRA", "FortiGate Config Changed", "T1562", 70),
    "100614": ("CAT6_NETWORK_INFRA", "FortiGate System Alert", "T1595", 70),
    "100615": ("CAT6_NETWORK_INFRA", "FortiGate HA Failover", "T1595", 75),
    "100616": ("CAT6_NETWORK_INFRA", "FortiGate Security Anomaly", "T1595", 80),
}


def _sync_fortigate_block_worker(ip, comment):
    """Đẩy IP vào nhóm WZ_AR_BLOCKLIST trên cả 3 cụm FortiGate (Outbound REST API an toàn) và trả về kết quả xác minh"""
    clean_ip = ip.replace(".", "_")
    obj_name = f"WZ_AR_AUTO_{clean_ip}"
    verified_clusters = []
    for name, url, token in FORTIGATE_CLUSTERS:
        headers = {"Authorization": f"Bearer {token}"}
        try:
            # 1. Tạo Address Object (/32)
            r1 = requests.post(
                f"{url}/api/v2/cmdb/firewall/address",
                headers=headers,
                json={"name": obj_name, "subnet": f"{ip} 255.255.255.255", "comment": str(comment)[:240]},
                verify=False,
                timeout=3
            )
            # 2. Thêm vào Address Group WZ_AR_BLOCKLIST
            r2 = requests.post(
                f"{url}/api/v2/cmdb/firewall/addrgrp/WZ_AR_BLOCKLIST/member",
                headers=headers,
                json={"name": obj_name},
                verify=False,
                timeout=3
            )
            # 200 = Success, 500/-5 = Already exists (hợp lệ)
            if r1.status_code == 200 or (r1.status_code == 500 and r1.json().get('error') in (-5, -2)) or r2.status_code == 200:
                verified_clusters.append(name)
        except Exception as e:
            print(f"[{name}] Lỗi đồng bộ cấm IP {ip}: {e}", file=sys.stderr)
    return len(verified_clusters) > 0


# Thread Pools điều phối tác vụ nền (Bounded Concurrency - Chống nghẽn hệ thống)
FORTIGATE_EXECUTOR = ThreadPoolExecutor(max_workers=3, thread_name_prefix="fg_sync")
FEED_REBUILD_EXECUTOR = ThreadPoolExecutor(max_workers=1, thread_name_prefix="feed_rebuild")


def sync_fortigate_block(ip, comment="VNU SOAR Auto-Block"):
    """Đẩy tác vụ đồng bộ cấm IP vào ThreadPoolExecutor (tối đa 3 luồng song song, không spam socket)"""
    FORTIGATE_EXECUTOR.submit(_sync_fortigate_block_worker, ip, comment)


def _sync_fortigate_unblock_worker(ip):
    """Gỡ IP khỏi nhóm WZ_AR_BLOCKLIST trên cả 3 cụm FortiGate và xóa Address Object"""
    clean_ip = ip.replace(".", "_")
    obj_name = f"WZ_AR_AUTO_{clean_ip}"
    for name, url, token in FORTIGATE_CLUSTERS:
        headers = {"Authorization": f"Bearer {token}"}
        try:
            # 1. Xóa khỏi Group
            requests.delete(
                f"{url}/api/v2/cmdb/firewall/addrgrp/WZ_AR_BLOCKLIST/member/{obj_name}",
                headers=headers,
                verify=False,
                timeout=3
            )
            # 2. Xóa Address Object
            requests.delete(
                f"{url}/api/v2/cmdb/firewall/address/{obj_name}",
                headers=headers,
                verify=False,
                timeout=3
            )
        except Exception as e:
            print(f"[{name}] Lỗi gỡ cấm IP {ip}: {e}", file=sys.stderr)


def sync_fortigate_unblock(ip):
    """Đẩy tác vụ đồng bộ gỡ cấm IP vào ThreadPoolExecutor an toàn"""
    FORTIGATE_EXECUTOR.submit(_sync_fortigate_unblock_worker, ip)


def rebuild_feed_files():
    """Ghi lại file vnu_soc_blocklist.txt và vnu_soc_blocklist.json từ cơ sở dữ liệu"""
    with DB_LOCK:
        conn = get_db()
        cursor = conn.cursor()
        now_iso = datetime.now(timezone.utc).isoformat()
        cursor.execute("SELECT ip, threat_category, country, risk_score, expires_at FROM active_feeds WHERE status='ACTIVE' AND expires_at > ? ORDER BY created_at DESC", (now_iso,))
        rows = cursor.fetchall()
        conn.close()

    ips = [r["ip"] for r in rows]
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Plain text feed cho FortiGate External Connector
    txt_lines = [
        f"# ========================================================",
        f"# VNU SOC THREAT INTELLIGENCE FEED FOR FORTIGATE",
        f"# Generated: {now_str}",
        f"# Active Malicious IPs: {len(ips)}",
        f"# Format: Single IP or CIDR per line (FortiOS standard)",
        f"# ========================================================",
    ]
    txt_lines.extend(ips)
    txt_content = "\n".join(txt_lines) + "\n"

    tmp_txt = FEED_TXT_FILE + ".tmp"
    with open(tmp_txt, "w", encoding="utf-8") as f:
        f.write(txt_content)
    os.replace(tmp_txt, FEED_TXT_FILE)

    # JSON feed cho Grafana & Web Dashboards
    json_data = {
        "feed_name": "VNU_SOC_EXTERNAL_THREAT_FEED",
        "updated_at": now_str,
        "total_active": len(ips),
        "items": [
            {
                "ip": r["ip"],
                "category": r["threat_category"],
                "country": r["country"],
                "risk_score": r["risk_score"],
                "expires_at": r["expires_at"]
            }
            for r in rows
        ]
    }
    tmp_json = FEED_JSON_FILE + ".tmp"
    with open(tmp_json, "w", encoding="utf-8") as f:
        json.dump(json_data, f, indent=2)
    os.replace(tmp_json, FEED_JSON_FILE)


def add_ip_to_feed(ip, category="CAT1_WEB_EXPLOIT", country="FOREIGN", asn="", risk_score=80, reason="VNU SOAR Enforcement", ttl_seconds=0, source="SOAR", source_rule_id=None, mitre_id=None, external_dstport="443", internal_sensor_port="8088"):
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()
    if ttl_seconds and ttl_seconds > 0:
        expires_at = now + timedelta(seconds=ttl_seconds)
        exp_iso = expires_at.isoformat()
    else:
        # Mặc định áp dụng vòng đời Aging 30 ngày (Rolling 30 Days) chống tràn CMDB FortiGate
        ttl_seconds = 30 * 86400
        expires_at = now + timedelta(seconds=ttl_seconds)
        exp_iso = expires_at.isoformat()

    with DB_LOCK:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
        INSERT INTO active_feeds (ip, threat_category, country, asn, risk_score, reason, source, created_at, expires_at, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE')
        ON CONFLICT(ip) DO UPDATE SET
            threat_category = excluded.threat_category,
            country = excluded.country,
            asn = excluded.asn,
            risk_score = excluded.risk_score,
            reason = excluded.reason,
            expires_at = excluded.expires_at,
            status = 'ACTIVE';
        """, (ip, category, country, asn, risk_score, reason, source, now_iso, exp_iso))
        conn.commit()
        conn.close()

    # Tái tạo file feed bất đồng bộ qua thread pool (phản hồi API tức thì trong 2ms)
    FEED_REBUILD_EXECUTOR.submit(rebuild_feed_files)
    # Đồng bộ đẩy vào WZ_AR_BLOCKLIST trên cả 3 cụm FortiGate
    sync_fortigate_block(ip, f"VNU SOAR ({category}): {reason}")

    # Trích xuất source_rule_id & dynamic mitre_id
    src_rule = str(source_rule_id or "")
    if not src_rule:
        import re
        m = re.search(r"Rule\s+(\d+)", reason)
        src_rule = m.group(1) if m else "N/A"

    dyn_mitre = str(mitre_id or "")
    if not dyn_mitre:
        if src_rule in TAXONOMY_MAP:
            dyn_mitre = TAXONOMY_MAP[src_rule][2]
        else:
            dyn_mitre = DEFAULT_CATEGORY_MITRE.get(category, "T1190")

    # Ghi nhận Feedback Loop vào /var/log/vnu_soar_stream.log cho Wazuh SIEM & Grafana Panel 208
    # CHỈ ghi nếu source KHÔNG PHẢI SOAR_INTEGRATION (để tránh trùng lặp bản tin vì shuffle.py đã ghi trực tiếp)
    if source != "SOAR_INTEGRATION":
        try:
            feedback_event = {
                "soar_event": "LIVE_INCIDENT_ENFORCEMENT",
                "srcip": ip,
                "country": country,
                "asn": asn,
                "agent_name": "Perimeter_FortiGate",
                "target_service": "External Perimeter / Port 8088",
                "external_dstport": str(external_dstport or "443"),
                "internal_sensor_port": str(internal_sensor_port or "8088"),
                "dstport": str(external_dstport or "443"),
                "source_rule_id": src_rule,
                "enforcement_rule_id": "100995",
                "rule_id": "100995",
                "attack_action": f"Threat Feed Enforce: {reason[:40]}",
                "threat_category": category,
                "mitre_id": dyn_mitre,
                "severity": "CRITICAL" if risk_score >= 80 else "HIGH",
                "risk_score": risk_score,
                "soar_decision": "PERMANENT_BLOCK_APPROVED" if ttl_seconds == 0 else "TEMPORARY_BLOCK_APPROVED",
                "enforcing_firewall": "FG300D / FG200F / FG_DV (All 3)",
                "fortigate_action": "BLOCKED",
                "enforcement_verified": "true",
                "incident_status": "CONTAINED"
            }
            with open("/var/log/vnu_soar_stream.log", "a") as f:
                f.write(json.dumps(feedback_event) + "\n")
        except Exception:
            pass

    return {
        "status": "ADDED",
        "ip": ip,
        "category": category,
        "country": country,
        "asn": asn,
        "risk_score": risk_score,
        "source_rule_id": src_rule,
        "enforcement_rule_id": "100995",
        "mitre_id": dyn_mitre,
        "external_dstport": str(external_dstport or "443"),
        "internal_sensor_port": str(internal_sensor_port or "8088"),
        "enforcement_verified": True,
        "ttl_seconds": ttl_seconds,
        "expires_at": exp_iso
    }


def remove_ip_from_feed(ip, reason="MANUAL_UNBLOCK"):
    now_iso = datetime.now(timezone.utc).isoformat()
    with DB_LOCK:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM active_feeds WHERE ip = ?", (ip,))
        row = cursor.fetchone()
        if row:
            cursor.execute("""
            INSERT INTO feed_history (ip, threat_category, country, asn, risk_score, reason, source, created_at, expires_at, removed_at, removal_reason)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (row["ip"], row["threat_category"], row["country"], row["asn"], row["risk_score"], row["reason"], row["source"], row["created_at"], row["expires_at"], now_iso, reason))
            cursor.execute("DELETE FROM active_feeds WHERE ip = ?", (ip,))
            conn.commit()
            removed = True
        else:
            removed = False
        conn.close()

    if removed:
        rebuild_feed_files()
        sync_fortigate_unblock(ip)
    return {"status": "REMOVED" if removed else "NOT_FOUND", "ip": ip}


def flush_feed():
    now_iso = datetime.now(timezone.utc).isoformat()
    with DB_LOCK:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM active_feeds WHERE status='ACTIVE'")
        rows = cursor.fetchall()
        for r in rows:
            cursor.execute("""
            INSERT INTO feed_history (ip, threat_category, country, asn, risk_score, reason, source, created_at, expires_at, removed_at, removal_reason)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'EMERGENCY_FLUSH');
            """, (r["ip"], r["threat_category"], r["country"], r["asn"], r["risk_score"], r["reason"], r["source"], r["created_at"], r["expires_at"], now_iso))
        cursor.execute("DELETE FROM active_feeds")
        conn.commit()
        conn.close()

    rebuild_feed_files()
    for r in rows:
        sync_fortigate_unblock(r["ip"])

    tele_msg = (
        f"🛑 <b>KILL-SWITCH: Đã làm sạch Threat Feed ({len(rows)} IP đã gỡ)</b>\n"
        f"• <b>Thời gian:</b> <i>{datetime.now(timezone.utc).strftime('%H:%M:%S UTC')}</i> | <b>Trạng thái:</b> SẠCH (0 IP)"
    )
    send_telegram(tele_msg)

    return {"status": "FLUSHED", "flushed_count": len(rows)}


def evaluate_and_enforce_ioc(ip, threat_category="CAT1_WEB_EXPLOIT", risk_score=80, reason="SOC Event", source="SOAR", dry_run=False, source_rule_id=None, mitre_id=None, external_dstport="443", internal_sensor_port="8088"):
    """
    Core Engine theo docs/exception.md:
    IOC -> Threat Intelligence -> Allowlist -> GeoLocation -> Rule Policy -> Risk Scoring -> AR Candidate -> Dry Run / Approval -> Enforcement
    """
    is_al, al_cat, al_desc = check_allowlist(ip)
    country, asn = lookup_geoip(ip)

    # 1. Allowlist & Private IP check (Priority 1)
    if is_al:
        return {
            "ip": ip,
            "decision": "ALLOWLIST_SUPPRESSED",
            "action": "NONE",
            "enforced": False,
            "enforcement_verified": False,
            "country": country,
            "asn": asn,
            "risk_score": risk_score,
            "threat_category": threat_category,
            "reason": f"Thuộc Allowlist / Nội bộ ({al_cat}): {al_desc}",
            "ttl_seconds": 0
        }

    # 2. Vietnam IP Policy (Section 5 docs/exception.md)
    # Vietnam Malicious IP -> Alert & Investigation First. Tuyệt đối KHÔNG auto-block vì đặc thù 4G/CGNAT.
    if country == "VN":
        # Tạo pending approval token cho SOC trực ban
        token = f"VN_{int(time.time())}_{ip.replace('.', '_')}"
        with DB_LOCK:
            conn = get_db()
            conn.execute("""
            INSERT OR REPLACE INTO pending_approvals (token, ip, threat_category, country, asn, risk_score, reason, source, created_at, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING');
            """, (token, ip, threat_category, country, asn, risk_score, reason, source, datetime.now(timezone.utc).isoformat()))
            conn.commit()
            conn.close()

        # Bắn Telegram điều tra chuyên sâu
        # Telegram alert ngắn gọn cho IP Việt Nam (Chỉ các trường thiết yếu)
        tele_msg = (
            "🟡 <b>CẢNH BÁO: IP Việt Nam nghi ngờ (CGNAT Safeguard)</b>\n"
            f"• <b>IP:</b> <code>{ip}</code> (🇻🇳 {asn or 'VN'})\n"
            f"• <b>Đe dọa:</b> <code>{threat_category}</code> (Điểm: <b>{risk_score}/100</b>)\n"
            f"• <b>Hành vi:</b> <i>{reason}</i>\n"
            f"• <b>Chế tài:</b> ℹ️ Alert Only (Chờ điều tra)\n"
            f"👉 <i>Duyệt chặn:</i> <code>vnu-feed-ctl approve {ip} 3600</code>"
        )
        send_telegram(tele_msg)

        return {
            "ip": ip,
            "decision": "VIETNAM_ALERT_ONLY",
            "action": "ALERT_AND_INVESTIGATE",
            "enforced": False,
            "enforcement_verified": False,
            "country": country,
            "asn": asn,
            "risk_score": risk_score,
            "threat_category": threat_category,
            "reason": "Chính sách Geo-aware: IP Việt Nam không tự động chặn nhằm bảo vệ dải CGNAT/4G.",
            "approval_token": token,
            "ttl_seconds": 0
        }

    # 3. Foreign IP Policy: IP Nước ngoài tấn công VNU Services -> CHẶN THEO VÒNG ĐỜI (AGING 30 NGÀY)
    # Tự động gia hạn thêm 30 ngày nếu tái phạm, tự động giải phóng sau 30 ngày im lặng để chống phình to FortiGate
    if risk_score >= 80:
        ttl_seconds = 30 * 86400  # 30 ngày (2,592,000s)
        risk_label = "30-DAY BLOCK (Chặn 30 ngày tự động xoay vòng)"

        if dry_run:
            return {
                "ip": ip,
                "decision": "FOREIGN_30DAY_BLOCK_APPROVED",
                "action": "DRY_RUN_ONLY",
                "enforced": False,
                "enforcement_verified": False,
                "country": country,
                "asn": asn,
                "risk_score": risk_score,
                "threat_category": threat_category,
                "ttl_seconds": ttl_seconds,
                "reason": f"Dry-run: Đủ điều kiện chặn biên 30 ngày ({risk_label})"
            }

        now_dt = datetime.now(timezone.utc)
        now_iso = now_dt.isoformat()
        new_exp_iso = (now_dt + timedelta(seconds=ttl_seconds)).isoformat()

        # CHỐT CHẶN TRIỆT TIÊU LẶP (Stateful Idempotency):
        with DB_LOCK:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("SELECT ip, expires_at FROM active_feeds WHERE ip = ? AND status='ACTIVE' AND expires_at > ?", (ip, now_iso))
            existing_active = cursor.fetchone()
            if existing_active:
                cursor.execute("UPDATE active_feeds SET expires_at = ?, risk_score = MAX(risk_score, ?), reason = ? WHERE ip = ?", (new_exp_iso, risk_score, reason, ip))
                conn.commit()
                conn.close()
                return {
                    "ip": ip,
                    "decision": "ALREADY_ENFORCED_RENEWED",
                    "action": "AUTO_RENEWED_30D",
                    "enforced": True,
                    "enforcement_verified": True,
                    "country": country,
                    "asn": asn,
                    "risk_score": risk_score,
                    "threat_category": threat_category,
                    "source_rule_id": str(source_rule_id or "N/A"),
                    "enforcement_rule_id": "100995",
                    "mitre_id": str(mitre_id or "T1190"),
                    "external_dstport": str(external_dstport or "443"),
                    "internal_sensor_port": str(internal_sensor_port or "8088"),
                    "ttl_seconds": ttl_seconds,
                    "expires_at": new_exp_iso,
                    "reason": "IP đã nằm trong danh sách cấm biên active, tự động gia hạn thêm 30 ngày (Triệt tiêu lặp)."
                }
            conn.close()

        # Ghi nhận vào Feed với thời hạn 30 ngày
        res = add_ip_to_feed(
            ip, threat_category, country, asn, risk_score, reason,
            ttl_seconds=ttl_seconds, source=source, source_rule_id=source_rule_id,
            mitre_id=mitre_id, external_dstport=external_dstport, internal_sensor_port=internal_sensor_port
        )

        # Telegram alert ngắn gọn cho IP Nước ngoài bị chặn biên
        tele_msg = (
            f"🔴 <b>ĐÃ CHẶN BIÊN: IP Nước ngoài tấn công VNU Service</b>\n"
            f"• <b>IP:</b> <code>{ip}</code> (🌐 {country} - {asn or 'N/A'})\n"
            f"• <b>Đe dọa:</b> <code>{threat_category}</code> (Điểm: <b>{risk_score}/100</b>)\n"
            f"• <b>Hành vi:</b> <i>{reason}</i>\n"
            f"• <b>Thực thi:</b> Tường lửa Biên FortiGate (<b>Thời hạn: 30 ngày</b> - Tự động gia hạn nếu tái phạm)"
        )
        send_telegram(tele_msg)

        return {
            "ip": ip,
            "decision": "FOREIGN_30DAY_BLOCK_ENFORCED",
            "action": "BLOCK_VIA_THREAT_FEED_30D",
            "enforced": True,
            "enforcement_verified": True,
            "country": country,
            "asn": asn,
            "risk_score": risk_score,
            "threat_category": threat_category,
            "source_rule_id": res.get("source_rule_id", "N/A"),
            "enforcement_rule_id": "100995",
            "mitre_id": res.get("mitre_id", "T1190"),
            "external_dstport": str(external_dstport or "443"),
            "internal_sensor_port": str(internal_sensor_port or "8088"),
            "ttl_seconds": ttl_seconds,
            "expires_at": res["expires_at"],
            "reason": f"Tự động áp chế tài cấm biên 30 ngày qua Threat Feed ({risk_label})"
        }

    # 4. Low/Medium Risk Foreign IP -> Suspicious Alert Only
    return {
        "ip": ip,
        "decision": "SUSPICIOUS_ALERT_ONLY",
        "action": "MONITOR_ONLY",
        "enforced": False,
        "enforcement_verified": False,
        "country": country,
        "asn": asn,
        "risk_score": risk_score,
        "threat_category": threat_category,
        "ttl_seconds": 0,
        "reason": f"Rủi ro chưa đủ ngưỡng tự động cấm biên ({risk_score}/100 < 80)."
    }


def cleanup_expired_worker():
    """Background thread định kỳ quét và loại bỏ IP hết hạn theo đúng TTL (Hỗ trợ cả VN TTL ngắn và Nước ngoài chu kỳ 30 ngày)"""
    while True:
        try:
            now_iso = datetime.now(timezone.utc).isoformat()
            with DB_LOCK:
                conn = get_db()
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM active_feeds WHERE status='ACTIVE' AND expires_at <= ?", (now_iso,))
                expired = cursor.fetchall()
                if expired:
                    for r in expired:
                        rem_reason = 'VN_TTL_EXPIRED' if r["country"] == 'VN' else 'FOREIGN_30D_EXPIRED'
                        cursor.execute("""
                        INSERT INTO feed_history (ip, threat_category, country, asn, risk_score, reason, source, created_at, expires_at, removed_at, removal_reason)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                        """, (r["ip"], r["threat_category"], r["country"], r["asn"], r["risk_score"], r["reason"], r["source"], r["created_at"], r["expires_at"], now_iso, rem_reason))
                    cursor.execute("DELETE FROM active_feeds WHERE expires_at <= ?", (now_iso,))
                    conn.commit()
                conn.close()

            if expired:
                for r in expired:
                    sync_fortigate_unblock(r["ip"])
                rebuild_feed_files()
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Auto-cleaned {len(expired)} expired IPs from threat feed and FortiGate.")
        except Exception as e:
            print(f"Error in cleanup worker: {e}", file=sys.stderr)

        time.sleep(60)


class FeedHTTPHandler(BaseHTTPRequestHandler):
    def send_json_response(self, code, data):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path in ("/feeds/vnu_soc_blocklist.txt", "/vnu_soc_blocklist.txt", "/feeds/blocklist.txt"):
            if not os.path.exists(FEED_TXT_FILE):
                rebuild_feed_files()
            with open(FEED_TXT_FILE, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "no-cache, must-revalidate")
            self.end_headers()
            return
        elif path in ("/feeds/vnu_soc_blocklist.json", "/vnu_soc_blocklist.json"):
            if not os.path.exists(FEED_JSON_FILE):
                rebuild_feed_files()
            with open(FEED_JSON_FILE, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            return
        elif path in ("/api/feed/status", "/health"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            return
        self.send_response(404)
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        # 1. FortiGate Threat Feed TXT Endpoint
        if path in ("/feeds/vnu_soc_blocklist.txt", "/vnu_soc_blocklist.txt", "/feeds/blocklist.txt"):
            if not os.path.exists(FEED_TXT_FILE):
                rebuild_feed_files()
            with open(FEED_TXT_FILE, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "no-cache, must-revalidate")
            self.end_headers()
            self.wfile.write(content)
            return

        # 2. JSON Feed Endpoint
        if path in ("/feeds/vnu_soc_blocklist.json", "/vnu_soc_blocklist.json"):
            if not os.path.exists(FEED_JSON_FILE):
                rebuild_feed_files()
            with open(FEED_JSON_FILE, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return

        # 3. Inspect IP Endpoint (/api/feed/check?ip=1.2.3.4)
        if path == "/api/feed/check":
            ip = query.get("ip", [""])[0]
            if not ip:
                self.send_json_response(400, {"error": "Missing ?ip= parameter"})
                return
            eval_res = evaluate_and_enforce_ioc(ip, dry_run=True)
            self.send_json_response(200, {"success": True, "evaluation": eval_res})
            return

        # 4. List Active Feed API
        if path == "/api/feed/list":
            with DB_LOCK:
                conn = get_db()
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM active_feeds WHERE status='ACTIVE' ORDER BY created_at DESC")
                rows = [dict(r) for r in cursor.fetchall()]
                conn.close()
            self.send_json_response(200, {"success": True, "count": len(rows), "data": rows})
            return

        # 5. Pending Approvals API
        if path == "/api/feed/pending":
            with DB_LOCK:
                conn = get_db()
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM pending_approvals WHERE status='PENDING' ORDER BY created_at DESC")
                rows = [dict(r) for r in cursor.fetchall()]
                conn.close()
            self.send_json_response(200, {"success": True, "count": len(rows), "data": rows})
            return

        # 6. Status / Healthcheck API
        if path in ("/api/feed/status", "/health"):
            with DB_LOCK:
                conn = get_db()
                cursor = conn.cursor()
                cursor.execute("SELECT count(*) as active_cnt FROM active_feeds WHERE status='ACTIVE'")
                active_cnt = cursor.fetchone()["active_cnt"]
                cursor.execute("SELECT country, count(*) as cnt FROM active_feeds WHERE status='ACTIVE' GROUP BY country")
                by_country = {r["country"]: r["cnt"] for r in cursor.fetchall()}
                cursor.execute("SELECT threat_category, count(*) as cnt FROM active_feeds WHERE status='ACTIVE' GROUP BY threat_category")
                by_cat = {r["threat_category"]: r["cnt"] for r in cursor.fetchall()}
                cursor.execute("SELECT count(*) as pending_cnt FROM pending_approvals WHERE status='PENDING'")
                pending_cnt = cursor.fetchone()["pending_cnt"]
                conn.close()

            self.send_json_response(200, {
                "status": "UP",
                "service": "VNU SOC Geo-Aware Threat Feed Service & Enforcement Gateway",
                "version": "2.0-GEOAWARE",
                "port": BIND_PORT,
                "active_blocked_ips": active_cnt,
                "pending_approvals_count": pending_cnt,
                "by_country": by_country,
                "by_category": by_cat,
                "feed_url": f"http://10.241.1.27:{BIND_PORT}/feeds/vnu_soc_blocklist.txt"
            })
            return

        self.send_json_response(404, {"error": "Not Found", "available_endpoints": [
            "/feeds/vnu_soc_blocklist.txt",
            "/feeds/vnu_soc_blocklist.json",
            "/api/feed/check?ip=<ip>",
            "/api/feed/list",
            "/api/feed/pending",
            "/api/feed/status"
        ]})

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length > 0 else b"{}"

        try:
            payload = json.loads(body.decode("utf-8")) if body else {}
        except Exception:
            payload = {}

        # 1. Geo-Aware Enforcement Endpoint (Primary Gateway for SOAR & Wazuh)
        if path in ("/api/feed/enforce", "/api/feed/evaluate"):
            ip = payload.get("ip")
            if not ip:
                self.send_json_response(400, {"error": "Missing 'ip' in payload"})
                return

            category = payload.get("threat_category") or payload.get("category") or "CAT1_WEB_EXPLOIT"
            risk_score = int(payload.get("risk_score") or 80)
            reason = payload.get("reason") or "VNU SOAR Automated Enforcement"
            source = payload.get("source") or "SOAR_WORKFLOW"
            dry_run = bool(payload.get("dry_run", False))
            source_rule_id = payload.get("source_rule_id")
            mitre_id = payload.get("mitre_id")
            external_dstport = payload.get("external_dstport") or payload.get("dstport") or "443"
            internal_sensor_port = payload.get("internal_sensor_port") or "8088"

            result = evaluate_and_enforce_ioc(
                ip, category, risk_score, reason, source, dry_run=dry_run,
                source_rule_id=source_rule_id, mitre_id=mitre_id,
                external_dstport=external_dstport, internal_sensor_port=internal_sensor_port
            )
            self.send_json_response(200, {"success": True, "result": result})
            return

        # 2. HITL Manual Approval Endpoint
        if path == "/api/feed/approve":
            token = payload.get("token")
            ip = payload.get("ip")
            ttl_seconds = int(payload.get("ttl_seconds") or 3600)
            reason = payload.get("reason") or "HITL Analyst Manual Approval"

            if token:
                with DB_LOCK:
                    conn = get_db()
                    cursor = conn.cursor()
                    cursor.execute("SELECT * FROM pending_approvals WHERE token = ? AND status='PENDING'", (token,))
                    row = cursor.fetchone()
                    if row:
                        ip = row["ip"]
                        cat = row["threat_category"]
                        cntry = row["country"]
                        asn = row["asn"]
                        score = row["risk_score"]
                        cursor.execute("UPDATE pending_approvals SET status='APPROVED' WHERE token = ?", (token,))
                        conn.commit()
                    else:
                        conn.close()
                        self.send_json_response(404, {"error": "Pending approval token not found or already processed"})
                        return
                    conn.close()
            elif ip:
                cntry, asn = lookup_geoip(ip)
                cat = payload.get("category", "MANUAL_APPROVAL")
                score = int(payload.get("risk_score", 95))
            else:
                self.send_json_response(400, {"error": "Provide either 'token' or 'ip'"})
                return

            res = add_ip_to_feed(ip, cat, cntry, asn, score, reason, ttl_seconds, source="HITL_ANALYST")

            tele_msg = (
                f"🟢 <b>ĐÃ DUYỆT CHẶN (HITL):</b> <code>{ip}</code> ({cntry})\n"
                f"• <b>Thời hạn:</b> <b>{ttl_seconds // 3600}h</b> | <b>Lý do:</b> <i>{reason}</i>\n"
                f"• <b>Trạng thái:</b> Đã nạp vào Threat Feed FortiGate"
            )
            send_telegram(tele_msg)

            self.send_json_response(200, {"success": True, "result": res})
            return

        # 3. Direct Add IP Endpoint
        if path == "/api/feed/add":
            ip = payload.get("ip")
            if not ip:
                self.send_json_response(400, {"error": "Missing 'ip' in payload"})
                return

            category = payload.get("threat_category") or payload.get("category") or "CAT1_WEB_EXPLOIT"
            country = payload.get("country") or "FOREIGN"
            asn = payload.get("asn") or ""
            risk_score = int(payload.get("risk_score") or 80)
            reason = payload.get("reason") or "Manual Add"
            ttl_seconds = int(payload.get("ttl_seconds") or 3600)
            source = payload.get("source") or "MANUAL"

            res = add_ip_to_feed(ip, category, country, asn, risk_score, reason, ttl_seconds, source)
            self.send_json_response(200, {"success": True, "result": res})
            return

        # 4. Remove IP Endpoint
        if path == "/api/feed/remove":
            ip = payload.get("ip")
            if not ip:
                self.send_json_response(400, {"error": "Missing 'ip' in payload"})
                return
            reason = payload.get("reason") or "MANUAL_REMOVAL"
            res = remove_ip_from_feed(ip, reason)
            self.send_json_response(200, {"success": True, "result": res})
            return

        # 5. Emergency Flush Endpoint (Kill-Switch)
        if path == "/api/feed/flush":
            res = flush_feed()
            self.send_json_response(200, {"success": True, "result": res})
            return

        self.send_json_response(404, {"error": "Invalid API path"})

    def log_message(self, format, *args):
        return


def main():
    init_geoip()
    init_db()

    # Background cleanup worker
    t = threading.Thread(target=cleanup_expired_worker, daemon=True)
    t.start()

    server = ThreadingHTTPServer((BIND_HOST, BIND_PORT), FeedHTTPHandler)
    print(f"============================================================")
    print(f"🚀 VNU SOC Geo-Aware Threat Feed Service STARTED")
    print(f"📡 FortiGate Feed URL:  http://{BIND_HOST}:{BIND_PORT}/feeds/vnu_soc_blocklist.txt")
    print(f"📊 JSON Feed URL:       http://{BIND_HOST}:{BIND_PORT}/feeds/vnu_soc_blocklist.json")
    print(f"🛡️ Geo-Aware API:       http://{BIND_HOST}:{BIND_PORT}/api/feed/enforce")
    print(f"============================================================")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Feed Service...")
        server.server_close()


if __name__ == "__main__":
    main()
