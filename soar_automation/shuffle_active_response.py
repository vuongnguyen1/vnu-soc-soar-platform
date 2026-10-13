#!/usr/bin/env python3
# Created by Shuffle, AS. <frikky@shuffler.io>.
# Based on the Slack integration using Webhooks
#
# Enhanced by VNU SOC:
# 1. Sliding Window Deduplication (5 phút theo cặp srcip + rule_id) - Chống nghẽn Shuffle.
# 2. Geo-aware Enrichment (MaxMind GeoLite2 Country & ASN) - Hỗ trợ chính sách CGNAT/4G.
# 3. External Threat Feed Enforcement Routing (Thay thế Address Object trực tiếp).
# 4. Two-Stream Routing: ENFORCEMENT (chỉ website service) vs INFRA (hạ tầng, ảo hóa, mạng - ALERT ONLY).
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

import json
import os
import sys
import time
import sqlite3
import ipaddress

# Exit error codes
ERR_NO_REQUEST_MODULE = 1
ERR_BAD_ARGUMENTS = 2
ERR_FILE_NOT_FOUND = 6
ERR_INVALID_JSON = 7

try:
    import requests
except ModuleNotFoundError:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(ERR_NO_REQUEST_MODULE)

try:
    import maxminddb
    HAS_MAXMIND = True
except ImportError:
    HAS_MAXMIND = False

# Global vars
debug_enabled = False
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
json_alert = {}
SKIP_RULE_IDS = [
    '87924',
    '87900',
    '87901',
    '87902',
    '87903',
    '87904',
    '86001',
    '86002',
    '86003',
    '87932',
    '80710',
    '87929',
    '87928',
    '5710',
    '100995',
    '100996',
]

# Log and Dedup paths
LOG_FILE = f'{pwd}/logs/integrations.log'
DEDUP_DB = f'{pwd}/var/shuffle_dedup.db'
DEDUP_WINDOW_SECONDS = 300  # 5 phút (300 giây) theo docs/exception.md

# GeoIP Databases
GEOIP_COUNTRY_DB = f'{pwd}/etc/geoip/GeoLite2-Country.mmdb'
GEOIP_ASN_DB = f'{pwd}/etc/geoip/GeoLite2-ASN.mmdb'

# Asset Map
ASSET_MAP_FILE = f'{pwd}/etc/vnu_asset_map.json'
_ASSET_MAP_CACHE = None

# SOAR Feedback Stream Log
SOAR_FEEDBACK_LOG = '/var/log/vnu_soar_stream.log'

# Constants
ALERT_INDEX = 1
WEBHOOK_INDEX = 3

# Collector hostnames to avoid false positive asset matching on forwarded logs
COLLECTOR_NAMES = {"wazuh-master", "node01", "node02", "node03", "wazuh-grafana-ubuntu24", "ingest-01", "ingest-02"}
INGEST_AGENT_IDS = {"011", "012"}

# Protected Networks & IPs
PROTECTED_NETWORKS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('112.137.128.0/19'),
]
TRUSTED_IPS = {'8.8.8.8', '8.8.4.4', '1.1.1.1', '10.243.1.32', '10.243.1.33'}


def get_asset_map():
    global _ASSET_MAP_CACHE
    if _ASSET_MAP_CACHE is None:
        try:
            with open(ASSET_MAP_FILE, 'r', encoding='utf-8') as f:
                _ASSET_MAP_CACHE = json.load(f).get("assets", {})
        except Exception as e:
            debug(f"# Error loading asset map: {e}")
            _ASSET_MAP_CACHE = {}
    return _ASSET_MAP_CACHE


def is_protected_ip(ip_str: str) -> bool:
    if not ip_str:
        return True
    if ip_str in TRUSTED_IPS:
        return True
    try:
        ip = ipaddress.ip_address(ip_str)
        for net in PROTECTED_NETWORKS:
            if ip in net:
                return True
    except Exception:
        return False
    return False


def get_exposure(ip_str: str) -> str:
    if not ip_str:
        return "internal"
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private or ip.is_loopback:
            return "internal"
        if ip in ipaddress.ip_network('112.137.128.0/19'):
            return "internal"
    except Exception:
        return "internal"
    return "external"


def resolve_asset(alert: dict) -> dict:
    """
    Tra cứu thông tin tài sản từ /var/ossec/etc/vnu_asset_map.json.
    Quy tắc VNU SOC:
      - Dù là font hay back cứ liên quan đến service website thì đều xếp vào 'web'.
      - Còn lại thì xếp vào 'network'.
      - Không xác định được -> 'unmapped'.
    """
    asset_map = get_asset_map()
    agent_info = alert.get("agent", {})
    agent_id = str(agent_info.get("id") or "").strip()
    agent_name = str(agent_info.get("name") or "").strip()
    agent_ip = str(agent_info.get("ip") or "").strip()
    full_log = str(alert.get("full_log") or "")
    data = alert.get("data", {})

    # 0. Nếu alert là từ syslog hoặc chuyển tiếp qua Ingest (011, 012):
    # Trích xuất địa chỉ IP hoặc tên thiết bị thực tế từ đường dẫn location (/var/log/wazuh-syslog/sec/ hay net/)
    location = str(alert.get("location") or "")
    import re
    m_loc = re.search(r'/var/log/wazuh-syslog/(?:sec|net)/([^/]+?)(?:\.log)?$', location)
    if m_loc:
        target_dev = m_loc.group(1).strip()
        if target_dev in asset_map:
            info = asset_map[target_dev]
            return {
                "is_mapped": True,
                "asset_name": target_dev,
                "asset_type": info.get("type", "network"),
                "role": info.get("role", "")
            }
        return {
            "is_mapped": True,
            "asset_name": target_dev,
            "asset_type": "network",
            "role": f"Thiết bị mạng/Syslog {target_dev}"
        }

    # 1. Khớp agent_id (nếu không phải 000 và không phải cụm Ingest collector 011/012)
    if agent_id and agent_id != "000" and agent_id not in INGEST_AGENT_IDS and agent_id in asset_map:
        info = asset_map[agent_id]
        return {
            "is_mapped": True,
            "asset_name": agent_name or info.get("agent_name", agent_id),
            "asset_type": info.get("type", "network"),
            "role": info.get("role", "")
        }

    # 2. Khớp agent_name (nếu không phải collector wazuh 000)
    if agent_name and agent_name not in COLLECTOR_NAMES and agent_name in asset_map:
        info = asset_map[agent_name]
        return {
            "is_mapped": True,
            "asset_name": agent_name,
            "asset_type": info.get("type", "network"),
            "role": info.get("role", "")
        }

    # 3. Khớp agent_ip (nếu agent_id != "000")
    if agent_ip and agent_id != "000" and agent_ip in asset_map:
        info = asset_map[agent_ip]
        return {
            "is_mapped": True,
            "asset_name": agent_name or agent_ip,
            "asset_type": info.get("type", "network"),
            "role": info.get("role", "")
        }

    # 4. Khớp devname / hostname / host từ syslog / FortiGate
    target_host = str(data.get("devname") or data.get("hostname") or data.get("host") or "").strip()
    if target_host and target_host in asset_map:
        info = asset_map[target_host]
        return {
            "is_mapped": True,
            "asset_name": target_host,
            "asset_type": info.get("type", "network"),
            "role": info.get("role", "")
        }

    # 5. Khớp từ khóa trong full_log (vcenter, esxi, 10.243.1.33, FG300D, FG200F, FG_DV...)
    lower_log = full_log.lower()
    for key, info in asset_map.items():
        if len(key) >= 4 and key.lower() in lower_log and key not in COLLECTOR_NAMES:
            return {
                "is_mapped": True,
                "asset_name": key,
                "asset_type": info.get("type", "network"),
                "role": info.get("role", "")
            }

    # 6. Không khớp -> UNMAPPED
    unmapped_key = target_host or (agent_name if agent_name not in COLLECTOR_NAMES else "") or data.get("srcip") or "UNKNOWN"
    return {
        "is_mapped": False,
        "asset_name": f"UNMAPPED_{unmapped_key}",
        "asset_type": "unmapped",
        "role": "Unmapped Infrastructure"
    }


def pick_flow(asset_info: dict, src_ip: str) -> str:
    """
    chỉ khi asset đã map VÀ type=web VÀ srcip không thuộc PROTECTED_IPS thì flow=ENFORCEMENT,
    còn lại flow=INFRA.
    """
    if asset_info.get("is_mapped") and asset_info.get("asset_type") == "web" and not is_protected_ip(src_ip):
        return "ENFORCEMENT"
    return "INFRA"


def check_and_record_dedup(src_ip: str, rule_id: str, window_seconds: int = 300):
    """
    Khử trùng lặp cảnh báo (Deduplication Guardrail) theo cặp (src_ip, rule_id)
    trong cửa sổ trượt window_seconds (mặc định 5 phút).
    """
    if not src_ip or not rule_id:
        return False, 1

    conn = None
    try:
        now = time.time()
        conn = sqlite3.connect(DEDUP_DB, timeout=5)
        conn.execute("PRAGMA journal_mode=WAL;")
        with conn:
            conn.execute("""
            CREATE TABLE IF NOT EXISTS dedup_cache (
                key TEXT PRIMARY KEY,
                src_ip TEXT,
                rule_id TEXT,
                last_seen REAL,
                count INTEGER
            );
            """)
            conn.execute("DELETE FROM dedup_cache WHERE last_seen < ?", (now - 3600,))

            key = f"{src_ip}_{rule_id}"
            cursor = conn.cursor()
            cursor.execute("SELECT last_seen, count FROM dedup_cache WHERE key = ?", (key,))
            row = cursor.fetchone()

            if row:
                last_seen, count = row
                if (now - last_seen) < window_seconds:
                    conn.execute("UPDATE dedup_cache SET count = count + 1, last_seen = ? WHERE key = ?", (now, key))
                    return True, count + 1
                else:
                    conn.execute("UPDATE dedup_cache SET count = 1, last_seen = ? WHERE key = ?", (now, key))
                    return False, 1
            else:
                conn.execute(
                    "INSERT INTO dedup_cache (key, src_ip, rule_id, last_seen, count) VALUES (?, ?, ?, ?, 1)",
                    (key, src_ip, rule_id, now)
                )
                return False, 1
    except Exception as e:
        debug(f"# Dedup cache check exception: {e}")
        return False, 1
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


def lookup_geoip(ip_str: str):
    """Tra cứu quốc gia và ASN qua cơ sở dữ liệu GeoLite2 cục bộ."""
    country = "UNKNOWN"
    asn = ""
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private or ip.is_loopback:
            return "INTERNAL", "RFC1918 Private Network"
    except Exception:
        return "INVALID", "Invalid IP"

    if HAS_MAXMIND and os.path.exists(GEOIP_COUNTRY_DB):
        try:
            with maxminddb.open_database(GEOIP_COUNTRY_DB) as reader:
                res = reader.get(ip_str)
                if res and "country" in res and "iso_code" in res["country"]:
                    country = res["country"]["iso_code"]
        except Exception:
            pass

    if HAS_MAXMIND and os.path.exists(GEOIP_ASN_DB):
        try:
            with maxminddb.open_database(GEOIP_ASN_DB) as reader:
                res = reader.get(ip_str)
                if res:
                    asn_num = res.get("autonomous_system_number", "")
                    asn_org = res.get("autonomous_system_organization", "")
                    asn = f"AS{asn_num} {asn_org}".strip()
        except Exception:
            pass

    return country, asn


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
    "100916": ("CAT1_WEB_EXPLOIT", "SEO Cloaking / Malicious Redirect", "T1190", 80),
    "100915": ("CAT1_WEB_EXPLOIT", "Malicious Dynamic Endpoint Crawl", "T1595.002", 80),
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
    "999914": ("CAT1_WEB_EXPLOIT", "VNU AR Positive Test (Dry-run)", "T1505.003", 90),
    "999912": ("CAT1_WEB_EXPLOIT", "VNU AR Positive Test (Dry-run)", "T1505.003", 90),
    "100900": ("CAT1_WEB_EXPLOIT", "VNU SOAR E2E Test (WebShell)", "T1505.003", 90),
}


def emit_infra_stream_alert(alert, src_ip, rule_id, asset_info, count=1):
    """
    Ghi nhận bản tin Hạ tầng & vCenter (ALERT ONLY) vào /var/log/vnu_soar_stream.log
    Không bao giờ gọi FortiGate API, không trigger webhook Shuffle.
    """
    try:
        if rule_id in ("100995", "100996"):
            return

        agent_info = alert.get("agent", {})
        agent_name = str(agent_info.get("name") or "N/A")
        rule_desc = str(alert.get("rule", {}).get("description") or "Infrastructure Event")
        level = int(alert.get("rule", {}).get("level") or 10)
        country, asn = lookup_geoip(src_ip) if src_ip else ("UNKNOWN", "")
        exposure = get_exposure(src_ip)

        severity = "CRITICAL" if level >= 12 else ("HIGH" if level >= 10 else ("MEDIUM" if level >= 6 else "LOW"))

        event = {
            "soar_event": "INFRA_OPERATIONAL_ALERT",
            "soar_decision": "ALERT_ONLY",
            "asset_name": asset_info.get("asset_name"),
            "asset_type": asset_info.get("asset_type"),
            "exposure": exposure,
            "srcip": src_ip or "N/A",
            "country": country,
            "asn": asn,
            "rule_id": rule_id,
            "attack_action": rule_desc[:60],
            "threat_category": "CAT6_NETWORK_VCENTER_INFRA",
            "severity": severity,
            "rule_level": level,
            "count": count,
            "collector": agent_name,
            "target_service": asset_info.get("role") or asset_info.get("asset_name")
        }

        with open(SOAR_FEEDBACK_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
        debug(f"# [INFRA STREAM] Logged INFRA_OPERATIONAL_ALERT for {asset_info.get('asset_name')} -> ALERT_ONLY")
    except Exception as e:
        debug(f"# [INFRA STREAM ERROR] {e}")


TEST_RULE_IDS = ("999914", "999912", "100900")
ENFORCEMENT_GATEWAY_URL = "http://10.0.0.20:3001/api/v1/hooks/webhook_soc_enforcement"


def call_enforcement_gateway(alert, src_ip, rule_id):
    """
    Gọi VNU SOC Enforcement Gateway và TRẢ VỀ KẾT QUẢ THẬT.
    Không tự suy diễn: nếu gateway lỗi/timeout thì ghi nhận GATEWAY_ERROR.
    Payload giữ nguyên chính sách cũ (category/score) để không thay đổi hành vi chặn.
    """
    rule_desc = alert.get('rule', {}).get('description', 'Wazuh Alert')
    cat = "CAT1_WEB_EXPLOIT" if rule_id in ("100920", "100922", "100924", "100933", "100934", "31103", "31104", "31105", "31106") else "CAT2_RECON_DOS"
    score = 90 if cat == "CAT1_WEB_EXPLOIT" else 80
    payload = {
        "ip": src_ip,
        "threat_category": cat,
        "risk_score": score,
        "reason": f"Wazuh Rule {rule_id}: {rule_desc}",
        "source": "SOAR_INTEGRATION"
    }
    try:
        res = requests.post(ENFORCEMENT_GATEWAY_URL, json=payload, timeout=3)
        http_code = res.status_code
        try:
            body = res.json()
        except Exception:
            body = {}
        result = body.get("result") or {}
        if 200 <= http_code < 300 and result.get("decision"):
            return {
                "decision": str(result.get("decision")),
                "action": str(result.get("action") or ""),
                "enforced": bool(result.get("enforced", False)),
                "gateway_http": http_code,
                "detail": str(result.get("reason") or "")[:200],
            }
        return {
            "decision": "GATEWAY_REJECTED",
            "action": "",
            "enforced": False,
            "gateway_http": http_code,
            "detail": str(body.get("error") or res.text)[:200],
        }
    except Exception as e:
        debug(f"# Enforcement Gateway exception: {e}")
        return {
            "decision": "GATEWAY_ERROR",
            "action": "",
            "enforced": False,
            "gateway_http": 0,
            "detail": str(e)[:200],
        }


def emit_soar_stream_feedback(alert, src_ip, rule_id, asset_info, gw_result, count=1):
    """
    Ghi nhận bản tin SOAR Feedback Loop vào /var/log/vnu_soar_stream.log
    Dành riêng cho luồng LIVE_INCIDENT_ENFORCEMENT (chỉ asset_type=web).
    CHỈ được gọi SAU khi đã có kết quả thật từ Enforcement Gateway (gw_result).
    Không còn gán cứng BLOCKED / CONTAINED / PERMANENT_BLOCK_APPROVED.
    """
    try:
        if not src_ip or rule_id in ("100995", "100996"):
            return

        agent_info = alert.get("agent", {})
        agent_name = str(agent_info.get("name") or "")
        data = alert.get("data", {})
        rule_desc = str(alert.get("rule", {}).get("description") or "")
        level = int(alert.get("rule", {}).get("level") or 0)

        country, asn = lookup_geoip(src_ip)
        exposure = get_exposure(src_ip)

        # Chỉ lấy URL thật; không fallback sang tên agent
        target_url = data.get("url") or ""
        if not target_url:
            full_log = str(alert.get("full_log") or "")
            import re
            m = re.search(r"(https?://[^\s]+|/(?:wp-[a-z0-9_/]+|api/[a-z0-9_/]+|[a-z0-9_/-]+\.(?:php|asp|aspx|jsp))[^\s]*)", full_log)
            target_url = m.group(1) if m else ""

        if rule_id in TAXONOMY_MAP:
            threat_cat, attack_action, mitre_id, _ = TAXONOMY_MAP[rule_id]
        else:
            threat_cat = ""
            attack_action = rule_desc[:80]
            mitre_id = ""

        severity = "CRITICAL" if level >= 12 else ("HIGH" if level >= 10 else ("MEDIUM" if level >= 6 else "LOW"))

        event = {
            "soar_event": "LIVE_INCIDENT_ENFORCEMENT",
            "asset_name": asset_info.get("asset_name") or agent_name,
            "asset_type": asset_info.get("asset_type", "web"),
            "exposure": exposure,
            "srcip": src_ip,
            "country": country,
            "asn": asn,
            "agent_name": agent_name,
            "url": target_url,
            "rule_id": rule_id,
            "rule_level": level,
            "attack_action": attack_action,
            "threat_category": threat_cat,
            "mitre_id": mitre_id,
            "severity": severity,
            # Kết quả THẬT từ Enforcement Gateway
            "soar_decision": gw_result.get("decision", ""),
            "soar_action": gw_result.get("action", ""),
            "soar_enforced": "true" if gw_result.get("enforced") else "false",
            "gateway_http": gw_result.get("gateway_http", 0),
            "gateway_detail": gw_result.get("detail", ""),
            "dstuser": data.get("dstuser") or "",
            "srcuser": data.get("srcuser") or "",
            "is_test": "true" if rule_id in TEST_RULE_IDS else "false",
            "count": count,
            "collector": agent_name
        }

        with open(SOAR_FEEDBACK_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
        debug(f"# [SOAR FEEDBACK LOOP] {src_ip} -> {event['soar_decision']} (enforced={event['soar_enforced']})")
    except Exception as e:
        debug(f"# [SOAR FEEDBACK LOOP ERROR] {e}")


def main(args):
    global debug_enabled
    try:
        # Read arguments
        bad_arguments: bool = False
        if len(args) >= 4:
            msg = '{0} {1} {2} {3} {4}'.format(
                args[1], args[2], args[3], args[4] if len(sys.argv) > 4 else '', args[5] if len(sys.argv) > 5 else ''
            )
            debug_enabled = len(args) > 4 and args[4] == 'debug'
        else:
            msg = '# ERROR: Wrong arguments'
            bad_arguments = True

        # Logging the call
        with open(LOG_FILE, 'a') as f:
            f.write(msg + '\n')

        if bad_arguments:
            debug('# ERROR: Exiting, bad arguments. Inputted: %s' % args)
            sys.exit(ERR_BAD_ARGUMENTS)

        # Core function
        process_args(args)

    except Exception as e:
        debug(str(e))
        raise


def process_args(args) -> None:
    debug('# Running Shuffle script')

    # Read args
    alert_file_location: str = args[ALERT_INDEX]
    webhook: str = args[WEBHOOK_INDEX]
    options_file_location: str = ''
    json_options: str = ''

    # Look for options file location
    for idx in range(4, len(args)):
        if args[idx][-7:] == 'options':
            options_file_location = args[idx]
            break

    # Load options. Parse JSON object.
    json_options = get_json_options(options_file_location)
    debug(f"# Opening options file at '{options_file_location}' with '{json_options}'")

    # Load alert. Parse JSON object.
    json_alert = get_json_alert(alert_file_location)
    debug(f"# Opening alert file at '{alert_file_location}' with '{json_alert}'")

    # Extract IP and Rule for Deduplication Guardrail
    rule_id = str(json_alert.get('rule', {}).get('id', ''))
    src_ip = (
        json_alert.get('data', {}).get('srcip')
        or json_alert.get('data', {}).get('src_ip')
        or json_alert.get('data', {}).get('win', {}).get('eventdata', {}).get('ipAddress')
        or ''
    ).strip()

    # Phân loại đối tượng và luồng xử lý
    asset_info = resolve_asset(json_alert)
    flow = pick_flow(asset_info, src_ip)
    exposure = get_exposure(src_ip)

    debug(f"# [ROUTING] Asset: {asset_info['asset_name']} ({asset_info['asset_type']}) | IP: {src_ip} ({exposure}) -> Flow: {flow}")

    # Khử trùng lặp trước khi vào Shuffle (docs/exception.md Mục 3)
    is_test_marker = rule_id in ('999914', '999912')
    dedup_count = 1
    if src_ip and rule_id and not is_test_marker:
        is_dup, dedup_count = check_and_record_dedup(src_ip, rule_id, window_seconds=DEDUP_WINDOW_SECONDS)
        if is_dup:
            throttle_log = f"# [DEDUP THROTTLED] IP: {src_ip} | Rule: {rule_id} bị bóp băng thông ({dedup_count} lần trong {DEDUP_WINDOW_SECONDS}s)."
            debug(throttle_log)
            return

    # NẾU FLOW LÀ INFRA: Ghi stream với soar_event=INFRA_OPERATIONAL_ALERT, soar_decision=ALERT_ONLY
    # RỒI RETURN SỚM, không bao giờ gọi workflow Shuffle / FortiGate API
    if flow == "INFRA":
        emit_infra_stream_alert(json_alert, src_ip, rule_id, asset_info, count=dedup_count)
        debug(f"# [INFRA FLOW COMPLETE] {asset_info['asset_name']} emitted to stream -> returning early.")
        return

    # NẾU FLOW LÀ ENFORCEMENT: Chỉ dành cho asset_type=web và srcip external không thuộc protected
    # Gửi tin nhắn qua Shuffle server (nếu cấu hình webhook hợp lệ)
    debug('# Generating message for Enforcement flow')
    msg: str = generate_msg(json_alert, json_options)
    if isinstance(msg, str) and msg and webhook:
        debug(f'# Sending message to Shuffle server: {webhook}')
        send_msg(msg, webhook)

    # Gọi VNU SOC Enforcement Gateway (Port 8088) TRƯỚC, rồi mới ghi Feedback Loop
    # với kết quả thật (decision/enforced) cho Wazuh SIEM & Grafana Panel 208.
    if src_ip:
        gw_result = call_enforcement_gateway(json_alert, src_ip, rule_id)
        emit_soar_stream_feedback(json_alert, src_ip, rule_id, asset_info, gw_result, count=dedup_count)


def debug(msg: str) -> None:
    if debug_enabled:
        print(msg)
        with open(LOG_FILE, 'a') as f:
            f.write(msg + '\n')


# Skips container kills to stop self-recursion
def filter_msg(alert) -> bool:
    return alert['rule']['id'] not in SKIP_RULE_IDS


def generate_msg(alert: any, options: any) -> str:
    if not filter_msg(alert):
        print('Skipping rule %s' % alert['rule']['id'])
        return ''

    level = alert['rule']['level']

    if level <= 4:
        severity = 1
    elif level >= 5 and level <= 7:
        severity = 2
    else:
        severity = 3

    # Extract source IP & GeoLocation
    src_ip = (
        alert.get('data', {}).get('srcip')
        or alert.get('data', {}).get('src_ip')
        or alert.get('data', {}).get('win', {}).get('eventdata', {}).get('ipAddress')
        or ''
    ).strip()

    country, asn = lookup_geoip(src_ip) if src_ip else ("UNKNOWN", "")
    is_vietnam = (country == "VN")

    target = alert.get('data', {}).get('extra_data') or alert.get('data', {}).get('target') or ''

    msg = {
        'severity': severity,
        'pretext': 'WAZUH Alert',
        'title': alert['rule']['description'] if 'description' in alert['rule'] else 'N/A',
        'text': alert.get('full_log'),
        'rule_id': alert['rule']['id'],
        'timestamp': alert['timestamp'],
        'id': alert['id'],
        'src_ip': src_ip,
        'geo_country': country,
        'geo_asn': asn,
        'is_vietnam': is_vietnam,
        'ar_mode': 'ALERT_ONLY' if is_vietnam else 'THREAT_FEED',
        'action_allowed': True,
        'fortigate_block_paused': False,
        'ingest_source': 'STANDARD_AGENT',
        'fgt_write_enabled': False,
        'fgt_object_test_enabled': False,
        'fgt_group_write_enabled': False,
        'fgt_policy_write_enabled': False,
        'fgt_prod_block_enabled': False,
        'enforcement_type': 'EXTERNAL_THREAT_FEED',
        'threat_feed_url': 'http://10.0.0.20:3001/api/v1/hooks/webhook_soc_enforcement',
        'threat_feed_enforce_api': 'http://10.0.0.20:3001/api/v1/hooks/webhook_soc_enforcement',
        'ar_target': str(target).strip().upper(),
        'all_fields': alert,
    }

    if options:
        msg.update(options)

    return json.dumps(msg)


def send_msg(msg: str, url: str) -> None:
    try:
        headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}
        res = requests.post(url, data=msg, headers=headers, timeout=5)
        debug('# Response received from Shuffle: %s' % res.status_code)
    except Exception as e:
        debug('# Warning: Failed sending message to Shuffle webhook: %s' % e)


def get_json_alert(file_location: str) -> any:
    try:
        with open(file_location) as alert_file:
            return json.load(alert_file)
    except FileNotFoundError:
        debug("# JSON file for alert %s doesn't exist" % file_location)
        sys.exit(ERR_FILE_NOT_FOUND)
    except json.decoder.JSONDecodeError as e:
        debug('Failed getting JSON alert. Error: %s' % e)
        sys.exit(ERR_INVALID_JSON)


def get_json_options(file_location: str) -> any:
    try:
        with open(file_location) as options_file:
            return json.load(options_file)
    except FileNotFoundError:
        debug("# JSON file for options %s doesn't exist" % file_location)
    except BaseException as e:
        debug('Failed getting JSON options. Error: %s' % e)
        sys.exit(ERR_INVALID_JSON)


if __name__ == '__main__':
    main(sys.argv)
