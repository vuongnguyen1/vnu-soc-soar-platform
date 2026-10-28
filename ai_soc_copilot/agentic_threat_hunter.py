#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==============================================================================
VNU SOC: NATIVE AGENTIC AI THREAT HUNTING & TIMELINE CORRELATION ENGINE
Based on Wazuh Agentic AI Architecture (wazuh.com/blog/threat-hunting-with-agentic-ai)
==============================================================================
Provides token-optimized, autonomous threat hunting with 4 core operational modes:
  1. rce-hunt         : Săn tìm Remote Code Execution & WebShell trên toàn bộ máy chủ (48h qua).
  2. exfil-hunt       : Săn tìm dấu hiệu rò rỉ dữ liệu (Data Exfiltration) ra ngoài (7 ngày qua).
  3. agent-triage     : Phân loại, sàng lọc và bóc tách bất thường trên 1 Agent cụ thể (N ngày).
  4. correlate-timeline: Xây dựng dòng thời gian tương quan (+/- 30 phút trước & sau) cho cảnh báo Level >= 12,
                        kết nối thông minh giữa Cảm biến mạng (Security Onion SPAN) và Máy chủ mục tiêu.

Outputs are strictly grounded in OpenSearch/Wazuh telemetry, token-optimized (~85% token savings),
and persisted into /var/ossec/soc_daily_reports/investigations.json.
==============================================================================
"""

import sys
import os
import re
import json
import time
import argparse
import requests
import urllib3
from datetime import datetime, timezone, timedelta

urllib3.disable_warnings()

OPENSEARCH_URL = os.getenv("OPENSEARCH_URL", "https://10.241.1.30:9200")
OPENSEARCH_USER = os.getenv("OPENSEARCH_USER", "admin")
OPENSEARCH_PASS = os.getenv("OPENSEARCH_PASS", "x?lx*47YGyNehMt+TWRDX6hsR7X7qDvC")

INVESTIGATIONS_FILE = "/var/ossec/soc_daily_reports/investigations.json"
LOCAL_TZ = timezone(timedelta(hours=7))

# Mapping from destination IP to actual VNU infrastructure agent
INFRASTRUCTURE_IP_MAP = {
    "112.137.142.44": {"id": "005", "name": "daotao_112.137.142.44", "os": "Windows", "role": "DAOTAOWEB"},
    "10.241.2.15": {"id": "015", "name": "Web_TuyensinhSDH_NEW_10.241.2.15", "os": "Windows", "role": "TSSDH"},
    "10.241.2.70": {"id": "014", "name": "cybersafe_10.241.2.70", "os": "Linux", "role": "it-cyber"},
    "112.137.142.6": {"id": "003", "name": "idp_web_112.137.142.6", "os": "Linux", "role": "idp-web"},
    "112.137.142.20": {"id": "004", "name": "eoffice_web_112.137.142.20", "os": "Linux", "role": "eoffice-web"},
    "112.137.142.21": {"id": "002", "name": "eoffice_db_112.137.142.21", "os": "Linux", "role": "eoffice-db"},
    "112.137.140.13": {"id": "001", "name": "CEA_NEW_112.137.140.13", "os": "Linux", "role": "CEA"},
    "112.137.143.34": {"id": "010", "name": "100years_112.137.143.34", "os": "Windows", "role": "100years"},
    "10.241.2.19": {"id": "013", "name": "khaosat_ulis_10.241.2.19", "os": "Windows", "role": "khaosat-ulis"},
    "112.137.132.118": {"id": "028", "name": "mta.vnu.vn", "os": "Linux", "role": "MTA-Stalwart"},
    "112.137.133.14": {"id": "009", "name": "aapanel-web-01", "os": "Linux", "role": "aaPanel"},
    "10.241.1.15": {"id": "021", "name": "prod-idp-lb-01", "os": "Linux", "role": "IDP-LB-01"},
    "10.241.1.16": {"id": "019", "name": "prod-idp-lb-02", "os": "Linux", "role": "IDP-LB-02"},
    "10.241.1.17": {"id": "020", "name": "prod-idp-web-01", "os": "Linux", "role": "IDP-WEB-01"},
    "10.241.1.18": {"id": "018", "name": "prod-idp-web-02", "os": "Linux", "role": "IDP-WEB-02"},
    "10.241.1.19": {"id": "022", "name": "prod-idp-db-01", "os": "Linux", "role": "IDP-DB-01"},
    "10.241.1.21": {"id": "017", "name": "prod-idp-db-02", "os": "Linux", "role": "IDP-DB-02"},
    "10.241.1.23": {"id": "016", "name": "dev-idp-dev-01", "os": "Linux", "role": "IDP-DEV"}
}

def opensearch_search(query_body, index="wazuh-alerts-*"):
    url = f"{OPENSEARCH_URL}/{index}/_search"
    resp = requests.post(
        url,
        json=query_body,
        auth=(OPENSEARCH_USER, OPENSEARCH_PASS),
        verify=False,
        timeout=25
    )
    if resp.status_code == 200:
        return resp.json()
    else:
        raise RuntimeError(f"OpenSearch error {resp.status_code}: {resp.text[:300]}")

def save_investigation_record(use_case, prompt, summary, timeline, observables):
    os.makedirs(os.path.dirname(INVESTIGATIONS_FILE), exist_ok=True)
    records = []
    if os.path.exists(INVESTIGATIONS_FILE):
        try:
            with open(INVESTIGATIONS_FILE, "r", encoding="utf-8") as f:
                records = json.load(f)
        except Exception:
            records = []

    inv_id = f"INV-{int(time.time())}-{use_case}"
    entry = {
        "investigation_id": inv_id,
        "timestamp": datetime.now(LOCAL_TZ).isoformat(),
        "use_case": use_case,
        "prompt": prompt,
        "summary": summary,
        "observables_count": len(observables),
        "observables": observables,
        "timeline_events_count": len(timeline),
        "timeline": timeline[:50]  # Cap for token conservation
    }
    records.insert(0, entry)
    # Retain last 50 investigations (monthly persistent storage)
    records = records[:50]

    with open(INVESTIGATIONS_FILE, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2, ensure_ascii=False)
    return inv_id

def clean_event_for_token_efficiency(hit):
    """
    Strips raw headers, retains only essential forensic attributes.
    Accurately maps passive network sensors (Security Onion / Ingest) to target hosts.
    Saves ~85% prompt tokens compared to raw Wazuh JSON.
    """
    src = hit.get("_source", {})
    rule = src.get("rule", {})
    agent = src.get("agent", {})
    data = src.get("data", {})
    win = data.get("win", {})
    eventdata = win.get("eventdata", {}) or data.get("eventdata", {})

    image = eventdata.get("image") or eventdata.get("Image") or ""
    parent = eventdata.get("parentImage") or eventdata.get("ParentImage") or ""
    cmd = eventdata.get("commandLine") or eventdata.get("CommandLine") or ""
    pid = eventdata.get("processId") or eventdata.get("ProcessId") or ""
    srcip = data.get("srcip") or data.get("src_ip") or eventdata.get("sourceIp") or ""
    dstip = data.get("dstip") or data.get("dest_ip") or eventdata.get("destinationIp") or ""
    dstport = data.get("dstport") or data.get("dest_port") or eventdata.get("destinationPort") or ""

    # Exploit and URL extraction
    raw_payload = data.get("payload_printable", "") or src.get("full_log", "")
    cve_match = re.search(r'CVE-\d{4}-\d{4,7}', f"{rule.get('description', '')} {raw_payload}", re.IGNORECASE)
    cve = cve_match.group(0).upper() if cve_match else ""

    http_data = data.get("http", {}) if isinstance(data.get("http"), dict) else {}
    url = http_data.get("url") or data.get("url") or ""
    if not url and raw_payload:
        u_match = re.search(r'^(GET|POST|PUT|DELETE)\s+([^\s]+)', raw_payload, re.MULTILINE)
        if u_match:
            url = f"{u_match.group(1)} {u_match.group(2)}"

    ag_name = agent.get("name", "unknown")
    ag_id = agent.get("id", "")
    is_passive = ("SecurityOnion" in ag_name or "ingest" in ag_name or ag_id == "027")

    # Smart Target Resolution
    target_name = ag_name
    target_id = ag_id
    if is_passive and dstip:
        clean_dstip = dstip.split(":")[0].strip()
        if clean_dstip in INFRASTRUCTURE_IP_MAP:
            mapping = INFRASTRUCTURE_IP_MAP[clean_dstip]
            target_name = mapping["name"]
            target_id = mapping["id"]
        else:
            target_name = f"External/Service ({dstip})"

    return {
        "timestamp": src.get("timestamp") or src.get("predecoder", {}).get("timestamp", ""),
        "sensor": ag_name,
        "is_passive_sensor": is_passive,
        "real_target_host": target_name,
        "real_target_id": target_id,
        "agent_id": ag_id,
        "rule_id": rule.get("id", ""),
        "level": rule.get("level", 0),
        "cve": cve,
        "affected_url": url[:100] if url else "",
        "desc": rule.get("description", "")[:120],
        "image": os.path.basename(image) if image else "",
        "parent": os.path.basename(parent) if parent else "",
        "cmdline": cmd[:150] if cmd else "",
        "pid": pid,
        "src_ip": srcip,
        "dst_ip": f"{dstip}:{dstport}" if dstip and dstport else dstip,
        "mitre": rule.get("mitre", {}).get("id", [])
    }

# ------------------------------------------------------------------------------
# USE CASE 1: REMOTE CODE EXECUTION (RCE) & WEBSHELL HUNTING (LAST 48H)
# ------------------------------------------------------------------------------
def hunt_rce(hours=48):
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=hours)

    query = {
        "size": 100,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "must": [
                    {"range": {"timestamp": {"gte": start.isoformat(), "lte": now.isoformat()}}},
                    {
                        "bool": {
                            "should": [
                                {"terms": {"rule.id": ["100013", "100975", "100968", "100969", "100931", "100933", "100924"]}},
                                {"wildcard": {"rule.description": "*WebShell*"}},
                                {"wildcard": {"rule.description": "*Remote Code Execution*"}},
                                {"wildcard": {"rule.description": "*Command Injection*"}},
                                {
                                    "bool": {
                                        "must": [
                                            {"wildcard": {"data.win.eventdata.parentImage": "*w3wp.exe"}},
                                            {"wildcard": {"data.win.eventdata.image": "*powershell.exe"}}
                                        ]
                                    }
                                },
                                {
                                    "bool": {
                                        "must": [
                                            {"wildcard": {"data.win.eventdata.parentImage": "*w3wp.exe"}},
                                            {"wildcard": {"data.win.eventdata.image": "*cmd.exe"}}
                                        ]
                                    }
                                }
                            ],
                            "minimum_should_match": 1
                        }
                    }
                ]
            }
        }
    }

    raw = opensearch_search(query)
    hits = raw.get("hits", {}).get("hits", [])
    timeline = [clean_event_for_token_efficiency(h) for h in hits]

    observables = list(set([e["src_ip"] for e in timeline if e["src_ip"]] + [e["dst_ip"].split(":")[0] for e in timeline if e["dst_ip"]]))
    summary = f"RCE & WebShell Hunt across all endpoints in last {hours}h: {len(hits)} suspicious events detected across {len(set(e['real_target_host'] for e in timeline))} target hosts."
    inv_id = save_investigation_record("rce_hunt", f"Hunt for RCE in last {hours}h", summary, timeline, observables)

    return {
        "investigation_id": inv_id,
        "summary": summary,
        "total_events": len(hits),
        "targets_affected": list(set(e['real_target_host'] for e in timeline)),
        "observables": observables,
        "events": timeline[:25]
    }

# ------------------------------------------------------------------------------
# USE CASE 2: DATA EXFILTRATION HUNTING (LAST 7 DAYS)
# ------------------------------------------------------------------------------
def hunt_data_exfiltration(days=7):
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=days)

    query = {
        "size": 100,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "must": [
                    {"range": {"timestamp": {"gte": start.isoformat(), "lte": now.isoformat()}}},
                    {
                        "bool": {
                            "should": [
                                {"terms": {"rule.id": ["100010", "100969"]}},
                                {"wildcard": {"rule.description": "*Exfiltration*"}},
                                {"wildcard": {"rule.description": "*Tunneling*"}},
                                {"wildcard": {"rule.description": "*Reverse Proxy*"}},
                                {"wildcard": {"rule.description": "*C2 Beaconing*"}},
                                {"terms": {"rule.mitre.id": ["T1048", "T1041", "T1567", "T1572"]}}
                            ],
                            "minimum_should_match": 1
                        }
                    }
                ]
            }
        }
    }

    raw = opensearch_search(query)
    hits = raw.get("hits", {}).get("hits", [])
    timeline = [clean_event_for_token_efficiency(h) for h in hits]

    observables = list(set([e["dst_ip"].split(":")[0] for e in timeline if e["dst_ip"]]))
    summary = f"Data Exfiltration & C2 Tunneling Hunt (last {days}d): {len(hits)} outbound indicators found."
    inv_id = save_investigation_record("exfil_hunt", f"Hunt for data exfiltration in last {days}d", summary, timeline, observables)

    return {
        "investigation_id": inv_id,
        "summary": summary,
        "total_events": len(hits),
        "suspected_c2_destinations": observables,
        "events": timeline[:25]
    }

# ------------------------------------------------------------------------------
# USE CASE 3: ENDPOINT ALERT TRIAGE FOR SPECIFIC AGENT (N DAYS)
# ------------------------------------------------------------------------------
def triage_agent(agent_target, days=7):
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=days)

    agent_clause = {"term": {"agent.id": agent_target}} if agent_target.isdigit() else {"wildcard": {"agent.name": f"*{agent_target}*"}}

    query = {
        "size": 150,
        "sort": [{"rule.level": {"order": "desc"}}, {"timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "must": [
                    {"range": {"timestamp": {"gte": start.isoformat(), "lte": now.isoformat()}}},
                    agent_clause,
                    {"range": {"rule.level": {"gte": 7}}}
                ]
            }
        }
    }

    raw = opensearch_search(query)
    hits = raw.get("hits", {}).get("hits", [])
    timeline = [clean_event_for_token_efficiency(h) for h in hits]

    # Group by severity & tactic
    crit_count = sum(1 for e in timeline if e["level"] >= 12)
    high_count = sum(1 for e in timeline if 8 <= e["level"] <= 11)

    observables = list(set([e["src_ip"] for e in timeline if e["src_ip"]] + [e["dst_ip"].split(":")[0] for e in timeline if e["dst_ip"]]))
    summary = f"Triage for Agent '{agent_target}' (last {days}d): {len(hits)} alerts (Critical: {crit_count}, High: {high_count})."
    inv_id = save_investigation_record("agent_triage", f"Triage alerts on agent {agent_target}", summary, timeline, observables)

    return {
        "investigation_id": inv_id,
        "agent": agent_target,
        "summary": summary,
        "critical_count": crit_count,
        "high_count": high_count,
        "observables": observables,
        "top_events": timeline[:30]
    }

# ------------------------------------------------------------------------------
# USE CASE 4: CROSS-LAYER TEMPORAL TIMELINE CORRELATION (+/- 30 MINUTES)
# ------------------------------------------------------------------------------
def correlate_high_severity_timeline(hours=24, window_minutes=30):
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=hours)

    # 1. Pull anchor Level >= 12 alerts
    anchor_query = {
        "size": 15,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "must": [
                    {"range": {"timestamp": {"gte": start.isoformat(), "lte": now.isoformat()}}},
                    {"range": {"rule.level": {"gte": 12}}}
                ]
            }
        }
    }

    anchor_raw = opensearch_search(anchor_query)
    anchors = anchor_raw.get("hits", {}).get("hits", [])

    if not anchors:
        return {
            "summary": f"No high severity (Level >= 12) alerts found in the last {hours} hours.",
            "correlations": []
        }

    correlations = []
    all_observables = set()

    for anchor in anchors:
        clean_anchor = clean_event_for_token_efficiency(anchor)
        anchor_time_str = anchor["_source"].get("timestamp")
        sensor_agent_id = clean_anchor.get("agent_id")
        target_agent_id = clean_anchor.get("real_target_id")
        attacker_ip = clean_anchor.get("src_ip")

        if not anchor_time_str:
            continue

        try:
            t_anchor = datetime.fromisoformat(anchor_time_str.replace("Z", "+00:00"))
        except Exception:
            continue

        window_start = (t_anchor - timedelta(minutes=window_minutes)).isoformat()
        window_end = (t_anchor + timedelta(minutes=window_minutes)).isoformat()

        # Build cross-layer query: Check BOTH Sensor AND Real Target Host!
        agent_terms = [sensor_agent_id]
        if target_agent_id and target_agent_id not in agent_terms and target_agent_id != "027":
            agent_terms.append(target_agent_id)

        should_clauses = [
            {"terms": {"agent.id": agent_terms}}
        ]
        if attacker_ip:
            should_clauses.append({"term": {"data.srcip": attacker_ip}})
            should_clauses.append({"term": {"data.win.eventdata.ipAddress": attacker_ip}})

        surround_query = {
            "size": 50,
            "sort": [{"timestamp": {"order": "asc"}}],
            "query": {
                "bool": {
                    "must": [
                        {"range": {"timestamp": {"gte": window_start, "lte": window_end}}},
                        {"bool": {"should": should_clauses, "minimum_should_match": 1}}
                    ]
                }
            }
        }

        surround_raw = opensearch_search(surround_query)
        surround_hits = surround_raw.get("hits", {}).get("hits", [])
        surround_timeline = [clean_event_for_token_efficiency(sh) for sh in surround_hits]

        obs = list(set([e["src_ip"] for e in surround_timeline if e["src_ip"]] + [e["dst_ip"].split(":")[0] for e in surround_timeline if e["dst_ip"]]))
        all_observables.update(obs)

        # Detect Kill Chain progression across sensor and host
        kill_chain_steps = []
        has_network_exploit = any(e["is_passive_sensor"] and e["level"] >= 10 for e in surround_timeline)
        has_host_exec = any(not e["is_passive_sensor"] and (e["cmdline"] or e["pid"]) for e in surround_timeline)
        has_fim_tamper = any("syscheck" in str(e) or e["rule_id"] in ["550", "554", "100931"] for e in surround_timeline)

        if has_network_exploit:
            kill_chain_steps.append("1_Initial_Access_Network_Probe")
        if has_host_exec:
            kill_chain_steps.append("2_Execution_Host_Process")
        if has_fim_tamper:
            kill_chain_steps.append("3_Persistence_File_Modification")

        correlations.append({
            "anchor_alert": clean_anchor,
            "temporal_window": f"+/- {window_minutes} minutes ({window_start} to {window_end})",
            "kill_chain_progress": " -> ".join(kill_chain_steps) if kill_chain_steps else "Single_Alert_Stage",
            "correlated_hosts": list(set([clean_anchor["sensor"], clean_anchor["real_target_host"]])),
            "surrounding_events_count": len(surround_hits),
            "investigation_timeline": surround_timeline[:25]
        })

    summary = f"Cross-Layer Correlation (+/- {window_minutes}m) for {len(anchors)} critical alerts in last {hours}h across Sensor & Host endpoints."
    inv_id = save_investigation_record("timeline_correlation", f"Correlate severity 12 alerts in last {hours}h", summary, correlations, list(all_observables))

    return {
        "investigation_id": inv_id,
        "summary": summary,
        "correlations_count": len(correlations),
        "correlations": correlations
    }

# ------------------------------------------------------------------------------
# USE CASE 5: 24-HOUR ATTACKER IP CAMPAIGN & BEHAVIOR CHAINING (DYNAMIC RANGE)
# ------------------------------------------------------------------------------
def hunt_ip_campaign_chain(hours=24, specific_ip=None, min_events=5, max_ips=10):
    """
    Tracks attacker behavior across 24h by Source IP Entity.
    Overcomes fixed 30-min window limitations by identifying the FULL attack duration
    (from First Seen to Last Seen), affected agents, probed URLs, and Kill Chain progression.
    """
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=hours)

    target_ips = []
    if specific_ip:
        target_ips = [specific_ip.strip()]
    else:
        # Aggregate top attacking IPs with Level >= 7 alerts in the specified period
        agg_query = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"timestamp": {"gte": start.isoformat(), "lte": now.isoformat()}}},
                        {"range": {"rule.level": {"gte": 7}}}
                    ]
                }
            },
            "aggs": {
                "top_ips": {
                    "terms": {
                        "field": "data.srcip",
                        "size": max_ips,
                        "min_doc_count": min_events
                    }
                }
            }
        }
        try:
            agg_res = opensearch_search(agg_query)
            buckets = agg_res.get("aggregations", {}).get("top_ips", {}).get("buckets", [])
            target_ips = [b["key"] for b in buckets if b["key"] not in ["127.0.0.1", "localhost", ""]]
        except Exception as e:
            target_ips = []

    if not target_ips:
        return {
            "summary": f"No persistent attacker campaigns detected with >= {min_events} events in the last {hours}h.",
            "campaigns": []
        }

    campaigns = []
    all_observables = set(target_ips)

    for attacker_ip in target_ips:
        # Query all events from this IP in the full 24h range
        ip_query = {
            "size": 150,
            "sort": [{"timestamp": {"order": "asc"}}],
            "query": {
                "bool": {
                    "must": [
                        {"range": {"timestamp": {"gte": start.isoformat(), "lte": now.isoformat()}}},
                        {
                            "bool": {
                                "should": [
                                    {"term": {"data.srcip": attacker_ip}},
                                    {"term": {"data.win.eventdata.ipAddress": attacker_ip}},
                                    {"term": {"data.src_ip": attacker_ip}}
                                ],
                                "minimum_should_match": 1
                            }
                        }
                    ]
                }
            }
        }

        raw_events = opensearch_search(ip_query)
        total_hits = raw_events.get("hits", {}).get("total", {}).get("value", 0)
        hits = raw_events.get("hits", {}).get("hits", [])
        if not hits:
            continue

        cleaned_events = [clean_event_for_token_efficiency(h) for h in hits]

        first_ts_str = cleaned_events[0]["timestamp"]
        last_ts_str = cleaned_events[-1]["timestamp"]

        # Calculate exact duration
        duration_desc = "Unknown"
        try:
            t1 = datetime.fromisoformat(first_ts_str.replace("Z", "+00:00"))
            t2 = datetime.fromisoformat(last_ts_str.replace("Z", "+00:00"))
            delta = t2 - t1
            hrs = delta.total_seconds() // 3600
            mins = (delta.total_seconds() % 3600) // 60
            duration_desc = f"{int(hrs)}h {int(mins)}m ({delta.total_seconds():.0f}s)"
        except Exception:
            duration_desc = f"{first_ts_str} to {last_ts_str}"

        # Classify behavioral tactics across the campaign
        tactics_observed = set()
        probed_urls = set()
        agents_targeted = set()
        rules_triggered = {}
        max_level = 0

        for ev in cleaned_events:
            r_id = ev["rule_id"]
            lvl = ev["level"]
            max_level = max(max_level, lvl)
            desc = ev["desc"].lower()
            url = ev["affected_url"]
            agent_target = ev["real_target_host"]

            agents_targeted.add(agent_target)
            if url:
                probed_urls.add(url.split("?")[0][:80])

            rules_triggered[r_id] = rules_triggered.get(r_id, 0) + 1

            if any(k in desc for k in ["xmlrpc", "scan", "crawl", "bot", "recon", "probe"]):
                tactics_observed.add("Reconnaissance_Scanning")
            if any(k in desc for k in ["brute force", "login", "auth", "failed", "100211", "5710", "4625"]):
                tactics_observed.add("Credential_Stuffing_BruteForce")
            if any(k in desc for k in ["exploit", "sqli", "injection", "php", "command execution", "100915"]):
                tactics_observed.add("Web_Exploitation")
            if any(k in desc for k in ["powershell", "cmd.exe", "w3wp", "process", "execve"]):
                tactics_observed.add("Host_Execution")
            if any(k in desc for k in ["syscheck", "modified", "tampered", "webshell"]):
                tactics_observed.add("Persistence_FileModification")

        # Determine defense recommendation based on target architecture (User Rule 10)
        defense_recom = "Chặn IP nguồn qua Firewall FortiGate + CrowdSec"
        is_lb_target = any("prod-idp" in a or "cybersafe" in a or "10.241.1" in a for a in agents_targeted)
        is_direct_target = any("daotao" in a or "TuyensinhSDH" in a or "aapanel" in a for a in agents_targeted)

        if is_lb_target:
            defense_recom = "Dịch vụ đứng sau Load Balancer: Chặn qua CrowdSec tại LB (cscli decisions add --ip) + Threat Feed FortiGate (CẤM dùng iptables DROP trên Web node backend)"
        elif is_direct_target:
            defense_recom = "Dịch vụ tiếp nhận trực tiếp: Kích hoạt Host AR (wazuh-firewall-drop / netsh advfirewall) + Threat Feed FortiGate"

        # Key milestone events (first event, highest level event, latest event)
        milestones = []
        milestones.append({"role": "FIRST_SEEN", "timestamp": first_ts_str, "agent": cleaned_events[0]["real_target_host"], "rule": cleaned_events[0]["rule_id"], "desc": cleaned_events[0]["desc"], "url": cleaned_events[0]["affected_url"]})
        highest_ev = max(cleaned_events, key=lambda x: x["level"])
        if highest_ev["timestamp"] != first_ts_str:
            milestones.append({"role": "HIGHEST_SEVERITY", "timestamp": highest_ev["timestamp"], "agent": highest_ev["real_target_host"], "rule": highest_ev["rule_id"], "level": highest_ev["level"], "desc": highest_ev["desc"], "url": highest_ev["affected_url"]})
        if cleaned_events[-1]["timestamp"] not in [first_ts_str, highest_ev["timestamp"]]:
            milestones.append({"role": "LATEST_ACTIVITY", "timestamp": last_ts_str, "agent": cleaned_events[-1]["real_target_host"], "rule": cleaned_events[-1]["rule_id"], "desc": cleaned_events[-1]["desc"], "url": cleaned_events[-1]["affected_url"]})

        campaigns.append({
            "attacker_ip": attacker_ip,
            "total_events_24h": total_hits,
            "timeline_range": {
                "first_seen": first_ts_str,
                "last_seen": last_ts_str,
                "campaign_duration": duration_desc
            },
            "max_severity_level": max_level,
            "tactics_chain": sorted(list(tactics_observed)),
            "targets_affected": sorted(list(agents_targeted)),
            "top_probed_urls": list(probed_urls)[:8],
            "rules_summary": rules_triggered,
            "defense_action": defense_recom,
            "milestone_events": milestones
        })

    summary = f"24h Attacker Campaign Correlation: Identified {len(campaigns)} persistent IP campaigns across {hours}h range."
    inv_id = save_investigation_record("ip_campaign_hunt", f"Hunt IP attack campaigns across {hours}h", summary, campaigns, list(all_observables))

    return {
        "investigation_id": inv_id,
        "summary": summary,
        "campaigns_count": len(campaigns),
        "campaigns": campaigns
    }

# ------------------------------------------------------------------------------
# CLI DISPATCHER
# ------------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="VNU SOC Native Agentic Threat Hunter & Correlation Engine")
    subparsers = parser.add_subparsers(dest="mode", help="Threat hunting operational mode")

    p_rce = subparsers.add_parser("rce-hunt", help="Hunt for Remote Code Execution & WebShells (last 48h)")
    p_rce.add_argument("--hours", type=int, default=48, help="Hours window (default: 48)")

    p_exfil = subparsers.add_parser("exfil-hunt", help="Hunt for Data Exfiltration & C2 Tunneling (last 7d)")
    p_exfil.add_argument("--days", type=int, default=7, help="Days window (default: 7)")

    p_triage = subparsers.add_parser("agent-triage", help="Triage all alerts on specific agent")
    p_triage.add_argument("agent", type=str, help="Agent ID or Name (e.g. 015, dksdh, daotao)")
    p_triage.add_argument("--days", type=int, default=7, help="Days window (default: 7)")

    p_corr = subparsers.add_parser("correlate-timeline", help="Correlate Level >= 12 alerts with +/- 30m timeline")
    p_corr.add_argument("--hours", type=int, default=24, help="Hours window (default: 24)")
    p_corr.add_argument("--window", type=int, default=30, help="Timeline window minutes before/after (default: 30)")

    p_camp = subparsers.add_parser("ip-campaign-hunt", help="Track attacker behavior campaigns across 24h by Source IP")
    p_camp.add_argument("--hours", type=int, default=24, help="Hours window (default: 24)")
    p_camp.add_argument("--ip", type=str, default=None, help="Specific attacker IP to trace")
    p_camp.add_argument("--min-events", type=int, default=5, help="Minimum events threshold (default: 5)")
    p_camp.add_argument("--max-ips", type=int, default=10, help="Max attacker IPs to return (default: 10)")

    parser.add_argument("--markdown", action="store_true", help="Output as readable Markdown instead of compact JSON")

    args = parser.parse_args()

    if not args.mode:
        parser.print_help()
        sys.exit(1)

    result = {}
    if args.mode == "rce-hunt":
        result = hunt_rce(hours=args.hours)
    elif args.mode == "exfil-hunt":
        result = hunt_data_exfiltration(days=args.days)
    elif args.mode == "agent-triage":
        result = triage_agent(agent_target=args.agent, days=args.days)
    elif args.mode == "correlate-timeline":
        result = correlate_high_severity_timeline(hours=args.hours, window_minutes=args.window)
    elif args.mode == "ip-campaign-hunt":
        result = hunt_ip_campaign_chain(hours=args.hours, specific_ip=args.ip, min_events=args.min_events, max_ips=args.max_ips)

    if args.markdown:
        print(f"# 🛡️ BÁO CÁO AGENTIC THREAT HUNTING: {args.mode.upper()}")
        print(f"> **Mã Điều tra (Investigation ID):** `{result.get('investigation_id', 'N/A')}`")
        print(f"> **Tóm tắt phát hiện:** {result.get('summary')}\n")
        print("```json")
        print(json.dumps(result, indent=2, ensure_ascii=False))
        print("```")
    else:
        # Compact token-optimized JSON
        print(json.dumps(result, ensure_ascii=False))

if __name__ == "__main__":
    main()
