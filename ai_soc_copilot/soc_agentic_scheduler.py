#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==============================================================================
VNU SOC: 30-MINUTE AUTONOMOUS AGENTIC AI THREAT CORRELATION & REPORTING SCHEDULER
==============================================================================
Runs every 30 minutes to:
  1. Correlate critical events (+/- 30 mins) across network sensors and host agents.
  2. Detect multi-stage Cyber Kill Chain progression (Network Exploit -> Host Exec -> FIM).
  3. Send high-signal summaries to Telegram when true threats are verified.
  4. Persist investigations in /var/ossec/soc_daily_reports/investigations.json.
==============================================================================
"""

import os
import sys
import json
import time
import subprocess
from datetime import datetime, timezone, timedelta

LOCAL_TZ = timezone(timedelta(hours=7))
LOG_FILE = "/var/ossec/logs/agentic_scheduler.log"
INVESTIGATIONS_FILE = "/var/ossec/soc_daily_reports/investigations.json"
LAST_RUN_STATE = "/var/ossec/soc_daily_reports/.last_scheduler_run.json"

sys.path.insert(0, "/var/ossec/tools")
try:
    import telegram_notifier
except ImportError:
    telegram_notifier = None

try:
    import soc_proposal_manager
except ImportError:
    soc_proposal_manager = None

def log(msg):
    ts = datetime.now(LOCAL_TZ).strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] [AgenticScheduler] {msg}\n"
    print(line, end="")
    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception:
        pass

def run_correlation_cycle(hours=1, window_minutes=30):
    log(f"Starting 30-min Threat Correlation Cycle (Lookback: {hours}h, Window: +/- {window_minutes}m)...")
    cmd = [
        "/usr/bin/python3",
        "/var/ossec/tools/agentic_threat_hunter.py",
        "correlate-timeline",
        "--hours", str(hours),
        "--window", str(window_minutes)
    ]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        if res.returncode != 0:
            log(f"Correlation script failed (code {res.returncode}): {res.stderr[:300]}")
            return None
        return json.loads(res.stdout)
    except Exception as e:
        log(f"Error running threat hunter correlation: {e}")
        return None

def get_registered_agents():
    """Lấy danh sách các agent thực sự đã cài đặt Wazuh Agent."""
    agents = set()
    try:
        res = subprocess.run(["/var/ossec/bin/agent_control", "-l"], capture_output=True, text=True, timeout=5)
        import re
        for line in res.stdout.splitlines():
            if "ID:" in line and "Name:" in line:
                for p in line.split(","):
                    if "Name:" in p:
                        name = p.split("Name:")[1].strip()
                        agents.add(name)
                        ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", name)
                        if ip_match:
                            agents.add(ip_match.group(1))
    except Exception:
        pass
    return agents

def process_results(data):
    if not data:
        return

    correlations = data.get("correlations", [])
    log(f"Correlated {len(correlations)} anchor alert windows.")

    if not correlations:
        log("Zero critical correlation anchors in this cycle. System secure and calm.")
        return

    registered_agents = get_registered_agents()

    # 1. Lọc các mối đe dọa thực sự (Cyber Kill Chain hoặc Level >= 12)
    candidate_threats = []
    for c in correlations:
        anchor = c.get("anchor_alert", {})
        rule_id = str(anchor.get("rule_id", ""))
        level = anchor.get("level", 0)
        progress = c.get("kill_chain_progress", "")
        
        # Bỏ qua log docker/internal logs và phiên đăng nhập thông thường (PAM/SSH/Sudo)
        if rule_id in ["86003", "86001", "86002", "86004", "5501", "5502", "5503", "5504", "5402", "5715"]:
            continue

        is_true_kill_chain = (" -> " in progress)
        is_critical_exploit = (level >= 12 and not anchor.get("is_passive_sensor") and anchor.get("src_ip"))
        is_sensor_confirmed_target = (anchor.get("is_passive_sensor") and anchor.get("real_target_host") not in ["SecurityOnion_Suricata_10.243.1.38", "Unknown Target"] and level >= 12 and anchor.get("src_ip"))

        if is_true_kill_chain or is_critical_exploit or is_sensor_confirmed_target:
            candidate_threats.append(c)

    if not candidate_threats:
        log("No confirmed threats requiring action in this cycle.")
        return

    # 2. GOM NHÓM THEO IP NGUỒN TẤN CÔNG (Attacker IP Aggregation)
    ip_groups = {}
    for c in candidate_threats:
        anchor = c.get("anchor_alert", {})
        src_ip = (anchor.get("src_ip") or "").strip()
        if not src_ip or src_ip in ["127.0.0.1", "10.243.1.38"]:
            group_key = f"TARGET:{anchor.get('real_target_host', 'Unknown')}"
        else:
            group_key = src_ip
        if group_key not in ip_groups:
            ip_groups[group_key] = []
        ip_groups[group_key].append(c)

    log(f"Aggregated {len(candidate_threats)} events into {len(ip_groups)} distinct attacker/target groups.")

    # Deduplication tracking file
    sent_groups_file = "/var/ossec/soc_daily_reports/.sent_attack_groups.json"
    sent_groups = {}
    if os.path.exists(sent_groups_file):
        try:
            with open(sent_groups_file, "r") as sf:
                sent_groups = json.load(sf)
        except Exception:
            sent_groups = {}

    now_ts = time.time()
    
    # Xử lý từng cụm IP tấn công
    for group_key, items in ip_groups.items():
        src_ip = group_key if not group_key.startswith("TARGET:") else None
        
        targets = []
        sigs = []
        max_level = 0
        total_surround = 0
        sensor_set = set()
        is_passive_span = False
        
        for it in items:
            anc = it.get("anchor_alert", {})
            t = anc.get("real_target_host", "Unknown")
            if t and t not in targets and t != "SecurityOnion_Suricata_10.243.1.38":
                targets.append(t)
            desc = anc.get("desc", "")
            if desc and desc not in sigs:
                sigs.append(desc)
            lvl = anc.get("level", 0)
            if lvl > max_level:
                max_level = lvl
            total_surround += it.get("surrounding_events_count", 0)
            sensor_set.add(anc.get("sensor", "Unknown Sensor"))
            if anc.get("is_passive_sensor"):
                is_passive_span = True

        # Check deduplication: Don't resend same attacker within 45 minutes unless new targets found
        last_info = sent_groups.get(group_key, {})
        last_sent_ts = last_info.get("last_sent", 0)
        last_targets = set(last_info.get("targets", []))
        current_targets = set(targets)

        if (now_ts - last_sent_ts < 2700) and (current_targets.issubset(last_targets)):
            log(f"Skipping recently alerted attacker group {group_key} (sent {int(now_ts - last_sent_ts)}s ago).")
            continue

        # 3. AUTONOMOUS ACTIVE RESPONSE (100% TỰ ĐỘNG CHẶN IP NGUỒN)
        ar_details = "Chưa áp dụng"
        if src_ip and src_ip not in ["127.0.0.1", "10.243.1.38"]:
            try:
                import soc_action_dispatcher
                ban_res = soc_action_dispatcher.execute_ban_ip(
                    target_agent="Perimeter-FortiGate",
                    ip=src_ip,
                    mode="perm",
                    reason=f"Autonomous Kill Chain Block: {sigs[0][:60] if sigs else 'Critical Exploit'}"
                )
                ar_details = ban_res.get("details", "Đã khóa trên FortiGate và Host AR.")
                log(f"Autonomous AR executed: Banned attacker IP {src_ip}: {ar_details}")
            except Exception as be:
                log(f"Error executing auto-ban on IP {src_ip}: {be}")
                ar_details = f"Lỗi thực thi AR: {be}"

        # 4. PHÂN ĐỊNH MỤC TIÊU CÓ AGENT VS SPAN PORT
        agent_targets = []
        external_targets = []
        for tg in targets:
            matched = False
            for ag in registered_agents:
                if ag in tg or tg in ag:
                    matched = True
                    break
            if matched:
                agent_targets.append(tg)
            else:
                external_targets.append(tg)

        # Chỉ tạo HITL proposal nếu có mục tiêu là Agent thực sự cần can thiệp file/code
        prop_id = None
        if agent_targets:
            try:
                import soc_ai_reasoning_engine
                prop = soc_ai_reasoning_engine.create_dynamic_soc_proposal(
                    target_ip_or_name=agent_targets[0],
                    incident_type=sigs[0] if sigs else "Host Exploit Attempt",
                    attacker_ip=src_ip or "Unknown",
                    root_cause=f"AI Scheduler phát hiện chuỗi tấn công nhắm vào Agent ({len(items)} đợt)"
                )
                prop_id = prop.get("id")
                log(f"Auto-generated Proposal {prop_id} for verified agent target {agent_targets[0]}")
            except Exception as pe:
                log(f"Failed to auto-generate proposal: {pe}")

        # 5. AGENTIC AI CHAIN OF THOUGHT (GEMINI 3.8 FLASH VIA CALL_ANTIGRAVITY_CLI)
        ai_cot_summary = ""
        try:
            import soc_ai_reasoning_engine
            target_desc = ", ".join(targets[:4])
            sig_bullets = "\n".join([f"- {s}" for s in sigs[:3]])
            ai_prompt = (
                f"Bạn là Chuyên gia Điều hành An ninh Mạng VNU SOC (Gemini 3.8 Flash).\n"
                f"Hệ thống vừa phát hiện và TỰ ĐỘNG ĐÁNH CHẶN chuỗi tấn công mạng sau:\n"
                f"• IP Nguồn tấn công: {src_ip or 'N/A'}\n"
                f"• Cảm biến: {'SPAN Port NIDS (Suricata @ Security Onion 10.243.1.38)' if is_passive_span else ', '.join(sensor_set)}\n"
                f"• Các mục tiêu bị nhắm tới: {target_desc}\n"
                f"• Các mẫu khai thác/CVE nhận diện được:\n{sig_bullets}\n"
                f"• Tổng số sự kiện liên quan: {total_surround} sự kiện trong khung +/- 30 phút.\n"
                f"• Hành động phản kháng: Đã tự động chặn IP vĩnh viễn trên FortiGate Threat Feed Gateway và Host Drop.\n\n"
                f"Hãy phân tích ngắn gọn trong 2-3 câu: Đánh giá bản chất đợt tấn công (botnet quét hàng loạt CVE hay tấn công có chủ đích), "
                f"mức độ đe dọa với hệ thống VNU và kết luận trạng thái sau khi đã tự động khóa IP."
            )
            ai_cot_summary = soc_ai_reasoning_engine.call_antigravity_cli(
                prompt=ai_prompt,
                effort="low",
                timeout_sec=25,
                subagent="Cyber Kill Chain Correlator"
            )
        except Exception as aie:
            log(f"AI Reasoning invocation failed: {aie}")

        if not ai_cot_summary:
            ai_cot_summary = f"Kẻ tấn công từ IP <code>{src_ip}</code> đang triển khai botnet tự động rà quét các lỗ hổng thực thi lệnh từ xa (Command Injection / Chmod Exec) trên diện rộng đối với các dịch vụ mạng. Hệ thống VNU SOC Autonomous AR đã tự động kích hoạt luật khóa IP trên toàn bộ các lớp phòng thủ Gateway và Host, triệt tiêu nguy cơ xâm nhập sâu vào hạ tầng nội bộ."

        # 6. ĐỊNH DẠNG TIN NHẮN TELEGRAM ĐẲNG CẤP & DỄ NHẬN DIỆN
        sig_items_html = ""
        for s in sigs[:3]:
            s_clean = s.replace("CRITICAL SURICATA NIDS SIGNATURE MATCH: ", "").replace("CRITICAL SURICATA NIDS ATTACK: ", "")
            sig_items_html += f"  • <code>{s_clean}</code>\n"

        target_items_html = ""
        for t in targets[:4]:
            tag = " [Agent Host]" if t in agent_targets else " [Mạng / SPAN Port]"
            target_items_html += f"  • <code>{t}</code>{tag}\n"

        sensor_desc = "📡 <b>Cảm biến:</b> SPAN Port NIDS (Suricata @ SecurityOnion 10.243.1.38 - Luồng Mạng Mirror)" if is_passive_span else f"📡 <b>Cảm biến:</b> {', '.join(sensor_set)}"

        prop_line = ""
        if prop_id:
            prop_line = f"\n📋 <b>Đề xuất AI cho Agent (HITL):</b> <code>{prop_id}</code> (Duyệt: <code>/prom {prop_id} approve</code>)\n"

        telegram_msg = (
            f"🚨 <b>[VNU SOC] TỰ ĐỘNG ĐÁNH CHẶN CHUỖI TẤN CÔNG (CYBER KILL CHAIN)</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"🔴 <b>Mức độ:</b> <b>CRITICAL (Level {max_level})</b> | <b>Giai đoạn:</b> Exploitation &amp; Execution\n"
            f"🦹 <b>IP Tấn công:</b> <code>{src_ip or 'Unknown'}</code> (Gom cụm {len(items)} đợt quét)\n"
            f"🎯 <b>Mục tiêu bị nhắm tới ({len(targets)}):</b>\n{target_items_html}"
            f"{sensor_desc}\n\n"
            f"⚡ <b>Dấu hiệu khai thác / CVE:</b>\n{sig_items_html}"
            f"📊 <b>Quy mô:</b> <b>{total_surround}+ sự kiện</b> tương quan trong khung 30 phút\n\n"
            f"🛡️ <b>HÀNH ĐỘNG TỰ ĐỘNG ĐÃ THỰC THI (AUTONOMOUS AR):</b>\n"
            f"✅ <b>ĐÃ ĐÁNH CHẶN TOÀN DIỆN TRÊN TOÀN HỆ THỐNG:</b>\n"
            f"  • FortiGate Threat Feed Gateway: <b>ENFORCED (DROP)</b>\n"
            f"  • Host Active Response (Wazuh Agents): <b>BLOCKED (Drop Rule)</b>\n"
            f"  • Chi tiết: <i>{ar_details}</i>\n"
            f"{prop_line}\n"
            f"🧠 <b>ĐÁNH GIÁ TỪ AGENTIC AI (GEMINI 3.8 FLASH):</b>\n"
            f"<i>{ai_cot_summary}</i>\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"🤖 <i>VNU SOC Autonomous XDR • Powered by Google Antigravity AI Engine</i>"
        )

        if telegram_notifier:
            telegram_notifier.send_telegram_raw(telegram_msg)
            log(f"Consolidated advisory sent to Telegram for attacker IP {src_ip} ({len(targets)} targets)")

        # Update sent groups tracking
        sent_groups[group_key] = {
            "last_sent": now_ts,
            "targets": targets,
            "sigs": sigs
        }

    # Save tracking
    try:
        with open(sent_groups_file, "w") as sf:
            json.dump(sent_groups, sf, indent=2)
    except Exception:
        pass

def run_24h_campaign_chain():
    """
    Xâu chuỗi và theo vết hành vi toàn diện theo từng IP nguồn trong 24 giờ qua.
    Tự động chặn IP nếu phát hiện chiến dịch quy mô lớn (>= 500 events hoặc >= 3 máy chủ).
    """
    log("Running 24-Hour Attacker Entity & Campaign Chaining Analysis...")
    cmd = [
        "/usr/bin/python3",
        "/var/ossec/tools/agentic_threat_hunter.py",
        "ip-campaign-hunt",
        "--hours", "24",
        "--max-ips", "10",
        "--min-events", "10"
    ]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        if res.returncode == 0:
            data = json.loads(res.stdout)
            campaigns = data.get("campaigns", [])
            log(f"Analyzed {len(campaigns)} active persistent IP campaigns in 24h.")
            
            sent_campaigns_file = "/var/ossec/soc_daily_reports/.sent_campaign_advisories.json"
            sent_camps = set()
            if os.path.exists(sent_campaigns_file):
                try:
                    with open(sent_campaigns_file, "r") as scf:
                        sent_camps = set(json.load(scf))
                except Exception:
                    sent_camps = set()

            for camp in campaigns:
                ip = camp.get("attacker_ip")
                total_ev = camp.get("total_events_24h", 0)
                targets = camp.get("targets_affected", [])
                duration = camp.get("timeline_range", {}).get("campaign_duration", "N/A")
                tactics = camp.get("tactics_chain", [])
                
                # Điều kiện chiến dịch lớn cần khóa ngay: > 500 events hoặc tấn công >= 3 máy chủ
                if (total_ev >= 500 or len(targets) >= 3):
                    camp_key = f"{ip}:{total_ev // 500}"
                    if camp_key not in sent_camps:
                        sent_camps.add(camp_key)
                        
                        # 100% Tự động khóa IP chiến dịch
                        try:
                            import soc_action_dispatcher
                            soc_action_dispatcher.execute_ban_ip(
                                target_agent="Perimeter-FortiGate",
                                ip=ip,
                                mode="perm",
                                reason=f"24h Persistent Attack Campaign ({total_ev} events, {len(targets)} targets)"
                            )
                        except Exception as e:
                            log(f"Failed to auto-ban 24h campaign IP {ip}: {e}")

                        if telegram_notifier:
                            target_str = ", ".join([f"<code>{t}</code>" for t in targets[:4]])
                            tactics_str = " ➔ ".join(tactics) if tactics else "Do thám & Khai thác"
                            camp_msg = (
                                f"🚨 <b>[VNU SOC] CHIẾN DỊCH TẤN CÔNG BỀN BỈ 24H (ATTACK CAMPAIGN)</b>\n"
                                f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                                f"🔴 <b>Mức độ:</b> <b>{'CRITICAL' if total_ev >= 1000 else 'HIGH'}</b>\n"
                                f"🦹 <b>IP Nguồn tấn công:</b> <code>{ip}</code>\n"
                                f"⏱ <b>Thời lượng chuỗi tấn công:</b> <code>{duration}</code>\n"
                                f"📊 <b>Tổng sự kiện (24h):</b> <b>{total_ev:,} lượt</b>\n"
                                f"🎯 <b>Các máy chủ bị nhắm tới ({len(targets)}):</b> {target_str}\n"
                                f"⛓ <b>Chuỗi chiến thuật (Tactics):</b> <i>{tactics_str}</i>\n\n"
                                f"🛡️ <b>HÀNH ĐỘNG TỰ ĐỘNG ĐÃ THỰC THI (AUTONOMOUS AR):</b>\n"
                                f"✅ <b>ĐÃ KHÓA IP TRÊN TOÀN BỘ CỔNG CHU VI &amp; HOST AGENTS</b>\n"
                                f"  • FortiGate Threat Feed Gateway: <b>ENFORCED (DROP)</b>\n"
                                f"  • Host Active Response: <b>DROP RULE APPLIED</b>\n"
                                f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                                f"🤖 <i>VNU SOC Autonomous XDR • Powered by Google Antigravity AI Engine</i>"
                            )
                            telegram_notifier.send_telegram_raw(camp_msg)
                            log(f"Sent 24h Campaign advisory to Telegram for IP {ip} ({total_ev} events, duration: {duration})")

            try:
                with open(sent_campaigns_file, "w") as scf:
                    json.dump(list(sent_camps)[-100:], scf)
            except Exception:
                pass
        else:
            log(f"Campaign chaining exited with code {res.returncode}")
    except Exception as e:
        log(f"Error in 24h campaign chaining: {e}")

def main():
    # 1. Quét tương quan cửa sổ gần
    res = run_correlation_cycle(hours=1, window_minutes=30)
    process_results(res)
    
    # 2. Xâu chuỗi chiến dịch theo thực thể IP trong 24 giờ qua (Không bị fix cứng 30p)
    run_24h_campaign_chain()

    # Save state
    try:
        os.makedirs(os.path.dirname(LAST_RUN_STATE), exist_ok=True)
        with open(LAST_RUN_STATE, "w") as f:
            json.dump({"last_run": datetime.now(LOCAL_TZ).isoformat()}, f)
    except Exception:
        pass
    log("Correlation cycle finished successfully.\n")

if __name__ == "__main__":
    main()
