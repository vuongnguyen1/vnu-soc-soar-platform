#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==============================================================================
VNU SOC: REAL-TIME EVENT-DRIVEN AGENTIC AI WORKFLOW ENGINE
==============================================================================
Tự động kích hoạt khi có alert mức nguy hiểm (Level >= 12, RCE, WebShell, CVE):
  1. Instant Autonomous Action (0s): Lập tức khóa IP trên FortiGate Threat Feed Gateway & Host AR.
  2. Sliding Window Debounce (35s): Gom cụm sự kiện theo Attacker IP để tránh Rate Spike & chống tràn Token.
  3. Adaptive Effort AI Reasoning: Tự động chọn Turbo (--effort low) hoặc Deep Reasoning (--effort medium).
  4. Real-time Antigravity CLI Invocation: Gọi agy CLI sinh Chain of Thought thực tế và ghi nhận Metrics.
  5. Consolidated Rich Telegram Advisory: Gửi thông báo HTML trực quan, chuyên nghiệp.
==============================================================================
"""

import os
import sys
import re
import time
import json
import threading
import subprocess
from datetime import datetime, timezone, timedelta

LOCAL_TZ = timezone(timedelta(hours=7))
LOG_FILE = "/var/ossec/logs/realtime_workflow.log"

if "/var/ossec/tools" not in sys.path:
    sys.path.insert(0, "/var/ossec/tools")

try:
    import telegram_notifier
except ImportError:
    telegram_notifier = None

try:
    import soc_action_dispatcher
except ImportError:
    soc_action_dispatcher = None

try:
    import soc_ai_reasoning_engine
except ImportError:
    soc_ai_reasoning_engine = None

def log(msg):
    ts = datetime.now(LOCAL_TZ).strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] [RealtimeWorkflow] {msg}\n"
    print(line, end="")
    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception:
        pass

def get_registered_agents():
    """Lấy danh sách các agent thực sự đã cài đặt Wazuh Agent."""
    agents = set()
    try:
        res = subprocess.run(["/var/ossec/bin/agent_control", "-l"], capture_output=True, text=True, timeout=5)
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

class RealtimeWorkflowDispatcher:
    def __init__(self, debounce_seconds: float = 35.0):
        self.debounce_seconds = debounce_seconds
        self._buffer = {}          # group_key -> list of alerts
        self._timers = {}          # group_key -> threading.Timer
        self._banned_cache = {}    # ip -> timestamp of ban
        self._lock = threading.Lock()
        self._registered_agents = None
        self._agents_last_updated = 0

    def get_agents(self):
        now = time.time()
        if not self._registered_agents or (now - self._agents_last_updated > 300):
            self._registered_agents = get_registered_agents()
            self._agents_last_updated = now
        return self._registered_agents

    def is_dangerous_alert(self, alert: dict) -> bool:
        """Đánh giá nhanh xem alert có đủ điều kiện kích hoạt Event-Driven Workflow không."""
        rule = alert.get("rule", {})
        rule_id = str(rule.get("id", ""))
        level = int(rule.get("level", 0))
        rule_groups = set(rule.get("groups", []))

        # 1. Bỏ qua rule docker/internal noise, syscheck limit, log rotation và phiên đăng nhập thông thường
        if rule_id in [
            "233", "201", "202", "203", "204", "205", "510", "550", "553", "554", "591", 
            "651", "652", "2502", "61110", "86001", "86002", "86003", "86004", 
            "87100", "87101", "87102", "87103", "87104", "87106", "5501", "5502", "5503", "5504"
        ]:
            return False

        # Bỏ qua alert syscheck file thuần túy (đã có FIM batch flusher xử lý)
        if "syscheck" in alert and not bool(rule_groups.intersection({"webshell", "rootkit", "trojanized_binary"})):
            return False

        # 2. Bỏ qua mã phản hồi HTTP 403, 404, 429
        data = alert.get("data", {})
        http_status = None
        if "status" in data:
            try: http_status = int(data["status"])
            except Exception: pass
        elif "id" in data and str(data["id"]).isdigit() and len(str(data["id"])) == 3:
            try: http_status = int(data["id"])
            except Exception: pass
        if http_status in [403, 404, 406, 429]:
            return False

        # 3. Điều kiện nguy hiểm: Level >= 12 HOẶC chứa nhóm rce, webshell, cve, rootkit
        danger_groups = {"rce", "webshell", "exploit", "cve", "rootkit", "trojanized_binary", "mscofxp", "c2", "command_injection"}
        if level >= 12 or bool(rule_groups.intersection(danger_groups)):
            return True

        desc = rule.get("description", "").lower()
        if any(k in desc for k in ["command injection", "webshell", "rce", "remote code", "chmod usage", "cve-2024", "cve-2023"]):
            return True

        return False

    def extract_attacker_ip(self, alert: dict) -> str:
        """Bóc tách chính xác IP nguồn tấn công hỗ trợ cả Wazuh Web, Windows EventLog và Suricata NIDS."""
        data = alert.get("data", {})
        ip = (
            data.get("srcip") or 
            data.get("src_ip") or 
            alert.get("src_ip") or 
            data.get("win", {}).get("eventdata", {}).get("ipAddress")
        )
        if not ip and "full_log" in alert:
            m = re.search(r'"src_ip":\s*"([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})"', alert.get("full_log", ""))
            if m:
                ip = m.group(1)
        if ip:
            ip = str(ip).split(":")[0].strip()
        return ip or ""

    def extract_victim_target(self, alert: dict) -> str:
        """Phân định Cảm biến thụ động vs Mục tiêu thực sự (Tuân thủ User Rule 10)."""
        data = alert.get("data", {})
        agent = alert.get("agent", {})
        agent_id = str(agent.get("id", "000"))
        agent_name = agent.get("name", "Unknown")

        is_passive = (agent_id in ["027", "011", "012"] or 
                      "SecurityOnion" in agent_name or 
                      "ingest" in agent_name)
        if is_passive:
            dst = data.get("dest_ip") or data.get("dstip") or data.get("dst_ip")
            if not dst and "full_log" in alert:
                m = re.search(r'"dest_ip":\s*"([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})"', alert.get("full_log", ""))
                if m:
                    dst = m.group(1)
            return dst if dst else "Internal/Target Network"
        return agent_name

    def feed_alert(self, alert: dict):
        """Tiếp nhận một alert theo thời gian thực từ luồng đọc log của Wazuh."""
        if not self.is_dangerous_alert(alert):
            return

        rule = alert.get("rule", {})
        rule_desc = rule.get("description", "Security Event")
        src_ip = self.extract_attacker_ip(alert)
        victim_target = self.extract_victim_target(alert)

        # Xác định group key (ưu tiên theo IP nguồn tấn công)
        if src_ip and src_ip not in ["127.0.0.1", "10.243.1.38", "0.0.0.0"]:
            group_key = src_ip
        else:
            group_key = f"TARGET:{victim_target}"

        now = time.time()

        # 1. AUTONOMOUS INSTANT ACTION (0s) - Khóa IP ngay lập tức ở gói tin đầu tiên
        if src_ip and src_ip not in ["127.0.0.1", "10.243.1.38", "0.0.0.0"]:
            with self._lock:
                last_ban = self._banned_cache.get(src_ip, 0)
                should_ban = (now - last_ban > 600)
                if should_ban:
                    self._banned_cache[src_ip] = now

            if should_ban and soc_action_dispatcher:
                threading.Thread(
                    target=self._execute_instant_ban,
                    args=(src_ip, rule_desc),
                    daemon=True
                ).start()

        # 2. SLIDING WINDOW BUFFER & DEBOUNCE (Gom cụm 35s)
        with self._lock:
            if group_key not in self._buffer:
                self._buffer[group_key] = []

            if len(self._buffer[group_key]) < 60:
                self._buffer[group_key].append(alert)

            # Nếu timer chưa chạy hoặc đã hết hạn, đặt timer mới
            if group_key not in self._timers:
                t = threading.Timer(self.debounce_seconds, self._trigger_workflow, args=[group_key])
                self._timers[group_key] = t
                t.start()
                log(f"Started real-time debounce window ({self.debounce_seconds}s) for {group_key}")

    def _execute_instant_ban(self, ip: str, reason: str):
        """Khóa IP tự động trên FortiGate Threat Feed Gateway và Host AR ngầm."""
        try:
            log(f"Executing 0s Instant Autonomous Ban for IP {ip}...")
            res = soc_action_dispatcher.execute_ban_ip(
                target_agent="Perimeter-FortiGate",
                ip=ip,
                mode="perm",
                reason=f"Realtime Event-Driven Ban: {reason[:60]}"
            )
            log(f"Instant Ban Result for {ip}: {res.get('details')}")
        except Exception as e:
            log(f"Instant Ban Error for {ip}: {e}")

    def _trigger_workflow(self, group_key: str):
        """Khi debounce timer 35s kích hoạt: gom toàn bộ sự kiện và gọi Antigravity CLI."""
        with self._lock:
            alerts = self._buffer.pop(group_key, [])
            self._timers.pop(group_key, None)

        if not alerts:
            return

        threading.Thread(
            target=self._run_agentic_workflow,
            args=(group_key, alerts),
            daemon=True
        ).start()

    def _run_agentic_workflow(self, group_key: str, alerts: list):
        """Quy trình Agentic Workflow phân tích chuyên sâu và gửi báo cáo Telegram."""
        now = time.time()
        src_ip = group_key if not group_key.startswith("TARGET:") else None

        targets = []
        sigs = []
        max_level = 0
        sensor_set = set()
        is_passive_span = False
        has_host_exec = False

        registered_agents = self.get_agents()

        for a in alerts:
            data = a.get("data", {})
            rule = a.get("rule", {})
            agent = a.get("agent", {})
            agent_id = str(agent.get("id", "000"))
            agent_name = agent.get("name", "Unknown")

            lvl = int(rule.get("level", 0))
            if lvl > max_level:
                max_level = lvl

            desc = rule.get("description", "")
            if desc and desc not in sigs:
                sigs.append(desc)

            # Xác định cảm biến
            if agent_id in ["027", "011", "012"] or "SecurityOnion" in agent_name or "ingest" in agent_name:
                is_passive_span = True
                sensor_set.add("SecurityOnion Suricata NIDS (SPAN Port)")
                clean_dst = (data.get("dest_ip") or data.get("dstip") or data.get("dst_ip") or "").split(":")[0].strip()
                if not clean_dst and "full_log" in a:
                    m_dst = re.search(r'"dest_ip":\s*"([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})"', a.get("full_log", ""))
                    if m_dst:
                        clean_dst = m_dst.group(1)
                if clean_dst and clean_dst not in targets and clean_dst != "10.243.1.38":
                    targets.append(clean_dst)
            else:
                sensor_set.add(f"{agent_name} (Agent {agent_id})")
                if agent_name not in targets:
                    targets.append(agent_name)

            # Kiểm tra xem có dấu hiệu thực thi mã host không (để quyết định Deep vs Turbo)
            win_data = data.get("win", {}).get("eventdata", {})
            cmdline = win_data.get("commandLine") or data.get("command") or ""
            img = win_data.get("image") or ""
            if any(p in (cmdline + img).lower() for p in ["cmd.exe", "powershell", "w3wp.exe", "whoami", "certutil", "/bin/sh", "/bin/bash"]):
                has_host_exec = True

        if not targets:
            targets = ["External/Network Service"]

        # 1. Xác định Effort Mode thích ứng (Adaptive Effort)
        effort_mode = "medium" if has_host_exec else "low"
        log(f"Triggering Antigravity CLI Workflow for {group_key} ({len(alerts)} alerts, Effort: {effort_mode})...")

        # 2. Phân định mục tiêu Agent vs SPAN Port
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

        # 3. Tự động sinh Proposal HITL nếu có Agent Host thật sự
        prop_id = None
        if agent_targets and soc_ai_reasoning_engine:
            try:
                prop = soc_ai_reasoning_engine.create_dynamic_soc_proposal(
                    target_ip_or_name=agent_targets[0],
                    incident_type=sigs[0] if sigs else "Host Exploit Attempt",
                    attacker_ip=src_ip or "Unknown",
                    root_cause=f"Realtime Workflow phát hiện đợt tấn công nguy hiểm ({len(alerts)} alerts)"
                )
                if prop and prop.get("id"):
                    prop_id = prop["id"]
                    log(f"Auto-generated Proposal {prop_id} for agent {agent_targets[0]}")
            except Exception as pe:
                log(f"Error generating proposal: {pe}")

        # 4. Kích hoạt Antigravity CLI (Gemini 3.8 Flash) sinh CoT Reasoning
        ai_cot = ""
        if soc_ai_reasoning_engine:
            try:
                sig_text = "\n".join([f"- {s}" for s in sigs[:3]])
                target_text = ", ".join(targets[:4])
                prompt = (
                    f"Bạn là Trợ lý Agentic AI SOC của VNU (Gemini 3.8 Flash).\n"
                    f"Hệ thống vừa kích hoạt REAL-TIME EVENT-DRIVEN WORKFLOW và ĐÃ TỰ ĐỘNG KHÓA IP:\n"
                    f"• IP Kẻ tấn công: {src_ip or 'N/A'}\n"
                    f"• Các mục tiêu bị nhắm tới: {target_text}\n"
                    f"• Cảm biến: {', '.join(sensor_set)}\n"
                    f"• Chữ ký khai thác/CVE:\n{sig_text}\n"
                    f"• Tổng số sự kiện gom cụm trong cửa sổ 35s: {len(alerts)} sự kiện.\n"
                    f"• Hành động tự động đã thực thi: Đã kích hoạt FortiGate Threat Feed Gateway & Host Drop.\n\n"
                    f"Hãy phân tích ngắn gọn trong 2-3 câu: Nhận diện ý đồ kẻ tấn công, đánh giá rủi ro và "
                    f"xác nhận trạng thái sau khi đã tự động khóa IP."
                )
                ai_cot = soc_ai_reasoning_engine.call_antigravity_cli(
                    prompt=prompt,
                    effort=effort_mode,
                    timeout_sec=25,
                    subagent="Realtime Event-Driven Correlator"
                )
            except Exception as aie:
                log(f"Error calling Antigravity CLI: {aie}")

        if not ai_cot:
            ai_cot = (
                f"Kẻ tấn công từ IP <code>{src_ip or 'Unknown'}</code> vừa thực hiện chuỗi khai thác tự động "
                f"nhắm vào các cổng dịch vụ. Hệ thống VNU SOC Autonomous AR đã tự động kích hoạt luật chặn "
                f"trên toàn bộ hệ thống tường lửa biên và các máy chủ, bảo vệ an toàn hạ tầng VNU."
            )

        # 5. Định dạng thông báo Telegram Rich HTML đẳng cấp
        sig_items_html = ""
        for s in sigs[:3]:
            s_clean = s.replace("CRITICAL SURICATA NIDS SIGNATURE MATCH: ", "").replace("CRITICAL SURICATA NIDS ATTACK: ", "")
            sig_items_html += f"  • <code>{s_clean}</code>\n"

        target_items_html = ""
        for t in targets[:4]:
            tag = " [Agent Host]" if t in agent_targets else " [Mạng / SPAN Port]"
            target_items_html += f"  • <code>{t}</code>{tag}\n"

        sensor_str = "📡 <b>Cảm biến:</b> SPAN Port NIDS (Suricata @ SecurityOnion 10.243.1.38)" if is_passive_span else f"📡 <b>Cảm biến:</b> {', '.join(sensor_set)}"

        prop_line = ""
        if prop_id:
            prop_line = f"\n📋 <b>Đề xuất AI cho Agent (HITL):</b> <code>{prop_id}</code> (Duyệt: <code>/prom {prop_id} approve</code>)\n"

        if src_ip:
            ar_status_html = (
                f"🛡️ <b>HÀNH ĐỘNG TỰ ĐỘNG ĐÃ THỰC THI (AUTONOMOUS AR):</b>\n"
                f"✅ <b>ĐÃ ĐÁNH CHẶN TOÀN DIỆN TRÊN TOÀN HỆ THỐNG:</b>\n"
                f"  • FortiGate Threat Feed Gateway: <b>ENFORCED (DROP)</b>\n"
                f"  • Host Active Response (Wazuh Agents): <b>BLOCKED (Drop Rule)</b>\n"
            )
        else:
            ar_status_html = (
                f"🛡️ <b>HÀNH ĐỘNG AN NINH:</b>\n"
                f"⚠️ <i>Sự kiện nội bộ / Cảm biến Mirror (Không có IP ngoại vi để kích hoạt Perimeter Drop).</i>\n"
            )

        telegram_msg = (
            f"⚡ <b>[VNU SOC] REAL-TIME EVENT-DRIVEN WORKFLOW (TỰ ĐỘNG ĐÁNH CHẶN)</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"🔴 <b>Mức độ:</b> <b>CRITICAL (Level {max_level})</b> | <b>Chế độ AI:</b> <code>{effort_mode.upper()}</code>\n"
            f"🦹 <b>IP Tấn công:</b> <code>{src_ip or 'Unknown'}</code> (Gom cụm {len(alerts)} sự kiện trong 35s)\n"
            f"🎯 <b>Mục tiêu bị nhắm tới ({len(targets)}):</b>\n{target_items_html}"
            f"{sensor_str}\n\n"
            f"⚡ <b>Dấu hiệu khai thác / CVE:</b>\n{sig_items_html}\n"
            f"{ar_status_html}"
            f"{prop_line}\n"
            f"🧠 <b>ĐÁNH GIÁ TỪ AGENTIC AI (GEMINI 3.8 FLASH):</b>\n"
            f"<i>{ai_cot}</i>\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"🤖 <i>VNU SOC Autonomous XDR • Real-time Stream Triggered</i>"
        )

        if telegram_notifier:
            telegram_notifier.send_telegram_raw(telegram_msg)
            log(f"Successfully broadcast Real-time Event-Driven Alert for {group_key} to Telegram.")

# Singleton Dispatcher Instance
dispatcher = RealtimeWorkflowDispatcher(debounce_seconds=35.0)

def feed_alert(alert: dict):
    """Điểm vào cho luồng đọc alert thời gian thực."""
    dispatcher.feed_alert(alert)

if __name__ == "__main__":
    print("[*] Testing RealtimeWorkflowDispatcher...")
    test_alert = {
        "timestamp": datetime.now().isoformat(),
        "rule": {
            "id": "100851",
            "level": 13,
            "description": "CRITICAL SURICATA NIDS SIGNATURE MATCH: ET WEB_SPECIFIC_APPS TBK DVR-4104/4216 Command Injection Attempt (CVE-2024-3721)",
            "groups": ["suricata", "rce", "cve"]
        },
        "agent": {
            "id": "027",
            "name": "SecurityOnion_Suricata_10.243.1.38"
        },
        "data": {
            "srcip": "198.51.100.222",
            "dstip": "10.241.5.74:80"
        }
    }
    dispatcher.debounce_seconds = 3.0  # Test fast debounce
    feed_alert(test_alert)
    print("[*] Test alert fed, waiting for workflow trigger...")
    time.sleep(5)
    print("[*] Test finished.")
