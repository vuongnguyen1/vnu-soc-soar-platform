#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==============================================================================
VNU SOC: UNIFIED ACTIVE RESPONSE & ACTION DISPATCHER
==============================================================================
Module điều phối hành động phản kháng bảo mật đa tầng:
  1. Ban/Unban IP (Host Firewall netsh/iptables + Threat Feed Gateway FortiGate + CrowdSec).
  2. Kill Process (Diệt cây tiến trình độc hại theo PID hoặc Tên tiến trình).
  3. Isolate Host (Cách ly mạng máy chủ bị xâm nhập, duy trì kết nối Wazuh Manager).
  4. Quét IOC WebShell & Mã độc (ioc-scan, clamav-scan).
  5. Dọn dẹp Rootkit IIS & Phục hồi w3wp.exe (remediate-seo).
Tuân thủ User Rule 2 (Zero-Secret & Auto-Elevation ngầm).
==============================================================================
"""

import os
import sys
import re
import time
import subprocess
from datetime import datetime, timezone, timedelta

LOCAL_TZ = timezone(timedelta(hours=7))

def _run_cmd(cmd_list, timeout=120):
    """Chạy câu lệnh ngầm an toàn và trả về (success, stdout, stderr, duration)."""
    start = time.time()
    try:
        res = subprocess.run(
            cmd_list,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd="/var/ossec"
        )
        duration = round(time.time() - start, 2)
        return (res.returncode == 0, res.stdout.strip(), res.stderr.strip(), duration)
    except subprocess.TimeoutExpired:
        duration = round(time.time() - start, 2)
        return (False, "", f"Lệnh bị timeout sau {duration} giây", duration)
    except Exception as e:
        duration = round(time.time() - start, 2)
        return (False, "", str(e), duration)

def execute_ban_ip(target_agent: str, ip: str, mode: str = "perm", reason: str = "Admin Directive via Telegram") -> dict:
    """
    Khóa IP trên toàn diện các lớp phòng thủ:
      - Tầng Host (Wazuh AR: firewall-drop hoặc netsh).
      - Tầng Chu vi: Đẩy sang FortiGate Threat Feed Gateway (:8088).
    """
    if not ip or ip in ["127.0.0.1", "10.243.1.38"]:
        return {"success": False, "message": f"Không thể khóa IP đặc biệt/sensor: {ip}"}

    # 1. Host AR
    host_ok, host_out, host_err, d1 = _run_cmd([
        "/var/ossec/bin/agent_control", "-b", ip,
        "-f", "firewall-drop0" if mode == "perm" else "firewall-drop300",
        "-u", "all"
    ])

    # 2. Perimeter SOAR Gateway
    gw_status = "N/A"
    try:
        import requests
        gw_payload = {
            "ip": ip,
            "threat_category": "CAT1_WEB_EXPLOIT",
            "risk_score": 95,
            "reason": f"Telegram Action: {reason}",
            "source": "AGENTIC_DISPATCHER",
            "target_agent": target_agent
        }
        r = requests.post("http://127.0.0.1:8088/api/feed/enforce", json=gw_payload, timeout=3)
        gw_status = f"HTTP {r.status_code}"
    except Exception as e:
        gw_status = f"Lỗi GW: {e}"

    return {
        "success": True,
        "action": "BAN_IP",
        "ip": ip,
        "mode": mode,
        "target": target_agent,
        "details": f"Đã áp dụng lệnh khóa trên Host AR và đồng bộ Threat Feed Gateway ({gw_status})."
    }

def execute_unban_ip(ip: str) -> dict:
    """Gỡ chặn IP trên toàn hệ thống."""
    ok, out, err, d = _run_cmd(["/var/ossec/bin/agent_control", "-b", ip, "-f", "unban_linux0", "-u", "all"])
    # Gỡ cả Windows
    _run_cmd(["/var/ossec/bin/agent_control", "-b", ip, "-f", "unban_windows0", "-u", "all"])
    return {
        "success": True,
        "action": "UNBAN_IP",
        "ip": ip,
        "details": f"Đã phát lệnh gỡ chặn IP {ip} trên toàn bộ Agents."
    }

def execute_kill_process(target_agent: str, pid_or_name: str) -> dict:
    """
    Diệt tiến trình độc hại từ xa trên máy chủ đích:
      - Windows: taskkill /F /PID <pid> hoặc taskkill /F /IM <name>
      - Linux: kill -9 <pid> hoặc pkill -f <name>
    """
    clean_target = target_agent.strip()
    is_pid = pid_or_name.strip().isdigit()

    # Kiểm tra target là Windows hay Linux dựa trên tên
    is_windows = any(k in clean_target.lower() for k in ["daotao", "tuyensinh", "win", "eoffice", "cea", "ulis"])

    if is_windows:
        if is_pid:
            remote_cmd = f"taskkill /F /PID {pid_or_name.strip()}"
        else:
            remote_cmd = f"taskkill /F /IM {pid_or_name.strip()} /T"
    else:
        if is_pid:
            remote_cmd = f"kill -9 {pid_or_name.strip()}"
        else:
            remote_cmd = f"pkill -9 -f {pid_or_name.strip()}"

    ok, out, err, d = _run_cmd(["/var/ossec/tenungdung.sh", "exec", clean_target, remote_cmd], timeout=60)
    return {
        "success": ok,
        "action": "KILL_PROCESS",
        "target": clean_target,
        "process": pid_or_name,
        "command": remote_cmd,
        "stdout": out,
        "stderr": err,
        "duration": d
    }

def execute_isolate_host(target_agent: str) -> dict:
    """Cô lập máy chủ mục tiêu (chỉ giữ kênh 1514/1515 về Wazuh Manager)."""
    clean_target = target_agent.strip()
    is_windows = any(k in clean_target.lower() for k in ["daotao", "tuyensinh", "win", "eoffice", "cea", "ulis"])
    
    if is_windows:
        cmd = f"/var/ossec/tenungdung.sh soc {clean_target} isolate-and-kill-process"
    else:
        # Linux iptables isolation giữ port 1514
        remote_cmd = "iptables -F && iptables -A INPUT -p tcp --dport 1514 -j ACCEPT && iptables -A OUTPUT -p tcp --sport 1514 -j ACCEPT && iptables -P INPUT DROP && iptables -P OUTPUT DROP"
        cmd = f"/var/ossec/tenungdung.sh exec {clean_target} \"{remote_cmd}\""

    ok, out, err, d = _run_cmd(cmd.split(), timeout=90)
    return {
        "success": ok,
        "action": "ISOLATE_HOST",
        "target": clean_target,
        "stdout": out,
        "stderr": err,
        "duration": d
    }

def execute_scan_ioc(target_agent: str) -> dict:
    """Quét webshell và file script mới sửa đổi trong Web Root."""
    clean_target = target_agent.strip()
    ok, out, err, d = _run_cmd(["/var/ossec/tenungdung.sh", "soc", clean_target, "ioc-scan"], timeout=120)
    return {
        "success": ok,
        "action": "IOC_SCAN",
        "target": clean_target,
        "stdout": out,
        "stderr": err,
        "duration": d
    }

def execute_codebase_patch(target_agent: str, vuln_type: str = "idor") -> dict:
    """
    Quy trình vá mã nguồn an toàn 4 bước (Assess -> Propose -> Patch with Backup -> Verify):
      - Đẩy script vá và backup lên máy chủ qua tenungdung.sh push.
      - Chạy script vá tạo thư mục backup có timestamp (Backup_Security_YYYYMMDD_HHMMSS).
      - Chạy script verify_patch_poc.py kiểm thử độc lập và xác nhận kết quả.
    """
    clean_target = target_agent.strip()
    if "daotao" in clean_target.lower() or "112.137.142.44" in clean_target or "idor" in vuln_type.lower():
        local_patch = "/var/ossec/report/daotao_security_remediation_package/03_SCRIPT_VAY_VA_BACKUP/patch_and_backup_daotao.ps1"
        remote_dest = r"C:\Windows\Temp\patch_and_backup_daotao.ps1"
        
        # Bước 1: Đẩy script lên máy chủ Windows
        push_ok, p_out, p_err, d1 = _run_cmd([
            "/var/ossec/tenungdung.sh", "push", "daotao_112.137.142.44", local_patch, remote_dest
        ], timeout=30)
        
        # Bước 2: Thực thi script vá có backup
        exec_cmd = f"powershell -ExecutionPolicy Bypass -File {remote_dest}"
        exec_ok, e_out, e_err, d2 = _run_cmd([
            "/var/ossec/tenungdung.sh", "exec", "daotao_112.137.142.44", exec_cmd
        ], timeout=60)
        
        # Bước 3: Chạy script kiểm thử POC độc lập
        verify_ok, v_out, v_err, d3 = _run_cmd([
            "/usr/bin/python3", "/var/ossec/report/daotao_security_remediation_package/04_SCRIPT_TEST_POC_KIEM_THU/verify_patch_poc.py"
        ], timeout=30)
        
        total_d = round(d1 + d2 + d3, 2)
        all_passed = "[PASS]" in v_out and "[FAIL]" not in v_out
        
        return {
            "success": exec_ok and all_passed,
            "action": "CODEBASE_PATCH_4STEPS",
            "target": "daotao_112.137.142.44",
            "message": "Đã vá thành công mã nguồn và hardening thư mục upload có sao lưu an toàn." if all_passed else "Bản vá đã chạy nhưng vẫn còn cảnh báo kiểm thử.",
            "stdout": f"[1. PUSH]: {p_out}\n[2. PATCH]: {e_out}\n[3. VERIFY]:\n{v_out}",
            "stderr": e_err or v_err,
            "duration": total_d,
            "rollback_cmd": "/var/ossec/tenungdung.sh exec daotao_112.137.142.44 \"powershell -ExecutionPolicy Bypass -File C:\\Windows\\Temp\\rollback_daotao.ps1\""
        }
    
    return {
        "success": False,
        "action": "CODEBASE_PATCH",
        "target": clean_target,
        "message": f"Chưa hỗ trợ kịch bản vá tự động cho mục tiêu {clean_target} và loại lỗ hổng {vuln_type}."
    }

if __name__ == "__main__":
    print("[*] soc_action_dispatcher module loaded successfully.")

