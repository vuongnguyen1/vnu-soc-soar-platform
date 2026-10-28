#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==============================================================================
VNU SOC: HUMAN-IN-THE-LOOP PROPOSAL & REMEDIATION MANAGER (soc_proposal_manager.py)
==============================================================================
Manages proposals that require Admin Approval before executing deep interventions:
  1. Patching source code or application logic.
  2. Executing Ansible playbooks or remediation scripts on remote agents.
  3. Applying auto-synthesized Wazuh custom rules.
  4. Blocking wide CIDR subnets (/24, /16) at perimeter firewalls.
  5. Restarting critical services (patroni, haproxy, keycloak, nginx).

Admins interact via Telegram:
  - /prom list          : List pending proposals
  - /prom <id> approve  : Approve and execute immediately in the background
  - /prom <id> reject   : Reject with optional reason
==============================================================================
"""

import os
import sys
import json
import time
import subprocess
from datetime import datetime, timezone, timedelta

LOCAL_TZ = timezone(timedelta(hours=7))
PROPOSALS_FILE = "/var/ossec/soc_daily_reports/proposals.json"
MAX_HISTORY = 100

def _load_proposals():
    if not os.path.exists(PROPOSALS_FILE):
        return []
    try:
        with open(PROPOSALS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[!] Error loading proposals: {e}")
        return []

def _save_proposals(proposals):
    os.makedirs(os.path.dirname(PROPOSALS_FILE), exist_ok=True)
    try:
        # Giữ lại tối đa MAX_HISTORY đề xuất gần nhất
        proposals = proposals[:MAX_HISTORY]
        with open(PROPOSALS_FILE, "w", encoding="utf-8") as f:
            json.dump(proposals, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"[!] Error saving proposals: {e}")
        return False

def generate_proposal_id():
    now_str = datetime.now(LOCAL_TZ).strftime("%Y%m%d")
    proposals = _load_proposals()
    today_count = sum(1 for p in proposals if p.get("id", "").startswith(f"PROP-{now_str}"))
    return f"PROP-{now_str}-{today_count + 1:03d}"

def create_proposal(action_type: str = "SOC_ACTION", title: str = "", target: str = "", description: str = "", command: str = "", soc_action: str = "", playbook: str = "", justification: str = "", risk_level: str = "MEDIUM", **kwargs):
    """
    Creates a new proposal awaiting Admin approval.
    action_type: SOC_ACTION | REMEDIATE_MALWARE | PATCH_SOURCE_CODE | APPLY_CUSTOM_RULE | BLOCK_SUBNET | RESTART_SERVICE | RUN_COMMAND
    """
    prop_id = generate_proposal_id()
    now_iso = datetime.now(LOCAL_TZ).isoformat()
    
    if not command:
        if soc_action:
            command = f"/var/ossec/tenungdung.sh soc {target} {soc_action}"
        elif playbook:
            command = f"/var/ossec/tenungdung.sh playbook {target} {playbook}"
        else:
            command = f"/var/ossec/tenungdung.sh test {target}"

    proposal = {
        "id": prop_id,
        "created_at": now_iso,
        "status": "PENDING",  # PENDING | APPROVED | REJECTED | EXECUTED | FAILED
        "action_type": action_type,
        "title": title,
        "target": target,
        "description": description,
        "command": command,
        "soc_action": soc_action,
        "playbook": playbook,
        "justification": justification,
        "risk_level": risk_level,
        "executed_at": None,
        "executed_by": None,
        "execution_result": None
    }
    
    proposals = _load_proposals()
    proposals.insert(0, proposal)
    _save_proposals(proposals)
    return proposal

def list_pending_proposals():
    """Returns all proposals with status PENDING"""
    proposals = _load_proposals()
    return [p for p in proposals if p.get("status") == "PENDING"]

def get_proposal(prop_id: str):
    proposals = _load_proposals()
    for p in proposals:
        if p.get("id", "").upper() == prop_id.upper().strip():
            return p
    return None

def reject_proposal(prop_id: str, reason: str = "Admin rejected", rejected_by: str = "admin"):
    proposals = _load_proposals()
    for p in proposals:
        if p.get("id", "").upper() == prop_id.upper().strip():
            if p.get("status") != "PENDING":
                return False, f"Đề xuất {prop_id} đã ở trạng thái {p.get('status')}!"
            p["status"] = "REJECTED"
            p["executed_at"] = datetime.now(LOCAL_TZ).isoformat()
            p["executed_by"] = rejected_by
            p["execution_result"] = {"reason": reason}
            _save_proposals(proposals)
            return True, f"Đã từ chối đề xuất {prop_id} thành công."
    return False, f"Không tìm thấy đề xuất {prop_id}."

def approve_and_execute(prop_id: str, approved_by: str = "admin", approver: str = None):
    """
    Approves and executes the proposal safely in the background.
    Returns (success: bool, message: str, result_dict: dict)
    """
    if approver:
        approved_by = approver
    proposals = _load_proposals()
    target_prop = None
    for p in proposals:
        if p.get("id", "").upper() == prop_id.upper().strip():
            target_prop = p
            break
            
    if not target_prop:
        return False, f"Không tìm thấy đề xuất {prop_id}!", {}
        
    if target_prop.get("status") != "PENDING":
        return False, f"Đề xuất {prop_id} đã ở trạng thái {target_prop.get('status')}, không thể thực thi lại!", {}

    cmd = target_prop.get("command", "")
    if not cmd:
        return False, "Đề xuất không có câu lệnh thực thi!", {}

    # Đánh dấu đang thực thi
    target_prop["status"] = "EXECUTING"
    target_prop["executed_by"] = approved_by
    _save_proposals(proposals)

    start_time = time.time()
    try:
        # Thực thi lệnh an toàn (tuân thủ User Rule 2: Zero-Secret & Auto-Elevation)
        res = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=180,
            cwd="/var/ossec"
        )
        duration = round(time.time() - start_time, 2)
        exec_res = {
            "exit_code": res.returncode,
            "stdout": res.stdout[:2000],  # Cắt ngắn để tránh quá dài
            "stderr": res.stderr[:1000],
            "duration_seconds": duration
        }
        
        if res.returncode == 0:
            target_prop["status"] = "EXECUTED"
            target_prop["executed_at"] = datetime.now(LOCAL_TZ).isoformat()
            target_prop["execution_result"] = exec_res
            _save_proposals(proposals)
            return True, f"Thực thi đề xuất {prop_id} THÀNH CÔNG trong {duration}s!", exec_res
        else:
            target_prop["status"] = "FAILED"
            target_prop["executed_at"] = datetime.now(LOCAL_TZ).isoformat()
            target_prop["execution_result"] = exec_res
            _save_proposals(proposals)
            return False, f"Thực thi đề xuất {prop_id} THẤT BẠI (Mã lỗi {res.returncode})!", exec_res

    except subprocess.TimeoutExpired:
        duration = round(time.time() - start_time, 2)
        exec_res = {"exit_code": 124, "error": f"Lệnh bị timeout sau {duration}s", "duration_seconds": duration}
        target_prop["status"] = "FAILED"
        target_prop["executed_at"] = datetime.now(LOCAL_TZ).isoformat()
        target_prop["execution_result"] = exec_res
        _save_proposals(proposals)
        return False, f"Thực thi đề xuất {prop_id} bị TIMEOUT sau {duration}s!", exec_res
    except Exception as e:
        duration = round(time.time() - start_time, 2)
        exec_res = {"exit_code": 999, "error": str(e), "duration_seconds": duration}
        target_prop["status"] = "FAILED"
        target_prop["executed_at"] = datetime.now(LOCAL_TZ).isoformat()
        target_prop["execution_result"] = exec_res
        _save_proposals(proposals)
        return False, f"Lỗi ngoại lệ khi thực thi đề xuất {prop_id}: {e}", exec_res

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="VNU SOC Human-in-the-Loop Proposal Manager")
    parser.add_argument("--list", action="store_true", help="Liệt kê toàn bộ đề xuất đang chờ duyệt")
    parser.add_argument("--create", type=str, help="Tiêu đề đề xuất mới")
    parser.add_argument("--target", type=str, default="local", help="Máy chủ mục tiêu (Host/Agent)")
    parser.add_argument("--type", type=str, default="SOC_ACTION", help="Phân loại hành động (SOC_ACTION, RUN_COMMAND, PLAYBOOK)")
    parser.add_argument("--soc-action", type=str, default="", help="Hành động SOC chuyên dụng (ioc-scan, iis-audit, clamav-scan...)")
    parser.add_argument("--command", type=str, default="", help="Câu lệnh cụ thể cần thực thi")
    parser.add_argument("--playbook", type=str, default="", help="Tên playbook ansible")
    parser.add_argument("--risk", type=str, default="MEDIUM", help="Mức độ rủi ro (LOW, MEDIUM, HIGH)")
    parser.add_argument("--desc", type=str, default="Đề xuất can thiệp SOC", help="Mô tả chi tiết")
    parser.add_argument("--approve", type=str, help="Phê duyệt và chạy ngay đề xuất theo ID")
    parser.add_argument("--reject", type=str, help="Từ chối đề xuất theo ID")
    parser.add_argument("--reason", type=str, default="Admin từ chối", help="Lý do từ chối")
    parser.add_argument("--test", action="store_true", help="Chạy kiểm thử tự động chu trình Proposal")

    args = parser.parse_args()

    if args.list:
        pending = list_pending_proposals()
        print(f"[*] Có {len(pending)} đề xuất đang chờ duyệt (PENDING):")
        for p in pending:
            print(f"  • [{p['id']}] {p['title']} | Target: {p['target']} | CMD: {p.get('command')}")
    elif args.create:
        p = create_proposal(
            action_type=args.type,
            title=args.create,
            target=args.target,
            description=args.desc,
            command=args.command,
            soc_action=args.soc_action,
            playbook=args.playbook,
            risk_level=args.risk
        )
        print(f"[+] Đã tạo thành công đề xuất: {p['id']} (Status: {p['status']})")
    elif args.approve:
        ok, msg, res = approve_and_execute(args.approve)
        print(f"[*] Kết quả phê duyệt: ok={ok} | {msg}")
    elif args.reject:
        ok, msg = reject_proposal(args.reject, reason=args.reason)
        print(f"[*] Kết quả từ chối: ok={ok} | {msg}")
    elif args.test:
        prop = create_proposal(
            action_type="RUN_COMMAND",
            title="Kiểm thử hệ thống HITL Proposal",
            target="Wazuh-Manager",
            description="Chạy kiểm tra trạng thái Wazuh cluster",
            command="/var/ossec/bin/cluster_control -a",
            justification="Đảm bảo luồng duyệt /prom approve hoạt động chuẩn xác",
            risk_level="LOW"
        )
        print("Created test proposal:", prop["id"])
        pending = list_pending_proposals()
        print(f"Pending proposals: {len(pending)}")
        ok, msg, res = approve_and_execute(prop["id"])
        print(f"Executed: ok={ok}, msg={msg}")
    else:
        parser.print_help()
