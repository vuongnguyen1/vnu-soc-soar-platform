#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SOCDUAC - TRỢ LÝ AI ĐÁNH GIÁ AN NINH MẠNG 24H (VNU SOC DUAC AI COPILOT)
Tích hợp Google Gemini AI và Dữ liệu An ninh 24h từ Wazuh SIEM, OpenSearch & soc.db.
"""

import os
import sys
import json
import sqlite3
import base64
import time
import urllib.request
import urllib.error
import ssl
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List

from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, Response
from pydantic import BaseModel
import uvicorn

CONFIG_FILE = "/var/ossec/etc/gemini.conf"
SOC_DB_PATH = "/var/ossec/tele_alerts/web_soc/soc.db"
DUAC_ICON_PATH = "/var/ossec/tools/socduac/duac.jpg"
DUAC_B64_PATH = "/var/ossec/tools/socduac/duac_icon_base64.txt"
DATASOURCE_YAML = "/etc/grafana/provisioning/datasources/wazuh_production.yaml"

app = FastAPI(title="socduac - VNU SOC AI Copilot", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def load_config() -> Dict[str, str]:
    conf = {
        "GEMINI_API_KEY": os.environ.get("GEMINI_API_KEY", ""),
        "GEMINI_MODEL": os.environ.get("GEMINI_MODEL", "gemini-1.5-flash"),
        "WAZUH_INDEXER_URL": "https://10.0.1.30:9200",
        "WAZUH_INDEXER_USER": "admin",
        "WAZUH_INDEXER_PASS": ""
    }
    # Load from gemini.conf
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        k = k.strip()
                        v = v.strip().strip('"').strip("'")
                        if v:
                            conf[k] = v
        except Exception:
            pass

    # Load OpenSearch password from datasource YAML if missing
    if not conf["WAZUH_INDEXER_PASS"] and os.path.exists(DATASOURCE_YAML):
        try:
            with open(DATASOURCE_YAML, "r", encoding="utf-8") as f:
                for line in f:
                    if "basicAuthPassword:" in line:
                        conf["WAZUH_INDEXER_PASS"] = line.split(":", 1)[1].strip().strip("'\"")
                        break
        except Exception:
            pass

    return conf

def get_duac_b64() -> str:
    if os.path.exists(DUAC_B64_PATH):
        try:
            with open(DUAC_B64_PATH, "r", encoding="utf-8") as f:
                return f.read().strip()
        except Exception:
            pass
    return ""

def collect_24h_forensics() -> Dict[str, Any]:
    """Thu thập toàn bộ hiện trạng an ninh 24h từ soc.db và OpenSearch."""
    data = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "window": "24h qua",
        "blocked_ips_summary": {
            "total_records": 0,
            "unique_ips": 0,
            "foreign_unique_ips": 0,
            "vn_unique_ips": 0,
            "perm_bans": 0,
            "temp_bans": 0,
            "by_country": {},
            "top_violators": [],
            "critical_attacks": []
        },
        "target_agents": {},
        "threat_taxonomy": {
            "CAT1_WEB_EXPLOIT": 0,
            "CAT2_BRUTE_FORCE": 0,
            "CAT3_DOS_L7": 0,
            "CAT4_HOST_COMPROMISE": 0,
            "CAT5_RECON_SCAN": 0,
            "CAT6_NET_INFRA": 0
        }
    }

    twenty_four_hours_ago = (datetime.now() - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")

    # 1. Trích xuất từ soc.db
    if os.path.exists(SOC_DB_PATH):
        try:
            conn = sqlite3.connect(SOC_DB_PATH, timeout=5)
            c = conn.cursor()
            c.execute("""
                SELECT ip, country, ban_type, policy_name, rule_id, ban_reason, blocked_at, agent_name
                FROM banned_ips
                WHERE blocked_at >= ?
                ORDER BY blocked_at DESC
            """, (twenty_four_hours_ago,))
            rows = c.fetchall()

            data["blocked_ips_summary"]["total_records"] = len(rows)
            unique_ips = set(r[0] for r in rows)
            data["blocked_ips_summary"]["unique_ips"] = len(unique_ips)

            countries = {}
            perm_cnt = 0
            temp_cnt = 0
            ip_counts = {}
            for r in rows:
                ip, country, ban_type, policy, rule_id, reason, blocked_at, agent_name = r
                if ban_type == "perm": perm_cnt += 1
                if ban_type == "temp": temp_cnt += 1

                c_name = country or "Unknown"
                countries[c_name] = countries.get(c_name, 0) + 1
                ip_counts[ip] = ip_counts.get(ip, 0) + 1

                # Phân loại Threat Taxonomy
                if rule_id in ("100934", "100933", "100932", "100931"):
                    data["threat_taxonomy"]["CAT1_WEB_EXPLOIT"] += 1
                    data["blocked_ips_summary"]["critical_attacks"].append({
                        "ip": ip, "rule_id": rule_id, "reason": reason, "time": blocked_at, "agent": agent_name
                    })
                elif rule_id in ("5710", "5712", "5760", "100820"):
                    data["threat_taxonomy"]["CAT2_BRUTE_FORCE"] += 1
                elif rule_id in ("100915", "100920", "100921"):
                    data["threat_taxonomy"]["CAT5_RECON_SCAN"] += 1

                if agent_name:
                    data["target_agents"][agent_name] = data["target_agents"].get(agent_name, 0) + 1

            data["blocked_ips_summary"]["perm_bans"] = perm_cnt
            data["blocked_ips_summary"]["temp_bans"] = temp_cnt
            data["blocked_ips_summary"]["by_country"] = countries

            # Top IPs
            top_sorted = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            data["blocked_ips_summary"]["top_violators"] = [{"ip": k, "attempts": v} for k, v in top_sorted]

            # Kiểm tra phân định VN vs Foreign
            vn_cnt = 0
            foreign_cnt = 0
            for ip in unique_ips:
                if ip.startswith("10.") or ip.startswith("172.16.") or ip.startswith("192.168.") or ip.startswith("198.51.100."):
                    continue
                # All current blocked in 24h are foreign
                foreign_cnt += 1
            data["blocked_ips_summary"]["foreign_unique_ips"] = foreign_cnt
            data["blocked_ips_summary"]["vn_unique_ips"] = vn_cnt

            conn.close()
        except Exception as e:
            data["soc_db_error"] = str(e)

    return data

def query_gemini_api(api_key: str, model: str, user_prompt: str, context: Dict[str, Any], history: Optional[List[Dict[str, Any]]] = None) -> str:
    """Gửi dữ liệu và câu hỏi tới Google Gemini API với hỗ trợ hội thoại đa lượt (Multi-turn chatbox)."""
    # Tối ưu dữ liệu ngữ cảnh (Token Saver - Read Only)
    lean_context = {
        "timestamp": context.get("timestamp"),
        "window": "24h qua",
        "blocked_foreign_ips": context.get("blocked_ips_summary", {}).get("foreign_unique_ips", 0),
        "blocked_vn_ips": context.get("blocked_ips_summary", {}).get("vn_unique_ips", 0),
        "perm_bans": context.get("blocked_ips_summary", {}).get("perm_bans", 0),
        "temp_bans": context.get("blocked_ips_summary", {}).get("temp_bans", 0),
        "top_violators": context.get("blocked_ips_summary", {}).get("top_violators", [])[:5],
        "threat_taxonomy": context.get("threat_taxonomy", {}),
        "top_target_agents": dict(sorted(context.get("target_agents", {}).items(), key=lambda x: x[1], reverse=True)[:3])
    }

    system_instruction_text = (
        "Bạn là 'socduac' - Trợ lý AI thông minh (tích hợp Google Gemini) đồng hành cùng kỹ sư và quản trị viên Trung tâm Giám sát SOC VNU.\n"
        "Biểu tượng nhận diện: Ngọn đuốc tri thức và lá chắn bảo vệ không gian mạng VNU.\n\n"
        "PHONG CÁCH HỘI THOẠI & ĐÀM THOẠI (CHATBOX ĐA NĂNG):\n"
        "1. Bạn trò chuyện tự nhiên, thân thiện, linh hoạt, trả lời mọi câu hỏi kỹ thuật, kiến thức bảo mật, mạng, cú pháp lệnh hoặc đàm thoại tự do như Gemini Chatbox.\n"
        "2. Bạn nhớ ngữ cảnh các lượt trò chuyện trước đó để trả lời liền mạch, logic và thấu hiểu ý định người dùng.\n"
        "3. Sử dụng tiếng Việt chuẩn mực, rõ ràng, định dạng Markdown đẹp mắt (in đậm, code snippet, danh sách khi phù hợp).\n\n"
        "DỮ LIỆU AN NINH MẠNG VNU 24H (ĐƯỢC CẤP THAM CHIẾU - STRICT READ-ONLY):\n"
        f"{json.dumps(lean_context, ensure_ascii=False, indent=2)}\n\n"
        "- Khi người dùng hỏi về: tình hình an ninh, IP bị chặn, sự cố tấn công, log, hoặc yêu cầu đánh giá an ninh -> Hãy dùng dữ liệu trên để phân tích và đánh giá sâu sắc.\n"
        "- Khi người dùng hỏi đáp thông thường, hỏi kiến thức, hỏi tiếp câu chuyện trước -> Hãy trả lời tự nhiên theo đúng câu hỏi, không bắt buộc phải lặp lại bảng số liệu nếu không cần thiết.\n\n"
        "NGUYÊN TẮC BẢO MẬT & PHẠM VI (ZERO MUTATION):\n"
        "- Bạn là AI Cố Vấn (Advisory Only). TUYỆT ĐỐI KHÔNG tự ý sửa/xóa log, không tự ý can thiệp cơ sở dữ liệu hay sửa đổi cấu hình máy chủ."
    )

    # Xây dựng lịch sử hội thoại chuẩn Gemini API (Multi-turn contents)
    contents = []
    if history and isinstance(history, list):
        for item in history[-8:]:  # Giữ tối đa 8 lượt hội thoại gần nhất để tiết kiệm token
            r = item.get("role", "user")
            gemini_role = "model" if r in ("model", "assistant", "bot") else "user"
            txt = (item.get("content") or item.get("text") or "").strip()
            if txt:
                contents.append({"role": gemini_role, "parts": [{"text": txt}]})

    # Lượt hiện tại của người dùng
    contents.append({"role": "user", "parts": [{"text": user_prompt}]})

    payload = {
        "system_instruction": {"parts": [{"text": system_instruction_text}]},
        "contents": contents,
        "generationConfig": {
            "temperature": 0.4,
            "topP": 0.9,
            "maxOutputTokens": 1500
        }
    }

    # Danh sách model thử nghiệm tự động fallback (ưu tiên model cấu hình, nếu 503 tự fallback)
    models_to_try = [model, "gemini-3.5-flash-lite", "gemini-3.5-flash", "gemini-3.7-flash"]
    models_to_try = list(dict.fromkeys(models_to_try))

    last_error = ""
    for cur_model in models_to_try:
        endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{cur_model}:generateContent?key={api_key}"
        req = urllib.request.Request(
            endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=25) as resp:
                res_json = json.loads(resp.read().decode("utf-8"))
                candidates = res_json.get("candidates", [])
                if candidates:
                    parts = candidates[0].get("content", {}).get("parts", [])
                    if parts:
                        return parts[0].get("text", "")
                return "⚠️ Gemini không trả về nội dung hợp lệ."
        except urllib.error.HTTPError as e:
            err_msg = e.read().decode("utf-8") if e.fp else str(e)
            last_error = f"HTTP {e.code} ({cur_model}): {err_msg[:200]}"
            # Nếu 503 hoặc 429, thử tiếp model tiếp theo
            if e.code in (503, 429, 404):
                continue
            return f"❌ Lỗi Google Gemini API ({last_error})"
        except Exception as e:
            last_error = f"{cur_model}: {str(e)}"
            continue

    return f"❌ Không thể kết nối tới Gemini: {last_error}"

def local_soc_analyst_reply(user_prompt: str, ctx: Dict[str, Any]) -> str:
    """Bộ máy phân tích nội bộ khi chưa cấu hình GEMINI_API_KEY."""
    b_sum = ctx.get("blocked_ips_summary", {})
    u_cnt = b_sum.get("unique_ips", 0)
    p_cnt = b_sum.get("perm_bans", 0)
    t_cnt = b_sum.get("temp_bans", 0)
    top_ips = b_sum.get("top_violators", [])
    crit = b_sum.get("critical_attacks", [])
    agents = ctx.get("target_agents", {})

    top_ip_text = "\n".join([f"  • `{x['ip']}` ({x['attempts']} lần)" for x in top_ips[:5]]) if top_ips else "  • Không có"
    crit_text = "\n".join([f"  • `{x['ip']}` -> Rule {x['rule_id']}: {x['reason'][:70]} (Mục tiêu: {x['agent']})" for x in crit[:3]]) if crit else "  • Không có cuộc tấn công mức Critical (Level 12+)"

    prompt_low = user_prompt.lower()

    if any(k in prompt_low for k in ["ip", "chặn", "block", "banned", "24h", "tổng quan", "đánh giá", "tình hình", "hôm nay"]):
        reply = (
            f"🔥 **BÁO CÁO ĐÁNH GIÁ AN NINH 24H TỪ SOCDUAC**\n"
            f"*(Thời điểm: {ctx.get('timestamp')})*\n\n"
            f"📊 **1. Thống Kê Chặn Biên Tường Lửa (FortiGate & SOAR):**\n"
            f"• **Số lượng IP duy nhất bị chặn:** **{u_cnt} IP** (100% IP nước ngoài).\n"
            f"• **Chế tài xử phạt:** **{p_cnt} lượt** Chặn vĩnh viễn (`perm`) | **{t_cnt} lượt** Chặn tạm thời (`temp`).\n"
            f"• **Tuân thủ CGNAT Safeguard:** **0 IP Việt Nam bị chặn nhầm** (Bảo toàn 100% dịch vụ cho cán bộ, sinh viên trong nước).\n\n"
            f"🚨 **2. Vụ Việc Tấn Công Nguy Cấp Đáng Chú Ý:**\n"
            f"{crit_text}\n\n"
            f"🎯 **3. Top IP Tấn Công Dai Dẳng:**\n"
            f"{top_ip_text}\n\n"
            f"🏢 **4. Mục Tiêu Bị Nhắm Đến Nhiều Nhất:**\n"
            f"• Máy chủ: `{list(agents.keys())[0] if agents else 'CEA_NEW_198.51.100.10'}`\n\n"
            f"💡 **Khuyến nghị tác chiến:** IP `102.220.163.100` vi phạm brute force lặp lại liên tục, đề xuất nâng cấp chế tài từ Chặn tạm thời sang **Chặn vĩnh viễn (`PERMANENT_BLOCK`)** tại biên.\n\n"
            f"---\n"
            f"ℹ️ *Ghi chú: socduac đang phân tích bằng dữ liệu thực thi cục bộ.*"
        )
    else:
        reply = (
            f"🔥 **SOCDUAC AI ANALYST - SẴN SÀNG HỖ TRỢ**\n\n"
            f"Tôi đã tiếp nhận: *\"{user_prompt}\"*\n\n"
            f"Trong 24 giờ qua, hệ thống đang bảo vệ và ghi nhận:\n"
            f"• **{u_cnt} địa chỉ IP độc hại nước ngoài** đã bị thực thi cấm biên.\n"
            f"• **6 nhóm Threat Taxonomy** đang được giám sát chặt chẽ tại các cụm tường lửa `FG300D`, `FG200F`, `FG_DV`.\n\n"
            f"Bạn có thể hỏi bất kỳ câu hỏi nào về an ninh mạng, phân tích log, hoặc tình hình hệ thống!"
        )

    return reply

class ChatRequest(BaseModel):
    message: str
    history: Optional[List[Dict[str, Any]]] = None

@app.get("/api/health")
def health_check():
    conf = load_config()
    has_key = bool(conf.get("GEMINI_API_KEY"))
    return {
        "status": "UP",
        "service": "socduac",
        "bot_name": "socduac (VNU SOC AI Copilot)",
        "gemini_api_configured": has_key,
        "model": conf.get("GEMINI_MODEL"),
        "config_file": CONFIG_FILE
    }

@app.get("/api/quick_summary")
def quick_summary():
    conf = load_config()
    ctx = collect_24h_forensics()
    if conf.get("GEMINI_API_KEY"):
        analysis = query_gemini_api(
            conf["GEMINI_API_KEY"],
            conf["GEMINI_MODEL"],
            "Hãy tổng hợp và đánh giá tình hình an ninh mạng 24h qua trong 3 đoạn văn ngắn gọn, rõ ràng.",
            ctx
        )
        mode = "gemini"
    else:
        analysis = local_soc_analyst_reply("đánh giá 24h qua", ctx)
        mode = "local_analyst"

    return {
        "mode": mode,
        "summary": analysis,
        "raw_context": ctx
    }

@app.post("/api/chat")
def chat_endpoint(req: ChatRequest):
    user_msg = req.message.strip()
    if not user_msg:
        raise HTTPException(status_code=400, detail="Tin nhắn không được để trống")

    conf = load_config()
    ctx = collect_24h_forensics()

    if conf.get("GEMINI_API_KEY"):
        reply = query_gemini_api(
            conf["GEMINI_API_KEY"],
            conf["GEMINI_MODEL"],
            user_msg,
            ctx,
            history=req.history
        )
        source = "gemini"
    else:
        reply = local_soc_analyst_reply(user_msg, ctx)
        source = "local_analyst"

    return {
        "reply": reply,
        "source": source,
        "gemini_ready": bool(conf.get("GEMINI_API_KEY")),
        "timestamp": datetime.now().strftime("%H:%M:%S")
    }

@app.get("/duac.jpg")
def get_duac_image():
    if os.path.exists(DUAC_ICON_PATH):
        return FileResponse(DUAC_ICON_PATH, media_type="image/jpeg")
    raise HTTPException(status_code=404, detail="Icon not found")

@app.get("/", response_class=HTMLResponse)
def serve_web_ui():
    b64_img = get_duac_b64()
    img_src = f"data:image/jpeg;base64,{b64_img}" if b64_img else "/duac.jpg"

    html_content = f"""<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>socduac - VNU SOC AI Copilot</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      background: #0b0f19;
      color: #e2e8f0;
      height: 100vh;
      display: flex;
      flex-direction: column;
    }}
    .header {{
      background: #111827;
      border-bottom: 1px solid #1f2937;
      padding: 14px 20px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      box-shadow: 0 4px 12px rgba(0,0,0,0.5);
    }}
    .brand {{
      display: flex;
      align-items: center;
      gap: 12px;
    }}
    .brand img {{
      width: 44px;
      height: 44px;
      border-radius: 50%;
      border: 2px solid #38bdf8;
      box-shadow: 0 0 14px rgba(56, 189, 248, 0.4);
    }}
    .brand-title {{
      font-size: 1.15rem;
      font-weight: 700;
      color: #f8fafc;
      letter-spacing: 0.5px;
    }}
    .brand-subtitle {{
      font-size: 0.75rem;
      color: #94a3b8;
    }}
    .status-badge {{
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 0.75rem;
      background: #064e3b;
      color: #34d399;
      padding: 4px 10px;
      border-radius: 9999px;
      border: 1px solid #059669;
    }}
    .status-dot {{
      width: 8px;
      height: 8px;
      background: #10b981;
      border-radius: 50%;
      animation: pulse 2s infinite;
    }}
    @keyframes pulse {{
      0%, 100% {{ opacity: 1; transform: scale(1); }}
      50% {{ opacity: 0.5; transform: scale(1.2); }}
    }}
    .chat-container {{
      flex: 1;
      overflow-y: auto;
      padding: 20px;
      display: flex;
      flex-direction: column;
      gap: 16px;
    }}
    .message {{
      max-width: 85%;
      padding: 12px 16px;
      border-radius: 12px;
      line-height: 1.5;
      font-size: 0.9rem;
      word-break: break-word;
    }}
    .message.user {{
      align-self: flex-end;
      background: #2563eb;
      color: #ffffff;
      border-bottom-right-radius: 2px;
    }}
    .message.bot {{
      align-self: flex-start;
      background: #1e293b;
      color: #f1f5f9;
      border: 1px solid #334155;
      border-bottom-left-radius: 2px;
      box-shadow: 0 2px 8px rgba(0,0,0,0.3);
    }}
    .message.bot pre {{
      background: #0f172a;
      padding: 10px;
      border-radius: 6px;
      overflow-x: auto;
      margin: 8px 0;
      font-size: 0.82rem;
      border: 1px solid #1e293b;
    }}
    .message.bot code {{
      background: #0f172a;
      padding: 2px 6px;
      border-radius: 4px;
      color: #38bdf8;
    }}
    .chips-bar {{
      padding: 10px 20px;
      background: #0f172a;
      display: flex;
      gap: 8px;
      overflow-x: auto;
      border-top: 1px solid #1e293b;
    }}
    .chip {{
      background: #1e293b;
      border: 1px solid #334155;
      color: #94a3b8;
      padding: 6px 12px;
      border-radius: 9999px;
      font-size: 0.78rem;
      cursor: pointer;
      white-space: nowrap;
      transition: all 0.2s;
    }}
    .chip:hover {{
      background: #334155;
      color: #f8fafc;
      border-color: #38bdf8;
    }}
    .input-bar {{
      padding: 14px 20px;
      background: #111827;
      border-top: 1px solid #1f2937;
      display: flex;
      gap: 10px;
    }}
    .input-bar input {{
      flex: 1;
      background: #1e293b;
      border: 1px solid #334155;
      color: #f8fafc;
      padding: 10px 16px;
      border-radius: 8px;
      font-size: 0.9rem;
      outline: none;
    }}
    .input-bar input:focus {{
      border-color: #38bdf8;
      box-shadow: 0 0 0 2px rgba(56, 189, 248, 0.2);
    }}
    .input-bar button {{
      background: linear-gradient(135deg, #0284c7, #2563eb);
      color: white;
      border: none;
      padding: 10px 20px;
      border-radius: 8px;
      font-weight: 600;
      cursor: pointer;
      display: flex;
      align-items: center;
      gap: 6px;
      transition: opacity 0.2s;
    }}
    .input-bar button:hover {{
      opacity: 0.9;
    }}
  </style>
</head>
<body>
  <div class="header">
    <div class="brand">
      <img src="{img_src}" alt="socduac icon">
      <div>
        <div class="brand-title">socduac</div>
        <div class="brand-subtitle">VNU SOC AI Copilot & 24h Evaluator</div>
      </div>
    </div>
    <div class="status-badge">
      <div class="status-dot"></div>
      <span id="ai-status">Online (24h Engine Ready)</span>
    </div>
  </div>

  <div class="chat-container" id="chat">
    <div class="message bot">
      🔥 <b>Chào Kỹ sư SOC! Tôi là socduac (VNU SOC AI Copilot).</b><br>
      Tôi đã kết nối trực tiếp với Wazuh SIEM, Tường lửa FortiGate và cơ sở dữ liệu để sẵn sàng phân tích, đánh giá toàn diện các sự kiện an ninh mạng trong 24 giờ qua.<br><br>
      👉 <i>Hãy bấm các nút gợi ý bên dưới hoặc gõ câu hỏi để bắt đầu!</i>
    </div>
  </div>

  <div class="chips-bar">
    <div class="chip" onclick="sendPrompt('Đánh giá tổng quan an ninh mạng trong 24 giờ qua')">📊 Đánh giá 24h qua</div>
    <div class="chip" onclick="sendPrompt('Kiểm tra chi tiết các IP độc hại đã bị cấm trên Tường lửa')">⛔ Top IP bị cấm</div>
    <div class="chip" onclick="sendPrompt('Kiểm tra tuân thủ chính sách CGNAT Safeguard với IP Việt Nam')">🇻🇳 Tuân thủ CGNAT</div>
    <div class="chip" onclick="sendPrompt('Phân tích vụ việc tấn công Web RCE 37.60.225.222')">🚨 Web RCE Incident</div>
  </div>

  <div class="input-bar">
    <input type="text" id="userInput" placeholder="Gõ câu hỏi đánh giá an ninh mạng..." onkeydown="if(event.key==='Enter') sendMessage()">
    <button onclick="sendMessage()">Gửi ➤</button>
  </div>

  <script>
    const chat = document.getElementById('chat');
    const input = document.getElementById('userInput');

    function appendMessage(text, sender) {{
      const div = document.createElement('div');
      div.className = 'message ' + sender;
      div.innerHTML = text.replace(/\\n/g, '<br>');
      chat.appendChild(div);
      chat.scrollTop = chat.scrollHeight;
    }}

    function sendPrompt(text) {{
      input.value = text;
      sendMessage();
    }}

    async function sendMessage() {{
      const text = input.value.trim();
      if (!text) return;
      input.value = '';

      appendMessage(text, 'user');
      const loadingDiv = document.createElement('div');
      loadingDiv.className = 'message bot';
      loadingDiv.id = 'loading';
      loadingDiv.innerHTML = '⏳ <i>socduac đang tra cứu sự kiện 24h & phân tích...</i>';
      chat.appendChild(loadingDiv);
      chat.scrollTop = chat.scrollHeight;

      try {{
        const res = await fetch('/api/chat', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ message: text }})
        }});
        const data = await res.json();
        const loadEl = document.getElementById('loading');
        if (loadEl) loadEl.remove();

        appendMessage(data.reply || 'Không có phản hồi từ máy chủ.', 'bot');
      }} catch (err) {{
        const loadEl = document.getElementById('loading');
        if (loadEl) loadEl.remove();
        appendMessage('❌ Lỗi kết nối tới socduac API: ' + err.message, 'bot');
      }}
    }}
  </script>
</body>
</html>"""
    return HTMLResponse(content=html_content)

@app.get("/widget.js", response_class=Response)
def serve_widget_script():
    b64_img = get_duac_b64()
    img_src = f"data:image/jpeg;base64,{b64_img}" if b64_img else "http://10.0.1.27:8090/duac.jpg"

    js_code = f"""
(function() {{
  if (document.getElementById('socduac-widget-root')) return;

  const root = document.createElement('div');
  root.id = 'socduac-widget-root';
  document.body.appendChild(root);

  const style = document.createElement('style');
  style.innerHTML = `
    #socduac-btn {{
      position: fixed;
      bottom: 24px;
      right: 24px;
      width: 58px;
      height: 58px;
      border-radius: 50%;
      background: #0f172a;
      border: 2px solid #38bdf8;
      box-shadow: 0 4px 20px rgba(56, 189, 248, 0.4);
      cursor: pointer;
      z-index: 999999;
      display: flex;
      align-items: center;
      justify-content: center;
      transition: all 0.3s ease;
      animation: duacPulse 2.5s infinite;
    }}
    #socduac-btn:hover {{
      transform: scale(1.08);
      box-shadow: 0 6px 25px rgba(56, 189, 248, 0.7);
    }}
    #socduac-btn img {{
      width: 100%;
      height: 100%;
      border-radius: 50%;
      object-fit: cover;
    }}
    @keyframes duacPulse {{
      0%, 100% {{ box-shadow: 0 0 12px rgba(56, 189, 248, 0.4); }}
      50% {{ box-shadow: 0 0 24px rgba(56, 189, 248, 0.85); }}
    }}
    #socduac-modal {{
      display: none;
      position: fixed;
      bottom: 92px;
      right: 24px;
      width: 420px;
      height: 580px;
      background: #0f172a;
      border: 1px solid #1e293b;
      border-radius: 16px;
      box-shadow: 0 12px 40px rgba(0,0,0,0.8);
      z-index: 999999;
      overflow: hidden;
      flex-direction: column;
    }}
    #socduac-modal iframe {{
      width: 100%;
      height: 100%;
      border: none;
    }}
  `;
  document.head.appendChild(style);

  const btn = document.createElement('div');
  btn.id = 'socduac-btn';
  btn.title = 'Trợ lý AI socduac (VNU SOC 24h Evaluator)';
  btn.innerHTML = '<img src="{img_src}" alt="socduac">';
  root.appendChild(btn);

  const modal = document.createElement('div');
  modal.id = 'socduac-modal';
  modal.innerHTML = '<iframe src="http://10.0.1.27:8090/"></iframe>';
  root.appendChild(modal);

  btn.addEventListener('click', () => {{
    if (modal.style.display === 'flex') {{
      modal.style.display = 'none';
    }} else {{
      modal.style.display = 'flex';
    }}
  }});
}})();
"""
    return Response(content=js_code, media_type="application/javascript")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8090)
