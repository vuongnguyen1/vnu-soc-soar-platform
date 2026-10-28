# 🛡️ Enterprise True Agentic AI SOC, SOAR & Autonomous Threat Response Platform (v2.6)

[![Wazuh SIEM](https://img.shields.io/badge/Wazuh-v4.9+-005571?style=for-the-badge&logo=wazuh&logoColor=white)](https://wazuh.com/)
[![Grafana](https://img.shields.io/badge/Grafana-v12.0+-F46800?style=for-the-badge&logo=grafana&logoColor=white)](https://grafana.com/)
[![FortiGate](https://img.shields.io/badge/FortiGate-REST_API-EE3124?style=for-the-badge&logo=fortinet&logoColor=white)](https://fortinet.com/)
[![Google Antigravity](https://img.shields.io/badge/Google_Antigravity-Gemini_3.8_Flash-4285F4?style=for-the-badge&logo=google&logoColor=white)](https://ai.google.dev/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK_Mapped-A6192E?style=for-the-badge)](https://attack.mitre.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

> **Hệ sinh thái Giám sát An toàn Thông tin (SIEM), Tự động hóa Phản ứng Biên (SOAR), Xâu chuỗi Chiến thuật Tấn công (Cyber Kill Chain) và Trợ lý Điều hành Agentic AI Copilot cấp Doanh nghiệp.**  
> Thiết kế đặc thù cho cụm hạ tầng đại học & doanh nghiệp quy mô lớn (29+ Nodes, hàng triệu tệp tin, máy chủ Linux, Windows Server, Mail Cluster, Keycloak IDP, cụm tường lửa FortiGate), giải quyết triệt để 5 bài toán thực chiến: **Triệt tiêu bão cảnh báo (Alert Fatigue), Bảo vệ dải IP 4G/CGNAT nội địa, Chống sập dịch vụ do khóa nhầm Ingress (Cloudflare Tunnel / Load Balancer), Quản trị hạn mức Token AI thời gian thực và Quy trình vá mã nguồn an toàn HITL (Human-in-the-Loop).**

---

## 📑 MỤC LỤC
1. [Kiến Trúc Tổng Thể & Luồng Dữ Liệu](#-kiến-trúc-tổng-thể--luồng-dữ-liệu)
2. [Điểm Sáng Công Nghệ Đột Phá (Core Engineering Highlights)](#-điểm-sáng-công-nghệ-đột-phá)
3. [Mô Hình Hybrid: "Deterministic Action, Generative Reasoning"](#-mô-hình-hybrid-deterministic-action-generative-reasoning)
4. [Kiến Trúc Toàn Diện & Đặc Tả Kỹ Thuật (Architecture Blueprint)](#-kiến-trúc-toàn-diện--đặc-tả-kỹ-thuật-v26)
5. [Cấu Trúc Thư Mục Repository](#-cấu-trúc-thư-mục-repository)
6. [Hướng Dẫn Triển Khai & Khởi Chạy](#-hướng-dẫn-triển-khai--khởi-chạy)
7. [Bản Quyền](#-bản-quyền)

---

## 🏛️ KIẾN TRÚC TỔNG THỂ & LUỒNG DỮ LIỆU

Hệ thống hoạt động theo mô hình phòng thủ khép kín 5 tầng:

```mermaid
flowchart TB
    subgraph SENSORS ["1. Log Collection & Distributed Sensors"]
        L1[Linux Hosts: Nginx / SSH / Syslog / Auditd]
        W1[Windows Hosts: IIS / Sysmon / Security Event 4688, 4104]
        S1[Passive NIDS: Suricata @ Security Onion via SPAN Port]
        F1[Perimeter: FortiGate Gateway Syslog]
    end

    subgraph CORE ["2. Wazuh SIEM & Telemetry Core"]
        DEC[Decoders & Custom MITRE ATT&CK Ruleset\n70,000+ Lines]
        OS[(OpenSearch Telemetry Cluster\nwazuh-alerts-*)]
    end

    subgraph HUNTER ["3. Autonomous Correlation & Threat Hunter"]
        CORR[30-min Cyber Kill Chain Correlator\nsoc_agentic_scheduler.py]
        CAMP[24h Attacker Campaign & Entity Chaining\nagentic_threat_hunter.py]
    end

    subgraph ENGINE ["4. Hybrid Action & Reasoning Engine"]
        DISP[soc_action_dispatcher.py\nDeterministic AR Execution]
        FG_FEED[FortiGate Dynamic Threat Feed\nPort 8088 / IP Aging 30d]
        HOST_AR[Host AR Drop / Process Kill / Host Isolation]
        AI_COPILOT[soc_ai_reasoning_engine.py\nGoogle Antigravity CLI (Gemini 3.8 Flash)]
        PROP[soc_proposal_manager.py\nHITL Remediation Proposals PROP-xxx]
    end

    subgraph OPS ["5. Mission Control & Human-in-the-Loop"]
        GRAF[Grafana Mission Control & AI Token Hub]
        TELE[Telegram SOC Bot Dispatcher & Contextual Reply]
    end

    SENSORS -->|rsyslog / Agent Event Channel| DEC
    DEC --> OS
    OS --> CORR & CAMP
    CORR & CAMP -->|100% Deterministic Trigger| DISP
    DISP --> FG_FEED & HOST_AR
    CORR -->|In-Context Telemetry Prompt| AI_COPILOT
    AI_COPILOT -->|Reasoning CoT & Assessment| TELE
    CORR -->|Source Code Vulnerability| PROP
    PROP -->|Approve via Telegram| TELE
    OS --> GRAF
    AI_COPILOT -->|Token Metrics Stream| GRAF
```

---

## 💎 ĐIỂM SÁNG CÔNG NGHỆ ĐỘT PHÁ

### 1. Thuật toán Khử Trùng Lặp Cửa Sổ Trượt (Sliding Window Deduplication 300s)
* **Vấn đề:** Khi kẻ tấn công brute-force SSH hoặc flood HTTP hàng nghìn request/phút, SIEM sinh bão cảnh báo (Alert Fatigue), làm nghẽn hàng đợi webhook và quá tải API thiết bị mạng.
* **Giải pháp:** Sử dụng SQLite chế độ WAL (Write-Ahead Logging) theo dõi cặp khóa `(src_ip, rule_id)` trong cửa sổ 5 phút. Alert đầu tiên được chuyển đi ngay để cấm biên; các alert tiếp theo chỉ tăng bộ đếm tần suất (`count += 1`), triệt tiêu hơn 95% tải thừa.

### 2. Bộ Lọc Bảo Vệ IP Nội Địa & Phân Đoạn Luồng Ingress
* **Vấn đề:** Các nhà mạng di động 4G tại Việt Nam dùng chung dải CGNAT (hàng ngàn người chung 1 IP public). Ngoài ra, các dịch vụ đứng sau Cloudflare Tunnel hoặc Load Balancer nếu bị chặn nhầm IP nguồn sẽ làm sập toàn bộ người dùng hợp lệ.
* **Giải pháp:** 
  - **Tách bạch Cảm biến vs Mục tiêu:** Nhận diện traffic từ Suricata SPAN port để không bao giờ chạy lệnh chặn vô tác dụng lên node Security Onion.
  - **Cloudflare Tunnel Aware:** Tuyệt đối không dùng `iptables DROP` trên máy chủ Master (tránh đứt tunnel `127.0.0.1`), thay vào đó khóa qua Cloudflare WAF + FortiGate Threat Feed.
  - **Load Balancer Aware:** Dịch vụ sau Load Balancer được chặn qua CrowdSec tại tầng Gateway, không chặn tại Web Backend Node.

### 3. FIM Phân Tầng Chọn Lọc (Tiered Integrity - Vượt Ngưỡng Rule 233)
* **Vấn đề:** Wazuh mặc định giới hạn 100.000 file trong Syscheck database. Quét toàn bộ Web Root WordPress/Drupal sẽ làm Agent chạm ngưỡng Rule 233 và tự ngắt bảo vệ.
* **Giải pháp:** Dùng thuộc tính `restrict` chỉ theo dõi các định dạng thực thi nguy hiểm (`.php`, `.aspx`, `.jsp`, `.dll`, `.sh`) và đưa thư mục dữ liệu tĩnh (`uploads/`, `cache/`) vào `<ignore>`, giảm từ 1.000.000 file xuống dưới 5.000 file trọng yếu, duy trì CPU Agent dưới 3%.

### 4. Quản Trị Quota AI, Chống Rate Spike & Token Metrics Hub
* **Vấn đề:** Chi phí token LLM và nguy cơ cạn kiệt Quota trượt khi hệ thống tự động chạy 24/7.
* **Giải pháp:**
  - Tích hợp **Google Antigravity CLI** (`agy`) chạy model **Gemini 3.8 Flash** với chế độ **Adaptive Effort**: Mặc định `low` (Turbo 3–4s, tiết kiệm token tối đa); tự động nâng `medium` khi Audit Source Code / Forensics.
  - Theo dõi cửa sổ trượt 5 giờ (1.5M tokens / 300 calls) và tuần (15M tokens / 3.000 calls).
  - Tự động phát hiện bất thường Rate Spike (>12 calls/phút) và trực quan hóa toàn bộ số liệu tiêu thụ token trên Grafana Dashboard.

### 5. Quy Trình Vá Mã Nguồn An Toàn HITL (Safe Code Remediation)
* **Vấn đề:** Tự động sửa code khi phát hiện lỗ hổng IDOR/WebShell có rủi ro gây sập ứng dụng (Application Downtime).
* **Giải pháp:** 
  - Quy trình 4 bước chuẩn: **Assess $\rightarrow$ Propose $\rightarrow$ Patch with Backup $\rightarrow$ Verify & Rollback**.
  - Tự động tạo bản sao lưu có timestamp (`Backup_Security_YYYYMMDD_HHMMSS`) trước khi ghi đè file.
  - Chạy script kiểm thử POC tự động và cho phép Admin rollback 1 lệnh qua Telegram.

---

## 🧠 MÔ HÌNH HYBRID: "DETERMINISTIC ACTION, GENERATIVE REASONING"

Để triển khai AI vào SOC production mà **không bao giờ lo sợ rủi ro AI ảo giác (Hallucination) gây gián đoạn hạ tầng**, hệ thống phân định rạch ròi 2 tầng:

| Thành phần | Vai trò | Cơ chế thực thi |
| :--- | :--- | :--- |
| **Hành Động (Action)** | **Cảnh sát thi hành công vụ** | **100% Code Python (Tất định / Deterministic):** Tự động lọc Whitelist, kiểm tra ngưỡng cảnh báo (Level $\ge 12$, số lượt quét $\ge 500$), thực thi lệnh Host Drop (`agent_control -b`) và nạp vào FortiGate Threat Feed trong 0.2s. |
| **Suy Luận (Reasoning)** | **Chuyên gia phân tích / Tham mưu** | **Google Gemini 3.8 Flash:** Đọc ngữ cảnh đã được tinh gọn, suy luận xâu chuỗi chuỗi tấn công (Cyber Kill Chain), phân tích xem là Botnet quét hàng loạt hay APT có chủ đích, và sinh bản báo cáo CoT cho kỹ sư trực ca. |

---

## 🏛️ KIẾN TRÚC TOÀN DIỆN & ĐẶC TẢ KỸ THUẬT V2.6

Tài liệu đặc tả chi tiết kiến trúc, thiết kế 5 tầng phòng thủ, cơ chế Token Hub & Quota trượt, cùng lộ trình kỹ thuật:
👉 [**docs/agentic_ai_architecture_and_roadmap.md**](docs/agentic_ai_architecture_and_roadmap.md)  
👉 [**docs/architecture_design.md**](docs/architecture_design.md)

---

## 📁 CẤU TRÚC THƯ MỤC REPOSITORY

```text
enterprise-wazuh-soc-soar/
├── README.md                                 # Tài liệu kiến trúc tổng thể v2.6
├── .gitignore                              # Đã cấu hình chặn 100% secrets, raw logs & DBs
├── .env.example                             # Mẫu biến môi trường an toàn (Zero-Secret)
├── docs/                                    
│   ├── agentic_ai_architecture_and_roadmap.md # 🏛️ Kiến trúc toàn diện & đặc tả kỹ thuật v2.6
│   ├── architecture_design.md               # Thiết kế chi tiết kiến trúc
│   ├── threat_taxonomy_matrix.md            # Ma trận phân loại đe dọa CAT1 - CAT6
│   └── learn.md                             # Kinh nghiệm vận hành thực tế
├── ai_soc_copilot/                          # Bộ não Agentic AI & Reasoning Engine
│   ├── soc_ai_reasoning_engine.py           # Cầu nối Antigravity CLI, Quota & Token Metrics Hub
│   ├── soc_agentic_scheduler.py             # Bộ điều phối tự động tương quan sự kiện 20 phút
│   ├── soc_action_dispatcher.py             # Bộ điều phối hành động phản kháng đa tầng (AR)
│   ├── soc_proposal_manager.py              # Bộ quản lý đề xuất vá HITL (PROP-xxx)
│   ├── agentic_threat_hunter.py             # Săn tìm RCE, WebShell, Exfiltration & Campaign 24h
│   ├── copilot_server.py                    # Server API Copilot
│   ├── widget_frontend.js                   # Web widget đàm thoại an ninh
│   └── guardrails.md                        # Quy tắc an toàn nghiêm ngặt
├── soar_automation/                         # Tự động hóa phản ứng chu vi & Báo cáo
│   ├── generate_daily_soc_report.py         # Pipeline trích xuất telemetry & báo cáo an ninh 24h
│   ├── soc_rule_tuner_24h.py                # Tự động tinh chỉnh core rules & kiểm thử wazuh-logtest
│   ├── threat_feed_service.py               # External Dynamic Threat Feed Gateway (Port 8088)
│   └── shuffle_active_response.py           # Webhook tích hợp Shuffle SOAR
├── detection_rules/                         # Tập luật phát hiện chuẩn MITRE ATT&CK
│   └── local_rules.xml                      # Ruleset tùy biến chống RCE, WebShell, SEO Cloaking
├── visualization_grafana/                   # Dashboard trực quan hóa
│   ├── soc_ultimate_4w_dashboard.json       # Dashboard điều hành 4W
│   └── silent_background_update.css         # CSS chống chớp màn hình SOC Wall
└── deploy_automation/                       # Tự động hóa triển khai & khắc phục sự cố
    ├── deploy_wazuh_agent.sh                # Triển khai Agent tự động
    └── playbooks/                           # Ansible playbooks
        ├── install_agent.yml
        ├── check_status.yml
        ├── scan_webshell.yml
        ├── remediate_seo_malware.yml        # Kịch bản dọn sạch malware & khôi phục w3wp.exe
        └── patch_cve_packages.yml
```

---

## 🚀 HƯỚNG DẪN TRIỂN KHAI & KHỞI CHẠY

### 1. Yêu cầu hệ thống
* Hệ điều hành: Ubuntu 22.04 / 24.04 LTS hoặc RHEL 8 / 9.
* Wazuh Manager v4.9+ & OpenSearch Telemetry Cluster.
* Python 3.10+ (cài đặt: `pip install requests fastapi uvicorn maxminddb`).
* Google Antigravity CLI (`agy`) đã cấu hình OAuth.

### 2. Các bước cấu hình nhanh
```bash
# 1. Clone repository
git clone https://github.com/vuongnguyen1/vnu-soc-soar-platform.git
cd vnu-soc-soar-platform

# 2. Cấu hình biến môi trường
cp .env.example .env
nano .env

# 3. Kích hoạt Scheduler điều phối tương quan an ninh AI (chạy ngầm mỗi 20 phút)
crontab -e
# Thêm dòng:
# */20 * * * * /usr/bin/python3 ai_soc_copilot/soc_agentic_scheduler.py >> /var/log/soc_scheduler.log 2>&1

# 4. Khởi chạy External Dynamic Threat Feed Server cho FortiGate (Cổng 8088)
python3 soar_automation/threat_feed_service.py --daemon
```

---

## 📄 BẢN QUYỀN
Phát hành theo giấy phép [MIT License](LICENSE).
