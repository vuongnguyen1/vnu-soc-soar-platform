# KIẾN TRÚC TỔNG THỂ HỆ THỐNG WAZUH SIEM & SOAR AUTOMATION

Tài liệu mô tả kiến trúc kỹ thuật 4 lớp (Multi-Tier Defense Architecture) của trung tâm giám sát và tự động phản ứng sự cố an toàn thông tin (SOC SIEM / SOAR).

---

## 1. SƠ ĐỒ LUỒNG DỮ LIỆU TÁC CHIẾN (END-TO-END FLOW)

```mermaid
flowchart TD
    subgraph SENSORS ["1. SENSORS & LOG COLLECTION LAYER"]
        A1[Linux Servers\nNginx, SSH, Syslog] -->|rsyslog / Agent| WAZUH_SRV
        A2[Windows Servers\nIIS, EventLog, Sysmon] -->|Wazuh Agent WinRM| WAZUH_SRV
        A3[Boundary Firewalls\nFortiGate Syslog] -->|Port 514 UDP| WAZUH_SRV
    end

    subgraph ENGINE ["2. SIEM CORE & DETECTION ENGINE"]
        WAZUH_SRV[Wazuh Manager\nDecoders & Rule Engine]
        WAZUH_SRV -->|Alert Events| INDEXER[(OpenSearch / Wazuh Indexer\nDistributed Cluster)]
        WAZUH_SRV -->|Level >= 8 Alerts| INTEGRATION[Active Response Integration\nshuffle.py]
    end

    subgraph SOAR ["3. SOAR AUTOMATION & BOUNDARY ENFORCEMENT"]
        INTEGRATION --> DEDUP{Sliding Window\nDeduplication 300s}
        DEDUP -->|Duplicate in 5m| DROP_ALERT[Count +1 / Ignore]
        DEDUP -->|New Threat IP| GEO_CHECK{MaxMind GeoIP\nCGNAT Safeguard}
        GEO_CHECK -->|Vietnam IP| HITL[Human-in-the-Loop\nTelegram Approval]
        GEO_CHECK -->|Foreign Attacker| FORTI_API[FortiGate REST API\nAdd to AUTO_SOC_BLACKLIST]
        FORTI_API --> TELEGRAM[Telegram SOC Alert\nInstant Notification]
    end

    subgraph VISUAL ["4. MISSION CONTROL & AI COPILOT"]
        INDEXER --> GRAFANA[Grafana 12 Mission Control\n4W Multi-Dimensional Dashboard]
        GRAFANA --> STALE[Stale-While-Revalidate\nSilent Background Update Engine]
        AI_BOT[socduac AI Copilot\nGoogle Gemini Flash] <-->|Contextual Advisory| GRAFANA
    end
```

---

## 2. PHÂN TÍCH CHI TIẾT CÁC LỚP BẢO VỆ

### Lớp 1: Thu thập nhật ký & Cảm biến giám sát (Sensors & Log Collection)
* Hỗ trợ đa nền tảng: Linux (Ubuntu, Debian, CentOS), Windows Server (IIS 8.5/10), thiết bị mạng tường lửa (FortiGate, Cisco).
* Thu thập chuyên sâu:
  - **Sysmon (System Monitor):** Giám sát Process Creation (Event 4688 với dòng lệnh chi tiết), Image Loading (Event 7 kiểm tra chữ ký số DLL), Network Connection (Event 3).
  - **Web Access Logs:** Phân tích thời gian thực request log Nginx, Apache và W3C Format trên IIS.
  - **FIM Phân tầng (Tiered Integrity):** Giám sát tính toàn vẹn tệp tin có chọn lọc bằng cờ `restrict` để ngăn chặn bão hòa dung lượng (Rule 233).

### Lớp 2: Lõi phân tích & Luật phát hiện (Detection Engineering)
* Phân tích tương quan sự kiện với hơn 70.000 dòng luật tùy biến.
* Mô hình phân loại 6 nhóm nguy cơ (**CAT1 - CAT6**) ánh xạ chuẩn MITRE ATT&CK.
* Ghi dữ liệu thời gian thực vào OpenSearch/Elasticsearch cluster phân tán.

### Lớp 3: Tự động hóa phản ứng biên (SOAR & Boundary Defense)
* **Khử trùng lặp cửa sổ trượt (Sliding Window Deduplication 300s):**
  - Sử dụng SQLite WAL cục bộ với khóa kép `(src_ip, rule_id)`.
  - Triệt tiêu 95% lưu lượng cảnh báo trùng lặp khi kẻ tấn công thực hiện dội bom yêu cầu (Flooding).
* **Bảo vệ IP nội địa (CGNAT Safeguard):**
  - Tích hợp MaxMind GeoLite2 City & ASN database.
  - Phân tách tuyệt đối giữa IP nước ngoài và IP trong nước, đảm bảo không bao giờ tự động chặn nhầm các dải CGNAT của nhà mạng 4G Viettel, VNPT, FPT.
* **Tự động chặn biên tường lửa (Boundary Enforcement):**
  - Gọi REST API trực tiếp đến FortiGate (`FG300D`, `FG200F`) đưa IP vào nhóm `AUTO_SOC_BLACKLIST`.
  - Hỗ trợ chế tài: Cấm tạm thời (Temporary Ban) và Cấm vĩnh viễn (Permanent Drop).

### Lớp 4: Trực quan hóa & Trợ lý ảo AI (Mission Control & AI Copilot)
* **Mô hình chu trình điều tra 4W:**
  - **Who:** Kẻ tấn công là ai? (Top IP Nguồn, Quốc gia, ASN).
  - **Where:** Máy chủ nào bị tấn công? (Top Wazuh Agent).
  - **Which Service:** Cổng dịch vụ / Domain nào bị nhắm tới? (HTTP, SSH, RDP).
  - **What Action:** Đe dọa là gì và chế tài xử lý ra sao? (Phân loại CAT1-CAT6, Drop/Deny).
* **Động cơ Silent Background Update:**
  - Vô hiệu hóa chớp nháy và thanh loading xoay tròn, giữ ổn định 100% bố cục trang hiển thị trên SOC Wall.
* **AI Copilot (socduac / ChatBotDUAC):**
  - Trợ lý AI đàm thoại đa lượt (Google Gemini Flash).
  - Thiết lập nghiêm ngặt: **Strict Read-Only & Zero-Mutation** (Chỉ đọc log & cố vấn tham mưu, không tự ý thay đổi hạ tầng).
