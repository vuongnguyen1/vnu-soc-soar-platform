# 🎯 VNU SOC INTERVIEW MASTER CHEATSHEET
## Kiến Trúc Hệ Thống & Bộ Câu Hỏi Phỏng Vấn Chuyên Sâu (Senior SecOps / DevSecOps / AI Security Architect)

> **Tài liệu đúc kết kinh nghiệm thiết kế & vận hành thực tế hệ thống VNU Enterprise True Agentic AI SOC & SOAR Platform.**  
> Dành riêng cho các buổi phỏng vấn kỹ thuật cấp cao, chứng minh năng lực giải quyết các bài toán hạ tầng quy mô lớn, an toàn vận hành và ứng dụng AI thực chất (không vẽ vời lý thuyết).

---

## 🏛️ PHẦN 1: BỨC TRANH KIẾN TRÚC TỔNG THỂ (ELEVATOR PITCH 2 PHÚT)

**Câu hỏi phỏng vấn:** *"Hãy giới thiệu về dự án an ninh mạng ấn tượng nhất mà bạn từng thiết kế và triển khai?"*

**Cách trả lời ghi điểm:**
> "Tôi đã thiết kế và vận hành hệ thống **Enterprise True Agentic AI SOC & SOAR Platform** cho cụm hạ tầng 29+ máy chủ (Linux, Windows Server, Cổng Đào tạo, Tuyển sinh, Keycloak IDP, Mail Server) tiếp nhận hàng triệu kết nối mỗi ngày.  
> Hệ thống kết hợp giữa **Wazuh SIEM Core**, **Suricata NIDS SPAN Port**, cụm tường lửa **FortiGate**, và **Google Antigravity AI Engine (Gemini 3.8 Flash)**.  
> Điểm đột phá lớn nhất của dự án là giải quyết triệt để 5 bài toán hóc búa của SOC truyền thống:
> 1. **Triệt tiêu bão cảnh báo (Alert Fatigue)** bằng thuật toán cửa sổ trượt Sliding Window 300s.
> 2. **Chống tự bắn vào chân mình (DoS nội bộ)** nhờ cơ chế Ingress Awareness (phân biệt IP Cloudflare Tunnel / Load Balancer / CGNAT 4G).
> 3. **Mô hình Hybrid Agentic AI**: *Deterministic Action, Generative Explanation* — Hành động chặn bằng code cứng an toàn 100%, AI phụ trách xâu chuỗi phân tích ngữ nghĩa (Kill Chain).
> 4. **Kiểm soát chi phí Token AI**: Quản lý Quota trượt 5 giờ & 7 ngày, phát hiện Rate Spike theo thời gian thực đưa lên Grafana Dashboard.
> 5. **Human-in-the-Loop (HITL) Source Patching**: Tự động sinh Proposal vá lỗ hổng (IDOR, WebShell) kèm cơ chế tự động Backup và Rollback trong 1 lệnh."

---

## 🧠 PHẦN 2: CÁC BÀI TOÁN KỸ THUẬT NỔI BẬT & GIẢI PHÁP THỰC CHIẾN

### 1. Kiến trúc Hybrid: "Deterministic Action, Generative Explanation"
* **Vấn đề khi phỏng vấn:** *"Tại sao bạn không để LLM (Gemini) tự động gọi tool và tự quyết định ban IP hay cô lập máy chủ hoàn toàn tự động?"*
* **Câu trả lời chuẩn Senior:**
  - **Rủi ro của Pure Autonomous Agent trong môi trường mạng thực:** LLM có thể bị **ảo giác (hallucination)** hoặc bị tấn công **Prompt Injection** qua payload log (ví dụ: User-Agent chứa lệnh inject). Nếu để LLM tự bấm nút ban IP ngầm, nó có thể chặn nhầm IP của Default Gateway, Core Switch, DNS 8.8.8.8 hoặc IP của Load Balancer làm sập toàn bộ dịch vụ mạng.
  - **Giải pháp của chúng tôi:** 
    - **Tầng Hành động (Action) là Tất định (Deterministic):** Code Python kiểm tra Whitelist, kiểm tra ngưỡng cảnh báo (Level >= 12, số lần quét >= 500), xác minh IP công cộng hợp lệ và tự động kích hoạt lệnh ban (Host AR + FortiGate Threat Feed).
    - **Tầng Suy luận (Reasoning) là Tạo sinh (Generative):** Gemini 3.8 Flash được cấp dữ liệu đã được tổng hợp để suy luận bản chất chiến dịch (Botnet quét hàng loạt CVE hay APT tấn công có chủ đích), viết tóm tắt CoT và diễn giải lý do cho đội trực ca SOC.

---

### 2. Quản Trị Quota AI, Chống Cạn Kiệt Token & Rate Spike Alert
* **Vấn đề khi phỏng vấn:** *"Làm sao bạn kiểm soát chi phí token và tránh bị API Rate Limit khi hàng triệu log đổ về?"*
* **Câu trả lời chuẩn Senior:**
  - **Không gọi AI thô trên từng log:** Chỉ kích hoạt AI trong 2 trường hợp: (1) Chu kỳ tương quan 20 phút khi phát hiện Cyber Kill Chain thực sự; (2) Khi Admin chủ động truy vấn qua Telegram.
  - **Tối ưu Prompt Token:** Dùng script tiền xử lý (`agentic_threat_hunter.py`) rút gọn log từ hàng chục KB xuống chỉ còn vài dòng JSON tóm tắt, giảm ~85% token đầu vào.
  - **Bộ đếm Quota trượt (Rolling Window):** Mô phỏng chính xác thuật toán Quota của Google AI (Hạn mức trượt 5 giờ: 1.5M tokens / 300 calls; Hạn mức tuần: 15M tokens / 3.000 calls).
  - **Phát hiện Rate Spike:** Nếu có hơn 12 lượt gọi AI trong 1 phút, hệ thống tự động gắn cờ cảnh báo `rate_spike_detected` và hiển thị trên Dashboard Grafana AI Hub.

---

### 3. Phân Đoạn Luồng Ingress & Chống Khóa Nhầm Hạ Tầng (Ingress-Aware SOAR)
* **Vấn đề khi phỏng vấn:** *"Một kẻ tấn công nhắm vào dịch vụ Web đứng sau Cloudflare hoặc Load Balancer, nếu SOAR tự động ban IP thì làm sao không làm sập người dùng khác?"*
* **Câu trả lời chuẩn Senior:**
  - Chúng tôi xây dựng ma trận phân loại luồng Ingress nghiêm ngặt:
    1. **Sensor SPAN Port vs Victim Target:** Khi Suricata trên Security Onion báo động, đó là cảm biến thụ động (Mirror traffic). Cấm tuyệt đối chạy lệnh chặn trên máy Security Onion vì vô tác dụng. Mục tiêu thực sự được bóc tách từ `data.dstip`.
    2. **Dịch vụ đi qua Cloudflare Tunnel (`conphong.io.vn`):** Traffic nội bộ đều có IP `127.0.0.1`. Cấm dùng `iptables DROP` trên máy chủ (sẽ làm đứt tunnel Cloudflare). Hành động đúng: Khóa IP trên Cloudflare WAF + Đẩy vào FortiGate Threat Feed.
    3. **Dịch vụ sau Load Balancer (IDP Keycloak):** Cấm drop IP trên backend web node vì sẽ chặn nhầm IP của Load Balancer. Hành động đúng: Chặn tại tầng Load Balancer qua CrowdSec và tường lửa biên FortiGate.
    4. **Dịch vụ trực tiếp (Direct Exposed):** Áp dụng song song Host AR (Wazuh `firewall-drop`) và FortiGate Threat Feed.

---

### 4. Quy Trình Vá Mã Nguồn An Toàn HITL (Safe Code Remediation)
* **Vấn đề khi phỏng vấn:** *"Khi phát hiện lỗ hổng ứng dụng (như IDOR hoặc WebShell), hệ thống tự động xử lý như thế nào mà không làm hỏng source code của khách hàng?"*
* **Câu trả lời chuẩn Senior:**
  - Chúng tôi tuân thủ quy trình 4 bước: **Assess $\rightarrow$ Propose $\rightarrow$ Patch with Backup $\rightarrow$ Verify & Rollback**:
    1. **Tách biệt quyền tự động:** Chặn IP / Kill tiến trình độc hại là 100% tự động; còn sửa file mã nguồn bắt buộc phải qua **Human-in-the-Loop (HITL)**.
    2. **Tạo Proposal:** AI phân tích lỗ hổng, sinh mã `PROP-YYYYMMDD-XXX` kèm diff code chính xác từng dòng.
    3. **Tự động sao lưu có timestamp:** Khi Admin duyệt qua Telegram (`approve`), script tự tạo thư mục `Backup_Security_YYYYMMDD_HHMMSS` trước khi ghi đè tệp tin.
    4. **Chạy POC kiểm thử tự động:** Tự động chạy script kiểm tra (ví dụ `verify_patch_poc.py`). Nếu có sự cố, Admin chỉ cần 1 lệnh rollback tức thì (`rollback.ps1` hoặc `rollback.sh`).

---

### 5. Tối Ưu FIM Vượt Ngưỡng Giới Hạn Wazuh Rule 233
* **Vấn đề khi phỏng vấn:** *"Làm thế nào để giám sát toàn vẹn tệp tin (FIM) trên máy chủ Web chứa hàng triệu file source/media mà không làm tràn bộ nhớ Agent?"*
* **Câu trả lời chuẩn Senior:**
  - Wazuh mặc định giới hạn 100.000 file trong Syscheck database. Quét toàn bộ thư mục Web sẽ làm Agent chạm ngưỡng Rule 233 và tự ngắt.
  - Chúng tôi áp dụng chiến lược **Tiered FIM (Phân tầng chọn lọc)**:
    - Sử dụng tham số `restrict="\.php$|\.aspx$|\.jsp$|\.py$|\.sh$|\.dll$"` chỉ theo dõi các định dạng file thực thi nhạy cảm.
    - Đưa toàn bộ các thư mục tĩnh (`uploads/`, `cache/`, `media/`, `tmp/`) vào danh sách `<ignore>`, giảm tải từ 1.000.000 tệp xuống chỉ còn dưới 5.000 tệp trọng yếu, duy trì CPU Agent dưới 3%.

---

## 💬 PHẦN 3: TỔNG HỢP CÂU HỎI PHỎNG VẤN NHANH (QUICK-FIRE Q&A)

| Câu hỏi | Trọng tâm trả lời |
| :--- | :--- |
| **Q1: Bạn dùng model AI nào và tại sao?** | Dùng **Gemini 3.8 Flash** thông qua Google Antigravity CLI chính thức (`agy`). Lý do: Độ trễ siêu thấp (3–4s ở mode turbo), context window lớn (1M tokens), chi phí tối ưu và suy luận bảo mật vượt trội. |
| **Q2: Làm sao hệ thống tương quan được cuộc tấn công diễn ra trong nhiều giờ?** | Module `ip-campaign-hunt` trong `agentic_threat_hunter.py` quét OpenSearch theo cửa sổ trượt 24h, gom cụm toàn bộ event theo từng IP nguồn và máy chủ nạn nhân, tự động nhận diện chuỗi chiến thuật MITRE ATT&CK (Recon $\rightarrow$ Exploit $\rightarrow$ C2). |
| **Q3: Cơ chế nào đảm bảo không bị lộ mật khẩu trong hệ thống phân tán?** | Nguyên tắc **Zero-Secret & Auto-Elevation**: Không lưu mật khẩu trong code, toàn bộ credentials được lưu tại tệp bảo mật `chmod 600`, remote runner tự động bọc quyền sudo/admin ngầm và không bao giờ xuất mật khẩu ra stdout/Telegram. |
| **Q4: Thiết bị chu vi FortiGate nạp danh sách chặn bằng cách nào để không bị tràn RAM?** | Sử dụng **External Threat Feed (Dynamic Blocklist)** qua cổng 8088. FortiGate đọc danh sách IP từ HTTP feed định kỳ và lưu trên bảng RAM độc lập, không tạo lẻ Object Address vào CMDB tránh gây Memory Leak. Áp dụng vòng đời **Aging 30 ngày** tự giải phóng IP hết thời hạn. |
