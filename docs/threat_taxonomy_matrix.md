# THREAT TAXONOMY MATRIX (MA TRẬN PHÂN LOẠI ĐE DỌA CAT1 - CAT6)

Hệ thống SOC áp dụng mô hình phân loại đe dọa 6 nhóm (Threat Taxonomy) kết hợp với framework **MITRE ATT&CK** nhằm chuẩn hóa quy trình phát hiện, tính toán độ nghiêm trọng và tự động hóa phản ứng biên.

---

## 1. BẢNG TỔNG QUAN PHÂN LOẠI 6 NHÓM ĐE DỌA

| Mã Nhóm | Tên Phân Loại | Kỹ thuật / Hành vi điển hình | Mức Cảnh Báo (Level) | Phản ứng SOAR / Tường lửa |
|:---|:---|:---|:---:|:---|
| **CAT1** | **Web Application Exploit** | SQL Injection (`UNION SELECT`, `SLEEP()`), Cross-Site Scripting (`<script>`), Remote Code Execution (`eval()`, `cmd.exe`), Webshell upload (`.php`, `.aspx`). | **10 - 14** (High / Critical) | **Permanent Block** (Cấm vĩnh viễn trên FortiGate) sau ngưỡng 3 lần vi phạm. |
| **CAT2** | **Credential Access & Brute-Force** | Dò quét mật khẩu SSH port 22, RDP port 3389, FTP, Nginx Basic Auth, WordPress wp-login. | **6 - 10** (Medium / High) | **Temporary Ban (1h - 24h)**. Tái phạm nhiều lần tự động chuyển sang Permanent Block. |
| **CAT3** | **Denial of Service (DoS / DDoS L7)** | HTTP Request Flooding, Slowloris, XML-RPC Pingback amplification, TCP SYN Flood. | **8 - 12** (High) | Kích hoạt rate-limiting WAF, cách ly IP vi phạm tại Firewall Policy. |
| **CAT4** | **Host Compromise & Persistence** | Thay đổi tệp nhị phân hệ thống, nạp DLL độc hại không chữ ký vào web service (`w3wp.exe`), tạo user ẩn, SEO Cloaking / Gambling App Redirect. | **12 - 15** (Critical) | Báo động đỏ Telegram khẩn cấp, cô lập máy chủ (Host Isolation), bảo lưu chứng cứ FIM. |
| **CAT5** | **Reconnaissance & Vulnerability Scanning** | Quét cổng Masscan/Nmap, dò quét công cụ tự động (Nikto, Nuclei, Acunetix, sqlmap, gobuster). | **6 - 8** (Medium) | Ghi nhận IP vào danh sách giám sát (Watchlist), kích hoạt bẫy Honeypot. |
| **CAT6** | **Network & Perimeter Infrastructure** | Vi phạm chính sách truy cập tường lửa FortiGate, dò quét cổng VPN/IPSec, spoofing IP, ARP poisoning. | **7 - 10** (High) | Cấm biên tức thì tại lớp tường lửa biên phòng thủ. |

---

## 2. CHI TIẾT KỸ THUẬT CÁC QUY TẮC NGUY CẤP

### 2.1. Nhóm CAT1: Web Exploit & Webshell Injection
* **Rule 100934 (Level 10):** SQL Injection Detection (So khớp các từ khóa độc hại `UNION SELECT`, `INFORMATION_SCHEMA`, `WAITFOR DELAY`, comment tricks `/**/`).
* **Rule 100933 (Level 12):** Remote Code Execution (RCE) / Command Injection (Phát hiện chuỗi lệnh hệ thống: `whoami`, `/bin/bash`, `powershell -enc`, `nc -e`).
* **Rule 100932 (Level 8):** Cross-Site Scripting (XSS) (Phát hiện chuỗi tiêm thẻ: `<script>`, `javascript:`, `onerror=`).

### 2.2. Nhóm CAT4: SEO Cloaking & Gambling App Redirect
* **Rule 100964 & 100966 (Level 14):** Phát hiện lưu lượng redirect ứng dụng cờ bạc trực tuyến dựa trên phân tích Header User-Agent di động kết hợp URL chứa mã khóa app lậu (`openInstallAppKey`, `inviteType`, `mmh2rv`).
* **Rule 100971 (Level 14):** Sysmon Event 7 - Giám sát chữ ký số của DLL nạp vào tiến trình web `w3wp.exe`. Mọi thư viện không có chữ ký số của Microsoft đều bị chặn và báo động.
