# BÀI HỌC KIẾN TRÚC & PHÂN TÍCH TÁC CHIẾN SOC: FORTIGATE NGFW VS WAF CHUYÊN DỤNG

> **Chủ đề:** Đánh giá logic luồng dữ liệu (traffic flow) qua FortiGate từ Layer 3/4 đến Layer 7; Lý do vì sao phải có WAF mới ngăn chặn được tấn công chèn (inject) link cờ bạc mà FortiGate không thể drop ngay lần đầu.

---

## 1. LOGIC TRAFFIC ĐI QUA FORTIGATE (TỪ LAYER NÀO QUA LAYER NÀO?)

Khi một gói tin từ Internet đi vào hệ thống máy chủ ứng dụng qua FortiGate, nó được xử lý tuần tự theo mô hình thẩm định từng lớp:

```
[ Internet Traffic ]
        │
        ▼ (Layer 3 - Network Layer)
  1. IP Filter & Threat Feed (ISDB, IP Blocklist, GeoIP)
        │
        ▼ (Layer 4 - Transport Layer)
  2. TCP/UDP State & Port (SYN check, Session Table, DoS/DDoS drop)
        │
        ▼ (Layer 4 -> Layer 7 Gateway)
  3. NAT & Firewall Policy Matching
        │
        ▼ (Tầng mù: Bắt tay mã hóa HTTPS / TLS 1.3 - Port 443)
  4. SSL/TLS Negotiation (SNI Inspection)
        │
        ├─► [Nếu KHÔNG có Full SSL Inspection]: Chỉ thấy IP:Port và SNI domain ──► Chuyển tiếp thẳng vào Web Server!
        │
        ▼ (Nếu CÓ SSL Inspection / Offloading)
  5. Layer 7 Security Profiles (IPS Engine, Antivirus, Web Filter)
        │
        ▼
  [ Web Server / Ứng Dụng ]
```

### Chi tiết các tầng kiểm soát:

1. **Tầng Layer 3 (Network Layer) & Layer 4 (Transport Layer):**
   - **Cơ chế:** FortiGate đối soát IP nguồn, IP đích, cổng dịch vụ (TCP 443/80), bảng trạng thái kết nối (Stateful Inspection).
   - **Khả năng chặn:** Chặn cực tốt các đợt tấn công hạ tầng mạng: DDoS SYN Flood, UDP Flood, ICMP Flood, quét cổng (Port scan), hoặc chặn **các IP độc hại đã biết trước** nằm trong danh sách đen (`Threat Feed / vnu_soc_blocklist.txt`).
   - **Hạn chế:** Các cuộc tấn công chèn link cờ bạc **đều đi qua cổng HTTPS 443 hợp lệ** và thiết lập bắt tay TCP 3 bước hoàn toàn chuẩn mực. Ở Layer 3/4, FortiGate nhìn nhận đây là một phiên duyệt web bình thường từ người dùng Internet.

2. **Tầng Layer 7 (Application Layer - Security Profiles):**
   - FortiGate tích hợp các module L7 như **IPS (Intrusion Prevention System)**, **Antivirus (Flow/Proxy AV)**, **Web Filtering**.
   - Tuy nhiên, khả năng phát hiện ở L7 của FortiGate bị giới hạn nghiêm ngặt bởi rào cản mã hóa HTTPS và tính chất logic của ứng dụng web.

---

## 2. VÌ SAO FORTIGATE KHÔNG DROP NGAY LẦN ĐẦU? CÓ PHẢI FORTIGATE KHÔNG CÓ RULE?

**Khẳng định:** Không phải FortiGate không có rule, mà FortiGate gặp **3 điểm mù mang tính bản chất kỹ thuật** của tường lửa mạng (Network Firewall):

### 2.1. "Điểm mù" mã hóa HTTPS (The SSL/TLS Blindspot)
- 99% website hiện đại chạy HTTPS (TLS 1.2 / TLS 1.3). Toàn bộ nội dung gói tin (URL path, Query string, Header, Cookie, POST Body chứa mã độc, nội dung inject) **đều bị mã hóa đầu-cuối** giữa Trình duyệt của kẻ tấn công và Web Server.
- Khi FortiGate chỉ chạy ở chế độ tiêu chuẩn (**Certificate Inspection** - chỉ đọc tên miền SNI trong bản tin Client Hello):
  - FortiGate **hoàn toàn "mù"** đối với nội dung HTTP bên trong đường truyền.
  - Do đó, **dù FortiGate có hàng nghìn rule IPS xịn nhất, nó cũng không thể quét được payload** vì không có dữ liệu dạng bản rõ (plaintext).
- *Yêu cầu để FortiGate đọc được:* Phải bật **Deep SSL Inspection** (giải mã SSL tại firewall). Nhưng việc này đòi hỏi cấu hình SSL Offloading phức tạp, tiêu tốn năng lượng phần cứng cực lớn và dễ gây lỗi bắt tay giao thức đối với các trình duyệt client bên ngoài Internet.

### 2.2. Bản chất của tấn công "Inject Link Cờ Bạc" không phải là tấn công mạng
Kẻ tấn công không sử dụng các chuỗi mã nhị phân nguy hiểm (shellcode thô) làm sập hệ điều hành, mà chúng khai thác theo các kịch bản mang tính **logic ứng dụng web**:
- **Kịch bản 1 - SQL Injection (SQLi):** Kẻ tấn công gửi payload qua form tìm kiếm hoặc API:  
  `POST /api/news HTTP/1.1 ... search=' UNION SELECT 1, 'link-co-bac-88.com' INTO OUTFILE ...`  
  *Đối với FortiGate, đây chỉ là một chuỗi ký tự text thông thường trong body HTTP.*
- **Kịch bản 2 - Upload File mã độc ẩn giấu (Webshell/Polyglot):** Kẻ tấn công tải lên file ảnh `logo.png` nhưng bên trong có nhúng mã PHP/ASP.NET, hoặc khai thác lỗ hổng plugin WordPress (Elementor, WooCommerce, Formidable...) để ghi trực tiếp bài viết vào cơ sở dữ liệu.
- **Kịch bản 3 - Chiếm đoạt tài khoản Quản trị (Admin Takeover):** Kẻ tấn công dò được mật khẩu CMS (qua brute-force hoặc lộ credential), đăng nhập hợp lệ vào `/wp-admin` rồi dùng đúng chức năng soạn thảo CMS để đăng bài viết chứa link cờ bạc.  
  *Trường hợp này hoàn toàn KHÔNG CÓ signature tấn công nào; đối với mọi tường lửa mạng, đây là hành vi đăng bài viết hoàn toàn hợp lệ.*

### 2.3. Khác biệt cốt tử giữa Rule IPS của FortiGate và Rule của WAF
- **Rule của FortiGate IPS (Pattern-based Signatures):**
  - Quét tìm các chuỗi bytes cố định của các mã khai thác CVE đã công bố.
  - Hacker chỉ cần dùng các kỹ thuật né tránh cơ bản: URL Encoding (`%27%20UNION`), Base64, chẻ nhỏ tham số (Parameter Pollution), hoặc biến đổi cú pháp SQL là vượt qua (bypass) signature của FortiGate IPS.
- **Rule của WAF chuyên dụng (Semantic & Application Context):**
  - WAF sở hữu bộ phân tích cú pháp **AST (Abstract Syntax Tree)** và thư viện chuẩn hóa (Normalization Engine).
  - WAF giải mã qua nhiều tầng (URL decode ➔ Hex decode ➔ HTML entity decode ➔ De-obfuscation) rồi mới phân tích cấu trúc ngữ nghĩa câu lệnh SQL, cú pháp script XSS, cấu trúc JSON/XML, hay quyền hạn form POST.

---

## 3. BẢNG SO SÁNH NĂNG LỰC BẢO VỆ: FORTIGATE NGFW VS WAF CHUYÊN DỤNG

| Tiêu chí so sánh | FortiGate NGFW (Tường lửa mạng) | WAF Chuyên Dụng (Web App Firewall) |
| :--- | :--- | :--- |
| **Vị trí tác chiến chính** | **Layer 3, Layer 4** và một phần Layer 7 (Network IPS) | **Layer 7 chuyên sâu (HTTP/HTTPS Logic)** |
| **Khả năng đọc HTTPS** | Mù nếu không cấu hình Deep SSL Inspection | **Giải mã HTTPS trực tiếp** (Đứng trước Web Server/Reverse Proxy) |
| **Cơ chế nhận diện** | So khớp chuỗi mẫu cố định (Signatures thô) | Phân tích cú pháp ngữ nghĩa (AST Syntax Parser, Tokenizer, Regex L7) |
| **Xử lý Input / Payload** | Kiểm tra thô theo từng packet mạng | Giải mã nhiều lớp (URL/Base64/Unicode/Gzip), kiểm tra JSON, XML, Form-data, Cookies |
| **Chống SQLi / XSS** | Bắt được các chuỗi mẫu thô phổ biến | Bắt được cả các biến thể làm rối mã (Obfuscation), Blind SQLi, Stored XSS |
| **Giám sát tệp tải lên** | Quét virus tệp tin (File AV hash/signature) | Kiểm tra đuôi file kép (`.php.jpg`), MIME-type, Magic bytes, kích thước, quyền thực thi |
| **Phát hiện Bot & Brute-force** | Rate-limit số lượng kết nối TCP/SYN | Phân tích hành vi duyệt web, Device Fingerprinting, CAPTCHA, tần suất gọi URL |

---

## 4. MÔ HÌNH PHÒNG THỦ CHIỀU SÂU PHỐI HỢP TRONG VNU SOC

Không một thiết bị đơn lẻ nào có thể giải quyết toàn bộ bài toán an toàn thông tin. VNU SOC triển khai mô hình tác chiến phối hợp 4 giai đoạn khép kín:

```
[ Internet Hacker / Botnet ] 
             │
             ▼ (Giai đoạn 1: FortiGate L3/L4 Perimeter)
   [ Tường Lửa FortiGate ] ──► Chặn ngay các IP trong Threat Feed (vnu_soc_blocklist.txt)
             │                 Chặn DDoS, quét cổng diện rộng, flood session TCP/UDP.
             ▼ (Giai đoạn 2: Traffic L3/L4 sạch đi tiếp vào L7)
       [ WAF / Nginx ]     ──► Giải mã HTTPS, soi từng tham số URL, POST data, File Upload.
             │                 Ngăn chặn SQLi, XSS, Webshell, chống inject link cờ bạc.
             ▼ (Giai đoạn 3: Nếu bypass được cả WAF vào server)
    [ Wazuh HIDS / FIM ]   ──► Giám sát File Integrity (FIM) phát hiện file mã nguồn bị sửa đổi,
             │                 kiểm toán log DB phát hiện query chèn bài viết/link lạ.
             ▼
   [ Phản Ứng Tự Động SOAR ]──► Tự động đẩy IP thủ phạm sang Threat Feed Gateway (Port 8088),
                               nạp ngược lại FortiGate để DROP toàn bộ traffic từ Layer 3!
```

### Kết luận cốt lõi:
1. **FortiGate** đóng vai trò là **"Cổng thành kiên cố"**: Ngăn chặn kẻ địch mang vũ khí nặng (DDoS, IP có tiền án tiền sự, traffic sai giao thức) từ tầng Layer 3/4.
2. **WAF** đóng vai trò là **"Máy soi chiếu X-quang tại cửa kiểm soát"**: Mở từng gói hàng (giải mã HTTPS), kiểm tra từng nội dung xem có chứa độc chất tinh vi (SQLi, Script chèn cờ bạc) mà mắt thường của cổng thành không thể nhìn thấy.
3. **Wazuh HIDS & SOAR** đóng vai trò là **"Camera an ninh nội bộ & Đội phản ứng nhanh"**: Phát hiện ngay lập tức dấu hiệu bất thường bên trong máy chủ nếu kẻ tấn công lọt qua được cửa ngoài, lập tức truyền lệnh đóng cổng thành (FortiGate) để cô lập vĩnh viễn kẻ tấn công.
