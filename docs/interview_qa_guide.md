# BỘ CÂU HỎI & TRẢ LỜI PHỎNG VẤN CHUYÊN SÂU (SOC & SIEM/SOAR ARCHITECT)

Tài liệu tổng hợp các câu hỏi phỏng vấn kỹ thuật hóc búa dành cho vị trí **Senior SOC Analyst, Detection Engineer và SIEM/SOAR Specialist**, cùng hướng trả lời thực chiến dựa trên dự án này.

---

### Câu hỏi 1: "Khi kẻ tấn công thực hiện flood hàng chục nghìn request/phút, bạn bảo vệ hạ tầng tự động hóa SOAR như thế nào để không bị nghẽn (Alert Fatigue / Queue Overflow)?"

> **Gợi ý trả lời thực chiến:**  
> "Khi bị tấn công từ chối dịch vụ hoặc brute-force dồn dập, Wazuh Engine có thể phát sinh hàng chục nghìn log mỗi phút. Nếu mỗi log đều bắn webhook sang SOAR, hệ thống tự động hóa sẽ lập tức bị nghẽn hàng đợi (Queue Overflow).  
> Để xử lý triệt để, tôi thiết kế cơ chế **Sliding Window Deduplication** ngay tại script tích hợp (`shuffle_active_response.py`):
> - Sử dụng SQLite chế độ WAL (Write-Ahead Logging) cục bộ để theo dõi cặp khóa `(src_ip, rule_id)` trong cửa sổ trượt 300 giây (5 phút).
> - Gói tin vi phạm đầu tiên được chuyển tiếp ngay lập tức sang SOAR để ra quyết định chặn tại tường lửa.
> - Tất cả các gói tin tiếp theo từ cùng IP vi phạm cùng luật trong 5 phút chỉ thực hiện tăng bộ đếm tần suất (`count += 1`), hoàn toàn không sinh webhook lặp lại.
> Cơ chế này giúp triệt tiêu hơn 95% lưu lượng dư thừa, bảo vệ SOAR engine luôn hoạt động mượt mà."

---

### Câu hỏi 2: "Tại sao trong môi trường viễn thông / mạng trường đại học, bạn không được tự động chặn mọi IP vi phạm? Bạn giải quyết bài toán False Positive do CGNAT như thế nào?"

> **Gợi ý trả lời thực chiến:**  
> "Tại Việt Nam, các nhà mạng di động 4G (Viettel, VinaPhone, FPT) sử dụng công nghệ CGNAT (Carrier-Grade NAT) để gom hàng ngàn thuê bao dùng chung một địa chỉ IP Public. Nếu chỉ có một thiết bị của sinh viên nhiễm mã độc gửi request quét cổng mà hệ thống tự động chặn IP Public đó tại tường lửa biên, hàng ngàn cán bộ giảng viên và sinh viên khác sẽ bị mất kết nối oan (DoS diện rộng).  
> Để giải quyết, tôi xây dựng chính sách **CGNAT Safeguard**:
> 1. Tích hợp MaxMind GeoLite2 ASN & Country database trực tiếp vào bộ lọc trước khi gửi lệnh chặn.
> 2. Phân tách rõ ràng:
>    - **100% IP nước ngoài (Foreign IPs)** có hành vi tấn công: Tự động kích hoạt chặn biên tức thời (Automatic Enforcement).
>    - **IP nguồn xuất xứ Việt Nam (Domestic IPs)**: Tuyệt đối không chặn tự động. Hệ thống chuyển sang luồng **Human-in-the-Loop (HITL)**: Cảnh báo chi tiết về Telegram của trực ban SOC để xác minh thủ công hoặc áp dụng chế tài cục bộ trên máy chủ (Host-level iptables/Nginx rate limit) thay vì chặn ở tường lửa biên."

---

### Câu hỏi 3: "Làm sao bạn giải quyết bài toán giám sát toàn vẹn file (FIM) trên hệ thống web lớn hàng triệu file mà không làm treo Wazuh Agent (vượt ngưỡng 100k files - Rule 233)?"

> **Gợi ý trả lời thực chiến:**  
> "Wazuh mặc định có ngưỡng giới hạn 100.000 file trong cơ sở dữ liệu Syscheck. Nếu cấu hình FIM quét bừa bãi toàn bộ thư mục Web Root của các CMS lớn (như WordPress, Drupal, thư mục ảnh uploads), agent sẽ chạm trần Rule 233, ngừng theo dõi file mới và tiêu tốn rất nhiều CPU/RAM máy chủ.  
> Để khắc phục, tôi áp dụng chiến lược **Tiered FIM (Giám sát Phân Tầng Chọn Lọc)**:
> 1. Sử dụng thuộc tính `restrict` để chỉ bắt các file chứa mã thực thi nguy hiểm: `.php`, `.asp`, `.aspx`, `.jsp`, `.exe`, `.dll`, `.sh`.
> 2. Đưa toàn bộ các thư mục chứa dữ liệu tĩnh hoặc file sinh tạm thời vào danh sách loại trừ (`<ignore>`): thư mục `uploads/`, `cache/`, `session/`, `temp/`.
> 3. Bật chế độ `realtime="yes"` có chọn lọc tại các thư mục cấu hình nhạy cảm và file nhị phân hệ thống (`/etc/`, `C:\Windows\System32\inetsrv\`).
> Nhờ đó, số lượng file giám sát thực tế giảm từ hơn 1.000.000 file xuống dưới 5.000 file trọng yếu, giữ cho Agent hoạt động cực kỳ nhẹ nhàng và không bao giờ vi phạm Rule 233."

---

### Câu hỏi 4: "Bạn phát hiện và ngăn chặn loại hình tấn công tinh vi SEO Cloaking / Gambling App Redirect trên hạ tầng IIS / Web Server như thế nào?"

> **Gợi ý trả lời thực chiến:**  
> "Đây là loại hình tấn công rất phổ biến nhắm vào các tên miền có độ uy tín cao (.edu.vn / .gov.vn) để trục lợi SEO cho các trang cờ bạc, cá độ trực tuyến. Kẻ tấn công cài webshell hoặc nạp DLL độc hại vào tiến trình web `w3wp.exe` trên IIS. Khi quản trị viên truy cập thì trang web trả về nội dung bình thường; nhưng khi người dùng truy cập từ thiết bị di động hoặc máy tìm kiếm, mã độc sẽ redirect sang link tải app cờ bạc lậu (OpenInstall).  
> Tôi triển khai phòng ngự 3 lớp:
> 1. **FIM & Sysmon Binary Integrity:** Bật Sysmon Event 7 kết hợp FIM giám sát chữ ký số của các DLL nạp vào `w3wp.exe`. Bất kỳ DLL không có chữ ký số hợp lệ của Microsoft đều kích hoạt cảnh báo nguy cấp Level 14.
> 2. **Wazuh Log Analysis Ruleset:** Viết luật so khớp URL giải mã regex phát hiện các tham số đặc trưng của app cờ bạc (`openInstallAppKey`, `inviteType`, `mmh2rv`) và chuỗi User-Agent di động kết hợp mã phản hồi HTTP 301/302 trên các URL tĩnh (Rule 100964, 100966).
> 3. **Phản ứng tự động:** Khi phát hiện, SOAR tự động cách ly file nghi ngờ, tạo bản ghi kiểm toán và cảnh báo khẩn cấp về Telegram để đội phản ứng sự cố vào xử lý triệt để mã nguồn."

---

### Câu hỏi 5: "Làm thế nào để đưa AI LLM vào trung tâm vận hành SOC mà không vi phạm nguyên tắc bảo mật và tránh hallucination (ảo tưởng)?"

> **Gợi ý trả lời thực chiến:**  
> "Để tích hợp AI Copilot an toàn vào SOC, tôi thiết kế kiến trúc theo 3 nguyên tắc bảo mật nghiêm ngặt:
> 1. **Strict Read-Only & Zero-Mutation Guardrail:** AI hoạt động thuần túy ở vai trò Cố vấn tham mưu (Advisory Only). AI bị cấm 100% quyền tự động sửa đổi log, xóa dữ liệu hay can thiệp tường lửa. Mọi hành động can thiệp bắt buộc phải do Kỹ sư (Human-in-the-Loop) trực tiếp xác nhận.
> 2. **Grounding trên dữ liệu thực tế (Evidence-Based):** Ngữ cảnh an ninh 24h từ OpenSearch được trích xuất và nén tinh gọn (`lean_context`) nạp vào System Instruction. AI trả lời dựa trên sự kiện có thật trong cơ sở dữ liệu thay vì tự suy đoán.
> 3. **On-Demand & Token Optimization:** Không chạy tiến trình định kỳ tốn kém token. AI chỉ được kích hoạt khi có kỹ sư chủ động hỏi, kết hợp cơ chế luân chuyển model thông minh (Gemini Flash Lite / Flash) để tối ưu độ trễ dưới 2 giây và tiết kiệm chi phí vận hành."
