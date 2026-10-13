# NGUYÊN TẮC BẢO MẬT & RÀO CHẮN AN TOÀN CHO AI SOC COPILOT

Tài liệu quy định rào chắn an toàn kỹ thuật (Security Guardrails) được áp dụng cho trợ lý AI `socduac` / `ChatBotDUAC` trong trung tâm giám sát an toàn thông tin.

---

## 1. NGUYÊN TẮC CHỈ ĐỌC & KHÔNG BIẾN ĐỔI (STRICT READ-ONLY - ZERO MUTATION)

1. **Phạm vi quyền hạn (Advisory Only):**  
   AI hoạt động hoàn toàn ở chế độ Cố vấn tham mưu. AI **tuyệt đối không được cấp quyền** và **không có cơ chế API** để:
   * Chỉnh sửa, ghi đè hoặc xóa các tệp nhật ký (Log files) trên hệ thống.
   * Xóa hoặc chỉnh sửa các bản ghi trong cơ sở dữ liệu `soc.db`, Elasticsearch hoặc OpenSearch.
   * Tự ý thêm/xóa địa chỉ IP trên tường lửa FortiGate hoặc iptables.
   * Can thiệp hoặc khởi động lại các tiến trình hệ điều hành.

2. **Cơ chế Human-in-the-Loop (HITL):**  
   Mọi hành động can thiệp (chặn IP, cô lập máy chủ, gỡ mã độc) bắt buộc phải do **Kỹ sư hoặc Chỉ huy SOC trực tiếp phê duyệt và thi hành thủ công**.

---

## 2. RÀO CHẮN CHỐNG THẤT THOÁT THÔNG TIN NHẠY CẢM (DATA PRIVACY GUARDRAILS)

1. **Không dump log thô (No Raw Log Dumping):**  
   Trước khi gửi dữ liệu sang mô hình ngôn ngữ lớn (LLM), backend tự động trích xuất các chỉ số thống kê đã được nén gọn (`lean_context`), bao gồm:
   * Số lượng IP vi phạm duy nhất.
   * Phân nhóm mối đe dọa (CAT1 - CAT6).
   * Danh sách Top 5 IP vi phạm và Top 3 máy chủ mục tiêu.
2. **Không chuyển tiếp PII và Credentials:**  
   Toàn bộ mật khẩu, cookie, session token và dữ liệu cá nhân của người dùng bị loại bỏ hoàn toàn khỏi ngữ cảnh prompt gửi lên LLM.

---

## 3. CƠ CHẾ TIẾT KIỆM TOKEN & KHẢ NĂNG SẴN SÀNG CAO (ON-DEMAND & RESILIENCE)

1. **Gọi theo nhu cầu (On-Demand Activation):**  
   Không có cron job hay tiến trình ngầm định kỳ gọi LLM. Chỉ khi người dùng chủ động gửi tin nhắn trong cửa sổ chatbox thì một request duy nhất mới được kích hoạt.
2. **Bể mô hình dự phòng (Model Fallback Pool):**  
   Nhằm tránh tình trạng quá tải hoặc nghẽn quota (HTTP 429 / 503), hệ thống tự động luân chuyển mô hình theo thứ tự ưu tiên:
   `gemini-3.5-flash-lite` ➔ `gemini-3.5-flash` ➔ `gemini-3.7-flash` ➔ `gemini-3.6-flash`.
