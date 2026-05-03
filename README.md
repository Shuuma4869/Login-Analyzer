# 🛡️ Login Analyzer - Phân tích Dữ liệu Đăng nhập Hệ thống

Ứng dụng web giúp giám sát, phân tích log hệ thống và phát hiện các hành vi tấn công brute-force hoặc đăng nhập trái phép một cách trực quan.

## 🧭 Giới thiệu
Trong bối cảnh các hệ thống thông tin ngày càng bị đe dọa bởi những cuộc tấn công mạng tinh vi, việc giám sát và phân tích log hệ thống trở thành một yêu cầu quan trọng. Dự án **Login Analyzer** được xây dựng nhằm giúp người quản trị phát hiện sớm các hành vi bất thường thông qua việc phân tích log máy chủ tự động.

### 💡 Lý do chọn đề tài
* **Chống tấn công Brute-force:** Phát hiện hình thức tấn công phổ biến nhất hiện nay.
* **Tự động hóa:** Thay thế việc phân tích log thủ công tốn thời gian và dễ sai sót.
* **Trực quan hóa:** Cung cấp công cụ dễ dùng cho quản trị viên qua biểu đồ.
* **Tính thực tế:** Phù hợp với hướng nghiên cứu *Cybersecurity Analytics*.

---

## 🎯 Mục tiêu
* **Tổng quát:** Xây dựng ứng dụng web cho phép tải file log, phân tích và trực quan hóa dữ liệu đăng nhập.
* **Cụ thể:**
    * Giao diện thân thiện với Streamlit.
    * Tự động phát hiện các IP nghi ngờ tấn công.
    * Trực quan hóa tần suất tấn công bằng biểu đồ.
    * Xuất báo cáo ra file CSV.

---

## 🧩 Công nghệ sử dụng
| Thành phần | Công nghệ |
| :--- | :--- |
| **Ngôn ngữ** | Python |
| **Giao diện** | Streamlit |
| **Xử lý dữ liệu** | Pandas |
| **Vẽ biểu đồ** | Matplotlib |
| **Lưu kết quả** | CSV export |
| **Môi trường** | Localhost / Python venv |

---

## 🧠 Cơ sở lý thuyết
1.  **Nguyên lý bảo mật:** Phát hiện dấu hiệu xâm nhập qua nhật ký hệ thống (logs).
2.  **Phân tích dữ liệu:** Sử dụng `pandas` để lọc, trích xuất IP, thời gian và trạng thái đăng nhập.
3.  **Nhận diện tấn công:** Thuật toán dựa trên ngưỡng (threshold) số lần đăng nhập thất bại trong một khoảng thời gian ngắn.

---

## 🔧 Hướng dẫn cài đặt và sử dụng

### 1. Chuẩn bị môi trường
Đảm bảo bạn đã cài đặt Python (phiên bản 3.8 trở lên).

### 2. Các bước thực hiện
```bash
# B1. Di chuyển đến thư mục project
cd login-analyzer

# B2. Khởi tạo và kích hoạt môi trường ảo (Khuyến khích)
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# B3. Cài đặt các thư viện cần thiết
pip install -r requirements.txt

# B4. Chạy ứng dụng
streamlit run app.py
