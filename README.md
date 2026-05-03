🛡️ ĐỀ TÀI: PHÂN TÍCH DỮ LIỆU ĐĂNG NHẬP HỆ THỐNG – LOGIN ANALYZER

🧭 Giới thiệu đề tài
Trong bối cảnh các hệ thống thông tin ngày càng bị đe dọa bởi những cuộc tấn công mạng tinh vi, đặc biệt là tấn công brute-force và đăng nhập trái phép, việc giám sát và phân tích log hệ thống trở thành một yêu cầu quan trọng để đảm bảo an toàn thông tin.
Dự án Login Analyzer được xây dựng với mục tiêu giúp người quản trị hệ thống phát hiện sớm các hành vi đăng nhập bất thường thông qua việc phân tích log đăng nhập từ hệ thống máy chủ.
---
💡 Lý do chọn đề tài
Tấn công đăng nhập sai liên tục (brute-force) là một trong những hình thức tấn công phổ biến nhất hiện nay.
Việc phân tích log thủ công tốn nhiều thời gian và dễ bỏ sót các dấu hiệu nghi ngờ.
Cần có một công cụ tự động, trực quan và dễ dùng giúp sinh viên, kỹ sư hoặc quản trị viên dễ dàng giám sát hệ thống của mình.
Dự án này mang tính ứng dụng thực tế cao và phù hợp với hướng nghiên cứu An ninh mạng – Cybersecurity Analytics.
---
🧠 Cơ sở lý thuyết
Ứng dụng được xây dựng dựa trên các nền tảng:
Nguyên lý bảo mật hệ thống thông tin: phát hiện hành vi đăng nhập trái phép qua log.
Phân tích dữ liệu log: sử dụng thư viện `pandas` để xử lý và trích xuất thông tin.
Trực quan hóa dữ liệu: áp dụng `matplotlib` để hiển thị biểu đồ tần suất tấn công.
Phân tích hành vi tấn công brute-force: dựa trên số lượng đăng nhập thất bại trong khoảng thời gian ngắn.
Framework Streamlit: tạo giao diện web đơn giản, dễ triển khai.
---
🎯 Mục tiêu của đề tài
Mục tiêu tổng quát:
Xây dựng một ứng dụng web mini giúp người dùng tải file log, phân tích dữ liệu đăng nhập, và trực quan hóa kết quả một cách nhanh chóng và dễ hiểu.
Mục tiêu cụ thể:
Tạo giao diện web thân thiện bằng Streamlit.
Cho phép upload file log hệ thống để xử lý tự động.
Phát hiện và liệt kê các IP nghi ngờ thực hiện tấn công brute-force.
Trực quan hóa kết quả phân tích bằng biểu đồ cột.
Xuất dữ liệu kết quả ra file CSV để lưu trữ hoặc báo cáo.
Tạo nền tảng để có thể mở rộng thành hệ thống giám sát bảo mật nâng cao trong tương lai.
---
🧩 Công nghệ sử dụng
Thành phần	Công nghệ
Ngôn ngữ	Python
Giao diện	Streamlit
Xử lý dữ liệu	Pandas
Vẽ biểu đồ	Matplotlib
Lưu kết quả	CSV export
Môi trường	Localhost hoặc Python venv
---
🔧 Cách chạy ứng dụng
```bash
# B1. Di chuyển đến thư mục project
cd login-analyzer"

# B2. Kích hoạt môi trường ảo (nếu có)
venv\\Scripts\\activate

# B3. Cài thư viện
pip install -r requirements.txt

# B4. Chạy ứng dụng
streamlit run app.py
```
Ứng dụng sẽ chạy tại địa chỉ:  
👉 http://localhost:8501
---
🧾 Tổng kết
Ứng dụng Login Analyzer tuy là một dự án mini nhưng đã thể hiện được:
Khả năng xử lý dữ liệu log thực tế.
Phát hiện tấn công brute-force hiệu quả.
Trực quan hóa dữ liệu bảo mật đơn giản mà mạnh mẽ.
Hướng phát triển trong tương lai:
Tích hợp cảnh báo qua email/Telegram.
Giám sát thời gian thực.
Kết nối trực tiếp với hệ thống firewall để chặn IP tự động.
---
