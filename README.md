# CyberScan - Advanced Web Vulnerability Scanner 🛡️

**CyberScan** là một công cụ rà quét lỗ hổng bảo mật web toàn diện, được xây dựng với kiến trúc hiện đại: **Python (Flask)** cho Backend mạnh mẽ và **Tailwind CSS** cho giao diện Frontend mượt mà (SPA).

Dự án này được thiết kế để tự động hóa quy trình kiểm thử xâm nhập (Pentest), bao gồm rà quét cấu hình tĩnh, tấn công động (Dynamic Analysis) và kiểm tra logic nghiệp vụ.

---

## 🚀 Tính Năng Chính

Hệ thống tích hợp 3 module quét chuyên sâu:

### 1. Static Scanners (Rà quét Tĩnh & Cấu hình)
* **Information Disclosure:** Phát hiện lộ lọt các file nhạy cảm (`.env`, `.git`, `backup.sql`, `robots.txt`, mã nguồn...).
* **Directory Listing:** Kiểm tra xem server có sơ hở cho phép liệt kê danh sách thư mục hay không.
* **Misconfiguration:** Phân tích các HTTP Headers thiếu an toàn và các phương thức HTTP nguy hiểm (`PUT`, `DELETE`, `TRACE`).

### 2. Dynamic Scanners (Rà quét Động - Web App)
* **SQL Injection (SQLi):**
    * Error-based: Phân tích lỗi trả về từ Database.
    * Time-based Blind: Phân tích thời gian phản hồi của server.
* **Cross-Site Scripting (XSS):** Phát hiện lỗ hổng Reflected XSS thông qua việc inject các payload phổ biến.
* **LFI/RFI:** Kiểm tra lỗ hổng chèn tệp tin cục bộ (Local File Inclusion) và từ xa.
* **Broken Authentication:** Phát hiện quản lý phiên (Session) yếu, rủi ro Session Fixation.
* **IDOR:** Kiểm tra tham chiếu đối tượng không an toàn bằng cách giả lập thay đổi ID người dùng.

### 3. Business Logic Scanners (Lỗi Nghiệp vụ)
* **Price/Quantity Manipulation:** Thử nghiệm đặt hàng với giá âm, số lượng âm hoặc giá trị bằng 0.
* **API Abuse:** Kiểm tra các endpoint API nhạy cảm.
* **Validation Bypass:** Thử nghiệm vượt qua các lớp kiểm tra dữ liệu đầu vào của server.

---

## 🛠️ Công Nghệ Sử Dụng

* **Backend:** Python 3.10+, Flask.
* **Database:** MongoDB (Sử dụng MongoEngine làm ORM).
* **Frontend:** HTML5, JavaScript (Vanilla JS), Tailwind CSS (CDN).
* **Network:** Thư viện `requests` với cơ chế Retry và Session Management.

---

## 📦 Hướng Dẫn Cài Đặt & Chạy

### 1. Yêu cầu tiên quyết
* Python (phiên bản 3.8 trở lên).
* MongoDB (Cần cài đặt và chạy service MongoDB trên máy hoặc dùng MongoDB Atlas).

### 2. Cài đặt thư viện
Mở terminal tại thư mục gốc của dự án và chạy lệnh:

```bash
pip install -r requirements.txt
(Nếu chưa có file requirements.txt, hãy cài các gói: flask, mongoengine, requests, python-dotenv, dnspython).

3. Cấu hình môi trường
Tạo file .env trong thư mục backend/src (cùng cấp với server.py) và thêm cấu hình database:

Đoạn mã

MONGODB_URI=mongodb://localhost:27017/cyberscan_db
# Hoặc chuỗi kết nối MongoDB Atlas của bạn
4. Khởi chạy Server
Di chuyển vào thư mục backend và chạy file server.py:

Bash

cd backend/src
python server.py
Server sẽ khởi động tại địa chỉ: http://127.0.0.1:5001

📂 Cấu trúc Dự án
Plaintext

CyberScan/
├── backend/
│   └── src/
│       ├── controllers/
│       │   ├── config.py       # Cấu hình Timeout, User-Agent
│       │   └── utils.py        # Hàm hỗ trợ session, classify URL
│       ├── models/             # Định nghĩa Schema Database (MongoDB)
│       ├── routers/
│       │   └── taskRouter.py   # API Routes
│       ├── Scanners/           # Chứa logic quét chính
│       │   ├── static_scanner.py
│       │   ├── dynamic_scanner.py
│       │   ├── business_scanner.py
│       │   └── group_scanners.py
│       ├── mainapi.py          # Xử lý logic luồng quét
│       └── server.py           # File khởi chạy Flask App
└── frontend/
    ├── static/
    │   ├── css.css             # Giao diện Tailwind tùy biến
    │   └── js.js               # Logic xử lý SPA (Single Page App)
    └── templates/
        └── html.html           # Giao diện chính (Dashboard)
⚠️ Tuyên Bố Miễn Trừ Trách Nhiệm (Disclaimer)
Công cụ này được phát triển chỉ dành cho mục đích giáo dục và kiểm thử bảo mật hợp pháp.

Người dùng chỉ được phép sử dụng CyberScan trên các hệ thống mạng/website mà mình sở hữu hoặc đã được cấp quyền kiểm thử bằng văn bản.

Tác giả không chịu trách nhiệm cho bất kỳ hành vi sử dụng sai trái, phá hoại hoặc vi phạm pháp luật nào gây ra bởi việc sử dụng công cụ này.

👨‍💻 Tác Giả
Trần Cao Trọng Quý Lớp: 24NS - Ngành An toàn thông tin

Trường Đại học Công nghệ Thông tin & Truyền thông Việt - Hàn (VKU)