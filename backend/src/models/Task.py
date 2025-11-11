from mongoengine import Document, StringField, ListField, DictField, DateTimeField
from datetime import datetime

class Task(Document):
    """
    Mô hình Task để lưu trữ thông tin và kết quả quét.
    """
    
    # URL mục tiêu, chúng ta có thể dùng nó làm khóa chính (primary_key)
    # để đảm bảo không có URL nào bị quét trùng lặp trong DB.
    url = StringField(required=True, primary_key=True)
    
    # Dùng để lưu trữ kết quả từ hàm classify_url
    # Ví dụ: ["absolute_url", "dynamic_url", "abusaly_url"]
    category = ListField(StringField())
    
    # Dùng DictField để lưu cấu trúc JSON/dict của kết quả quét
    # Ví dụ: {"static_holes": {...}, "dynamic_holes": {...}}
    scan_results = DictField()
    
    # Thời điểm quét (được gán bằng datetime.now())
    scanned_at = DateTimeField(default=datetime.now)
    
    # Cấu hình meta cho collection
    meta = {
        'collection': 'scan_tasks',  # Tên collection trong MongoDB
        'indexes': [
            'scanned_at'  # Index theo thời gian để truy vấn nhanh hơn
        ]
    }