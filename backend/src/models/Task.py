from mongoengine import Document, StringField, BooleanField, DateTimeField,DictField,IntField
from datetime import datetime, timedelta

vn_time = datetime.utcnow() + timedelta(hours=7)

from mongoengine import Document, StringField, ListField

class Task(Document):
    """
    Model lưu trữ thông tin scan URL security
    """
    
    # Thông tin cơ bản
    url = StringField(required=True, unique=True, max_length=2048)
    
    # Phân loại URL (absolute/relative, static/dynamic, shortened)
    category = ListField(StringField(), default=list)
    
    # Kết quả phân tích (nested dict)
    analysis_result = DictField(default=dict)
    
    # Metadata
    scanned_at = DateTimeField(default=datetime.now)
    created_at = DateTimeField(default=datetime.now)
    updated_at = DateTimeField(default=datetime.now)
    
    # Thống kê
    scan_count = IntField(default=1)  # Số lần scan URL này
    vulnerabilities_count = IntField(default=0)  # Tổng số lỗ hổng phát hiện
    
    # Trạng thái
    status = StringField(
        choices=['pending', 'scanning', 'completed', 'error'],
        default='completed'
    )
    
    # Có lỗ hổng hay không (để query nhanh)
    has_vulnerabilities = BooleanField(default=False)
    
    # Error message nếu scan thất bại
    error_message = StringField(max_length=1024, default=None)
    
    # Cookie được dùng để test (không lưu giá trị thực, chỉ lưu metadata)
    cookie_used = BooleanField(default=False)
    
    # Metadata settings
    meta = {
        'collection': 'tasks',  # Tên collection trong MongoDB
        'indexes': [
            'url',  # Index cho search nhanh
            'scanned_at',  # Index cho sort by time
            'has_vulnerabilities',  # Index cho filter vulnerable URLs
            '-created_at',  # Descending index
            {
                'fields': ['url', 'scanned_at'],
                'unique': False
            }
        ],
        'ordering': ['-scanned_at']  # Mặc định sort theo thời gian scan mới nhất
    }
    
    def __str__(self):
        return f"Task({self.url[:50]}... | {self.status} | Vulns: {self.vulnerabilities_count})"
    
    def to_dict(self):
        """Convert document to dictionary for JSON response"""
        return {
            'id': str(self.id),
            'url': self.url,
            'category': self.category,
            'analysis_result': self.analysis_result,
            'scanned_at': self.scanned_at.isoformat() if self.scanned_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'scan_count': self.scan_count,
            'vulnerabilities_count': self.vulnerabilities_count,
            'status': self.status,
            'has_vulnerabilities': self.has_vulnerabilities,
            'error_message': self.error_message,
            'cookie_used': self.cookie_used
        }
    
    @classmethod
    def get_or_create(cls, url):
        """Get existing task or create new one"""
        task = cls.objects(url=url).first()
        if task:
            # Update scan count và timestamp
            task.scan_count += 1
            task.scanned_at = datetime.now()
            return task, False  # (task, created)
        else:
            task = cls(url=url)
            return task, True  # (task, created)
    
    def update_analysis(self, category, analysis_result):
        """Update analysis results and calculate vulnerabilities"""
        self.category = category
        self.analysis_result = analysis_result
        self.updated_at = datetime.now()
        self.scanned_at = datetime.now()
        
        # Đếm số lỗ hổng phát hiện
        vuln_count = 0
        
        # Đếm từ static analysis
        if 'static_analysis' in analysis_result:
            static = analysis_result['static_analysis']
            if 'phat_hien_lo_hong' in static:
                vuln_count += len(static['phat_hien_lo_hong'])
        
        # Đếm từ dynamic analysis
        if 'dynamic_analysis' in analysis_result:
            dynamic = analysis_result['dynamic_analysis']
            if 'vulnerabilities_found' in dynamic:
                vulns = dynamic['vulnerabilities_found']
                if isinstance(vulns, list):
                    vuln_count += len(vulns)
        
        # Đếm từ file upload test
        if 'file_upload_test' in analysis_result:
            upload = analysis_result['file_upload_test']
            if 'results' in upload:
                for result in upload['results']:
                    if 'VULNERABLE' in result.get('verdict', ''):
                        vuln_count += 1
        
        self.vulnerabilities_count = vuln_count
        self.has_vulnerabilities = vuln_count > 0
        self.status = 'completed'
        
        self.save()
    
    def mark_error(self, error_message):
        """Mark task as error"""
        self.status = 'error'
        self.error_message = error_message
        self.updated_at = datetime.now()
        self.save()
    
    @classmethod
    def get_vulnerable_urls(cls, limit=100):
        """Get all URLs with vulnerabilities"""
        return cls.objects(has_vulnerabilities=True).limit(limit)
    
    @classmethod
    def get_recent_scans(cls, limit=50):
        """Get recent scanned URLs"""
        return cls.objects().order_by('-scanned_at').limit(limit)
    
    @classmethod
    def get_stats(cls):
        """Get statistics"""
        total = cls.objects.count()
        vulnerable = cls.objects(has_vulnerabilities=True).count()
        safe = total - vulnerable
        
        return {
            'total_scans': total,
            'vulnerable_urls': vulnerable,
            'safe_urls': safe,
            'vulnerability_rate': round(vulnerable / total * 100, 2) if total > 0 else 0
        }
    