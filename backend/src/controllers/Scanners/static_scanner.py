# scanners/static_scanner.py
import os, sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import time
import re
from urllib.parse import urlparse, urljoin
from utils import create_session, get_request_delay, get_base_url, log_info, log_error
from controllers.config import DEFAULT_TIMEOUT

def scan_information_disclosure(base_url):
    vulnerabilities = []
    sensitive_files = [
        "robots.txt", ".env", ".env.local", ".env.production", ".env.backup",
        ".git/config", ".git/HEAD", ".git/index", ".git/logs/HEAD",
        ".svn/entries", ".svn/wc.db",
        "composer.json", "composer.lock", "package.json", "package-lock.json",
        "yarn.lock", "pom.xml", "build.gradle", "requirements.txt",
        ".DS_Store", "Thumbs.db", "desktop.ini",
        "phpinfo.php", "info.php", "test.php",
        ".htaccess", ".htpasswd", "web.config",
        "backup.sql", "database.sql", "dump.sql",
        "README.md", "CHANGELOG.md", "TODO.txt",
        ".dockerenv", "Dockerfile", "docker-compose.yml"
    ]
    
    parsed = urlparse(base_url)
    path_parts = parsed.path.strip('/').split('/')
    current_file = path_parts[-1] if path_parts and path_parts[-1] else None
    
    if current_file:
        for ext in [".bak", ".old", ".orig", ".save", ".tmp", ".backup", 
                      ".zip", ".tar.gz", ".rar", ".7z", ".sql", ".db"]:
            sensitive_files.append(f"{current_file}{ext}")
    
    try:
        base = get_base_url(parsed)
    except ValueError:
        return vulnerabilities # Không phải absolute URL

    session = create_session()
    log_info(f"[Static] Quét Information Disclosure: {base_url}")
    
    for filename in sensitive_files:
        try:
            time.sleep(get_request_delay())
            test_url = urljoin(base, filename.lstrip('/'))
            # filename.lstrip dùng để xóa dấu / ở file
            # urljoin nối base vào file name để tạo thành url hoàn chỉnh
            resp = session.get(test_url, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
            #allow_redirects=False không theo dõi chuyển hướng Giả sử http://github.com sẽ luôn chuyển hướng sang giao thức an toàn https://github.com, allow_redirect sẽ ngnanw chuyển hướng 
            if resp.status_code == 200 and len(resp.content) > 10:
                content_preview = resp.content[:256].lower()
                if b'<html' in content_preview or b'<!doctype' in content_preview:
                    continue
                #khi quét nếu trả về trang html thì bỏ qua không báo lỗi
                # Khi bạn scan các file như .env, database.sql, hay config.json, nội dung của chúng là dạng văn bản thuần (plain text) hoặc JSON, không bao giờ chứa mã HTML.
                #Nếu server trả về 200 OK nhưng nội dung lại chứa HTML, khả năng cao đó là một trang "Custom 404 Error Page" (trang báo lỗi tùy chỉnh) hoặc trang chủ mặc định mà server trả về cho mọi đường dẫn sai. Nếu không lọc cái này, tool của bạn sẽ báo mọi đường dẫn đều là lỗi bảo mật (False Positive).
                preview = resp.content[:200].decode('utf-8', errors='replace')
                #decode chuyển đổi byte thành chuỗi utf-8, errors='replace' thay thế ký tự không thể decode bằng ký tự thay thế
                vulnerabilities.append({
                    "category": "Information Disclosure",
                    "type": "Sensitive File Exposed",
                    "url": test_url, "file": filename, "status": "VULNERABLE",
                    "risk": "HIGH", "evidence": f"File size: {len(resp.content)} bytes",
                    "preview": preview
                })
                log_info(f"⚠️ [Info Disclosure] Phát hiện: {test_url}")
        
        except Exception as e:
            continue
        # Nếu trong quá trình gửi request gặp bất kỳ lỗi nào (mất mạng, server từ chối kết nối, lỗi SSL, timeout...), chương trình sẽ nhảy vào dòng except.
        # Ở đây, ta chỉ đơn giản là dùng continue để bỏ qua lỗi và tiếp tục quét các file tiếp theo mà không ghi log lỗi chi tiết nhằm tránh làm rối log hoặc lỗi server, công sức quét trước đó sẽ lỗi hết. 
    return vulnerabilities

def scan_directory_listing(base_url):
    # Quét Directory Listing trong các thư mục phổ biến
    vulnerabilities = []
    common_dirs = [
        "backup/", "backups/", "old/", "temp/", "tmp/",
        "uploads/", "upload/", "files/", "images/", "media/",
        "config/", "configs/", "conf/", "admin/", "administrator/", "wp-admin/",
        "test/", "tests/", "dev/", "development/", "api/", "assets/", 
        "static/", "public/", "logs/", "log/", "cache/"
    ]
    
    parsed = urlparse(base_url)
    try:
        base = get_base_url(parsed)
    except ValueError:
        return vulnerabilities
# khác với if, continue  : nếu gặp lỗi thì bỏ qua luôn không thực hiện các lệnh bên dưới nữa
# với try except : nếu gặp lỗi thì thực hiện các lệnh trong except, vẫn tiếp tục thực hiện các lệnh bên dưới
    session = create_session()
    log_info(f"[Static] Quét Directory Listing: {base_url}")

    listing_signatures = [
    "Index of",
    "Directory listing",
    "<title>Index of",
    "Parent Directory",
    "[To Parent Directory]",
    "<h1>Index of",
    # Các từ khóa bổ sung an toàn hơn thay vì dòng bị lỗi ô vuông:
    "Last modified",
    "Description",
    "Size"
    ]

    for dir_path in common_dirs:
        test_url = urljoin(base, dir_path)
        try:
            time.sleep(get_request_delay())
            resp = session.get(test_url, timeout=DEFAULT_TIMEOUT, allow_redirects=False)

            if resp.status_code in (200, 403):
                content = resp.content.decode('utf-8', errors='replace')
                if any(sig.lower() in content.lower() for sig in listing_signatures):
                    vulnerabilities.append({
                        "category": "Directory Listing",
                        "type": "Directory Indexing Enabled",
                        "url": test_url, "directory": dir_path, "status": "VULNERABLE",
                        "risk": "MEDIUM", "evidence": "Directory listing indicators found"
                    })
                    log_info(f"⚠️ [Dir Listing] Phát hiện: {test_url}")

        except Exception as e:
            log_error(test_url, f"Directory listing error: {e}")
            continue
    return vulnerabilities

def scan_misconfiguration(base_url):
    vulnerabilities = []
    session = create_session()
    parsed = urlparse(base_url)

    try:
        base = get_base_url(parsed)
    except ValueError:
        return vulnerabilities

    log_info(f"[Static] Quét Misconfiguration: {base_url}")

    # 1. Kiểm tra HTTP Methods
    try:
        time.sleep(get_request_delay())
        resp = session.options(base, timeout=DEFAULT_TIMEOUT)
        allow_header = resp.headers.get("Allow", "")
        dangerous_methods = {"PUT", "DELETE", "TRACE", "CONNECT"}
        found = [m for m in dangerous_methods if m in allow_header]
        if found:
            vulnerabilities.append({
                "category": "Misconfiguration", "type": "Dangerous HTTP Methods",
                "url": base, "status": "VULNERABLE", "risk": "HIGH",
                "evidence": f"Server cho phép: {', '.join(found)}"
            })
            log_info(f"⚠️ [Misconfig] Cho phép phương thức nguy hiểm: {found}")
    except Exception:
        pass

    # 2. Kiểm tra Headers nhạy cảm
    try:
        time.sleep(get_request_delay())
        resp = session.get(base, timeout=DEFAULT_TIMEOUT)
        sensitive_headers = ["Server", "X-Powered-By", "X-AspNet-Version"]
        for header in sensitive_headers:
            if header in resp.headers:
                vulnerabilities.append({
                    "category": "Misconfiguration", "type": "Information Disclosure (Headers)",
                    "url": base, "status": "VULNERABLE", "risk": "MEDIUM",
                    "evidence": f"{header}: {resp.headers[header]}"
                })
                log_info(f"⚠️ [Misconfig] Header nhạy cảm: {header}={resp.headers[header]}")
    except Exception:
        pass

    return vulnerabilities