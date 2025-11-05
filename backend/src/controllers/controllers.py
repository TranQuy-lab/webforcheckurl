from datetime import datetime
import os, re, time, random, requests
from flask import request, jsonify
from models.Task import Task
from urllib.parse import urlparse, parse_qs, urlencode, urljoin
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import logging

USER_AGENT = "GadgetRent-Scanner/1.0 (+you@example.com)"
DEFAULT_TIMEOUT = 7

# --- 1. Quản lý session & cookie ---
def get_session_with_cookie(cookie_value=None):
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT, "Accept": "*/*"})
    if cookie_value:
        if isinstance(cookie_value, dict):
            session.cookies.update(cookie_value)
        elif isinstance(cookie_value, str):
            session.headers.update({"Cookie": cookie_value})
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

# --- 2. Điều chỉnh REQUEST_DELAY chống flood ---
def get_request_delay():
    return random.uniform(0.5, 1.2)

# --- 3. Logging dùng logging module ---
logging.basicConfig(
    filename='scan_error.log', 
    level=logging.INFO,
    format='%(asctime)s | %(message)s'
)

def log_network_error(url, error, status_code=None):
    msg = f"URL: {url} | Status: {status_code} | Error: {error}"
    logging.info(msg)

# --- 4. Payload file nguy hiểm ---
def dangerous_file_payloads():
    return [
        ('shell.php', b'<?php system("id"); ?>', 'application/x-php'),
        ('attack.sh', b'echo hacked', 'application/x-sh'),
        ('exploit.jsp', b'<% out.println("vuln"); %>', 'application/x-jsp'),
        ('evil.exe', b'MZ\x90\x00', 'application/x-msdownload'),
        ('backdoor.aspx', b'<% Response.Write("pwned"); %>', 'application/x-aspx')
    ]

# --- 5. Robust classify URL ---
def classify_url(url: str):
    SHORTENED_DOMAINS = {"bit.ly", "goo.gl", "tinyurl.com", "t.co"}
    result = []
    url = (url or "").strip()
    
    if not url:
        return ["no url provided"]

    parsed = urlparse(url)
    domain = parsed.netloc.lower().split(":")[0] if parsed.netloc else None

    # Kiểm tra absolute/relative
    if parsed.scheme and parsed.netloc:
        result.append("absolute url")
    else:
        result.append("relative url")

    # Kiểm tra static/dynamic (mutual exclusive)
    token_pattern = r"/[A-Za-z0-9_\-]{16,}"
    has_query = bool(parsed.query or "?" in url)
    has_numeric_id = bool(re.search(r"/\d+", parsed.path))
    has_token = bool(re.search(token_pattern, parsed.path))
    
    if has_query or has_numeric_id or has_token:
        result.append("dynamic url")
    else:
        result.append("static url")

    # Kiểm tra shortened URL
    if domain and domain in SHORTENED_DOMAINS:
        result.append("shortened url")
    
    return result

# --- 6. Get base URL ---
def get_base(parsed):
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    raise ValueError("URL không phải absolute, cần base đầy đủ")

# --- 7. Static hole analyze ---
def static_hole_analyze(classify_results, base_url):
    is_static = "static url" in classify_results
    
    if not is_static:
        return {"error": "URL không phải dạng static, bỏ qua kiểm tra static hole."}

    endpoints = [
        "robots.txt", ".env", ".git/config", ".git/HEAD", 
        "backup/", "config/", "uploads/", ".htaccess",
        "wp-config.php", "composer.json", "package.json"
    ]
    exts = [".bak", ".old", ".zip", ".tar.gz", ".rar", ".7z", ".sql"]
    
    parsed = urlparse(base_url)
    try:
        base = get_base(parsed)
    except Exception as e:
        return {"error": str(e)}
    
    # Lấy filename từ path
    path_parts = parsed.path.strip('/').split('/')
    filename = path_parts[-1] if path_parts and path_parts[-1] else "index"
    
    # Build list file cần check
    files_to_check = [urljoin(base, e.lstrip('/')) for e in endpoints]
    
    # Thêm các variant của file hiện tại
    for ext in exts:
        files_to_check.append(urljoin(base, f"{filename}{ext}"))

    not_found, vuln_found, safe_or_html = [], [], []
    session = get_session_with_cookie()
    
    for url in files_to_check:
        try:
            time.sleep(get_request_delay())
            resp = session.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
            code = resp.status_code
            
            if code == 404:
                not_found.append((url, "404 Not Found"))
                continue
            
            if code >= 400:
                not_found.append((url, f"HTTP {code} {resp.reason}"))
                continue
            
            if code in [301, 302, 303, 307, 308]:
                safe_or_html.append((url, f"Redirect {code}"))
                continue
            
            if not resp.content or len(resp.content) < 10:
                safe_or_html.append((url, "Trả về trống hoặc ngắn"))
                continue
            
            # Kiểm tra HTML response
            if b'<html' in resp.content[:256].lower() or b'<!doctype' in resp.content[:256].lower():
                safe_or_html.append((url, "Trả về HTML"))
                continue
            
            # Preview nội dung file
            preview_bytes = resp.content[:120]
            encoding = resp.encoding if resp.encoding else 'utf-8'
            try:
                text_preview = preview_bytes.decode(encoding, errors='replace')
            except Exception:
                text_preview = repr(preview_bytes[:60])
            
            vuln_found.append((url, f"⚠️ Phát hiện lộ file! Preview: {text_preview}"))
            
        except requests.exceptions.Timeout:
            log_network_error(url, "Timeout")
            not_found.append((url, "Timeout"))
        except requests.exceptions.RequestException as e:
            log_network_error(url, str(e))
            not_found.append((url, f"Lỗi mạng: {type(e).__name__}"))
        except Exception as e:
            log_network_error(url, str(e))
            not_found.append((url, f"Lỗi: {str(e)}"))
    
    return {
        "url_kiem_tra": base_url,
        "tong_so_file_kiem_tra": len(files_to_check),
        "phat_hien_lo_hong": vuln_found,
        "khong_phat_hien_lo_hong": safe_or_html,
        "khong_tim_thay": not_found,
    }

# --- 8. Dynamic hole analyze ---
def dynamic_hole_analyze(classify_results, base_url, cookie_value=None):
    is_dynamic = "dynamic url" in classify_results
    
    if not is_dynamic:
        return {"error": "URL không phải dạng dynamic, bỏ qua kiểm tra dynamic hole."}

    parsed = urlparse(base_url)
    query_params = parse_qs(parsed.query)
    
    if not query_params:
        return {"info": "URL động nhưng không có query parameters để test"}

    # Các payload test thông thường
    test_payloads = {
        "sql_injection": ["' OR '1'='1", "1' AND '1'='2", "admin'--"],
        "xss": ["<script>alert('XSS')</script>", "javascript:alert(1)"],
        "path_traversal": ["../../etc/passwd", "....//....//etc/passwd"],
        "command_injection": ["; ls -la", "| whoami", "&& cat /etc/passwd"],
        "nosql_injection": ["[$ne]", "'; return true; var dummy='"]
    }

    results = []
    session = get_session_with_cookie(cookie_value)
    
    for param_name in query_params.keys():
        for attack_type, payloads in test_payloads.items():
            for payload in payloads:
                # Tạo URL test
                test_params = query_params.copy()
                test_params[param_name] = [payload]
                test_query = urlencode(test_params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                
                try:
                    time.sleep(get_request_delay())
                    resp = session.get(test_url, timeout=DEFAULT_TIMEOUT)
                    
                    # Phát hiện dấu hiệu lỗ hổng
                    vulnerable = False
                    evidence = []
                    
                    if attack_type == "sql_injection":
                        sql_errors = [b"sql syntax", b"mysql", b"postgresql", b"ora-", b"sqlite"]
                        for err in sql_errors:
                            if err in resp.content.lower():
                                vulnerable = True
                                evidence.append(f"SQL error detected: {err.decode()}")
                    
                    elif attack_type == "xss":
                        if payload.encode() in resp.content:
                            vulnerable = True
                            evidence.append("Payload reflected in response")
                    
                    elif attack_type == "path_traversal":
                        if b"root:" in resp.content or b"[extensions]" in resp.content:
                            vulnerable = True
                            evidence.append("System file content detected")
                    
                    if vulnerable:
                        results.append({
                            "param": param_name,
                            "attack_type": attack_type,
                            "payload": payload,
                            "status": "⚠️ VULNERABLE",
                            "evidence": evidence,
                            "url": test_url
                        })
                    
                except Exception as e:
                    log_network_error(test_url, str(e))
                    continue
    
    return {
        "url_kiem_tra": base_url,
        "parameters_tested": list(query_params.keys()),
        "total_tests": len(results),
        "vulnerabilities_found": results if results else "Không phát hiện lỗ hổng rõ ràng"
    }

# --- 9. Test dangerous file upload ---
def test_dangerous_file_upload(upload_url, cookie_value=None):
    results = []
    session = get_session_with_cookie(cookie_value)
    
    for filename, content, mime_type in dangerous_file_payloads():
        try:
            time.sleep(get_request_delay())
            
            files = {'file': (filename, content, mime_type)}
            resp = session.post(upload_url, files=files, timeout=DEFAULT_TIMEOUT)
            
            result = {
                "filename": filename,
                "mime_type": mime_type,
                "status_code": resp.status_code,
            }
            
            # Kiểm tra phản hồi
            if resp.status_code == 200:
                if b"success" in resp.content.lower() or b"uploaded" in resp.content.lower():
                    result["verdict"] = "⚠️ VULNERABLE - File được upload"
                else:
                    result["verdict"] = "✓ SAFE - Upload không thành công"
            elif resp.status_code in [400, 403, 415]:
                result["verdict"] = "✓ SAFE - File bị chặn"
            else:
                result["verdict"] = f"? UNKNOWN - HTTP {resp.status_code}"
            
            results.append(result)
            
        except Exception as e:
            log_network_error(upload_url, str(e))
            results.append({
                "filename": filename,
                "verdict": f"ERROR - {type(e).__name__}",
                "error": str(e)
            })
    
    return {
        "upload_url": upload_url,
        "tests_performed": len(results),
        "results": results
    }

# --- 10. API handle_url ---
def handle_url():
    data = request.get_json()
    
    if not data:
        return jsonify({"error": "Request body phải là JSON"}), 400
    
    url = data.get("url")
    user_cookie = data.get("cookie", None)

    if not url:
        return jsonify({"error": "Thiếu URL trong request"}), 400

    # Phân loại URL
    category = classify_url(url)

    # Reject nếu URL là relative
    if "relative url" in category:
        return jsonify({"error": "URL phải là absolute URL (có http:// hoặc https://)"}), 400

    # Thực hiện phân tích dựa trên loại URL
    analysis_result = {}
    
    if "static url" in category:
        analysis_result["static_analysis"] = static_hole_analyze(category, url)
    
    if "dynamic url" in category:
        analysis_result["dynamic_analysis"] = dynamic_hole_analyze(category, url, cookie_value=user_cookie)
    
    # Test file upload nếu URL chứa pattern upload
    if any(keyword in url.lower() for keyword in ["/upload", "/file", "/attachment"]):
        analysis_result["file_upload_test"] = test_dangerous_file_upload(url, cookie_value=user_cookie)

    # Lưu vào database
    try:
        Task.objects(url=url).update_one(
            set__category=category,
            set__analysis_result=analysis_result,
            set__scanned_at=datetime.now(),
            upsert=True
        )
    except Exception as e:
        logging.error(f"Database error: {str(e)}")
        return jsonify({"error": f"Lỗi khi lưu vào database: {str(e)}"}), 500

    return jsonify({
        "status": "success",
        "url": url,
        "cookie_provided": bool(user_cookie),
        "category": category,
        "analysis": analysis_result,
        "timestamp": datetime.now().isoformat()
    })