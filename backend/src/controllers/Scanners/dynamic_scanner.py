# scanners/dynamic_scanner.py
import time
import re
from urllib.parse import urlparse, parse_qs, urlencode
from utils import create_session, get_request_delay, log_info
from controllers.config import DEFAULT_TIMEOUT
import requests
<<<<<<< HEAD
=======
# parse_qs : phân tích chuỗi truy vấn của url thành các tham số và giá trị của trúng dưới dạng list []
# urlencode : chuyển đổi dict thành chuỗi truy vấn của url theo định dạng key1=value1&key2=value2
>>>>>>> 6449eb3 (Cap nhat code moi nhat)

def scan_sql_injection(target_url):
    vulnerabilities = []
    sql_payloads = [
        # Basic
        "' OR '1'='1", "' OR 1=1--", "admin'--", "' OR 'a'='a",
        # Union
        "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--", 
        # Time-based
        "'; WAITFOR DELAY '0:0:5'--", "' OR SLEEP(5)--", "'; SELECT SLEEP(5)--",
        # Error-based
        "' AND 1=CONVERT(int,(SELECT @@version))--",
        "' AND extractvalue(1,concat(0x7e,version()))--",
    ]
    
    # (Tối ưu) Đưa danh sách lỗi ra ngoài vòng lặp để đỡ tốn RAM khai báo lại nhiều lần
    sql_errors = [
        b"sql syntax", b"mysql", b"postgresql", b"ora-", b"sqlite",
        b"sqlstate", b"syntax error", b"unclosed quotation",
    ]

    # đối với dirct trả về kiểu dữ liệu dạng {" key "[value1, value2,...]}
    parsed = urlparse(target_url)
    query_params = parse_qs(parsed.query)
    
    if not query_params:
        return vulnerabilities
    """
    nếu query_params rỗng tức là không có tham số nào trong url thì trả về vulnerabilities rỗng luôn
    Th1 : url có tham số : http://example.com/page.php?id=2&cat=books
    -> query_params = {'id': ['2'], 'cat': ['books']}
    -> tiếp tục chạy lệnh 
    th2 : url không có tham số : http://example.com/page.php
    hoặc nói đúng hơn ủa không có chuỗi truy vấn sau dấu ?
    -> query_params = {}
    """

    session = create_session()
    log_info(f"[Dynamic] Quét SQL Injection: {target_url}")
    
    for param_name in query_params.keys():
        for payload in sql_payloads:
            try:
                time.sleep(get_request_delay())
                test_params = query_params.copy()
                test_params[param_name] = [payload]
                # đối với từng tham số param_name ta sẽ thử từng payload trong sql_payloads
                test_query = urlencode(test_params, doseq=True)
                # doseq=True : nếu giá trị là list thì sẽ tạo nhiều cặp key=value, tức là lấy giá trị trong ngoặc [] list bởi kiểu dirct 
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                
                start_time = time.time()
                resp = session.get(test_url, timeout=DEFAULT_TIMEOUT)
                elapsed = time.time() - start_time
                # bộ đếm thời gian thực thi lệnh get
                # Error-based check
                
                if any(err in resp.content.lower() for err in sql_errors):
                    vulnerabilities.append({
                        "category": "SQL Injection", "type": "Error-based SQLi",
                        "parameter": param_name, "payload": payload, "url": test_url,
                        "status": "VULNERABLE", "risk": "CRITICAL",
                        "evidence": "SQL error detected in response"
                    })
                    log_info(f"⚠️ [SQLi] Phát hiện tại: {param_name}")
                    break # Next param

                # Time-based check
                if elapsed > 4.5 and ("SLEEP" in payload.upper() or "WAITFOR" in payload.upper()):
                    #kiểm tra thời gian thực thi lệnh get có lớn hơn 4.5s không và payload có chứa từ khóa SLEEP hoặc WAITFOR không
                    vulnerabilities.append({
                        "category": "SQL Injection", "type": "Time-based Blind SQLi",
                        "parameter": param_name, "payload": payload, "url": test_url,
                        "status": "VULNERABLE", "risk": "HIGH",
                        "evidence": f"Response time: {elapsed:.2f}s"
                    })
                    log_info(f"⚠️ [SQLi Time-based] Phát hiện tại: {param_name}")
                    break # Next param
                    
            except Exception:
                continue
    return vulnerabilities

def scan_xss(target_url):
    vulnerabilities = []
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert('XSS')>",
        "<iframe src=javascript:alert(1)>",
        "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>",
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
                
                    # Chỉ cần thấy đoạn script xuất hiện, hoặc đoạn alert xuất hiện
                    # Lưu ý: Cách này có thể gây dương tính giả (False Positive) nhưng bắt được nhiều lỗi hơn
                if b"alert('XSS')" in resp.content or b"alert(1)" in resp.content:
                    # ... Báo cáo lỗi
                    vulnerabilities.append({
                        "category": "XSS", "type": "Reflected XSS",
                        "parameter": param_name, "payload": payload, "url": test_url,
                        "status": "VULNERABLE", "risk": "HIGH",
                        "evidence": "Payload reflected in response"
                    })
                    log_info(f"⚠️ [XSS] Phát hiện tại: {param_name}")
                    break
            except Exception:
                continue
    return vulnerabilities

def scan_file_inclusion(target_url):
    vulnerabilities = []
    lfi_payloads = [
        "../../etc/passwd", "../../../etc/passwd",
        "..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "php://filter/convert.base64-encode/resource=index.php",
    ]
    lfi_indicators = [b"root:", b"daemon:", b"[extensions]", b"# hosts"]
    # File /etc/passwd trên hệ điều hành Linux/Unix.
    # kết quả sẽ chứa root:x:0:0:root:/root:/bin/bash
        #daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
    #File C:\Windows\win.ini trên Windows.:->extensions -> nhận biết server chạy trên nền win 
    # vì thư viện resp lấy dữ liệu dạng byte nên các chuỗi kiểm tra cũng phải ở dạng byte (b"")
    parsed = urlparse(target_url)
    query_params = parse_qs(parsed.query)
    
    file_params = [k for k in query_params.keys() 
                   if any(x in k.lower() for x in ['file', 'path', 'page', 'include'])]
    
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
                
                if any(indicator in resp.content for indicator in lfi_indicators):
                    vulnerabilities.append({
                        "category": "LFI/RFI", "type": "Local File Inclusion",
                        "parameter": param_name, "payload": payload, "url": test_url,
                        "status": "VULNERABLE", "risk": "CRITICAL",
                        "evidence": "File content detected in response"
                    })
                    log_info(f"⚠️ [LFI] Phát hiện tại: {param_name}")
                    break
            except Exception:
                continue
    return vulnerabilities

def scan_broken_authentication(target_url):
    vulnerabilities = []
    session = create_session()
    log_info(f"[Dynamic] Quét Broken Authentication: {target_url}")
    
    # Test session fixation đơn giản
    try:
        resp1 = session.get(target_url, timeout=DEFAULT_TIMEOUT)
        cookies1 = session.cookies.get_dict()
        time.sleep(get_request_delay())
        resp2 = session.get(target_url, timeout=DEFAULT_TIMEOUT)
        cookies2 = session.cookies.get_dict()
        
        if cookies1 == cookies2 and cookies1:
            vulnerabilities.append({
                "category": "Broken Authentication", "type": "Weak Session Management",
                "url": target_url, "status": "VULNERABLE", "risk": "MEDIUM",
                "evidence": "Session ID không thay đổi (Check sơ bộ)"
            })
    except Exception:
        pass
    
    return vulnerabilities

def scan_idor_dynamic(target_url):
    vulnerabilities = []
    test_ids = ["1", "2", "100", "admin"]
    parsed = urlparse(target_url)
    query_params = parse_qs(parsed.query)
    session = create_session()
    log_info(f"[Dynamic] Quét IDOR: {target_url}")
    
    # 1. Quét IDOR trên URL Path (ví dụ: /users/1)
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
            except Exception:
                continue
        
        if len(responses) >= 2 and len(set(responses.values())) >= 2:
            vulnerabilities.append({
                "category": "IDOR", "type": "Insecure Direct Object Reference (Path)",
                "url": target_url, "status": "VULNERABLE", "risk": "HIGH",
                "evidence": f"Truy cập được {len(responses)} IDs khác nhau trên Path"
            })
            log_info(f"⚠️ [IDOR Path] Phát hiện tại: {target_url}")

    # 2. Quét IDOR trên Tham số (ví dụ: ?id=1) - PHẦN BỔ SUNG QUAN TRỌNG
    idor_params = [k for k in query_params.keys() if "id" in k.lower()]
    for param in idor_params:
        responses_param = {}
        original_len = 0
        try:
             orig_resp = session.get(target_url, timeout=DEFAULT_TIMEOUT)
             original_len = len(orig_resp.content)
        except:
             continue

        for test_id in test_ids:
            try:
                time.sleep(get_request_delay())
                test_params = query_params.copy()
                test_params[param] = [test_id]
                test_query = urlencode(test_params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                
                resp = session.get(test_url, timeout=DEFAULT_TIMEOUT)
                if resp.status_code == 200:
                     if abs(len(resp.content) - original_len) > 50: 
                        responses_param[test_id] = len(resp.content)
            except Exception:
                continue
        
        if responses_param:
             vulnerabilities.append({
                "category": "IDOR", "type": "Insecure Direct Object Reference (Param)",
                "parameter": param, "url": target_url, "status": "VULNERABLE", "risk": "HIGH",
                "evidence": f"Thay đổi tham số {param} dẫn đến phản hồi khác nhau"
            })
             log_info(f"⚠️ [IDOR Param] Phát hiện tại tham số: {param}")

    return vulnerabilities