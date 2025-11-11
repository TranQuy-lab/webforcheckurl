import os, sys, time, re
from urllib.parse import urlparse, urljoin

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils import create_session, get_request_delay, get_base_url, log_info, log_error
from controllers.config import DEFAULT_TIMEOUT

def scan_business_logic(target_url):
    """Quét lỗi logic nghiệp vụ: giá âm, số lượng âm, bypass validation"""
    vulnerabilities = []
    session = create_session()
    headers = {"Content-Type": "application/json"}
    
    log_info(f"[Abusaly] Quét Business Logic: {target_url}")
    
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
            resp = session.post(target_url, json=test, headers=headers, timeout=DEFAULT_TIMEOUT)
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
            log_error(f"Lỗi khi test {test}: {e}")
    
    if any(keyword in target_url.lower() for keyword in ['order', 'cart', 'checkout', 'payment']):
        try:
            test_order = {
                "items": [{"id": 1, "quantity": -1}, {"id": 2, "quantity": 0}],
                "total": 0
            }
            resp = session.post(target_url, json=test_order, headers=headers, timeout=DEFAULT_TIMEOUT)
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
            log_error(f"Lỗi khi test order: {e}")
    
    return vulnerabilities
