import os, sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))  # ✅ thêm src vào sys.path

from flask import Flask, request, jsonify
from datetime import datetime
from mongoengine import connect
from models.Task import Task
from controllers.utils import *
from Scanners.group_scanners import *

# ========== FLASK APP ==========
app = Flask(__name__)

def handle_scan_request():
    """
    API endpoint chính để xử lý yêu cầu quét
    """
    data = request.get_json()
    
    if not data:
        return jsonify({"error": "Request body phải là JSON"}), 400
    
    url = data.get("url")
    scan_types = data.get("scan_types", ["static", "dynamic", "abusaly"])
    
    if not url:
        return jsonify({"error": "Thiếu URL trong request"}), 400
    
    url_category = classify_url(url)
    
    if "relative_url" in url_category:
        return jsonify({
            "error": "URL phải là absolute URL (có http:// hoặc https://)"
        }), 400
    
    log_info(f"========== BẮT ĐẦU QUÉT ==========")
    log_info(f"URL: {url}")
    log_info(f"Category: {url_category}")
    
    scan_results = {}
    
    # 1. STATIC HOLES
    if "static" in scan_types and "static_url" in url_category:
        log_info(">>> Quét STATIC HOLES")
        scan_results["static_holes"] = scan_static_holes(url)
    
    # 2. DYNAMIC HOLES
    if "dynamic" in scan_types and "dynamic_url" in url_category:
        log_info(">>> Quét DYNAMIC HOLES")
        scan_results["dynamic_holes"] = scan_dynamic_holes(url)
    
    # 3. ABUSALY HOLES
    if "abusaly" in scan_types and "abusaly_url" in url_category:
        log_info(">>> Quét ABUSALY HOLES")
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
        log_error(url, f"Database error: {str(e)}")
        return jsonify({
            "error": f"Lỗi khi lưu vào database: {str(e)}"
        }), 500
    
    # Tổng hợp kết quả
    total_vulnerabilities = 0
    for result in scan_results.values():
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

