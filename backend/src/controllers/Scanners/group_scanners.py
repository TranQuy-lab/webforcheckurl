# scanners/group_scanners.py
import os, sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from static_scanner import *
from dynamic_scanner import *
from business_scanner import *
def scan_static_holes(base_url):
    vulnerabilities = []
    vulnerabilities.extend(scan_information_disclosure(base_url))
    vulnerabilities.extend(scan_directory_listing(base_url))
    vulnerabilities.extend(scan_misconfiguration(base_url))
    
    return {
        "scan_type": "static_holes",
        "target": base_url,
        "vulnerabilities": vulnerabilities,
        "summary": {
            # ===== FIX: Sửa lại summary cho đúng =====
            "vulnerable_count": len(vulnerabilities),
            "info_disclosure": len([v for v in vulnerabilities if v['category'] == 'Information Disclosure']),
            "dir_listing": len([v for v in vulnerabilities if v['category'] == 'Directory Listing']),
            "misconfiguration": len([v for v in vulnerabilities if v['category'] == 'Misconfiguration'])
        }
    }

def scan_dynamic_holes(target_url):
    vulnerabilities = []
    vulnerabilities.extend(scan_sql_injection(target_url))
    vulnerabilities.extend(scan_xss(target_url))
    vulnerabilities.extend(scan_file_inclusion(target_url))
    vulnerabilities.extend(scan_broken_authentication(target_url))
    vulnerabilities.extend(scan_idor_dynamic(target_url))
    
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

def scan_abusaly_holes(target_url):
    vulnerabilities = []
    vulnerabilities.extend(scan_privilege_escalation(target_url))
    vulnerabilities.extend(scan_mass_assignment(target_url))
    vulnerabilities.extend(scan_api_security(target_url))
    vulnerabilities.extend(scan_csrf(target_url))
    vulnerabilities.extend(scan_file_upload_abuse(target_url))
    vulnerabilities.extend(scan_business_logic(target_url))
    
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
            # ===== FIX: Sửa lỗi typo =====
            "file_upload": len([v for v in vulnerabilities if v['category'] == 'File Upload']),
            "business_logic": len([v for v in vulnerabilities if v['category'] == 'Business Logic'])
        }
    }