# utils.py
import logging
import random
import re
import requests
from urllib.parse import urlparse
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from controllers.config import USER_AGENT, DEFAULT_TIMEOUT, REQUEST_DELAY_MIN, REQUEST_DELAY_MAX

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

# ========== URL HELPERS ==========
def get_base_url(parsed):
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    raise ValueError("URL không phải absolute URL")

def classify_url(url: str):
    SHORTENED_DOMAINS = {"bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly"}
    result = []
    url = (url or "").strip()
    
    if not url:
        return ["no_url_provided"]

    parsed = urlparse(url)
    domain = parsed.netloc.lower().split(":")[0] if parsed.netloc else None
    path = parsed.path.lower()

    if parsed.scheme and parsed.netloc:
        result.append("absolute_url")
    else:
        result.append("relative_url")

    # 1. STATIC URL
    static_indicators = [
        not parsed.query,
        path.endswith(('.html', '.htm', '.php', '.asp', '.jsp')),
        bool(re.match(r'^/[\w\-/]*$', path)), 
    ]

    # 2. DYNAMIC URL
    dynamic_indicators = [
        bool(parsed.query),
        bool(re.search(r'\?[\w\-]+=', url)),
        bool(re.search(r'/\d+', path)),
    ]

    # 3. ABUSALY/BUSINESS URL
    abusaly_indicators = [
        '/api/' in path,
        path.startswith('/v1/') or path.startswith('/v2/'),
        bool(re.search(r'/(user|admin|account|profile|order|payment)', path)),
        path.endswith('.json'),
    ]

    static_score = sum(static_indicators)
    dynamic_score = sum(dynamic_indicators)
    abusaly_score = sum(abusaly_indicators)
    
    if abusaly_score >= 1:
        result.append("abusaly_url")
    if dynamic_score >= 1:
        result.append("dynamic_url")
    if static_score >= 2 or (not parsed.query and abusaly_score == 0):
        result.append("static_url")
    if domain and domain in SHORTENED_DOMAINS:
        result.append("shortened_url")
    
    return result

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