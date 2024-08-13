import requests

def scan_url(url):
    vulnerabilities = []
    
    # Example scan: Check for open redirects
    try:
        response = requests.get(url, allow_redirects=True)
        if url not in response.url:
            vulnerabilities.append(f"Open redirect detected. Redirects to: {response.url}")
    except requests.RequestException as e:
        vulnerabilities.append(f"Error accessing URL: {e}")
    
    return vulnerabilities

def check_sql_injection(url):
    payloads = ["' OR '1'='1", "' OR 'a'='a", "' OR 1=1 --"]
    vulnerabilities = []
    
    for payload in payloads:
        try:
            response = requests.get(f"{url}?id={payload}")
            if "error" in response.text or "SQL" in response.text:
                vulnerabilities.append(f"SQL Injection vulnerability found with payload: {payload}")
        except requests.RequestException as e:
            vulnerabilities.append(f"Error accessing URL: {e}")
    
    return vulnerabilities

def check_xss(url):
    payloads = ["<script>alert('XSS')</script>", "'\"><img src='x' onerror='alert(1)'>"]
    vulnerabilities = []
    
    for payload in payloads:
        try:
            response = requests.get(f"{url}?search={payload}")
            if payload in response.text:
                vulnerabilities.append(f"XSS vulnerability detected with payload: {payload}")
        except requests.RequestException as e:
            vulnerabilities.append(f"Error accessing URL: {e}")
    
    return vulnerabilities

def check_security_headers(url):
    required_headers = [
        "Content-Security-Policy", "X-Frame-Options", "X-XSS-Protection", "Strict-Transport-Security"
    ]
    vulnerabilities = []
    
    try:
        response = requests.get(url)
        headers = response.headers
        missing_headers = [header for header in required_headers if header not in headers]
        
        if missing_headers:
            vulnerabilities.append(f"Missing security headers: {', '.join(missing_headers)}")
    except requests.RequestException as e:
        vulnerabilities.append(f"Error accessing URL: {e}")
    
    return vulnerabilities
