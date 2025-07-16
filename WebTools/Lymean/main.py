from urllib.parse import urlparse, urljoin, parse_qs, urlencode
import time
import difflib
import pyfiglet #for styling word "Security Tools"
from colorama import Fore, Style #for styling word "Security Tools"

import DirectoryFinding

# SECURITY_HEADERS = [
#     'Content-Security-Policy',
#     'Strict-Transport-Security',
#     'X-Content-Type-Options',
#     'X-Frame-Options',
#     'Referrer-Policy',
#     'Permissions-Policy'
# ]
USER_AGENT = 'Mozilla/5.0 (compatible; WebVulnScanner/1.0; +https://example.com)'

# SQL_ERROR_SIGNATURES = [
#     'you have an error in your sql syntax',
#     'warning: mysql',
#     'unclosed quotation mark',
#     'quoted string not properly terminated',
#     'pg_query()',
#     'sql syntax error',
#     'mysql_fetch_array()',
#     'syntax error'
# ]

# XSS_TEST_PAYLOAD = '<script>alert("xss")</script>'

REQUEST_DELAY = 1  # seconds delay between requests to reduce blocking

def get_headers():
    return {'User-Agent': USER_AGENT}

def get_base_url(input_str):
    if input_str.startswith('http://') or input_str.startswith('https://'):
        return input_str.rstrip('/')
    else:
        return 'http://' + input_str.rstrip('/')


# def analyze_security_headers(base_url):
#     print("\n[+] Security Headers Analysis")
#     try:
#         r = requests.get(base_url, headers=get_headers(), timeout=7)
#         missing = [h for h in SECURITY_HEADERS if h not in r.headers]
#         if missing:
#             print("  [Warning] Missing security headers:")
#             for h in missing:
#                 print(f"    - {h}")
#         else:
#             print("  [Good] All important security headers are present.")
#     except requests.RequestException as e:
#         print(f"  [Error] Could not analyze headers: {e}")

# def scan_sqli(base_url):
#     print("\n[+] SQL Injection Test")
#     parsed = urlparse(base_url)
#     if not parsed.query:
#         print("  [Info] No URL parameters to test for SQL Injection.")
#         return

#     qs = parse_qs(parsed.query)
#     vulnerable_params = []

#     # Request original page
#     try:
#         original_resp = requests.get(base_url, headers=get_headers(), timeout=7)
#         original_content = original_resp.text
#     except requests.RequestException as e:
#         print(f"  [Error] Could not fetch original page: {e}")
#         return

#     for param in qs.keys():
#         for char in ["'", '"']:
#             test_qs = qs.copy()
#             test_qs[param] = [qs[param][0] + char]
#             test_url = parsed._replace(query=urlencode(test_qs, doseq=True)).geturl()

#             try:
#                 r = requests.get(test_url, headers=get_headers(), timeout=7)
#                 time.sleep(REQUEST_DELAY)
#                 # Check for error signatures and significant content change
#                 lowered = r.text.lower()
#                 content_diff = difflib.SequenceMatcher(None, original_content, r.text).ratio()

#                 if any(sig in lowered for sig in SQL_ERROR_SIGNATURES) and content_diff < 0.95:
#                     print(f"  [VULN] SQL Injection likely on parameter '{param}' with payload {char}")
#                     vulnerable_params.append(param)
#                     break  # no need to try both chars if one succeeds

#             except requests.RequestException as e:
#                 print(f"  [Error] Testing SQLi on {test_url}: {e}")

#     if not vulnerable_params:
#         print("  [Safe] No SQL Injection vulnerabilities detected."

def main():
    #start title styling
    ascii_art = pyfiglet.figlet_format("SECURITY TOOLS", font="doom", width=200)
    colored_art = ""
    for ch in ascii_art:
        if ch == " ":
            colored_art += ch  # keep spaces default color
        else:
            colored_art += Fore.BLUE + ch + Style.RESET_ALL  # color letters blue

    print(colored_art)
    #end title styling

    #input url, domain, or ip
    target = input("Enter target (IP, domain, or full URL): ").strip()
    if not target:
        print("[Error] No input provided, exiting.")
        return
    base_url = get_base_url(target)

    print(f"Please options 1 - 5: \n" 
          "1.\033[1;34m Directory and Email Scanning \033[0m(weaknesses related to how a website or server exposes its directory, structure, files, and email to public)\n" 
          "2.\033[1;34m SQL Injection Scanning \033[0m\n"
        )
    option = int(input("Please choose option: "))
    print(f"[Info] Target base URL: {base_url}")

    if option == 1:
        found_dirs = DirectoryFinding.directory_brute_force(base_url)
        google_dork= DirectoryFinding.search_google_dork(base_url)
        scan_email = DirectoryFinding.scan_emails(base_url)
    # analyze_security_headers(base_url)
    # scan_sqli(base_url)

if __name__ == "__main__":
    main()
