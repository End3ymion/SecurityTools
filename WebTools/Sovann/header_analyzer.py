import requests
from urllib.parse import urlparse

requests.packages.urllib3.disable_warnings()

COL = {
    "H": "\033[91m",  # Red
    "M": "\033[93m",  # Yellow
    "L": "\033[94m",  # Blue
    "I": "\033[90m",  # Gray
    "END": "\033[0m"
}

SECURITY_HEADERS = {
    'Strict-Transport-Security': 'Enforces HTTPS (HSTS)',
    'Content-Security-Policy': 'Mitigates XSS & data injection',
    'X-Frame-Options': 'Prevents clickjacking',
    'X-Content-Type-Options': 'Prevents MIME sniffing',
    'Referrer-Policy': 'Controls referrer privacy',
    'Permissions-Policy': 'Restricts browser features (Geo, Cam)',
    'Cross-Origin-Embedder-Policy': 'Isolation for COOP/COEP',
    'Cross-Origin-Opener-Policy': 'Isolates top-level browsing context',
    'Expect-CT': 'Enforces Certificate Transparency',
    'Access-Control-Allow-Origin': 'CORS controls for APIs',
    'X-DNS-Prefetch-Control': 'Controls DNS prefetching',
    'Set-Cookie': 'Secure/HttpOnly on cookies'
}

def analyze_headers(url):
    print(f"\n[+] Scanning {url}")
    try:
        res = requests.get(url, timeout=5, verify=False)
    except Exception as e:
        print(f"{COL['H']}❌ Error: {e}{COL['END']}")
        return

    headers = res.headers
    found = 0
    total = len(SECURITY_HEADERS)

    for h, desc in SECURITY_HEADERS.items():
        if h in headers:
            if h == 'Set-Cookie' and ('Secure' not in headers[h] or 'HttpOnly' not in headers[h]):
                print(f"{COL['M']}❌ {h}: Missing Secure/HttpOnly{COL['END']}")
            else:
                print(f"{COL['L']}✅ {h}: {desc}{COL['END']}")
                found += 1
        else:
            print(f"{COL['M']}❌ {h}: {desc}{COL['END']}")

    # Adjusted grading logic
    if found >= 10:
        grade = f"{COL['L']}A{COL['END']}"
    elif found >= 8:
        grade = f"{COL['L']}B{COL['END']}"
    elif found >= 6:
        grade = f"{COL['M']}C{COL['END']}"
    elif found >= 4:
        grade = f"{COL['M']}D{COL['END']}"
    else:
        grade = f"{COL['H']}F{COL['END']}"

    print(f"\n{COL['I']}✔ Summary: {found}/{total} headers found → Grade: {grade}{COL['END']}")

def main():
    raw = input("Enter target (URL, domain, or IP): ").strip()
    if not raw.startswith("http"):
        raw = "http://" + raw
    parsed = urlparse(raw)
    target_url = f"{parsed.scheme}://{parsed.hostname}"
    analyze_headers(target_url)

if __name__ == "__main__":
    main()
