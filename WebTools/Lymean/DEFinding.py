import requests
import re
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup #for email
import time
import os # Added for clear_screen
import pyfiglet # for styling word "Security Tools"
from colorama import Fore, Style, init #for styling word "Security Tools"

# Configuration
# List of possible directories
COMMON_DIRS = [
    'admin', 'login', 'dashboard', 'config', 'backup', 'test', 'dev', 'debug.log', 'error.log', 'en',
    'uploads', 'images', 'css', 'js', 'api', 'robots.txt', 'robot.txt', 'users', 'phpinfo.php', 'user'
]

# Key of Lymean account in Serpapi (like google dork search engine) 
API_KEY = 'd71f9fbd17b6839f19a9ca9e469c63298f90d66202765c72ceb6cf4eb7834fe5'

# List of possible file extensions
TARGET_EXTENSIONS = ['txt', 'pdf', 'env', 'ini', 'log', 'xml', 'png','jpeg', 'jpg', 'mp3', 'xls', 'csv', 'doc'] 

EMAIL_REGEX = r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
MAX_PAGES = 30  
TIMEOUT = 10

def clear_screen():
    """Clears the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def get_headers():
    """
    Returns a dictionary of HTTP headers to be used in requests.
    This helps in mimicking a legitimate browser request.
    """
    return {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
    }

#start directory scan
def directory_brute_force(base_url):
    print("\n[+] Starting Directory Brute Force...\n", "="*50)
    found_dirs = []
    for d in COMMON_DIRS:
        url = urljoin(base_url + '/', d)
        try:
            r = requests.get(url, headers=get_headers(), timeout=7)
            if r.status_code in [200, 403]:
                print(f"  [Found] {url} (status: {r.status_code})")
                found_dirs.append(url)
            time.sleep(2)
        except requests.RequestException as e:
            print(f"  [Error] {url}: {e}")
    if not found_dirs:
        print("  No common directories found.")
    print(f"\033[1;33m*[200] \033[0m : Directory exist, sometime you are allowed to access and sometime not")
    print(f"\033[1;33m*[403] \033[0m : Directory exist but server block your request")
    print(f"\033[1;33m*\033[0m Better Destroy of the file if it is not necessary because it might be a vulnerability later.\n", "="*50)
    return found_dirs # It's good practice to return the found directories
#end of directory scan

#start using google dork
def search_google_dork(base_url):
    found_any = False
    for ext in TARGET_EXTENSIONS:
        query = f"site:{base_url} filetype:{ext}"
        params = {
            "engine": "google",
            "q": query,
            "api_key": API_KEY,
        }
        print(f"[Searching] {query} using Google Dork search engine")
        try:
            response = requests.get("https://serpapi.com/search", params=params)
            response.raise_for_status()
            data = response.json()
        except Exception as e:
            print(f"  [Error] API request failed: {e}")
            continue

        results = data.get("organic_results", [])
        if results:
            print(f"  \033[1;34m[+] Found {len(results)} results for extension '.{ext}' \033[0m")
            found_any = True
            # print URLs found
            for res in results:
                print(f"     - {res.get('link')} ")
        else:
            print(f"  \033[1;31m[-] No results for extension '.{ext}' \033[0m")

        time.sleep(2)  # Respect API rate limits
    print(f"\033[1;33m*\033[0m Better keep important file in private. It can be an information for Attacker")
    print("="*50)

    if not found_any:
        print("No files found on Google with the specified extensions.\n", "="*50)
#end of using google dork

#Start scan email
def scan_emails(base_url):
    visited = set()
    found_emails = set()

    def is_internal(link):
        return urlparse(link).netloc == "" or urlparse(link).netloc == urlparse(base_url).netloc

    def crawl(url):
        if url in visited or len(visited) >= MAX_PAGES:
            return

        try:
            visited.add(url)
            print(f"[+] Scanning: {url}")
            response = requests.get(url, headers=get_headers(), timeout=TIMEOUT)
            content = response.text

            new_emails = set(re.findall(EMAIL_REGEX, content)) - found_emails
            for email in new_emails:
                print(f"    [FOUND] {email}")
            found_emails.update(new_emails)

            soup = BeautifulSoup(content, "html.parser")
            for tag in soup.find_all("a", href=True):
                link = urljoin(url, tag['href'])
                if is_internal(link) and link not in visited:
                    crawl(link)

        except requests.RequestException as e:
            print(f"    [ERROR] Could not scan {url}: {e}")

    # Start the scan
    print("\n[+] Starting email exposure scan...\n")
    crawl(base_url)

    print(f"\033[1;32m \n[✔] Scan complete.\033[0m")
    if found_emails:
        print(f"\033[1;34m [!] Total emails found: {len(found_emails)} \033[0m")
        for email in found_emails:
            print(f"  - {email}")
    else:
        print(f"\033[1;31m[-] No emails found. \033[0m")

# --- Main function for DEFinding.py (restored) ---
def main():
    init(autoreset=True)  # Ensure colors reset correctly on all terminals

    # Start title styling
    ascii_art = pyfiglet.figlet_format("Directory / Email Brute-Force", font="doom", width=200)
    colored_art = ""

    for ch in ascii_art:
        if ch == " ":
            colored_art += ch  # keep spaces default color
        else:
            colored_art += Fore.BLUE + ch + Style.RESET_ALL  # color letters blue

    print(colored_art)  # <-- only print once after loop
    # End title styling
    base_url = input("Enter the target base URL (e.g., example.com or http://example.com): ").strip()

    # Automatically prepend http:// if no scheme is provided
    if not base_url.startswith(("http://", "https://")):
        base_url = "http://" + base_url
    
    # Basic validation to ensure it's a somewhat valid URL after modification
    try:
        result = urlparse(base_url)
        if not all([result.scheme, result.netloc]):
            print("Invalid URL format after attempting to add scheme. Please try again.")
            return
    except ValueError:
        print("Invalid URL format. Please try again.")
        return

    while True:
        clear_screen()
        print(f"--- Scan Options for {base_url} ---")
        print("1. Directory Brute Force")
        print("2. Google Dork Search (for specific file types)")
        print("3. Scan for Emails")
        print("b. Back to Main Modules Menu") # Changed from "WebTools Menu" for clarity
        print("-" * 20)
        choice = input("Choose a scan option: ").lower().strip()

        if choice == '1':
            directory_brute_force(base_url)
        elif choice == '2':
            search_google_dork(base_url)
        elif choice == '3':
            scan_emails(base_url)
        elif choice == 'b':
            break
        else:
            print("Invalid choice. Please try again.")
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    main()

