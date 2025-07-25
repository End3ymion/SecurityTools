import re
import requests
import sys
from urllib.parse import urlparse
import pyfiglet # for styling word "Security Tools"
from colorama import Fore, Style, init #for styling word "Security Tools"

from Lymean import DEFinding

# headers = {
#     "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
# }

REQUEST_DELAY = 1  # seconds delay between requests to reduce blocking

def get_headers():
    return {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    }

def get_base_url(input_str):
    if input_str.startswith('http://') or input_str.startswith('https://'):
        return input_str.rstrip('/')
    else:
        return 'http://' + input_str.rstrip('/')
    
def is_valid_target(target):
    domain_pattern = re.compile(r"^(?!\-)([a-zA-Z0-9\-]{1,63}\.)+[a-zA-Z]{2,}$")
    url_pattern = re.compile(r"^(https?://)?(www\.)?([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}(/[\w\-./?%&=]*)?$")
    return bool(domain_pattern.match(target) or url_pattern.match(target))

def check_webpage_exists(target):

    if not target.startswith("http"):
        target = "http://" + target

    parsed = urlparse(target)
    base = parsed.netloc or parsed.path  # handles raw IP/domain inputs

    for scheme in ["http", "https"]:
        try:
            response = requests.get(f"{scheme}://{base}", timeout=5)
            if response.status_code < 400:
                return True
        except requests.RequestException:
            continue
    return False
    
def return_to_home():
    while True:
        choice = input("Enter 0 to return to home, or q to quit: ").strip()
        if choice == '0':
            main()
        elif choice.lower() == 'q':
            print("Exiting program.")
            exit()
        else:
            print("❌ Invalid choice. Please enter 0 or q.")

def main():
    attempts = 0

    # Header lines using "_" * length
    print(" "+"_"*50 + "_"*80)

    # Title row
    print(f"| {'\033[1;34m\t\tModules\033[0m':<47}| {'\033[1;34m\t\t\t\tDefinition\033[0m':<66}|")

    # Divider
    print("|" + "_"*49 + "|" + "_"*80 + "|")

    # Rows
    print(f"| 1. Directory & Email Brute Force                | Finding exposed directory and Email " + " "*43 + "|")

    print("|" + "_"*49 + "|" + "_"*80 + "|")  

    print(f"| 2. Security Header Analyzer                     | Finding header vulnerabilities." + " "*48 + "|")

    print("|" + "_"*49 + "|" + "_"*80 + "|")

    print(f"| 3. SQL Injection Scanner                        | Detect SQL injection flaws in input fields or URLs." + " "*28 + "|")

    print("|" + "_"*49 + "|" + "_"*80 + "|")

    print(f"| 4. XSS Auto-Scanner                             | Scan for cross-site scripting (XSS) vulnerabilities automatically." + " "*13 + "|")

    print("|" + "_"*49 + "|" + "_"*80 + "|")

    print(f"| 5. Web Login Brute-Forcer                       | Attempt to brute-force login forms using known username/password lists." + " "*8 + "|")

    print("|" + "_"*49 + "|" + "_"*80 + "|")

    print(f"| 6. Component Version Enumerator                 | Identify versions of web components to find outdated or vulnerable ones." + " "*7 + "|")

    # Bottom line
    print("|" + "_"*49 + "|" + "_"*80 + "|")

    while attempts < 3:
        try:
            option = int(input("Please choose option (1–7): "))

            if option == 1:
                 # input url, domain, or ip
                attempts = 0
                while attempts < 3:
                    target = input("Enter target (domain or full URL): ").strip()

                    if not target:
                        attempts += 1
                        print(f"\033[1;31m[Error]\033[0m No input provided. Attempts left: {3 - attempts}")
                        continue

                    if not is_valid_target(target):
                        attempts += 1
                        print(f"\033[1;31m[Error]\033[0m Invalid format. Attempts left: {3 - attempts}")
                        continue

                    if not check_webpage_exists(target):
                        attempts += 1
                        print(f"\033[1;31m[Error]\033[0m Webpage not reachable. Attempts left: {3 - attempts}")
                        continue

                    print(f"\033[1;32m[OK]\033[0m Valid and reachable target: {target}")
                    base_url = get_base_url(target)
                    break
                else:
                    print(f"\033[1;31mYou ran out of attempts.\033[0m")
                    sys.exit()

                found_dirs = DEFinding.directory_brute_force(base_url)
                # google_dork = DEFinding.search_google_dork(base_url)  # Don't open this function guys!!
                scan_email = DEFinding.scan_emails(base_url)
                return_to_home()

            # elif option == 2:
            #     return_to_home()

            # elif option == 3:
            #     return_to_home()

            # elif option == 4:
            #     return_to_home()

            # elif option == 5:
            #     return_to_home()

            # elif option == 6:
            #     return_to_home()

            else:
                attempts += 1
                print(f"\033[1;31m[Error]\033[0m Invalid option. Please choose a number between 1 and 7. Attempts left: {3 - attempts}")

        except ValueError:
            attempts += 1
            print(f"\033[1;31m[Error]\033[0m Invalid input. Please enter a number (1–7). Attempts left: {3 - attempts}")
    print(f"\033[1;31mYou run out of time.\033[0m")
    exit()

if __name__ == "__main__":
    init(autoreset=True)  # Ensure colors reset correctly on all terminals

    # Start title styling
    ascii_art = pyfiglet.figlet_format("WEB SECURITY TOOLS", font="doom", width=200)
    colored_art = ""

    for ch in ascii_art:
        if ch == " ":
            colored_art += ch  # keep spaces default color
        else:
            colored_art += Fore.BLUE + ch + Style.RESET_ALL  # color letters blue

    print(colored_art)  # <-- only print once after loop
    # End title styling

    main()