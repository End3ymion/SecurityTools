import pyfiglet # for styling word "Security Tools"
from colorama import Fore, Style #for styling word "Security Tools"

import DirectoryFinding

USER_AGENT = 'Mozilla/5.0 (compatible; WebVulnScanner/1.0; +https://example.com)'

REQUEST_DELAY = 1  # seconds delay between requests to reduce blocking

def get_headers():
    return {'User-Agent': USER_AGENT}

def get_base_url(input_str):
    if input_str.startswith('http://') or input_str.startswith('https://'):
        return input_str.rstrip('/')
    else:
        return 'http://' + input_str.rstrip('/')

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
        # google_dork= DirectoryFinding.search_google_dork(base_url) # Don't open this function guys!!
        scan_email = DirectoryFinding.scan_emails(base_url)

if __name__ == "__main__":
    main()
