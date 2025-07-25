import socket
import subprocess
import json
import requests
import os
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style, init
from pyfiglet import Figlet
from termcolor import colored

def print_tool_name():
    f = Figlet(font='standard')
    tool_name = "P1 - SCAN"

    # Render the big banner text in cyan and bold
    styled_text = colored(f.renderText(tool_name), 'cyan', attrs=['bold'])
    print(styled_text)

    # Add stylized description and lines below it
    print(colored("=" * 60, 'cyan', attrs=['bold']))
    print(colored("P1 - SCAN  •  Advanced Port & Vulnerability Scanner", 'green', attrs=['bold']))
    print(colored("=" * 60, 'cyan', attrs=['bold'])) # Cyan colored line

def validate_target(target):
    try:
        socket.inet_aton(target)
        return target
    except socket.error:
        try:
            return socket.gethostbyname(target)
        except socket.gaierror:
            print(f"[!] Could not resolve {target}")
            return None

def banner_grab(ip, port, timeout=2):
    try:
        with socket.socket() as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            banner = s.recv(1024).decode(errors='ignore').strip()
            return banner
    except:
        return None

def scan_port(ip, port, timeout=1):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                banner = banner_grab(ip, port)
                return port, service, banner
    except Exception:
        pass
    return None

def scan_ports(target, ports):
    open_ports = {}
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(scan_port, target, port) for port in ports]
        for future in futures:
            result = future.result()
            if result:
                port, service, banner = result
                open_ports[port] = {
                    "name": service,
                    "state": "open",
                    "banner": banner or "N/A",
                    "vulnerabilities": search_vulns(service, banner)
                }
    return open_ports

def search_vulns(service, banner):
    """Basic CVE lookup using the CIRCL public API for demonstration."""
    cve_api = "https://cve.circl.lu/api/search/"
    query = banner if banner and len(banner) > 3 else service
    if not query:
        return []

    try:
        response = requests.get(cve_api + query, timeout=5)
        if response.status_code == 200:
            data = response.json()
            vulns = []
            for item in data.get("data", [])[:5]:  # Limit to 5 for brevity
                vulns.append({
                    "id": item.get("id"),
                    "summary": item.get("summary", "")[:100]
                })
            return vulns
    except Exception as e:
        pass
    return []

def get_domain_from_ip(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return None
    
import platform
import re

def os_fingerprint(ip):
    try:
        if platform.system().lower() == "windows":
            cmd = ["ping", "-n", "1", ip]
        else:
            cmd = ["ping", "-c", "1", ip]

        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        out, _ = proc.communicate()
        output = out.decode(errors='ignore')

        ttl_match = re.search(r"ttl[=|:](\d+)", output, re.IGNORECASE)
        if ttl_match:
            ttl_value = int(ttl_match.group(1))

            if ttl_value <= 64:
                return "Linux/Unix-based (TTL ~64)"
            elif ttl_value <= 128:
                return "Windows (TTL ~128)"
            elif ttl_value <= 255:
                return "Network Device / BSD / Cisco (TTL ~255)"
            else:
                return f"Unexpected TTL value ({ttl_value})"
    except Exception as e:
        pass

    return "Unknown"

def print_results(results, output_file=None):
    print(f"\n{Fore.GREEN}{Style.BRIGHT}[+] Scan Results:")
    print(f"{Fore.CYAN}- Target: {results['target']}")
    print(f"{Fore.CYAN}- IP: {results['ip']}")
    print(f"{Fore.CYAN}- Domain: {results['domain'] or 'N/A'}")
    print(f"{Fore.CYAN}- OS Guess: {results['os_info']}")
    print(f"{Fore.CYAN}- Open Ports: {len(results['open_ports'])}\n")

    for port, info in sorted(results['open_ports'].items()):
        print(f"{Fore.YELLOW}[PORT {port}] {info['name'].upper()}")
        print(f"  {Fore.LIGHTBLUE_EX}State      : {info['state']}")
        print(f"  {Fore.LIGHTBLUE_EX}Banner     : {info['banner']}")
        
        if info['vulnerabilities']:
            print(f"  {Fore.LIGHTRED_EX}Vulnerabilities:")
            for vuln in info['vulnerabilities']:
                print(f"    {Fore.RED}- {vuln['id']}: {vuln['summary']}")
        else:
            print(f"  {Fore.GREEN}No vulnerabilities found.")
        print()
    if output_file:
        if not output_file.endswith(".json"):
            output_file += ".json"
        # script_dir = os.path.dirname(os.path.abspath(__file__))
        # save_path  = os.path.join(script_dir, output_file)
        script_dir = os.path.dirname(os.path.abspath(__file__))
        result_dir = os.path.join(script_dir, "result")
        os.makedirs(result_dir, exist_ok=True)
        save_path = os.path.join(result_dir, output_file)

        # output_file = os.path.basename(output_file)
        with open(save_path, "w") as f:
            json.dump(results, f, indent=4)
        print(f"{Fore.GREEN}[+] Results saved to {Style.BRIGHT}{save_path}\n")
  
def main(target, full_scan=False, output_file=False):
    target_ip = validate_target(target)
    if not target_ip:
        return

    print(f"[*] Scanning {target} (IP: {target_ip})")

    if full_scan:
        ports = list(range(1, 65536))
    else:
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389, 8080]

    os_info = os_fingerprint(target_ip)

    results = {
        "target": target,
        "ip": target_ip,
        "domain": get_domain_from_ip(target_ip),
        "timestamp": datetime.now().isoformat(),
        "os_info": os_info,
        "open_ports": scan_ports(target_ip, ports)
    }
    print_results(results, output_file)

init(autoreset=True)
      
if __name__ == "__main__":
    print_tool_name()
    parser = argparse.ArgumentParser(description="Advanced Port & Info Scanner")
    target = input("Enter target IP or domain: ").strip()

    full_input = input("Do you want to scan all 65535 ports? (y/n): ").strip().lower()
    full_scan = full_input == "y"

    save_output = input("Do you want to save the results to a file? (y/n): ").strip().lower()
    if save_output == "y":
        filename = input("Enter output filename (without .json): ").strip()
        output_file = filename
    else:
        output_file = None
        
    args = parser.parse_args()
    main(target, full_scan, output_file)
