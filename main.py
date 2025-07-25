import os
import sys
import subprocess
# Added for console coloring and banner
from colorama import Fore, Style, init
import pyfiglet

# Base directory of the main script (for dynamic path resolution)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def clear_screen():
    """Clears the terminal screen for a cleaner menu display."""
    os.system('cls' if os.name == 'nt' else 'clear')

def run_tool(path_to_script, *args):
    """
    Executes a Python script as a subprocess, allowing it to inherit
    stdin, stdout, and stderr for interactive use.
    Handles path quoting and normalization for Windows paths with spaces.

    Args:
        path_to_script (str): The relative or absolute path to the Python script to execute.
        *args: Any additional command-line arguments to pass to the script.
    """
    # Ensure the script path is absolute and normalized
    full_script_path = os.path.abspath(path_to_script)
    
    print(f"\n--- Running: {os.path.basename(full_script_path)} ---")
    try:
        if sys.platform.startswith('win'):
            # Normalize paths for Windows to ensure consistent backslashes and case
            full_script_path_norm = os.path.normpath(full_script_path)
            python_executable_norm = os.path.normpath(sys.executable)

            # Quote paths for the command line
            full_script_path_quoted = f'"{full_script_path_norm}"'
            python_executable_quoted = f'"{python_executable_norm}"'
            
            cmd_parts = [python_executable_quoted, full_script_path_quoted]
            for arg in args:
                # Quote arguments too, especially if they might contain spaces
                cmd_parts.append(f'"{arg}"') 
            
            cmd_str = " ".join(cmd_parts)
            print(f"DEBUG (Windows cmd): {cmd_str}") # Debug print: Shows the exact command being run
            process = subprocess.Popen(cmd_str, stdin=sys.stdin, stdout=sys.stdout, stderr=subprocess.STDOUT, shell=True)
        else:
            # For Linux/macOS, pass the command as a list of arguments.
            command = [sys.executable, full_script_path] + list(args)
            process = subprocess.Popen(command, stdin=sys.stdin, stdout=sys.stdout, stderr=subprocess.STDOUT)
        
        process.wait() # Wait for the subprocess to complete
        print(f"\n--- Finished: {os.path.basename(full_script_path)} ---")
    except KeyboardInterrupt:
        print(f"\nTool '{os.path.basename(full_script_path)}' execution interrupted by user.")
    except FileNotFoundError:
        print(f"Error: The script '{full_script_path}' was not found. Please check the path.")
    except Exception as e:
        print(f"An unexpected error occurred while running '{os.path.basename(full_script_path)}': {e}")
    
    input("\nPress Enter to return to the menu...")

def net_tools_menu():
    """Displays the menu for Network Tools and handles user selection."""
    while True:
        clear_screen()
        print("--- NetTools Menu ---")
        print("1. Persistence (Linux)")
        print("2. FTP Brute Forcer")
        print("3. Port Service Scanner")
        print("4. Loot Collector")
        print("5. Port Scanner")
        print("b. Back to Main Menu")
        print("-" * 20)
        choice = input("Choose an option: ").lower().strip()

        if choice == '1':
            run_tool(os.path.join(BASE_DIR, "NetTools", "David", "persistence.py"))
        elif choice == '2':
            print("\nNote: FTP Brute Forcer requires a target IP.")
            print("Example: python FTP_Brute_Forcer.py -t 192.168.1.1")
            target = input("Enter target FTP server IP: ").strip()
            if target:
                run_tool(os.path.join(BASE_DIR, "NetTools", "Kimhong", "FTP_Brute_Forcer.py"), "-t", target)
            else:
                print("Target IP is required for FTP Brute Forcer. Returning to menu.")
                input("Press Enter to continue...")
        elif choice == '3':
            run_tool(os.path.join(BASE_DIR, "NetTools", "Vathana", "port_service.py"), "--tui")
        elif choice == '4':
            # Path based on your provided 'tree' structure
            run_tool(os.path.join(BASE_DIR, "NetTools", "Karona", "loot_collector.py"))
        elif choice == '5':
            # Path based on your provided 'tree' structure
            run_tool(os.path.join(BASE_DIR, "NetTools", "Panha", "port_scan.py"))
        
        elif choice == 'b':
            break
        else:
            print("Invalid choice. Please try again.")
            input("Press Enter to continue...")

def web_tools_menu():
    """Displays the menu for Web Tools and handles user selection."""
    while True:
        clear_screen()
        print("--- WebTools Menu ---")
        print("1. Directory & Email Finding")
        print("2. Component Version Enumeration")
        print("3. XSS Scanner")
        print("4. Header Analyzer")
        print("5. SQL Injection")
        print("b. Back to Main Menu")
        print("-" * 20)
        choice = input("Choose an option: ").lower().strip()

        if choice == '1':
            run_tool(os.path.join(BASE_DIR, "WebTools", "Lymean", "DEFinding.py"))
        elif choice == '2':
            run_tool(os.path.join(BASE_DIR, "WebTools", "Monyneath", "component_version_enumeration.py"))
        elif choice == '3':
            print("\nNote: XSS Scanner requires Selenium and a Chrome/Chromium browser installed.")
            print("It will prompt for the URL.")
            run_tool(os.path.join(BASE_DIR, "WebTools", "Phanith", "XSS_scanner.py"))
        elif choice == '4':
            run_tool(os.path.join(BASE_DIR, "WebTools", "Sovann", "header_analyzer.py"))
        elif choice == '5': 
            run_tool(os.path.join(BASE_DIR, "WebTools", "Bunhouy", "sql_injection.py"))
        elif choice == 'b':
            break
        else:
            print("Invalid choice. Please try again.")
            input("Press Enter to continue...")

def main():
    """Main entry point for the Tool Portal, displaying top-level categories."""
    # Initialize colorama for cross-platform colored output
    init(autoreset=True) 

    # Start title styling
    # Assuming pyfiglet is installed for the banner
    try:
        ascii_art = pyfiglet.figlet_format("SECURITY TOOLS", font="doom", width=200)
        colored_art = ""
        for ch in ascii_art:
            if ch == " ":
                colored_art += ch  # keep spaces default color
            else:
                colored_art += Fore.BLUE + ch + Style.RESET_ALL  # color letters blue
        print(colored_art)
    except Exception as e:
        print(f"Warning: Could not generate ASCII banner (pyfiglet might be missing or font 'doom' not found). Error: {e}")
        print("--- SECURITY TOOLS ---")
    # End title styling

    while True:
        clear_screen()
        print("--- Main Tool Portal ---")
        print("Welcome to your Security Tool Hub!")
        print("\nChoose a category of tools to explore:")
        print("1. NetTools (Network-focused utilities)")
        print("2. WebTools (Web application utilities)")
        print("q. Quit (Exit the portal)")
        print("-" * 20)
        choice = input("Choose a category: ").lower().strip()

        if choice == '1':
            net_tools_menu()
        elif choice == '2':
            web_tools_menu()
        elif choice == 'q':
            print("Exiting Tool Portal. Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")
            input("Press Enter to continue...")

if __name__ == "__main__":
    main()

