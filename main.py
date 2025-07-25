import os
import sys
import subprocess

def clear_screen():
    """Clears the terminal screen for a cleaner menu display."""
    os.system('cls' if os.name == 'nt' else 'clear')

def run_tool(path_to_script, *args):
    """
    Executes a Python script as a subprocess, allowing it to inherit
    stdin, stdout, and stderr for interactive use.

    Args:
        path_to_script (str): The relative path to the Python script to execute.
        *args: Any additional command-line arguments to pass to the script.
    """
    # Construct the command using the current Python executable
    command = [sys.executable, path_to_script] + list(args)
    
    try:
        print(f"\n--- Running: {os.path.basename(path_to_script)} ---")
        # Use Popen to allow the subprocess to run interactively
        process = subprocess.Popen(command, stdin=sys.stdin, stdout=sys.stdout, stderr=subprocess.STDOUT)
        process.wait() # Wait for the subprocess to complete
        print(f"\n--- Finished: {os.path.basename(path_to_script)} ---")
    except KeyboardInterrupt:
        # Handle Ctrl+C during tool execution
        print(f"\nTool '{os.path.basename(path_to_script)}' execution interrupted by user.")
    except FileNotFoundError:
        print(f"Error: The script '{path_to_script}' was not found. Please check the path.")
    except Exception as e:
        print(f"An unexpected error occurred while running '{os.path.basename(path_to_script)}': {e}")
    
    input("\nPress Enter to return to the menu...")

def net_tools_menu():
    """Displays the menu for Network Tools and handles user selection."""
    while True:
        clear_screen()
        print("--- NetTools Menu ---")
        print("1. Persistence (Linux)")
        print("2. FTP Brute Forcer")
        print("3. Port Service Scanner")
        print("b. Back to Main Menu")
        print("-" * 20)
        choice = input("Choose an option: ").lower().strip()

        if choice == '1':
            # Persistence tool is interactive and has its own menu
            run_tool("NetTools/David/persistence.py")
        elif choice == '2':
            # FTP Brute Forcer requires a target argument
            print("\nNote: FTP Brute Forcer requires a target IP.")
            print("Example: python FTP_Brute_Forcer.py -t 192.168.1.1")
            target = input("Enter target FTP server IP: ").strip()
            if target:
                run_tool("NetTools/Kimhong/FTP_Brute_Forcer.py", "-t", target)
            else:
                print("Target IP is required for FTP Brute Forcer. Returning to menu.")
                input("Press Enter to continue...")
        elif choice == '3':
            # Port Service Scanner has a Text-based User Interface (TUI)
            run_tool("NetTools/Vathana/port_service.py", "--tui")
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
        print("b. Back to Main Menu")
        print("-" * 20)
        choice = input("Choose an option: ").lower().strip()

        if choice == '1':
            # Directory & Email Finding tool is interactive
            run_tool("WebTools/Lymean/DEFinding.py")
        elif choice == '2':
            # Component Version Enumeration tool is interactive
            run_tool("WebTools/Monyneath/component_version_enumeration.py")
        elif choice == '3':
            # XSS Scanner requires Selenium and a browser (e.g., Chrome)
            print("\nNote: XSS Scanner requires Selenium and a Chrome/Chromium browser installed.")
            print("It will prompt for the URL.")
            run_tool("WebTools/Phanith/XSS_scanner.py")
        elif choice == '4':
            # Header Analyzer tool is interactive
            run_tool("WebTools/Sovann/header_analyzer.py")
        elif choice == 'b':
            break
        else:
            print("Invalid choice. Please try again.")
            input("Press Enter to continue...")

def main():
    """Main entry point for the Tool Portal, displaying top-level categories."""
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

