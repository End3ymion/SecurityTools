Security Tool Hub

A collection of custom-built security scripts for network and web application assessment, compiled into a single, easy-to-use command-line interface. This project was developed by students of CADT for educational purposes.
Tools Included
NetTools (Network Security)

    Persistence (Linux): A tool to create various forms of persistence on a Linux target, such as via SSH keys, cron jobs, or .bashrc files.

    FTP Brute Forcer: A script that attempts to find valid login credentials for an FTP server by trying a list of common usernames and passwords.

    Port Service Scanner: A comprehensive scanner that identifies open ports, the services running on them, and queries the NVD for known CVEs.

    Loot Collector: A post-exploitation script that gathers system information, user details, network configuration, and command history from a target machine.

    Advanced Port Scanner (P1-SCAN): A fast, multi-threaded port scanner that also performs banner grabbing and basic OS fingerprinting.

    SSH Brute-Force Engine: A multithreaded tool to brute-force SSH credentials.

WebTools (Web Application Security)

    Directory & Email Finding: A script to discover hidden directories and email addresses on a web server.

    Component Version Enumeration: A tool that identifies the versions of web components (like frameworks and libraries) in use.

    XSS Scanner: A script designed to automatically test web pages for Cross-Site Scripting (XSS) vulnerabilities.

    Header Analyzer: A utility that inspects HTTP security headers of a website and reports on their configuration.

    SQL Injection: A tool to scan for and identify potential SQL injection vulnerabilities in web applications.

Installation

    Clone the repository:

    git clone https://github.com/End3ymion/SecurityTools.git
    cd SecurityTools

    Install the required dependencies:


    pip install -r requirements.txt

Usage

To start the Security Tool Hub, run the main.py script from the root of the project directory.

python main.py

This will launch the main menu, where you can navigate to the NetTools or WebTools submenus to select and run any of the included scripts.
Disclaimer

This toolkit is intended for educational and authorized security testing purposes only. Do not use these tools on any system or network without explicit permission from the owner. The developers are not responsible for any misuse or damage caused by this software.
