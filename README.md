
# Security Tool Hub

A collection of custom-built security scripts for network and web application assessment, compiled into a single, easy-to-use command-line interface.

> Developed by students of CADT for **educational purposes** only.

---

## Tools Included

### NetTools (Network Security)
- **Persistence (Linux)**: Creates various forms of persistence on a Linux system using SSH keys, cron jobs, or `.bashrc`.
- **FTP Brute Forcer**: Attempts login with common FTP credentials.
- **Port Service Scanner**: Scans open ports, identifies running services, and checks for known CVEs via NVD.
- **Loot Collector**: Post-exploitation script that extracts system info, user data, network configs, and command history.
- **Advanced Port Scanner (P1-SCAN)**: Fast, multi-threaded scanner with banner grabbing and basic OS fingerprinting.
- **SSH Brute-Force Engine**: Multi-threaded tool to brute-force SSH logins.

### WebTools (Web Application Security)
- **Directory & Email Finder**: Crawls websites to discover hidden directories and email addresses.
- **Component Version Enumerator**: Identifies versions of web technologies (frameworks/libraries).
- **XSS Scanner**: Automatically tests for Cross-Site Scripting vulnerabilities.
- **Header Analyzer**: Checks HTTP security headers and reports on configuration.
- **SQL Injection Tester**: Scans for and identifies SQL injection points.

---

## Installation

Clone the repository:

```bash
git clone https://github.com/End3ymion/SecurityTools.git
cd SecurityTools
````

Install the dependencies:

```bash
pip install -r requirements.txt
```

---

## Usage

Launch the main menu interface:

```bash
python main.py
```

From there, navigate to **NetTools** or **WebTools** and choose the script you want to run.

---

## Disclaimer

This toolkit is intended **for educational and authorized security testing purposes only**.
Do **not** use these tools on any network, system, or website without **explicit permission** from the owner.
The developers assume **no responsibility** for misuse or damages caused by this software.

---

