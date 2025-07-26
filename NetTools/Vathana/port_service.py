#!/usr/bin/env python3
# --- Network Service Fingerprinting Engine with NVD API Integration ---
# For legitimate network security assessment and infrastructure auditing
# *** LEGAL WARNING: Only scan systems you have explicit permission to test ***

import socket
import time
import re
import json
import ssl
import struct
import random
import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple
import argparse
import platform
from datetime import datetime
import os
import sys
import textwrap

# --- Conditional Imports for Optional Libraries ---
try:
    from scapy.all import sr1, IP, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
try:
    import nvdlib
    NVDLIB_AVAILABLE = True
except ImportError:
    NVDLIB_AVAILABLE = False
try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False
try:
    from colorama import init, Fore, Style
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False

# --- Configuration ---
NVD_API_KEY = os.getenv('NVD_API_KEY', '5323209c-2b2e-431c-8f5a-c86d9f2420e7')
CACHE_FILE = 'cve_cache.json'
# Default ports are a selection of commonly used ports, similar to Nmap's top ports.
# For a full Nmap-like 1000 common ports, specify '1-1000' in the TUI.
DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 111, 139, 445, 512, 513, 514, 1099, 1524, 2049, 2121, 3306, 3632, 5432, 5900, 6000, 6667, 6697, 8009, 8180, 8787]
DEFAULT_THREADS = 20
DEFAULT_TIMEOUT = 5
MAX_REPORT_LINE_WIDTH = 100

# --- ServiceFingerprint Data Class ---
@dataclass
class ServiceFingerprint:
    port: int
    protocol: str
    state: str
    service: str
    version: str
    banner: str
    cve_vulnerabilities: List[Dict[str, str]]
    general_risks: List[Dict[str, str]]
    recommendations: List[str]
    confidence: float
    extra_info: Dict[str, str]

# --- OSFingerprint Data Class ---
@dataclass
class OSFingerprint:
    os_family: str
    os_version: str
    confidence: float
    method: str
    details: str

# --- ServiceSignatures Class ---
class ServiceSignatures:
    """Manages service signatures, port vulnerabilities, and OS fingerprinting patterns."""
    def __init__(self):
        self.signatures = {
            'apache': {
                'patterns': [r'Apache/(\d+\.\d+\.\d+)', r'Server: Apache'],
                'ports': [80, 443, 8080, 8180, 8443],
                'recommendations': [
                    'Update Apache to latest stable version',
                    'Disable server signature (ServerSignature Off)',
                    'Configure proper SSL/TLS settings'
                ]
            },
            'nginx': {
                'patterns': [r'nginx/(\d+\.\d+\.\d+)', r'Server: nginx'],
                'ports': [80, 443, 8080],
                'recommendations': [
                    'Update nginx to latest version',
                    'Hide nginx version (server_tokens off)'
                ]
            },
            'openssh': {
                'patterns': [r'OpenSSH_(\d+\.\d+[a-z0-9]*)', r'SSH-2.0-OpenSSH'],
                'ports': [22],
                'recommendations': [
                    'Update OpenSSH to latest version',
                    'Disable root login',
                    'Use key-based authentication'
                ]
            },
            'vsftpd': {
                'patterns': [r'vsFTPd (\d+\.\d+\.\d+)', r'220.*vsFTPd'],
                'ports': [21, 2121],
                'recommendations': [
                    'Update vsftpd to latest version',
                    'Disable anonymous FTP',
                    'Use FTPS instead of plain FTP'
                ]
            },
            'mysql': {
                'patterns': [r'(\d+\.\d+\.\d+[a-z]*)-.*MySQL', r'mysql_native_password'],
                'ports': [3306],
                'recommendations': [
                    'Update MySQL to latest version',
                    'Use strong passwords'
                ]
            },
            'postgresql': {
                'patterns': [r'PostgreSQL (\d+\.\d+\.\d+)', r'SCRAM-SHA-256'],
                'ports': [5432],
                'recommendations': [
                    'Update PostgreSQL to latest version',
                    'Configure proper authentication'
                ]
            },
            'bind': {
                'patterns': [r'BIND (\d+\.\d+\.\d+)', r'ISC BIND'],
                'ports': [53],
                'recommendations': [
                    'Update BIND to latest version',
                    'Restrict recursive queries'
                ]
            },
            'samba': {
                'patterns': [r'Samba (\d+\.\d+\.\d+)', r'smbd.*Samba'],
                'ports': [139, 445],
                'recommendations': [
                    'Update Samba to latest version',
                    'Disable SMBv1 protocol'
                ]
            },
            'postfix': {
                'patterns': [r'Postfix.*smtpd', r'ESMTP Postfix'],
                'ports': [25],
                'recommendations': [
                    'Update Postfix to latest version',
                    'Configure spam filtering'
                ]
            },
            'proftpd': {
                'patterns': [r'ProFTPD (\d+\.\d+\.\d+)', r'220.*ProFTPD'],
                'ports': [21, 2121],
                'recommendations': [
                    'Update ProFTPD to latest version',
                    'Disable anonymous access'
                ]
            },
            'unrealircd': {
                'patterns': [r'Unreal(\d+\.\d+)', r'UnrealIRCd'],
                'ports': [6667, 6697],
                'recommendations': [
                    'Update UnrealIRCd to latest version',
                    'Configure SSL/TLS'
                ]
            },
            'tomcat': {
                'patterns': [r'Apache Tomcat/(\d+\.\d+)', r'Coyote.*(\d+\.\d+)'],
                'ports': [8080, 8180],
                'recommendations': [
                    'Update Tomcat to latest version',
                    'Remove default applications'
                ]
            },
            'vnc': {
                'patterns': [r'VNC.*protocol (\d+\.\d+)', r'RFB (\d+\.\d+)'],
                'ports': [5900],
                'recommendations': [
                    'Update VNC software',
                    'Use strong passwords'
                ]
            },
            'java-rmi': {
                'patterns': [r'GNU Classpath', r'rmi registry'],
                'ports': [1099],
                'recommendations': [
                    'Restrict RMI access',
                    'Update Java runtime'
                ]
            },
            'bindshell': {
                'patterns': [r'Metasploitable root shell', r'sh-'],
                'ports': [1524],
                'recommendations': [
                    'Remove backdoor immediately',
                    'Secure system access'
                ]
            },
            'nfs': {
                'patterns': [r'nfs', r'NFS'],
                'ports': [2049],
                'recommendations': [
                    'Restrict NFS access',
                    'Use strong authentication'
                ]
            },
            'ajp': {
                'patterns': [r'Apache Jserv', r'ajp'],
                'ports': [8009],
                'recommendations': [
                    'Update AJP server',
                    'Restrict AJP access'
                ]
            },
            'x11': {
                'patterns': [r'X11', r'X Window'],
                'ports': [6000],
                'recommendations': [
                    'Restrict X11 access',
                    'Use SSH tunneling'
                ]
            },
            'distccd': {
                'patterns': [r'distccd', r'DistCC'],
                'ports': [3632],
                'recommendations': [
                    'Restrict distccd access',
                    'Update distccd to latest version'
                ]
            }
        }
        # Defines general risks associated with common ports
        self.port_vulnerabilities = {
            21: {'service': 'FTP', 'risks': ['Plain text credentials', 'Data interception']},
            22: {'service': 'SSH', 'risks': ['Brute force attacks', 'Weak algorithms']},
            23: {'service': 'Telnet', 'risks': ['Plain text protocol', 'No encryption']},
            25: {'service': 'SMTP', 'risks': ['Email relay abuse', 'Information disclosure']},
            53: {'service': 'DNS', 'risks': ['DNS amplification attacks', 'Cache poisoning']},
            80: {'service': 'HTTP', 'risks': ['Web application vulnerabilities', 'Information disclosure']},
            111: {'service': 'RPC', 'risks': ['Remote procedure call abuse', 'Information disclosure']},
            139: {'service': 'NetBIOS', 'risks': ['Information disclosure', 'Null session attacks']},
            445: {'service': 'SMB', 'risks': ['EternalBlue', 'Credential relay attacks']},
            512: {'service': 'rexec', 'risks': ['Remote execution', 'Plain text authentication']},
            513: {'service': 'rlogin', 'risks': ['Remote login vulnerabilities', 'Weak authentication']},
            514: {'service': 'rsh', 'risks': ['Remote shell access', 'No encryption']},
            1099: {'service': 'Java RMI', 'risks': ['Deserialization attacks']},
            1524: {'service': 'Bindshell', 'risks': ['Unauthenticated shell access']},
            2049: {'service': 'NFS', 'risks': ['File system exposure']},
            2121: {'service': 'FTP', 'risks': ['Plain text credentials']},
            3306: {'service': 'MySQL', 'risks': ['SQL injection', 'Weak authentication']},
            3632: {'service': 'distccd', 'risks': ['Remote code execution']},
            5432: {'service': 'PostgreSQL', 'risks': ['SQL injection', 'Privilege escalation']},
            5900: {'service': 'VNC', 'risks': ['Weak authentication']},
            6000: {'service': 'X11', 'risks': ['Unauthorized display access']},
            6667: {'service': 'IRC', 'risks': ['Botnet communication']},
            6697: {'service': 'IRC', 'risks': ['Botnet communication']},
            8009: {'service': 'AJP', 'risks': ['Ghostcat vulnerability']},
            8180: {'service': 'HTTP', 'risks': ['Web application vulnerabilities']},
            8787: {'service': 'Unknown', 'risks': ['Unidentified service exposure']}
        }
        # Defines OS fingerprinting patterns based on banners and TCP traits
        self.os_signatures = {
            'linux': {
                'patterns': [r'Linux.*(\d+\.\d+\.\d+)', r'Ubuntu.*(\d+\.\d+)'],
                'banner_indicators': ['Linux', 'Ubuntu', 'Debian', 'GNU'],
                'tcp_traits': {'ttl': range(60, 65), 'window': [5840, 29200, 65535]}
            },
            'windows': {
                'patterns': [r'Windows.*(\d+)', r'Microsoft.*Windows.*(\d+)'],
                'banner_indicators': ['Windows', 'Microsoft', 'IIS'],
                'tcp_traits': {'ttl': range(120, 129), 'window': [8192, 16384, 65535]}
            }
        }

# --- NetworkScanner Class ---
class NetworkScanner:
    """Core class for network scanning, service fingerprinting, and vulnerability assessment."""
    def __init__(self, timeout=DEFAULT_TIMEOUT, threads=DEFAULT_THREADS, nvd_api_key=NVD_API_KEY):
        self.timeout = timeout
        self.threads = min(threads, 500)
        self.signatures = ServiceSignatures()
        self.results = []
        self.os_info = None
        self.start_time = None
        self.nvd_api_key = nvd_api_key
        self.cve_cache = self.load_cve_cache()
        if COLORAMA_AVAILABLE:
            init()

    # --- Load CVE Cache ---
    def load_cve_cache(self) -> Dict:
        """Loads CVE data from a local JSON cache file."""
        try:
            if os.path.exists(CACHE_FILE):
                with open(CACHE_FILE, 'r') as f:
                    return json.load(f)
        except Exception as e:
            print(f"Warning: Could not load CVE cache: {e}")
        return {}

    # --- Save CVE Cache ---
    def save_cve_cache(self):
        """Saves CVE data to a local JSON cache file."""
        try:
            with open(CACHE_FILE, 'w') as f:
                json.dump(self.cve_cache, f, indent=2)
        except Exception as e:
            print(f"Warning: Could not save CVE cache: {e}")

    # --- Grab Banner Asynchronously ---
    async def grab_banner_async(self, host: str, port: int, retries=3) -> Tuple[str, Dict[str, str]]:
        """Asynchronously attempts to grab a service banner from a given host and port."""
        extra_info = {}
        for attempt in range(retries):
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=self.timeout
                )
                probes = self.get_service_probes(port)
                banner = ""

                for probe in probes:
                    try:
                        if probe:
                            writer.write(probe.encode())
                            await writer.drain()
                        data = await asyncio.wait_for(reader.read(4096), timeout=3)
                        decoded = data.decode('utf-8', errors='ignore')
                        if decoded:
                            banner += decoded
                            if port == 21 and "230" in decoded:
                                extra_info['ftp_anon'] = "Anonymous FTP login allowed"
                            elif port == 22 and "SSH-" in decoded:
                                extra_info['ssh_protocol'] = decoded.split('\n')[0]
                            elif port in (139, 445) and "samba" in decoded.lower():
                                extra_info['smb_version'] = decoded.split('\n')[0]
                            elif port == 3306 and "mysql" in decoded.lower():
                                extra_info['mysql_version'] = decoded.split('\n')[0]
                            elif port == 5432 and "postgresql" in decoded.lower():
                                extra_info['postgresql_info'] = decoded.split('\n')[0]
                    except:
                        continue

                writer.close()
                await writer.wait_closed()
                return banner.strip() or "No banner received", extra_info
            except (asyncio.TimeoutError, socket.error):
                if attempt == retries - 1:
                    return "Error grabbing banner", extra_info
                time.sleep(0.5)
        return "Error grabbing banner", extra_info

    # --- Grab Banner Synchronously ---
    def grab_banner(self, sock: socket.socket, port: int) -> Tuple[str, Dict[str, str]]:
        """Synchronously attempts to grab a service banner from a given socket and port."""
        extra_info = {}
        try:
            sock.settimeout(3)
            data = sock.recv(4096)
            try:
                banner = data.decode('utf-8', errors='ignore').strip()
            except UnicodeDecodeError:
                banner = f"Binary protocol (hex: {data.hex()[:50]}...)"
            if port in (139, 445):
                extra_info['smb_version'] = "Detected (version probing limited)"
            elif port == 53:
                extra_info['dns_info'] = "DNS service detected"
            return banner or "No banner received", extra_info
        except:
            return "Error grabbing banner", extra_info

    # --- Get Service Probes ---
    def get_service_probes(self, port: int) -> List[str]:
        """Returns a list of probes to send to a port to elicit a banner."""
        return {
            21: ["", "USER anonymous\r\n"],
            22: [""],
            23: [""],
            25: ["EHLO test.com\r\n"],
            53: ["\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x76\x65\x72\x00"],
            80: ["GET / HTTP/1.1\r\nHost: target\r\n\r\n"],
            111: ["\x80\x00\x00\x28\x72\x70\x63\x62\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xa0"],
            139: ["\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8"],
            445: ["\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8"],
            512: [""],
            513: [""],
            514: [""],
            1099: [""],
            1524: [""],
            2049: ["\x80\x00\x00\x28\x72\x70\x63\x62\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xa0"],
            2121: ["USER anonymous\r\n"],
            3306: [""],
            3632: [""],
            5432: ["\x00\x00\x00\x08\x04\xD2\x16\x2F"],
            5900: ["RFB 003.008\n"],
            6000: [""],
            6667: ["NICK test\r\nUSER test test test :test\r\n"],
            6697: ["NICK test\r\nUSER test test test :test\r\n"],
            8009: ["\x12\x34\x00\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00"],
            8180: ["GET / HTTP/1.1\r\nHost: target\r\n\r\n"],
            8787: [""]
        }.get(port, [""])

    # --- Query NVD CVE ---
    def query_nvd_cve(self, service: str, version: str) -> Tuple[List[Dict[str, str]], bool]:
        """Queries the NVD API for CVEs related to a given service and version."""
        if not NVDLIB_AVAILABLE:
            return [{'id': 'N/A', 'description': 'nvdlib not installed. Install with: pip install nvdlib', 'severity': 'N/A', 'cvss_score': 'N/A', 'solution': 'Install nvdlib to query NVD API'}], False
        
        cache_key = f"{service.lower()}:{version}"
        if cache_key in self.cve_cache:
            print(f"  {Fore.CYAN}[NVD]{Style.RESET_ALL} Using cached CVEs for {cache_key}")
            return self.cve_cache[cache_key], True

        try:
            if not version or version == 'unknown':
                return [], True
            
            # Mapping common service names to CPE format for NVD API
            cpe_map = {
                'apache': 'apache:http_server', 'nginx': 'nginx:nginx',
                'openssh': 'openbsd:openssh', 'vsftpd': 'vsftpd:vsftpd',
                'mysql': 'mysql:mysql', 'postgresql': 'postgresql:postgresql',
                'bind': 'isc:bind', 'samba': 'samba:samba',
                'postfix': 'postfix:postfix', 'proftpd': 'proftpd:proftpd',
                'unrealircd': 'unrealircd:unrealircd', 'tomcat': 'apache:tomcat',
                'vnc': 'realvnc:vnc', 'java-rmi': 'oracle:jre',
                'nfs': 'linux:kernel', 'ajp': 'apache:tomcat',
                'x11': 'x.org:x_server', 'telnet': 'linux:kernel',
                'rsh': 'linux:kernel', 'rexec': 'linux:kernel',
                'rlogin': 'linux:kernel', 'dns': 'isc:bind',
                'rpc': 'rpcbind:rpcbind', 'netbios': 'samba:samba',
                'distccd': 'distcc:distcc'
            }
            
            vendor_product = cpe_map.get(service.lower(), f"{service}:{service}")
            vendor, product = vendor_product.split(':')

            # NVD API rate limiting: 6s with key, 12s without
            delay = 6 if self.nvd_api_key else 12
            print(f"  {Fore.CYAN}[NVD]{Style.RESET_ALL} Searching for CVEs: {vendor} {product} {version}...")
            
            results = nvdlib.searchCVE(
                keywordSearch=f"{vendor} {product} {version}",
                key=self.nvd_api_key,
                delay=delay,
                limit=10
            )
            
            vulnerabilities = []
            for cve in results:
                severity = 'UNKNOWN'
                cvss_score = 'N/A'
                
                if hasattr(cve, 'score') and cve.score:
                    if len(cve.score) > 0:
                        cvss_score = cve.score[0]
                    if len(cve.score) > 2:
                        severity = cve.score[2]
                
                solution = 'No specific solution provided. Check vendor advisories or update to latest version.'
                if hasattr(cve, 'references'):
                    for ref in cve.references:
                        if hasattr(ref, 'tags') and ('patch' in ref.tags or 'vendor-advisory' in ref.tags):
                            solution = f"Apply patch or follow advisory: {ref.url}"
                            break
                        elif 'patch' in ref.url.lower() or 'advisory' in ref.url.lower():
                            solution = f"Apply patch or follow advisory: {ref.url}"
                            break
                
                vulnerabilities.append({
                    'id': cve.id,
                    'description': cve.descriptions[0].value if cve.descriptions else 'No description available',
                    'severity': severity,
                    'cvss_score': str(cvss_score),
                    'solution': solution
                })
            
            print(f"  {Fore.CYAN}[NVD]{Style.RESET_ALL} Found {len(vulnerabilities)} CVE(s)")
            self.cve_cache[cache_key] = vulnerabilities
            self.save_cve_cache()
            return vulnerabilities, True
            
        except Exception as e:
            print(f"  {Fore.RED}[NVD ERROR]{Style.RESET_ALL} API query failed: {str(e)}")
            return [{'id': 'ERROR', 'description': f'NVD API query failed: {str(e)}', 'severity': 'N/A', 'cvss_score': 'N/A', 'solution': 'Check network connection, API key, or retry later'}], False

    # --- TCP Fingerprint ---
    def tcp_fingerprint(self, host: str) -> Optional[OSFingerprint]:
        """Attempts to fingerprint the operating system of the target host."""
        banners = []
        test_ports = [22, 80, 443, 3306]
        for port in test_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                if sock.connect_ex((host, port)) == 0:
                    banner, _ = self.grab_banner(sock, port)
                    if banner and "Error" not in banner:
                        banners.append(banner)
                sock.close()
            except:
                continue

        all_banners = ' '.join(banners).lower()
        # Check for OS indicators in banners
        for os_name, os_data in self.signatures.os_signatures.items():
            for pattern in os_data['patterns']:
                match = re.search(pattern, all_banners, re.IGNORECASE)
                if match:
                    version = match.group(1) if match.groups() else 'unknown'
                    return OSFingerprint(
                        os_family=os_name,
                        os_version=version,
                        confidence=0.85,
                        method='banner_analysis',
                        details=f'Detected from banners: {all_banners[:50]}...'
                    )
            for indicator in os_data['banner_indicators']:
                if indicator.lower() in all_banners:
                    return OSFingerprint(
                        os_family=os_name,
                        os_version='unknown',
                        confidence=0.65,
                        method='banner_indicators',
                        details=f'Found "{indicator}" in banners'
                    )

        # Use Scapy for TCP stack fingerprinting if available
        if SCAPY_AVAILABLE:
            try:
                pkt = sr1(IP(dst=host)/TCP(dport=80, flags="S"), timeout=2, verbose=0)
                if pkt:
                    ttl = pkt[IP].ttl
                    window = pkt[TCP].window
                    for os_name, os_data in self.signatures.os_signatures.items():
                        if ttl in os_data['tcp_traits']['ttl'] and window in os_data['tcp_traits']['window']:
                            return OSFingerprint(
                                os_family=os_name,
                                os_version='2.6.9 - 2.6.33' if os_name == 'linux' else 'unknown',
                                confidence=0.75,
                                method='tcp_stack',
                                details=f'TTL: {ttl}, Window: {window}'
                            )
            except Exception as e:
                pass
        return None

    # --- Scan Port Asynchronously ---
    async def scan_port_async(self, host: str, port: int, protocol: str = 'tcp') -> Dict:
        """Asynchronously scans a single port for a given protocol."""
        result = {
            'host': host,
            'port': port,
            'protocol': protocol,
            'state': 'unknown',
            'banner': 'No banner received',
            'service': {'name': 'unknown', 'version': 'unknown', 'recommendations': [], 'confidence': 0.0},
            'extra_info': {},
            'cve_vulnerabilities': [],
            'general_risks': [],
            'nvd_success': False
        }

        if protocol == 'tcp':
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=self.timeout
                )
                result['state'] = 'open'
                banner, extra_info = await self.grab_banner_async(host, port)
                result['banner'] = banner
                result['extra_info'] = extra_info
                service_info = self.identify_service(port, banner)
                result['service'] = service_info
                # Query NVD for CVEs if service and version are identified
                result['cve_vulnerabilities'], result['nvd_success'] = self.query_nvd_cve(service_info['name'], service_info['version'])
                result['general_risks'] = self.get_general_risks(port)
                writer.close()
                await writer.wait_closed()
            except asyncio.TimeoutError:
                result['state'] = 'filtered'
            except ConnectionRefusedError:
                result['state'] = 'closed'
            except socket.error:
                result['state'] = 'filtered'
        else:  # UDP scanning requires Scapy
            if not SCAPY_AVAILABLE:
                result['state'] = 'unknown'
                result['banner'] = 'scapy required for UDP scanning'
                return result
            try:
                # UDP scanning is less precise; open and filtered often look the same
                pkt = sr1(IP(dst=host)/UDP(dport=port), timeout=2, verbose=0)
                if pkt:
                    result['state'] = 'open|filtered'
                    result['banner'] = 'UDP service detected'
                    result['extra_info'] = {'udp_info': 'UDP response received'}
                    service_info = self.identify_service(port, result['banner'])
                    result['service'] = service_info
                    result['cve_vulnerabilities'], result['nvd_success'] = self.query_nvd_cve(service_info['name'], service_info['version'])
                    result['general_risks'] = self.get_general_risks(port)
                else:
                    result['state'] = 'closed'
            except Exception as e:
                result['state'] = 'error'
                result['banner'] = f"UDP scan error: {e}"

        return result

    # --- Get General Risks ---
    def get_general_risks(self, port: int) -> List[Dict[str, str]]:
        """Returns general security risks associated with a given port."""
        if port in self.signatures.port_vulnerabilities:
            port_info = self.signatures.port_vulnerabilities[port]
            return [{
                'type': 'General Risk',
                'description': f"Port {port} ({port_info['service']}) common risks: {', '.join(port_info['risks'])}",
                'recommendation': 'Apply general security best practices for this service'
            }]
        return []

    # --- Scan Host ---
    def scan_host(self, host: str, ports: List[int], scan_udp: bool = False) -> List[ServiceFingerprint]:
        """Initiates a multi-threaded scan of specified ports on a target host."""
        random.shuffle(ports)
        results = []
        protocols = ['tcp']
        if scan_udp and SCAPY_AVAILABLE:
            protocols.append('udp')

        for protocol in protocols:
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_port = {
                    executor.submit(asyncio.run, self.scan_port_async(host, port, protocol)): port
                    for port in ports
                }
                if TQDM_AVAILABLE:
                    futures_iter = tqdm(as_completed(future_to_port), total=len(ports), desc=f"Scanning {protocol.upper()} ports")
                else:
                    futures_iter = as_completed(future_to_port)
                
                for future in futures_iter:
                    result = future.result()
                    fingerprint = ServiceFingerprint(
                        port=result['port'],
                        protocol=result['protocol'],
                        state=result['state'],
                        service=result['service']['name'],
                        version=result['service']['version'],
                        banner=result['banner'],
                        cve_vulnerabilities=result['cve_vulnerabilities'],
                        general_risks=result['general_risks'],
                        recommendations=result['service']['recommendations'],
                        confidence=result['service']['confidence'],
                        extra_info=result['extra_info']
                    )
                    results.append(fingerprint)
        return results

    # --- Identify Service ---
    def identify_service(self, port: int, banner: str) -> Dict:
        """Identifies the service running on a port based on banner analysis and known signatures."""
        service_info = {
            'name': 'unknown',
            'version': 'unknown',
            'recommendations': [],
            'confidence': 0.0
        }
        banner_lower = banner.lower()
        best_match = None
        best_confidence = 0.0

        # Prioritize matches from explicit service signatures
        for service_name, sig_data in self.signatures.signatures.items():
            if port in sig_data['ports']:
                for pattern in sig_data['patterns']:
                    match = re.search(pattern, banner, re.IGNORECASE)
                    if match:
                        confidence = 0.95 if match.groups() else 0.9
                        version = match.group(1) if match.groups() else 'unknown'
                        if confidence > best_confidence:
                            best_confidence = confidence
                            best_match = {
                                'name': service_name,
                                'version': version,
                                'recommendations': sig_data['recommendations'],
                                'confidence': confidence
                            }
        if best_match:
            service_info = best_match

        # Fallback to general patterns if no strong signature match
        service_patterns = {
            'telnet': ['telnet', 'linux telnetd'], 'smtp': ['esmtp', 'postfix', 'sendmail', 'exim'],
            'dns': ['bind', 'isc bind', 'domain'], 'rpc': ['rpcbind', 'portmapper'],
            'netbios': ['netbios'], 'rsh': ['rsh'], 'rexec': ['rexec'],
            'rlogin': ['rlogin'], 'irc': ['irc', 'unrealircd']
        }
        for service, patterns in service_patterns.items():
            for pattern in patterns:
                if pattern in banner_lower and service_info['confidence'] < 0.8:
                    service_info['name'] = service
                    service_info['confidence'] = 0.75

        # Use port-based service identification as a last resort
        if port in self.signatures.port_vulnerabilities:
            port_info = self.signatures.port_vulnerabilities[port]
            if service_info['name'] == 'unknown':
                service_info['name'] = port_info['service']
                service_info['confidence'] = 0.7
        return service_info

    # --- Generate Report ---
    def generate_report(self, results: List[ServiceFingerprint], host: str, short_report: bool = False) -> str:
        """Generates a human-readable report for terminal output."""
        report = []
        scan_duration = (datetime.now() - self.start_time).total_seconds()

        # RE-CALCULATE summary counts to ensure accuracy
        critical_cve_count = 0
        high_cve_count = 0
        medium_cve_count = 0
        low_cve_count = 0
        total_cve_count = 0
        services_with_risks = 0
        all_cve_details_for_summary = []

        for service in results:
            service_has_risks = False
            for vuln in service.cve_vulnerabilities:
                if 'CVE-' in vuln['id']:
                    total_cve_count += 1
                    if vuln['severity'] == 'CRITICAL':
                        critical_cve_count += 1
                    elif vuln['severity'] == 'HIGH':
                        high_cve_count += 1
                    elif vuln['severity'] == 'MEDIUM':
                        medium_cve_count += 1
                    else:
                        low_cve_count += 1
                    service_has_risks = True
                    all_cve_details_for_summary.append(vuln)

            if service.general_risks:
                service_has_risks = True
            
            if service_has_risks:
                services_with_risks += 1

        # Report Header
        report.append(f"{Fore.CYAN}{'='*MAX_REPORT_LINE_WIDTH}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
        report.append(f"{Fore.CYAN}=== Network Security Assessment Report ==={Style.RESET_ALL if COLORAMA_AVAILABLE else ''}".center(MAX_REPORT_LINE_WIDTH + (len(Fore.CYAN) + len(Style.RESET_ALL) if COLORAMA_AVAILABLE else 0)))
        report.append(f"{Fore.CYAN}{'='*MAX_REPORT_LINE_WIDTH}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
        report.append(f"  Target: {Fore.WHITE}{host}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
        report.append(f"  Scan Time: {Fore.WHITE}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
        report.append(f"  Scan Duration: {Fore.WHITE}{scan_duration:.2f} seconds{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
        report.append(f"  Services Detected: {Fore.WHITE}{len([r for r in results if r.state == 'open'])}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
        report.append(f"  Total Ports Scanned: {Fore.WHITE}{len(set((r.port, r.protocol) for r in results))}")
        report.append(f"{Fore.CYAN}{'-'*MAX_REPORT_LINE_WIDTH}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}\n")

        # Filter results for display: only show open/open|filtered ports
        results_to_display = [r for r in results if r.state in ['open', 'open|filtered']]

        # Detailed Service Information
        for service in sorted(results_to_display, key=lambda x: (x.port, x.protocol)):
            state_color = {
                'open': Fore.GREEN,
                'closed': Fore.RED,
                'filtered': Fore.YELLOW,
                'open|filtered': Fore.YELLOW,
                'error': Fore.MAGENTA
            }.get(service.state, Fore.WHITE)
            
            # Determine highest CVE severity for the current service for short report display
            highest_severity_for_service = "NONE"
            service_cve_count_display = 0
            for vuln in service.cve_vulnerabilities:
                if 'CVE-' in vuln['id']:
                    service_cve_count_display += 1
                    if vuln['severity'] == 'CRITICAL':
                        highest_severity_for_service = 'CRITICAL'
                    elif vuln['severity'] == 'HIGH' and highest_severity_for_service != 'CRITICAL':
                        highest_severity_for_service = 'HIGH'
                    elif vuln['severity'] == 'MEDIUM' and highest_severity_for_service not in ['CRITICAL', 'HIGH']:
                        highest_severity_for_service = 'MEDIUM'
                    elif vuln['severity'] == 'LOW' and highest_severity_for_service not in ['CRITICAL', 'HIGH', 'MEDIUM']:
                        highest_severity_for_service = 'LOW'
            
            if short_report:
                # Condensed output for --short flag
                line_color = Fore.BLUE
                if highest_severity_for_service == 'CRITICAL':
                    line_color = Fore.RED
                elif highest_severity_for_service == 'HIGH':
                    line_color = Fore.YELLOW
                
                report.append(f"{line_color}--- PORT {service.port}/{service.protocol.upper()} --- {service.service.upper()} ({service.version}) [{state_color}{service.state.upper()}{line_color}]{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
                
                if service_cve_count_display > 0:
                    report.append(f"  {Fore.RED}Vulnerabilities:{Style.RESET_ALL if COLORAMA_AVAILABLE else ''} {service_cve_count_display} CVE(s) found. Highest Severity: {highest_severity_for_service}")
                elif any(v['id'] == 'ERROR' for v in service.cve_vulnerabilities):
                    report.append(f"  {Fore.YELLOW}NVD Query Error:{Style.RESET_ALL if COLORAMA_AVAILABLE else ''} Could not retrieve CVEs.")
                else:
                    report.append(f"  {Fore.GREEN}Vulnerabilities:{Style.RESET_ALL if COLORAMA_AVAILABLE else ''} No known CVEs.")

                if service.general_risks:
                    risks_summary = ", ".join([r['type'] for r in service.general_risks])
                    report.append(f"  {Fore.YELLOW}General Risks:{Style.RESET_ALL if COLORAMA_AVAILABLE else ''} {textwrap.fill(risks_summary, width=MAX_REPORT_LINE_WIDTH - 20, initial_indent=' '*20, subsequent_indent=' '*20).strip()}")
                
                if service.recommendations:
                    recs_summary = "; ".join(service.recommendations)
                    report.append(f"  {Fore.GREEN}Recommendations:{Style.RESET_ALL if COLORAMA_AVAILABLE else ''} {textwrap.fill(recs_summary, width=MAX_REPORT_LINE_WIDTH - 20, initial_indent=' '*20, subsequent_indent=' '*20).strip()}")
                
                report.append(f"{Fore.BLUE}{'-'*40}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}\n")

            else:
                # Full verbose output
                report.append(f"{Fore.BLUE}--- PORT {service.port}/{service.protocol.upper()} ---{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
                report.append(f"  Service: {Fore.WHITE}{service.service.upper()}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
                report.append(f"  State: {state_color}{service.state.upper()}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
                report.append(f"  Version: {Fore.WHITE}{service.version}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
                
                # Wrap banner if it's too long
                wrapped_banner = textwrap.fill(service.banner, width=MAX_REPORT_LINE_WIDTH - 10, initial_indent='  Banner: ', subsequent_indent='            ')
                report.append(f"{Fore.WHITE}{wrapped_banner}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
                report.append(f"  Confidence: {Fore.WHITE}{service.confidence*100:.1f}%{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
                
                if service.extra_info:
                    report.append(f"  {Fore.MAGENTA}Extra Info:{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
                    for key, value in service.extra_info.items():
                        wrapped_extra_info = textwrap.fill(f"• {key}: {value}", width=MAX_REPORT_LINE_WIDTH - 10, initial_indent='    ', subsequent_indent='    ')
                        report.append(f"  {Fore.WHITE}{wrapped_extra_info}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")

                # Only show vulnerability/risk details for open/open|filtered ports
                if service.state == 'open' or service.state == 'open|filtered':
                    if service.cve_vulnerabilities:
                        cve_found_for_service = False
                        for vuln in service.cve_vulnerabilities:
                            if 'CVE-' in vuln['id']:
                                cve_found_for_service = True
                                break
                        
                        if cve_found_for_service:
                            report.append(f"{Fore.RED}  !!! VULNERABILITIES FOUND !!!{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
                            for vuln in service.cve_vulnerabilities:
                                if 'CVE-' in vuln['id']:
                                    color = Fore.WHITE
                                    if vuln['severity'] == 'CRITICAL':
                                        color = Fore.RED
                                    elif vuln['severity'] == 'HIGH':
                                        color = Fore.YELLOW
                                    elif vuln['severity'] == 'MEDIUM':
                                        color = Fore.BLUE
                                    else:
                                        color = Fore.GREEN
                                    report.append(f"    {color}• {vuln['id']} (Severity: {vuln['severity']}, CVSS: {vuln['cvss_score']}){Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
                                    wrapped_desc = textwrap.fill(vuln['description'], width=MAX_REPORT_LINE_WIDTH - 10, initial_indent='      Description: ', subsequent_indent='                 ')
                                    report.append(f"  {Fore.WHITE}{wrapped_desc}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
                                    wrapped_sol = textwrap.fill(vuln['solution'], width=MAX_REPORT_LINE_WIDTH - 10, initial_indent='      Solution: ', subsequent_indent='                ')
                                    report.append(f"  {Fore.WHITE}{wrapped_sol}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}\n")
                        elif any(v['id'] == 'ERROR' for v in service.cve_vulnerabilities):
                            report.append(f"{Fore.YELLOW}  >> NVD QUERY ERROR <<{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
                            for vuln in service.cve_vulnerabilities:
                                if vuln['id'] == 'ERROR':
                                    report.append(f"    • {Fore.WHITE}{vuln['description']}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
                                    report.append(f"      (Severity: {vuln['severity']}){Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
                                    wrapped_sol = textwrap.fill(vuln['solution'], width=MAX_REPORT_LINE_WIDTH - 10, initial_indent='      Solution: ', subsequent_indent='                ')
                                    report.append(f"  {Fore.WHITE}{wrapped_sol}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}\n")
                        else:
                            report.append(f"{Fore.GREEN}  >> NO CVEs FOUND <<{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
                            report.append(f"    • No known vulnerabilities found in NVD database for this version.")
                            report.append(f"      Solution: {Fore.WHITE}Ensure service is up to date.{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")

                    if service.general_risks:
                        report.append(f"{Fore.YELLOW}  >> GENERAL SECURITY RISKS <<{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
                        for risk in service.general_risks:
                            report.append(f"    • {Fore.WHITE}{risk['type']}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
                            wrapped_desc = textwrap.fill(risk['description'], width=MAX_REPORT_LINE_WIDTH - 10, initial_indent='      Description: ', subsequent_indent='                 ')
                            report.append(f"  {Fore.WHITE}{wrapped_desc}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
                            wrapped_rec = textwrap.fill(risk['recommendation'], width=MAX_REPORT_LINE_WIDTH - 10, initial_indent='      Recommendation: ', subsequent_indent='                     ')
                            report.append(f"  {Fore.WHITE}{wrapped_rec}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}\n")

                    if service.recommendations:
                        report.append(f"{Fore.GREEN}  >> RECOMMENDATIONS <<{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
                        for rec in service.recommendations:
                            wrapped_rec = textwrap.fill(rec, width=MAX_REPORT_LINE_WIDTH - 10, initial_indent='    • ', subsequent_indent='      ')
                            report.append(f"  {Fore.WHITE}{wrapped_rec}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
                report.append(f"{Fore.BLUE}{'-'*40}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}\n")

        # Security Summary
        report.append(f"{Fore.CYAN}{'='*MAX_REPORT_LINE_WIDTH}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
        report.append(f"{Fore.CYAN}=== SECURITY SUMMARY ==={Style.RESET_ALL if COLORAMA_AVAILABLE else ''}".center(MAX_REPORT_LINE_WIDTH + (len(Fore.CYAN) + len(Style.RESET_ALL) if COLORAMA_AVAILABLE else 0)))
        report.append(f"{Fore.CYAN}{'='*MAX_REPORT_LINE_WIDTH}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
        report.append(f"  Total CVEs Found: {Fore.WHITE}{total_cve_count}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
        report.append(f"  Critical CVEs: {Fore.RED}{critical_cve_count}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
        report.append(f"  High CVEs: {Fore.YELLOW}{high_cve_count}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
        report.append(f"  Medium CVEs: {Fore.BLUE}{medium_cve_count}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
        report.append(f"  Low CVEs: {Fore.GREEN}{low_cve_count}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
        report.append(f"  Services with Risks: {Fore.WHITE}{services_with_risks}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
        report.append(f"  Total Open Services: {Fore.WHITE}{len([r for r in results if r.state == 'open'])}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}\n")
        
        if critical_cve_count > 0:
            report.append(f"{Fore.RED}  🚨 CRITICAL VULNERABILITIES DETECTED! IMMEDIATE ACTION REQUIRED!{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
        elif high_cve_count > 0:
            report.append(f"{Fore.YELLOW}  ⚠️ High severity vulnerabilities detected. Action recommended.{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
        elif services_with_risks > 0:
            report.append(f"{Fore.YELLOW}  ⚠️ Security improvements recommended.{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
        else:
            report.append(f"{Fore.GREEN}  ✅ No major vulnerabilities detected.{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")

        # OS Fingerprint
        os_info = self.tcp_fingerprint(host)
        if os_info:
            report.append(f"\n{Fore.CYAN}{'='*MAX_REPORT_LINE_WIDTH}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
            report.append(f"{Fore.CYAN}=== OS Fingerprint ==={Style.RESET_ALL if COLORAMA_AVAILABLE else ''}".center(MAX_REPORT_LINE_WIDTH + (len(Fore.CYAN) + len(Style.RESET_ALL) if COLORAMA_AVAILABLE else 0)))
            report.append(f"{Fore.CYAN}{'='*MAX_REPORT_LINE_WIDTH}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
            report.append(f"  OS Family: {Fore.WHITE}{os_info.os_family}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
            report.append(f"  OS Version: {Fore.WHITE}{os_info.os_version}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
            report.append(f"  Confidence: {Fore.WHITE}{os_info.confidence*100:.1f}%{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
            report.append(f"  Method: {Fore.WHITE}{os_info.method}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
            wrapped_details = textwrap.fill(os_info.details, width=MAX_REPORT_LINE_WIDTH - 10, initial_indent='  Details: ', subsequent_indent='            ')
            report.append(f"  {Fore.WHITE}{wrapped_details}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
        report.append(f"\n{Fore.CYAN}{'='*MAX_REPORT_LINE_WIDTH}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}\n")

        # Detailed CVEs if not in short mode and there are CVEs
        if not short_report and all_cve_details_for_summary:
            report.append(f"{Fore.CYAN}{'='*MAX_REPORT_LINE_WIDTH}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
            report.append(f"{Fore.CYAN}=== DETAILED CVE VULNERABILITIES ==={Style.RESET_ALL if COLORAMA_AVAILABLE else ''}".center(MAX_REPORT_LINE_WIDTH + (len(Fore.CYAN) + len(Style.RESET_ALL) if COLORAMA_AVAILABLE else 0)))
            report.append(f"{Fore.CYAN}{'='*MAX_REPORT_LINE_WIDTH}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}\n")
            for vuln in sorted(all_cve_details_for_summary, key=lambda x: x.get('severity', 'UNKNOWN'), reverse=True):
                color = Fore.WHITE
                if vuln['severity'] == 'CRITICAL':
                    color = Fore.RED
                elif vuln['severity'] == 'HIGH':
                    color = Fore.YELLOW
                elif vuln['severity'] == 'MEDIUM':
                    color = Fore.BLUE
                elif vuln['severity'] == 'LOW':
                    color = Fore.GREEN
                report.append(f"{color}• {vuln['id']} (Severity: {vuln['severity']}, CVSS: {vuln['cvss_score']}){Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
                wrapped_desc = textwrap.fill(vuln['description'], width=MAX_REPORT_LINE_WIDTH - 10, initial_indent='  Description: ', subsequent_indent='               ')
                report.append(f"  {Fore.WHITE}{wrapped_desc}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
                wrapped_sol = textwrap.fill(vuln['solution'], width=MAX_REPORT_LINE_WIDTH - 10, initial_indent='  Solution: ', subsequent_indent='              ')
                report.append(f"  {Fore.WHITE}{wrapped_sol}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}\n")
            report.append(f"{Fore.CYAN}{'='*MAX_REPORT_LINE_WIDTH}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}\n")


        return "\n".join(report)

# --- Get Common Ports ---
def get_common_ports():
    """Returns the list of default common ports to scan."""
    return DEFAULT_PORTS

# --- Clear Screen ---
def clear_screen():
    """Clears the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

# --- Get User Input ---
def get_user_input(prompt: str, default_value: str = "", validator=None) -> str:
    """Gets user input with a default value and optional validation."""
    while True:
        try:
            user_input = input(f"{Fore.LIGHTBLUE_EX}{prompt} [{default_value}]{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}: ").strip()
            if not user_input:
                user_input = default_value
            if validator:
                validator(user_input)
            return user_input
        except ValueError as e:
            print(f"{Fore.RED}Invalid input: {e}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}Operation cancelled.{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
            sys.exit(0)

# --- Validate Ports ---
def validate_ports(ports_str: str):
    """Validates port string format."""
    if not ports_str:
        return
    if '-' in ports_str:
        parts = ports_str.split('-')
        if len(parts) != 2:
            raise ValueError("Port range must be in 'start-end' format.")
        start, end = int(parts[0]), int(parts[1])
        if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
            raise ValueError("Ports must be between 1 and 65535, and start <= end.")
    else:
        ports = [int(p.strip()) for p in ports_str.split(',')]
        if not all(1 <= p <= 65535 for p in ports):
            raise ValueError("Ports must be between 1 and 65535.")

# --- Parse Ports ---
def parse_ports(ports_str: str) -> List[int]:
    """Parses a port string into a list of integers."""
    if not ports_str:
        return DEFAULT_PORTS
    if '-' in ports_str:
        start, end = map(int, ports_str.split('-'))
        return list(range(start, end + 1))
    else:
        return [int(p.strip()) for p in ports_str.split(',')]

# --- Display Paged Output (Removed Pagination for direct print) ---
# This function is no longer used for direct printing to terminal
# but kept for potential future use or if user changes mind.
def display_paged_output(lines: List[str], page_size: int = 25):
    """Displays output in a paginated manner with navigation."""
    current_page = 0
    total_pages = (len(lines) + page_size - 1) // page_size

    while True:
        clear_screen()
        start_idx = current_page * page_size
        end_idx = start_idx + page_size
        
        print(f"{Fore.CYAN}--- Page {current_page + 1}/{total_pages} ---{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}\n")
        for line in lines[start_idx:end_idx]:
            print(line)
        
        if total_pages <= 1:
            input(f"\n{Fore.GREEN}Press Enter to continue...{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
            break
        
        prompt_options = []
        if current_page < total_pages - 1:
            prompt_options.append("n: Next")
        if current_page > 0:
            prompt_options.append("p: Previous")
        prompt_options.append("q: Quit")
        
        choice = input(f"\n{Fore.GREEN}Navigate ({' | '.join(prompt_options)}){Style.RESET_ALL if COLORAMA_AVAILABLE else ''}: ").strip().lower()

        if choice == 'n' or choice == '':
            if current_page < total_pages - 1:
                current_page += 1
        elif choice == 'p':
            if current_page > 0:
                current_page -= 1
        elif choice == 'q':
            break
        else:
            print(f"{Fore.RED}Invalid input. Please use 'n', 'p', or 'q'.{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
            time.sleep(1)
    clear_screen()

# --- TUI Main Function ---
def tui_main(initial_config: Dict = None):
    """Main function for the Text-based User Interface."""
    clear_screen()
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
    print(f"{Fore.CYAN}=== Network Service Fingerprinting Engine ==={Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}\n")
    print(f"{Fore.RED}*** LEGAL WARNING: Only scan systems you have explicit permission to test ***{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}\n")

    # Default configuration values
    config = {
        'host': '',
        'ports': '',
        'timeout': str(DEFAULT_TIMEOUT),
        'threads': str(DEFAULT_THREADS),
        'nvd_api_key': NVD_API_KEY,
        'udp_scan': 'no',
        'short_report': 'yes',
        'output_file': ''
    }

    # Apply initial configuration from command-line arguments if provided
    if initial_config:
        config.update(initial_config)
        if initial_config.get('ports') == ','.join(map(str, DEFAULT_PORTS)):
            config['ports'] = ''

    while True:
        clear_screen()
        print(f"{Fore.YELLOW}--- Scan Configuration ---{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
        print(f"1. Target Host: {Fore.WHITE}{config['host'] if config['host'] else 'Not set'}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
        
        display_ports_tui = "Popular Ports (Default)" if not config['ports'] else config['ports']
        print(f"2. Ports: {Fore.WHITE}{display_ports_tui}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
        
        print(f"3. Timeout (seconds): {Fore.WHITE}{config['timeout']}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
        print(f"4. Threads: {Fore.WHITE}{config['threads']}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
        print(f"5. NVD API Key: {Fore.WHITE}{config['nvd_api_key'] if config['nvd_api_key'] else 'Not set (rate-limited)'}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
        print(f"6. Include UDP Scan: {Fore.WHITE}{config['udp_scan']}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
        print(f"7. Short Report Mode: {Fore.WHITE}{config['short_report']}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
        print(f"8. Output Report to File: {Fore.WHITE}{config['output_file'] if config['output_file'] else 'No (print to terminal)'}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
        print(f"\n{Fore.GREEN}9. Start Scan{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
        print(f"{Fore.RED}0. Exit{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
        print(f"{Fore.CYAN}{'-'*60}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")

        choice = get_user_input("Enter your choice", validator=lambda x: x.isdigit() and int(x) in range(0, 10))

        if choice == '1':
            config['host'] = get_user_input("Enter Target Host (IP or hostname)")
            try:
                socket.inet_aton(config['host'])
            except socket.error:
                try:
                    socket.gethostbyname(config['host'])
                except socket.gaierror:
                    print(f"{Fore.RED}Invalid host '{config['host']}'. Please try again.{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
                    config['host'] = ''
                    input("Press Enter to continue...")
        elif choice == '2':
            config['ports'] = get_user_input("Enter Ports (e.g., 80,443 or 1-1000, leave empty for popular ports) (1-65535)", default_value=config['ports'], validator=validate_ports)
        elif choice == '3':
            config['timeout'] = get_user_input("Enter Timeout in seconds", default_value=config['timeout'], validator=lambda x: int(x) > 0)
        elif choice == '4':
            config['threads'] = get_user_input("Enter Number of Threads (1-500)", default_value=config['threads'], validator=lambda x: 1 <= int(x) <= 500)
        elif choice == '5':
            config['nvd_api_key'] = get_user_input("Enter NVD API Key (leave empty for default/env)", default_value=config['nvd_api_key'])
        elif choice == '6':
            config['udp_scan'] = get_user_input("Include UDP Scan? (yes/no)", default_value=config['udp_scan'], validator=lambda x: x.lower() in ['yes', 'no']).lower()
        elif choice == '7':
            config['short_report'] = get_user_input("Generate Short Report? (yes/no)", default_value=config['short_report'], validator=lambda x: x.lower() in ['yes', 'no']).lower()
        elif choice == '8':
            config['output_file'] = get_user_input("Enter output filename (e.g., report.txt, leave empty to print to terminal)")
        elif choice == '9':
            if not config['host']:
                print(f"{Fore.RED}Error: Target Host must be set before starting scan.{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
                input("Press Enter to continue...")
                continue
            
            host = config['host']
            ports = parse_ports(config['ports'])
            timeout = int(config['timeout'])
            threads = int(config['threads'])
            nvd_api_key = config['nvd_api_key'] if config['nvd_api_key'] else NVD_API_KEY
            scan_udp = config['udp_scan'] == 'yes'
            short_report = config['short_report'] == 'yes'
            output_file = config['output_file'] if config['output_file'] else None

            clear_screen()
            print(f"\n{Fore.GREEN}Starting network security assessment of {host}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
            print(f"Scanning {len(ports)} ports with {threads} threads")
            if scan_udp:
                print("UDP scanning enabled")
            if not SCAPY_AVAILABLE:
                print(f"{Fore.YELLOW}Warning: 'scapy' not installed; OS fingerprinting limited and UDP scanning disabled.{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
            if not NVDLIB_AVAILABLE:
                print(f"{Fore.YELLOW}Warning: 'nvdlib' not installed; CVE queries disabled.{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
            if not TQDM_AVAILABLE:
                print(f"{Fore.LIGHTBLACK_EX}Info: 'tqdm' not installed; progress bar disabled.{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
            if not COLORAMA_AVAILABLE:
                print(f"{Fore.LIGHTBLACK_EX}Info: 'colorama' not installed; color output disabled.{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
            if not nvd_api_key and NVD_API_KEY == os.getenv('NVD_API_KEY', '5323209c-2b2e-431c-8f5a-c86d9f2420e7'):
                print(f"{Fore.YELLOW}Warning: No NVD API key provided; NVD queries may be rate-limited.{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
            print(f"{Fore.CYAN}{'=' * 50}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}\n")

            scanner = NetworkScanner(timeout=timeout, threads=threads, nvd_api_key=nvd_api_key)
            scanner.start_time = datetime.now()
            results = scanner.scan_host(host, ports, scan_udp=scan_udp)

            if results:
                report_content = scanner.generate_report(results, host, short_report=short_report)
                
                if output_file:
                    final_output_filename = output_file
                    if not final_output_filename.endswith('.txt'):
                        final_output_filename = f"{host.replace('.', '_')}.txt"
                    with open(final_output_filename, 'w') as f:
                        f.write(report_content)
                    print(f"{Fore.GREEN}Report saved to {final_output_filename}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
                else:
                    print(report_content)
                input(f"{Fore.GREEN}Scan report displayed. Press Enter to return to main menu.{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
            else:
                print(f"{Fore.YELLOW}No ports scanned successfully.{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
                input("Press Enter to continue...")
        elif choice == '0':
            print(f"\n{Fore.CYAN}Exiting scanner. Goodbye!{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
            sys.exit(0)

# --- Main Function for Argument Parsing and TUI/Direct Scan Logic ---
def main():
    parser = argparse.ArgumentParser(
        description=f'{Fore.LIGHTBLUE_EX}Network Service Fingerprinting Engine with NVD API Integration{Style.RESET_ALL if COLORAMA_AVAILABLE else ""}\n'
                    f'{Fore.RED}*** LEGAL WARNING: Only scan systems you have explicit permission to test ***{Style.RESET_ALL if COLORAMA_AVAILABLE else ""}',
        epilog=f'{Fore.YELLOW}Examples:{Style.RESET_ALL if COLORAMA_AVAILABLE else ""}\n'
               f'  python service.py # To launch interactive TUI with default settings\n'
               f'  python service.py 172.16.119.128 # To launch TUI with host pre-filled\n'
               f'  python service.py --tui # To explicitly launch TUI\n'
               f'  python service.py 172.161.119.128 -p 80,443 --short # To run a direct scan\n'
               f'  python service.py 172.16.119.128 192.168.1.1 # To run a direct scan on multiple hosts\n'
               f'  python service.py --default # To run a direct default scan (popular ports, default settings)'
    )
    parser.add_argument('host', nargs='*', help='Target host(s) to scan (IP or hostname). Can be multiple.')
    parser.add_argument('-p', '--ports', help='Ports to scan (comma-separated or range, e.g., 80,443 or 1-1000)')
    parser.add_argument('-t', '--timeout', type=int, help='Connection timeout in seconds (default: 5)')
    parser.add_argument('--threads', type=int, help='Number of threads (1-500, default: 20)')
    parser.add_argument('--nvd-api-key', help='NVD API key for higher rate limits (default: env NVD_API_KEY or built-in key)')
    parser.add_argument('-o', '--output', help='Output file for report')
    parser.add_argument('--json', action='store_true', help='Output report in JSON format')
    parser.add_argument('--default', action='store_true', help='Run default scan (popular ports, default settings)')
    parser.add_argument('--udp', action='store_true', help='Include UDP scanning for applicable ports')
    parser.add_argument('--short', action='store_true', help='Generate a short, condensed report for terminal output')
    parser.add_argument('--tui', action='store_true', help='Force launch the Text-based User Interface')

    args = parser.parse_args()

    # Determine if we should run in TUI mode or direct scan mode
    run_tui = False

    # Condition 1: No arguments provided (just 'service.py')
    if len(sys.argv) == 1:
        run_tui = True
    # Condition 2: --tui flag is explicitly used
    elif args.tui:
        run_tui = True
    # Condition 3: Host(s) are provided, but no other scan-specific arguments (implies TUI with first host pre-filled)
    elif args.host and not (args.ports or args.timeout or args.threads or args.nvd_api_key or args.output or args.json or args.udp or args.short or args.default):
        run_tui = True
    # Condition 4: --default is used, but not --tui (implies direct default scan)
    elif args.default and not args.tui:
        run_tui = False
    
    if run_tui:
        initial_tui_config = {
            'host': args.host[0] if args.host else '',
            'ports': args.ports if args.ports else '',
            'timeout': str(args.timeout) if args.timeout else str(DEFAULT_TIMEOUT),
            'threads': str(args.threads) if args.threads else str(DEFAULT_THREADS),
            'nvd_api_key': args.nvd_api_key if args.nvd_api_key else NVD_API_KEY,
            'udp_scan': 'yes' if args.udp else 'no',
            'short_report': 'yes' if args.short else 'no',
            'output_file': args.output if args.output else ''
        }
        if args.default and args.tui:
            initial_tui_config['ports'] = ''
            initial_tui_config['timeout'] = str(DEFAULT_TIMEOUT)
            initial_tui_config['threads'] = str(DEFAULT_THREADS)
            initial_tui_config['udp_scan'] = 'no'
            initial_tui_config['short_report'] = 'yes'

        tui_main(initial_tui_config)
    else:
        hosts_to_scan = args.host

        if args.default:
            ports = get_common_ports()
            threads = DEFAULT_THREADS
            timeout = DEFAULT_TIMEOUT
            nvd_api_key = args.nvd_api_key or NVD_API_KEY
            scan_udp = args.udp
            short_report = args.short
            
            if not hosts_to_scan:
                print(f"{Fore.RED}Error: '--default' requires a target host or implies scanning default targets not yet implemented.{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
                parser.print_help()
                sys.exit(1)

        else:
            if not hosts_to_scan:
                parser.print_help()
                sys.exit(1)

            if args.ports:
                try:
                    ports = parse_ports(args.ports)
                except ValueError as e:
                    print(f"{Fore.RED}Error: Invalid port specification - {e}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
                    sys.exit(1)
            else:
                ports = get_common_ports()

            threads = args.threads or DEFAULT_THREADS
            timeout = args.timeout or DEFAULT_TIMEOUT
            nvd_api_key = args.nvd_api_key or NVD_API_KEY
            scan_udp = args.udp
            short_report = args.short

        for host in hosts_to_scan:
            try:
                socket.inet_aton(host)
            except socket.error:
                try:
                    socket.gethostbyname(host)
                except socket.gaierror:
                    print(f"{Fore.RED}Error: Invalid host '{host}'. Skipping.{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
                    continue

            print(f"\n{Fore.GREEN}Starting network security assessment of {host}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
            print(f"Scanning {len(ports)} ports with {threads} threads")
            if scan_udp:
                print("UDP scanning enabled")
            if not SCAPY_AVAILABLE:
                print(f"{Fore.YELLOW}Warning: 'scapy' not installed; OS fingerprinting limited and UDP scanning disabled. Install with: pip install scapy{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
            if not NVDLIB_AVAILABLE:
                print(f"{Fore.YELLOW}Warning: 'nvdlib' not installed; CVE queries disabled. Install with: pip install nvdlib{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
            if not TQDM_AVAILABLE:
                print(f"{Fore.LIGHTBLACK_EX}Info: 'tqdm' not installed; progress bar disabled. Install with: pip install tqdm{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
            if not COLORAMA_AVAILABLE:
                print(f"{Fore.LIGHTBLACK_EX}Info: 'colorama' not installed; color output disabled. Install with: pip install colorama{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
            if not nvd_api_key and NVD_API_KEY == os.getenv('NVD_API_KEY', '5323209c-2b2e-431c-8f5a-c86d9f2420e7'):
                print(f"{Fore.YELLOW}Warning: No NVD API key provided; NVD queries may be rate-limited.{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
            print(f"{Fore.CYAN}{'=' * 50}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}\n")

            scanner = NetworkScanner(timeout=timeout, threads=threads, nvd_api_key=nvd_api_key)
            scanner.start_time = datetime.now()
            results = scanner.scan_host(host, ports, scan_udp=scan_udp)

            if results:
                if args.json:
                    json_report = {
                        'host': host,
                        'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'services': [asdict(r) for r in results]
                    }
                    os_info = scanner.tcp_fingerprint(host)
                    if os_info:
                        json_report['os_fingerprint'] = asdict(os_info)
                    
                    if args.output:
                        mode = 'a' if len(hosts_to_scan) > 1 else 'w'
                        with open(args.output, mode) as f:
                            json.dump(json_report, f, indent=2)
                            if len(hosts_to_scan) > 1:
                                f.write(",\n")
                        print(f"{Fore.GREEN}JSON report saved to {args.output}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
                    else:
                        print(json.dumps(json_report, indent=2))
                else:
                    report = scanner.generate_report(results, host, short_report=short_report)
                    print(report)
                    if args.output:
                        mode = 'a' if len(hosts_to_scan) > 1 else 'w'
                        output_filename = args.output
                        if not output_filename:
                            output_filename = f"{host.replace('.', '_')}.txt"
                        
                        with open(output_filename, mode) as f:
                            f.write(report)
                            if len(hosts_to_scan) > 1:
                                f.write("\n\n")
                        print(f"{Fore.GREEN}Report saved to {output_filename}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
            else:
                print(f"{Fore.YELLOW}No ports scanned successfully for {host}.{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")

if __name__ == "__main__":
    main()
