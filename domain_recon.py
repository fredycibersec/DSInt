#!/usr/bin/env python3

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import time
import concurrent.futures
import socket
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set, Any, Optional, Tuple, Union
try:
    from tqdm import tqdm
    from tqdm.contrib.concurrent import thread_map
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False
    print("tqdm not installed. Progress bars won't be shown.")
    print("Install with: pip install tqdm")

try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.panel import Panel
    from rich.table import Table
    from rich import box
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None

# ANSI Colors for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'          # Cyan color for section headers
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[35m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    ORANGE = '\033[38;5;208m'  # Orange color for warnings
    
    @staticmethod
    def colorize(text, color):
        """Apply color to text"""
        return f"{color}{text}{Colors.ENDC}"
        
    @staticmethod
    def bold(text):
        """Make text bold"""
        return f"{Colors.BOLD}{text}{Colors.ENDC}"
        
    @staticmethod
    def header(text):
        """Format as header"""
        return f"{Colors.HEADER}{Colors.BOLD}{text}{Colors.ENDC}"
# Verbosity levels
VERBOSE_MINIMAL = 0
VERBOSE_NORMAL = 1
VERBOSE_DETAILED = 2

# Define tool names
TOOL_NAMES = {
    "amass": "amass",
    "subfinder": "subfinder",
    "dnsenum": "dnsenum",
    "sublist3r": "sublist3r",
    "massdns": "massdns",
    "dig": "dig"
}

# Function to locate tools
def locate_tools():
    """Locate the required tools in PATH or common locations."""
    tools = {}
    
    for name, command in TOOL_NAMES.items():
        # Try to find tool in PATH first
        path = shutil.which(command)
        
        if path:
            tools[name] = path
        else:
            # Try common locations as fallbacks
            common_locations = []
            
            # Special case for massdns - add the bin path first
            if name == "massdns":
                common_locations.append(os.path.join(os.path.expanduser("~"), "pentest", "OSINT", "massdns", "bin", "massdns"))
            
            # Add standard locations
            common_locations.extend([
                os.path.join(os.path.expanduser("~"), "pentest", "OSINT", command),
                os.path.join(os.path.expanduser("~"), "tools", command),
                os.path.join("/usr", "local", "bin", command),
                os.path.join("/opt", command, command)
            ])
            
            for location in common_locations:
                if os.path.exists(location) and os.access(location, os.X_OK):
                    tools[name] = location
                    break
    
    return tools

# Initialize tools dictionary
TOOLS = locate_tools()
# Define ports for SSL checks
SSL_PORTS = [443, 8443, 7443]  # Puertos comunes para servicios HTTPS

# Default small wordlist for subdomain bruteforcing
DEFAULT_WORDLIST = [
    "www", "mail", "webmail", "smtp", "pop", "pop3", "imap", "ftp", "cpanel", "whm",
    "ns1", "ns2", "dns", "dns1", "dns2", "ns", "api", "api1", "api2", "dev", "test",
    "admin", "stage", "staging", "app", "apps", "secure", "vpn", "cloud", "cdn",
    "docs", "en", "es", "mx", "de", "fr", "it", "pt", "ru", "blog", "m", "mobile",
    "shop", "store", "web", "portal", "support", "help", "kb", "faq", "wiki", "git",
    "github", "gitlab", "jenkins", "jira", "confluence", "intranet", "remote", "host",
    "autodiscover", "news", "forum", "chat", "analytics", "stats", "metrics"
]

# Define a function for starting time tracking
# Global variables
start_time = 0
output_dir = None

def start_timer():
    """Start the timer for measuring execution time."""
    global start_time
    start_time = time.time()
    return start_time

def get_output_path(filename: str, directory: Optional[str] = None) -> str:
    """Create a path to a file in the output directory."""
    if directory is None:
        # Use global output_dir if available, otherwise use current directory
        directory = output_dir if "output_dir" in globals() and output_dir else "."
    return os.path.join(directory, filename)

def get_resolvers_path():
    """Get path to DNS resolvers file, creating it if it doesn't exist."""
    # Check multiple locations
    possible_paths = [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "resolvers.txt"),
        os.path.join(os.getcwd(), "resolvers.txt"),
        os.path.expanduser("~/pentest/OSINT/resolvers.txt"),
        os.path.expanduser("~/.config/dsint/resolvers.txt")
    ]
    
    for path in possible_paths:
        if os.path.exists(path):
            return path
    
    # If not found, create in current directory
    default_path = os.path.join(os.getcwd(), "resolvers.txt")
    try:
        with open(default_path, "w") as f:
            f.write("1.1.1.1\n8.8.8.8\n9.9.9.9\n208.67.222.222\n")
        print(f"{Colors.YELLOW}[!] Created a basic resolvers file at {default_path}{Colors.ENDC}")
        return default_path
    except Exception as e:
        print(f"{Colors.RED}[!] Could not create resolvers file: {str(e)}{Colors.ENDC}")
        # Return a fallback but don't write to disk
        return default_path

def print_section_header(title: str, verbosity: int = VERBOSE_NORMAL):
    """Print a formatted section header."""
    if verbosity >= VERBOSE_MINIMAL:
        width = shutil.get_terminal_size().columns
        padding = max(0, (width - len(title) - 4) // 2)
        print(f"\n{Colors.CYAN}{'=' * padding} {title} {'=' * padding}{Colors.ENDC}\n")

def print_banner(verbosity: int = VERBOSE_NORMAL):
    """Print a fancy banner for the tool."""
    # Start the timer when we print the banner
    start_timer()
    
    if verbosity == VERBOSE_MINIMAL:
        # For minimal verbosity, just print a simple one-line header
        print(f"\n{Colors.header('Domain & Subdomain Intelligence Tool')}\n")
        return
        
    # For normal and detailed verbosity, print the fancy banner
    if RICH_AVAILABLE and verbosity >= VERBOSE_NORMAL:
        banner_text = """
██████╗ ███████╗██╗███╗   ██╗████████╗    ████████╗ ██████╗  ██████╗ ██╗     
██╔══██╗██╔════╝██║████╗  ██║╚══██╔══╝    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     
██║  ██║███████╗██║██╔██╗ ██║   ██║          ██║   ██║   ██║██║   ██║██║     
██║  ██║╚════██║██║██║╚██╗██║   ██║          ██║   ██║   ██║██║   ██║██║     
██████╔╝███████║██║██║ ╚████║   ██║          ██║   ╚██████╔╝╚██████╔╝███████╗
╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝          ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝
        """
        
        subtitle = "Domain & Subdomain Intelligence Tool"
        description = "Advanced reconnaissance for security researchers"
        
        panel = Panel(
            f"[bold cyan]{banner_text}[/]\n[bold yellow]{subtitle}[/]\n[green]{description}[/]",
            expand=False,
            border_style="blue"
        )
        console.print(panel)
    else:
        try:
            # Try to import and use the ascii_banner module
            import ascii_banner
            # Use the new enhanced banner
            print(ascii_banner.get_banner("standard"))
        except ImportError:
            # Fallback to the original banner if module not found
            banner = f"""
{Colors.BLUE}╔═══════════════════════════════════════════════════════════════════════════╗
║  {Colors.MAGENTA}{Colors.BOLD}██████╗ ███████╗██╗███╗   ██╗████████╗    ████████╗ ██████╗  ██████╗ ██╗     {Colors.BLUE}  ║
║  {Colors.MAGENTA}{Colors.BOLD}██╔══██╗██╔════╝██║████╗  ██║╚══██╔══╝    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     {Colors.BLUE}  ║
║  {Colors.MAGENTA}{Colors.BOLD}██║  ██║███████╗██║██╔██╗ ██║   ██║          ██║   ██║   ██║██║   ██║██║     {Colors.BLUE}  ║
║  {Colors.MAGENTA}{Colors.BOLD}██║  ██║╚════██║██║██║╚██╗██║   ██║          ██║   ██║   ██║██║   ██║██║     {Colors.BLUE}  ║
║  {Colors.MAGENTA}{Colors.BOLD}██████╔╝███████║██║██║ ╚████║   ██║          ██║   ╚██████╔╝╚██████╔╝███████╗{Colors.BLUE}  ║
║  {Colors.MAGENTA}{Colors.BOLD}╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝          ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝{Colors.BLUE}  ║
╠═══════════════════════════════════════════════════════════════════════════╣
║  {Colors.YELLOW}Domain & Subdomain Intelligence Tool{Colors.BLUE}                                     ║
║  {Colors.GREEN}Advanced reconnaissance for security researchers{Colors.BLUE}                         ║
╚═══════════════════════════════════════════════════════════════════════════╝{Colors.ENDC}
"""
            print(banner)

def check_missing_tools(verbosity: int = VERBOSE_NORMAL) -> List[str]:
    """Check which required tools are missing."""
    missing_tools = []
    
    for name in TOOL_NAMES:
        if name not in TOOLS:
            missing_tools.append(name)
    
    if missing_tools and verbosity >= VERBOSE_MINIMAL:
        print(f"{Colors.YELLOW}[!] Missing tools: {', '.join(missing_tools)}{Colors.ENDC}")
        
        # Show installation instructions
        print(f"{Colors.BLUE}[*] Installation instructions:{Colors.ENDC}")
        for tool in missing_tools:
            if tool == "amass":
                print(f"{Colors.BLUE}  - amass: snap install amass{Colors.ENDC}")
            elif tool == "subfinder":
                print(f"{Colors.BLUE}  - subfinder: GO111MODULE=on go get -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder{Colors.ENDC}")
            elif tool == "dnsenum":
                print(f"{Colors.BLUE}  - dnsenum: apt install dnsenum{Colors.ENDC}")
            elif tool == "sublist3r":
                print(f"{Colors.BLUE}  - sublist3r: apt install sublist3r{Colors.ENDC}")
            elif tool == "massdns":
                print(f"{Colors.BLUE}  - massdns: git clone https://github.com/blechschmidt/massdns.git && cd massdns && make{Colors.ENDC}")
            elif tool == "dig":
                print(f"{Colors.BLUE}  - dig: apt install dnsutils{Colors.ENDC}")
    
    return missing_tools

def check_tools(verbosity=VERBOSE_NORMAL) -> bool:
    """Check if all required tools are available and print their status."""
    all_available = True
    print(f"{Colors.BLUE}[*] Checking for required tools...{Colors.ENDC}")
    
    if RICH_AVAILABLE and verbosity >= VERBOSE_NORMAL:
        table = Table(show_header=True, header_style="bold cyan", box=box.ROUNDED)
        table.add_column("Tool", style="dim")
        table.add_column("Status", style="dim")
        table.add_column("Path", style="dim")
        
        for tool_name in TOOL_NAMES:
            if tool_name in TOOLS:
                table.add_row(tool_name, "[bold green]✓ Found", TOOLS[tool_name])
            else:
                all_available = False
                table.add_row(tool_name, "[bold red]✗ Missing", "Not found")
        
        console.print(table)
    else:
        for tool_name in TOOL_NAMES:
            if tool_name in TOOLS:
                if verbosity > VERBOSE_MINIMAL:
                    print(f"{Colors.GREEN}[✓] {tool_name}: Found at {TOOLS[tool_name]}{Colors.ENDC}")
            else:
                print(f"{Colors.RED}[!] {tool_name}: Not found{Colors.ENDC}")
                all_available = False
    
    if not all_available:
        print(f"\n{Colors.RED}[!] Some required tools are missing. Please install them or add them to your PATH.{Colors.ENDC}")
    
    return all_available

def run_command(command: List[str], description: str, verbosity: int = VERBOSE_NORMAL, timeout=None) -> Optional[str]:
    """Run a command and return its output, handling errors gracefully."""
    try:
        if verbosity >= VERBOSE_MINIMAL:
            print(f"{Colors.BLUE}[*] {description}...{Colors.ENDC}")
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        
        stdout, stderr = process.communicate(timeout=timeout)
        
        if process.returncode != 0:
            if verbosity >= VERBOSE_MINIMAL:
                print(f"{Colors.RED}[!] Error running {command[0]}: {stderr.strip()}{Colors.ENDC}")
            return None
        return stdout
    except subprocess.TimeoutExpired:
        process.kill()
        if verbosity >= VERBOSE_MINIMAL:
            print(f"{Colors.RED}[!] Command timed out after {timeout} seconds: {command[0]}{Colors.ENDC}")
        return None
    except Exception as e:
        if verbosity >= VERBOSE_MINIMAL:
            print(f"{Colors.RED}[!] Error running {command[0]}: {str(e)}{Colors.ENDC}")
        return None

def extract_subdomains_from_output(output: str) -> Set[str]:
    """Extract subdomains from command output."""
    if not output:
        return set()
    
    subdomains = set()
    for line in output.splitlines():
        line = line.strip()
        if line and "." in line:
            # Simple filtering - ignore IP addresses and non-domain lines
            if not line[0].isdigit() and " " not in line:
                subdomains.add(line.lower())
    
    return subdomains

def run_amass(domain: str, verbosity: int = VERBOSE_NORMAL) -> Set[str]:
    """Run Amass for subdomain enumeration."""
    if "amass" not in TOOLS:
        if verbosity >= VERBOSE_MINIMAL:
            print(f"{Colors.YELLOW}[!] Skipping Amass (not installed){Colors.ENDC}")
        return set()
        
    if verbosity >= VERBOSE_NORMAL:
        print(f"{Colors.YELLOW}[*] Running Amass passive enumeration for {domain}...{Colors.ENDC}")
        
    output = run_command(
        [TOOLS["amass"], "enum", "-passive", "-d", domain],
        "Running Amass passive enumeration",
        verbosity
    )
    return extract_subdomains_from_output(output or "")

def run_subfinder(domain: str, verbosity: int = VERBOSE_NORMAL) -> Set[str]:
    """Run Subfinder for subdomain enumeration."""
    if "subfinder" not in TOOLS:
        if verbosity >= VERBOSE_MINIMAL:
            print(f"{Colors.YELLOW}[!] Skipping Subfinder (not installed){Colors.ENDC}")
        return set()
        
    if verbosity >= VERBOSE_NORMAL:
        print(f"{Colors.YELLOW}[*] Running Subfinder for {domain}...{Colors.ENDC}")
        
    output = run_command(
        [TOOLS["subfinder"], "-d", domain, "-silent"],
        "Running Subfinder",
        verbosity
    )
    return extract_subdomains_from_output(output or "")

def run_dnsenum(domain: str, verbosity: int = VERBOSE_NORMAL) -> Set[str]:
    """Run DNSenum for subdomain enumeration."""
    if "dnsenum" not in TOOLS:
        if verbosity >= VERBOSE_MINIMAL:
            print(f"{Colors.YELLOW}[!] Skipping DNSenum (not installed){Colors.ENDC}")
        return set()
        
    if verbosity >= VERBOSE_NORMAL:
        print(f"{Colors.YELLOW}[*] Running DNSenum for {domain}...{Colors.ENDC}")
    
    # Set a timeout for the DNSenum process (60 seconds)
    try:
        output = run_command(
            [TOOLS["dnsenum"], "--noreverse", "--dnsserver", "1.1.1.1", "--timeout", "20", domain],
            "Running DNSenum",
            verbosity,
            timeout=60  # Add timeout parameter to run_command call
        )
    except Exception as e:
        if verbosity >= VERBOSE_MINIMAL:
            print(f"{Colors.RED}[!] DNSenum failed: {e} - continuing with other tools{Colors.ENDC}")
        return set()
    
    subdomains = set()
    if output:
        # DNSenum has a different output format - extract subdomains from multiple sections
        lines = output.splitlines()
        for i, line in enumerate(lines):
            if domain in line and "NS" not in line and "MX" not in line:
                parts = line.split()
                for part in parts:
                    if domain in part and part.endswith(domain):
                        subdomains.add(part.strip().lower())
    
    return subdomains

def run_sublist3r(domain: str, verbosity: int = VERBOSE_NORMAL) -> Set[str]:
    """Run Sublist3r for subdomain enumeration."""
    if "sublist3r" not in TOOLS:
        if verbosity >= VERBOSE_MINIMAL:
            print(f"{Colors.YELLOW}[!] Skipping Sublist3r (not installed){Colors.ENDC}")
        return set()
        
    if verbosity >= VERBOSE_NORMAL:
        print(f"{Colors.YELLOW}[*] Running Sublist3r for {domain}...{Colors.ENDC}")
        
    output = run_command(
        [TOOLS["sublist3r"], "-d", domain, "-o", "/dev/stdout"],
        "Running Sublist3r",
        verbosity
    )
    return extract_subdomains_from_output(output or "")

def run_wordlist_bruteforce(domain: str, wordlist: List[str], verbosity: int = VERBOSE_NORMAL) -> Set[str]:
    """Perform dictionary-based bruteforce to discover subdomains."""
    found_subdomains = set()
    total_words = len(wordlist)
    
    if verbosity >= VERBOSE_NORMAL:
        print(f"{Colors.YELLOW}[*] Running dictionary bruteforce with {total_words} words...{Colors.ENDC}")
    
    # Function to check a single subdomain
    def check_subdomain(word):
        subdomain = f"{word}.{domain}"
        try:
            # Use socket to attempt a DNS resolution
            socket.gethostbyname(subdomain)
            return subdomain
        except socket.gaierror:
            return None
    
    # Use progress bar if tqdm is available and verbosity is high enough
    if TQDM_AVAILABLE and verbosity >= VERBOSE_NORMAL:
        results = thread_map(check_subdomain, wordlist, desc="Bruteforcing subdomains", unit="word")
        for result in results:
            if result:
                found_subdomains.add(result)
    # Use Rich progress if available and verbosity is high enough
    elif RICH_AVAILABLE and verbosity >= VERBOSE_NORMAL:
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            *Progress.get_default_columns(),
            console=console
        ) as progress:
            task = progress.add_task("Bruteforcing subdomains", total=total_words)
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                futures = [executor.submit(check_subdomain, word) for word in wordlist]
                for i, future in enumerate(concurrent.futures.as_completed(futures)):
                    progress.update(task, advance=1)
                    result = future.result()
                    if result:
                        found_subdomains.add(result)
    # Basic implementation for minimal verbosity or when libraries aren't available
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(check_subdomain, word) for word in wordlist]
            
            if verbosity == VERBOSE_NORMAL:
                print(f"{Colors.BLUE}[*] Checking subdomains...{Colors.ENDC}")
                
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    found_subdomains.add(result)
    
    elapsed_time = time.time() - start_time
    
    if verbosity >= VERBOSE_MINIMAL:
        print(f"{Colors.GREEN}[✓] Dictionary bruteforce found {len(found_subdomains)} subdomains in {elapsed_time:.2f} seconds{Colors.ENDC}")
        
    return found_subdomains

def run_massdns(domain: str, subdomains: Set[str], verbosity: int = VERBOSE_NORMAL) -> Set[str]:
    """Run MassDNS to resolve and validate subdomains."""
    if "massdns" not in TOOLS:
        if verbosity >= VERBOSE_MINIMAL:
            print(f"{Colors.YELLOW}[!] Skipping MassDNS (not installed){Colors.ENDC}")
        return subdomains
    
    # Verify massdns path is correct (points to executable, not directory)
    massdns_path = TOOLS["massdns"]
    if os.path.isdir(massdns_path):
        # If it's a directory, try to find the executable inside
        possible_exe = os.path.join(massdns_path, "bin", "massdns")
        if os.path.exists(possible_exe) and os.access(possible_exe, os.X_OK):
            massdns_path = possible_exe
            if verbosity >= VERBOSE_NORMAL:
                print(f"{Colors.BLUE}[*] Using MassDNS executable at {massdns_path}{Colors.ENDC}")
        else:
            if verbosity >= VERBOSE_MINIMAL:
                print(f"{Colors.RED}[!] MassDNS path is a directory and executable not found{Colors.ENDC}")
            return subdomains
            
    if not subdomains:
        return set()
    
    # Determine where to create temporary files
    temp_dir = output_dir if output_dir else tempfile.gettempdir()
    os.makedirs(temp_dir, exist_ok=True)
    
    # Create a temporary file with all subdomains in the output directory if available
    temp_file_path = os.path.join(temp_dir, f"{domain}_subdomains_temp.txt")
    with open(temp_file_path, "w") as temp_file:
        for subdomain in subdomains:
            temp_file.write(f"{subdomain}\n")
    
    # Get resolvers path
    resolvers_path = get_resolvers_path()
    
    # Run MassDNS
    output = run_command(
        [
            massdns_path,
            "-r", resolvers_path,
            "-t", "A",
            "-o", "S",
            "-w", "/dev/stdout",
            temp_file_path
        ],
        "Running MassDNS to resolve subdomains",
        verbosity
    )
    
    # Clean up the temporary file
    try:
        os.unlink(temp_file_path)
    except Exception as e:
        print(f"{Colors.YELLOW}[!] Could not remove temporary file {temp_file_path}: {str(e)}{Colors.ENDC}")
    
    resolved_subdomains = set()
    if output:
        for line in output.splitlines():
            parts = line.strip().split()
            if len(parts) >= 1:
                subdomain = parts[0].lower().rstrip(".")
                if domain in subdomain:
                    resolved_subdomains.add(subdomain)
    
    return resolved_subdomains

def is_ip_address(input_str: str) -> bool:
    """Check if the input string is an IP address."""
    ip_pattern = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')
    match = ip_pattern.match(input_str)
    if not match:
        return False
    
    # Check if each octet is in the range 0-255
    for i in range(1, 5):
        if int(match.group(i)) > 255:
            return False
    
    return True

def perform_reverse_dns_lookup(ip_address: str) -> Set[str]:
    """Perform a reverse DNS lookup on an IP address using dig."""
    print(f"{Colors.BLUE}[*] Performing reverse DNS lookup for {ip_address}...{Colors.ENDC}")
    
    command = [TOOLS["dig"], "-x", ip_address, "+short"]
    output = run_command(command, f"Reverse DNS lookup for {ip_address}")
    
    domains = set()
    if output:
        for line in output.splitlines():
            domain = line.strip().rstrip(".")
            if domain:
                domains.add(domain)
                print(f"{Colors.GREEN}[✓] Found domain: {domain}{Colors.ENDC}")
    
    return domains

def get_ips_for_subdomains(subdomains: Set[str]) -> Dict[str, List[str]]:
    """
    Takes a set of subdomains and returns a dictionary mapping each subdomain to its IP addresses.
    Uses 'dig' to resolve each subdomain to its IP addresses.
    """
    subdomain_to_ips = {}
    
    print(f"{Colors.BLUE}[*] Resolving IP addresses for {len(subdomains)} subdomains...{Colors.ENDC}")
    
    # Use tqdm for progress bar if available
    iterator = tqdm(subdomains) if TQDM_AVAILABLE else subdomains
    
    for subdomain in iterator:
        try:
            command = [TOOLS["dig"], subdomain, "+short", "A"]
            result = subprocess.run(command, capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0 and result.stdout.strip():
                # Extract IP addresses from the output
                ips = [ip.strip() for ip in result.stdout.splitlines() if ip.strip() and is_ip_address(ip.strip())]
                if ips:
                    subdomain_to_ips[subdomain] = ips
        except (subprocess.SubprocessError, subprocess.TimeoutExpired) as e:
            print(f"{Colors.YELLOW}[!] Error resolving {subdomain}: {str(e)}{Colors.ENDC}")
    
    print(f"{Colors.GREEN}[✓] Found IP addresses for {len(subdomain_to_ips)} out of {len(subdomains)} subdomains{Colors.ENDC}")
    return subdomain_to_ips

def build_ip_to_domains_map(subdomain_to_ips: Dict[str, List[str]]) -> Dict[str, Set[str]]:
    """
    Inverts the subdomain_to_ips dictionary to create a mapping of IPs to the domains that resolve to them.
    Returns a dictionary where keys are IP addresses and values are sets of domains.
    """
    ip_to_domains = {}
    
    for subdomain, ips in subdomain_to_ips.items():
        for ip in ips:
            if ip not in ip_to_domains:
                ip_to_domains[ip] = set()
            ip_to_domains[ip].add(subdomain)
    
    # Sort IPs by the number of domains they host (descending)
    ip_to_domains = {ip: domains for ip, domains in sorted(
        ip_to_domains.items(), 
        key=lambda item: len(item[1]), 
        reverse=True
    )}
    
    return ip_to_domains

def get_domains_from_ip(ip_address: str) -> Set[str]:
    """Get all domains associated with an IP address."""
    domains = perform_reverse_dns_lookup(ip_address)
    
    # Try to extract more domains using other techniques
    # 1. Using SSL certificates (requires openssl)
    try:
        print(f"{Colors.BLUE}[*] Checking for SSL certificates on {ip_address}...{Colors.ENDC}")
        ssl_command = ["openssl", "s_client", "-connect", f"{ip_address}:443", "-showcerts", "-servername", "localhost"]
        ssl_process = subprocess.Popen(
            ssl_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            stdin=subprocess.PIPE
        )
        # Give it a brief timeout
        ssl_stdout, ssl_stderr = ssl_process.communicate(input="Q\n", timeout=5)
        
        # Extract domains from the SSL certificate
        cert_domains = set()
        cert_domain_pattern = re.compile(r'(?:DNS:|Subject:.*CN=)([\w\.-]+)')
        
        for match in cert_domain_pattern.finditer(ssl_stdout):
            domain = match.group(1).lower()
            if domain and "." in domain:
                cert_domains.add(domain)
                print(f"{Colors.GREEN}[✓] Found domain from SSL: {domain}{Colors.ENDC}")
        
        domains.update(cert_domains)
    except Exception as e:
        print(f"{Colors.YELLOW}[!] Could not retrieve SSL certificates: {str(e)}{Colors.ENDC}")
    
    # 2. Try a few common hostnames
    common_vhosts = ["www", "mail", "webmail", "smtp", "pop", "ftp", "dns", "ns1", "ns2"]
    for domain in list(domains):
        domain_parts = domain.split(".")
        if len(domain_parts) >= 2:
            base_domain = ".".join(domain_parts[-2:])
            for vhost in common_vhosts:
                full_domain = f"{vhost}.{base_domain}"
                print(f"{Colors.BLUE}[*] Checking common vhost: {full_domain}{Colors.ENDC}")
                try:
                    # Check if the domain resolves to the same IP
                    command = [TOOLS["dig"], full_domain, "+short"]
                    output = subprocess.check_output(command, text=True)
                    
                    if output and ip_address in output:
                        domains.add(full_domain)
                        print(f"{Colors.GREEN}[✓] Found additional domain: {full_domain}{Colors.ENDC}")
                except Exception:
                    pass
    
    return domains

def recursive_domain_enumeration(domains: Set[str], max_depth: int = 3) -> Dict[str, Set[str]]:
    """Recursively enumerate subdomains for all discovered domains."""
    all_results = {}
    processed_domains = set()
    current_depth = 0
    
    # Start with the initial domains
    domains_to_process = list(domains)
    
    while domains_to_process and current_depth < max_depth:
        current_domain = domains_to_process.pop(0)
        
        # Skip if we've already processed this domain
        if current_domain in processed_domains:
            continue
        
        print(f"\n{Colors.YELLOW}[*] Recursive enumeration depth {current_depth+1}/{max_depth}: {current_domain}{Colors.ENDC}")
        
        # Process the current domain
        tool_results = {}
        all_subdomains = set()
        
        # Run each tool
        tool_functions = [
            ("amass", run_amass),
            ("subfinder", run_subfinder), 
            ("dnsenum", run_dnsenum),
            ("sublist3r", run_sublist3r)
        ]
        
        for tool_name, tool_func in tool_functions:
            try:
                subdomains = tool_func(current_domain)
                tool_results[tool_name] = subdomains
                all_subdomains.update(subdomains)
            except Exception as e:
                print(f"{Colors.RED}[!] Error running {tool_name} on {current_domain}: {str(e)}{Colors.ENDC}")
        
        # Verify with MassDNS
        if all_subdomains:
            resolved_subdomains = run_massdns(current_domain, all_subdomains)
            tool_results["massdns"] = resolved_subdomains
            
            if resolved_subdomains:
                all_subdomains = resolved_subdomains
        
        # Store results for this domain
        all_results[current_domain] = all_subdomains
        processed_domains.add(current_domain)
        
        # Extract new base domains from subdomains
        for subdomain in all_subdomains:
            parts = subdomain.split('.')
            if len(parts) >= 3:  # Extract potential base domains
                # Check if this is a new base domain (e.g., example.org from sub.example.org)
                potential_base = '.'.join(parts[1:])
                
                # Add the new domain if we haven't processed it yet
                if potential_base not in processed_domains and potential_base not in domains_to_process:
                    domains_to_process.append(potential_base)
        
        current_depth = min(current_depth + 1, max_depth)
    
    return all_results

def save_results(target: str, subdomains: Set[str], tool_results: Dict[str, Set[str]], 
                 recursive_results: Optional[Dict[str, Set[str]]] = None, 
                 custom_output_dir: Optional[str] = None,
                 ip_to_domains_map: Optional[Dict[str, Set[str]]] = None) -> Dict[str, str]:
    """Save results to JSON and TXT files."""
    global output_dir
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Use custom output directory if provided, otherwise use default "results" directory
    base_dir = custom_output_dir if custom_output_dir else "results"
    
    # Create the target-specific directory name
    target_dir = f"{target}_{timestamp}"
    
    # Build the full path using os.path.join for proper OS-specific path handling
    output_dir = os.path.join(os.getcwd(), base_dir, target_dir)
    
    # Create the directory
    try:
        os.makedirs(output_dir, exist_ok=True)
        print(f"{Colors.GREEN}[✓] Created output directory: {output_dir}{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.RED}[!] Error creating output directory: {str(e)}{Colors.ENDC}")
        # Fallback to a directory in the current working directory if there's an error
        output_dir = os.path.join(os.getcwd(), target_dir)
        os.makedirs(output_dir, exist_ok=True)
        print(f"{Colors.YELLOW}[!] Using fallback directory: {output_dir}{Colors.ENDC}")
    
    # Save all subdomains to a text file
    txt_file = os.path.join(output_dir, f"{target}_subdomains.txt")
    with open(txt_file, "w") as f:
        for subdomain in sorted(subdomains):
            f.write(f"{subdomain}\n")
    
    # Save detailed results to a JSON file
    json_file = os.path.join(output_dir, f"{target}_results.json")
    results = {
        "target": target,
        "timestamp": timestamp,
        "total_subdomains_found": len(subdomains),
        "subdomains": sorted(list(subdomains)),
        "tool_results": {tool: sorted(list(subs)) for tool, subs in tool_results.items()}
    }
    
    # Add recursive results if available
    if recursive_results:
        results["recursive_results"] = {
            domain: sorted(list(subs)) for domain, subs in recursive_results.items()
        }
        # Count total unique subdomains across all recursive scans
        all_recursive_subdomains = set()
        for subs in recursive_results.values():
            all_recursive_subdomains.update(subs)
        results["total_recursive_subdomains"] = len(all_recursive_subdomains)
    
    with open(json_file, "w") as f:
        json.dump(results, f, indent=4)
    
    # Add email security results if available
    if "email_security" in tool_results:
        results["email_security"] = tool_results["email_security"]
    
    summary_file = os.path.join(output_dir, f"{target}_summary.txt")
    with open(summary_file, "w") as f:
        if is_ip_address(target):
            f.write(f"IP Reconnaissance Summary for {target}\n")
        else:
            f.write(f"Domain Reconnaissance Summary for {target}\n")
        
        f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total subdomains found: {len(subdomains)}\n\n")
        
        f.write("Tool Statistics:\n")
        for tool, subs in tool_results.items():
            f.write(f"- {tool}: {len(subs)} subdomains\n")
        
        # Add recursive enumeration statistics if applicable
        # Add recursive enumeration statistics if applicable
        if recursive_results:
            f.write("\nRecursive Enumeration Summary:\n")
            f.write(f"Total domains recursively enumerated: {len(recursive_results)}\n")
            
            # Calculate total unique subdomains across all domains
            all_recursive_subdomains = set()
            for domain, subs in recursive_results.items():
                all_recursive_subdomains.update(subs)
            
            f.write(f"Total unique subdomains discovered recursively: {len(all_recursive_subdomains)}\n\n")
            
            # List domains and their subdomains count
            f.write("Domains enumerated:\n")
            for domain, subs in recursive_results.items():
                f.write(f"- {domain}: {len(subs)} subdomains\n")
            
            # For IP-based reconnaissance, add a section showing the relationship
            if is_ip_address(target):
                f.write(f"\nIP Address: {target}\n")
                f.write("Associated Domains and Subdomains:\n")
                for domain in recursive_results.keys():
                    f.write(f"- {domain}\n")
                    # List a few subdomains as examples (up to 5)
                    subdomain_examples = list(recursive_results[domain])[:5]
                    for subdomain in subdomain_examples:
                        f.write(f"  • {subdomain}\n")
                    if len(recursive_results[domain]) > 5:
                        f.write(f"  • ... and {len(recursive_results[domain]) - 5} more\n")
    
        # Add email security results if available
        if "email_security" in tool_results:
            f.write("\nEmail Security Analysis:\n")
            f.write(f"SPF Record: {'Present' if tool_results['email_security']['spf']['present'] else 'Missing'}\n")
            if tool_results['email_security']['spf']['present']:
                f.write(f"SPF Policy: {tool_results['email_security']['spf']['policy']}\n")
                f.write(f"SPF Record: {tool_results['email_security']['spf']['record']}\n")
                
            f.write(f"DMARC Record: {'Present' if tool_results['email_security']['dmarc']['present'] else 'Missing'}\n")
            if tool_results['email_security']['dmarc']['present']:
                f.write(f"DMARC Policy: {tool_results['email_security']['dmarc']['policy']}\n")
                f.write(f"DMARC Record: {tool_results['email_security']['dmarc']['record']}\n")
                
            f.write(f"DKIM Records: {'Found' if tool_results['email_security']['dkim']['present'] else 'Not Found'}\n")
            if tool_results['email_security']['dkim']['present']:
                f.write(f"DKIM Selectors: {', '.join(tool_results['email_security']['dkim']['selectors_found'])}\n")
                
            f.write(f"\nEmail Spoofing Protection: {'PROTECTED' if not tool_results['email_security']['spoofable'] else 'VULNERABLE'}\n")
            if tool_results['email_security']['spoofable'] and tool_results['email_security']['reasons']:
                f.write("Vulnerability Reasons:\n")
                for reason in tool_results['email_security']['reasons']:
                    f.write(f"- {reason}\n")
    
    # Print a summary of saved files
    print(f"{Colors.GREEN}[✓] Saved results to directory: {output_dir}{Colors.ENDC}")
    print(f"{Colors.BLUE}    - Subdomains list: {os.path.basename(txt_file)}{Colors.ENDC}")
    print(f"{Colors.BLUE}    - Detailed results: {os.path.basename(json_file)}{Colors.ENDC}")
    print(f"{Colors.BLUE}    - Summary report: {os.path.basename(summary_file)}{Colors.ENDC}")
    
    # Save IP to domains mapping if available
    ip_mapping_file = None
    ip_text_file = None
    if ip_to_domains_map:
        ip_mapping_file = os.path.join(output_dir, f"{target}_ip_mapping.json")
        ip_mapping_data = {
            "target": target,
            "timestamp": timestamp,
            "total_mapped_ips": len(ip_to_domains_map),
            "ip_mapping": {ip: sorted(list(domains)) for ip, domains in ip_to_domains_map.items()}
        }
        with open(ip_mapping_file, "w") as f:
            json.dump(ip_mapping_data, f, indent=4)
        
        # Also save a readable text version
        ip_text_file = os.path.join(output_dir, f"{target}_ip_mapping.txt")
        with open(ip_text_file, "w") as f:
            f.write(f"IP to Domain Mapping for {target}\n")
            f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"Total IPs mapped: {len(ip_to_domains_map)}\n\n")
            for ip, domains in ip_to_domains_map.items():
                f.write(f"IP: {ip}\n")
                f.write(f"Domains ({len(domains)}):\n")
                for domain in sorted(domains):
                    f.write(f"  - {domain}\n")
                f.write("\n")
        
        print(f"{Colors.BLUE}    - IP to domain mapping (JSON): {os.path.basename(ip_mapping_file)}{Colors.ENDC}")
        print(f"{Colors.BLUE}    - IP to domain mapping (TXT): {os.path.basename(ip_text_file)}{Colors.ENDC}")
    
    return {
        "txt": txt_file,
        "json": json_file,
        "summary": summary_file,
        "ip_mapping_json": ip_mapping_file if ip_mapping_file else None,
        "ip_mapping_txt": ip_text_file if ip_text_file else None,
        "directory": output_dir
    }
def check_email_security(domain: str, verbosity: int = VERBOSE_NORMAL) -> Dict[str, Any]:
    """Check email security (SPF, DKIM, DMARC) and determine if the domain is spoofable."""
    if verbosity >= VERBOSE_NORMAL:
        print_section_header(f"Email Security Analysis: {domain}", verbosity)
    
    results = {
        "spf": {"present": False, "record": None, "policy": None},
        "dmarc": {"present": False, "record": None, "policy": None},
        "dkim": {"present": False, "selectors_found": [], "records": {}},
        "spoofable": True,
        "reasons": []
    }
    
    # Check SPF records
    if verbosity >= VERBOSE_NORMAL:
        print(f"{Colors.BLUE}[*] Checking SPF records...{Colors.ENDC}")
    
    spf_command = [TOOLS["dig"], domain, "TXT", "+short"]
    spf_output = run_command(spf_command, "Checking SPF records", verbosity)
    
    spf_record = None
    if spf_output:
        for line in spf_output.splitlines():
            line = line.strip().strip('"')
            if "v=spf1" in line:
                spf_record = line
                results["spf"]["present"] = True
                results["spf"]["record"] = spf_record
                
                # Determine SPF policy
                if "~all" in spf_record:
                    results["spf"]["policy"] = "softfail"
                    if verbosity >= VERBOSE_NORMAL:
                        print(f"{Colors.YELLOW}[!] SPF policy is set to softfail (~all){Colors.ENDC}")
                elif "-all" in spf_record:
                    results["spf"]["policy"] = "hardfail"
                    if verbosity >= VERBOSE_NORMAL:
                        print(f"{Colors.GREEN}[✓] SPF policy is set to hardfail (-all){Colors.ENDC}")
                elif "+all" in spf_record:
                    results["spf"]["policy"] = "allow"
                    if verbosity >= VERBOSE_NORMAL:
                        print(f"{Colors.RED}[!] SPF policy is set to allow all (+all) - Very insecure!{Colors.ENDC}")
                elif "?all" in spf_record:
                    results["spf"]["policy"] = "neutral"
                    if verbosity >= VERBOSE_NORMAL:
                        print(f"{Colors.ORANGE}[!] SPF policy is set to neutral (?all) - Not recommended{Colors.ENDC}")
                else:
                    results["spf"]["policy"] = "unknown"
                    if verbosity >= VERBOSE_NORMAL:
                        print(f"{Colors.ORANGE}[!] SPF record found but policy is unclear{Colors.ENDC}")
                
                break
    
    if not results["spf"]["present"]:
        results["reasons"].append("No SPF record found")
        if verbosity >= VERBOSE_NORMAL:
            print(f"{Colors.RED}[!] No SPF record found for {domain}{Colors.ENDC}")
    
    # Check DMARC records
    if verbosity >= VERBOSE_NORMAL:
        print(f"{Colors.BLUE}[*] Checking DMARC records...{Colors.ENDC}")
    
    dmarc_domain = f"_dmarc.{domain}"
    dmarc_command = [TOOLS["dig"], dmarc_domain, "TXT", "+short"]
    dmarc_output = run_command(dmarc_command, "Checking DMARC records", verbosity)
    
    dmarc_record = None
    if dmarc_output:
        for line in dmarc_output.splitlines():
            line = line.strip().strip('"')
            if "v=DMARC1" in line:
                dmarc_record = line
                results["dmarc"]["present"] = True
                results["dmarc"]["record"] = dmarc_record
                
                # Extract DMARC policy
                policy_match = re.search(r'p=(\w+)', dmarc_record)
                if policy_match:
                    policy = policy_match.group(1).lower()
                    results["dmarc"]["policy"] = policy
                    
                    if policy == "reject":
                        if verbosity >= VERBOSE_NORMAL:
                            print(f"{Colors.GREEN}[✓] DMARC policy is set to reject{Colors.ENDC}")
                    elif policy == "quarantine":
                        if verbosity >= VERBOSE_NORMAL:
                            print(f"{Colors.YELLOW}[!] DMARC policy is set to quarantine{Colors.ENDC}")
                    elif policy == "none":
                        if verbosity >= VERBOSE_NORMAL:
                            print(f"{Colors.ORANGE}[!] DMARC policy is set to none (monitoring mode){Colors.ENDC}")
                        results["reasons"].append("DMARC policy set to 'none' (monitoring only)")
                    else:
                        if verbosity >= VERBOSE_NORMAL:
                            print(f"{Colors.ORANGE}[!] Unknown DMARC policy: {policy}{Colors.ENDC}")
                        results["reasons"].append(f"Unknown DMARC policy: {policy}")
                
                # Check for subdomain policy
                subdomain_match = re.search(r'sp=(\w+)', dmarc_record)
                if subdomain_match:
                    sp_policy = subdomain_match.group(1).lower()
                    results["dmarc"]["subdomain_policy"] = sp_policy
                    
                    if sp_policy == "reject":
                        if verbosity >= VERBOSE_NORMAL:
                            print(f"{Colors.GREEN}[✓] DMARC subdomain policy is set to reject{Colors.ENDC}")
                    elif sp_policy == "quarantine":
                        if verbosity >= VERBOSE_NORMAL:
                            print(f"{Colors.YELLOW}[!] DMARC subdomain policy is set to quarantine{Colors.ENDC}")
                    elif sp_policy == "none":
                        if verbosity >= VERBOSE_NORMAL:
                            print(f"{Colors.ORANGE}[!] DMARC subdomain policy is set to none (monitoring mode){Colors.ENDC}")
                        results["reasons"].append("DMARC subdomain policy set to 'none' (monitoring only)")
                else:
                    if verbosity >= VERBOSE_NORMAL:
                        print(f"{Colors.BLUE}[*] No explicit DMARC subdomain policy (inherits from main policy){Colors.ENDC}")
                
                break
    
    if not results["dmarc"]["present"]:
        results["reasons"].append("No DMARC record found")
        if verbosity >= VERBOSE_NORMAL:
            print(f"{Colors.RED}[!] No DMARC record found for {domain}{Colors.ENDC}")
    
    # Try to find DKIM records with common selectors
    if verbosity >= VERBOSE_NORMAL:
        print(f"{Colors.BLUE}[*] Checking DKIM records with common selectors...{Colors.ENDC}")
    
    common_selectors = ["default", "dkim", "mail", "email", "selector1", "selector2", "k1", "key1", "google"]
    found_selectors = []
    
    for selector in common_selectors:
        dkim_domain = f"{selector}._domainkey.{domain}"
        dkim_command = [TOOLS["dig"], dkim_domain, "TXT", "+short"]
        dkim_output = run_command(dkim_command, f"Checking DKIM for selector '{selector}'", verbosity)
        
        if dkim_output:
            for line in dkim_output.splitlines():
                line = line.strip().strip('"')
                if "v=DKIM1" in line or "k=rsa" in line:
                    results["dkim"]["present"] = True
                    results["dkim"]["selectors_found"].append(selector)
                    results["dkim"]["records"][selector] = line
                    found_selectors.append(selector)
                    if verbosity >= VERBOSE_NORMAL:
                        print(f"{Colors.GREEN}[✓] DKIM record found for selector '{selector}'{Colors.ENDC}")
                    break
    
    if not results["dkim"]["present"]:
        results["reasons"].append("No DKIM records found with common selectors")
        if verbosity >= VERBOSE_NORMAL:
            print(f"{Colors.YELLOW}[!] No DKIM records found with common selectors{Colors.ENDC}")
            print(f"{Colors.BLUE}[*] Note: DKIM selectors are specific to email providers; absence doesn't guarantee spoofability{Colors.ENDC}")
    
    # Determine if the domain is spoofable
    if results["spf"]["present"] and results["spf"]["policy"] in ["hardfail"]:
        if results["dmarc"]["present"] and results["dmarc"]["policy"] in ["reject", "quarantine"]:
            results["spoofable"] = False
            if verbosity >= VERBOSE_NORMAL:
                print(f"{Colors.GREEN}[✓] Domain {domain} is well-protected against email spoofing{Colors.ENDC}")
        else:
            if verbosity >= VERBOSE_NORMAL:
                print(f"{Colors.YELLOW}[!] Domain {domain} has SPF but insufficient DMARC protection{Colors.ENDC}")
            results["reasons"].append("Has SPF with hardfail, but DMARC is missing or weak")
    elif results["dmarc"]["present"] and results["dmarc"]["policy"] in ["reject", "quarantine"]:
        if verbosity >= VERBOSE_NORMAL:
            print(f"{Colors.YELLOW}[!] Domain {domain} has strong DMARC but weak or missing SPF{Colors.ENDC}")
        results["reasons"].append("Has strong DMARC, but SPF is missing or weak")
        # A strong DMARC policy can compensate for a missing SPF to some extent
        if results["dmarc"]["policy"] == "reject":
            results["spoofable"] = False
    else:
        if verbosity >= VERBOSE_NORMAL:
            print(f"{Colors.RED}[!] Domain {domain} is vulnerable to email spoofing{Colors.ENDC}")
    
    # Print detailed verdict
    if verbosity >= VERBOSE_NORMAL:
        if results["spoofable"]:
            print(f"\n{Colors.RED}[!] VERDICT: {domain} is VULNERABLE to email spoofing{Colors.ENDC}")
            print(f"{Colors.RED}[!] Reasons:{Colors.ENDC}")
            for reason in results["reasons"]:
                print(f"{Colors.RED}  - {reason}{Colors.ENDC}")
        else:
            print(f"\n{Colors.GREEN}[✓] VERDICT: {domain} is PROTECTED against email spoofing{Colors.ENDC}")
    
    return results

def main():
    """Main function to coordinate the subdomain enumeration."""
    parser = argparse.ArgumentParser(description="Domain & IP Reconnaissance Tool")
    parser.add_argument("target", help="Target domain or IP address to enumerate")
    parser.add_argument("--ip", action="store_true", help="Specify that the target is an IP address")
    parser.add_argument("--recursive", action="store_true", help="Enable recursive enumeration of discovered domains")
    parser.add_argument("--max-depth", type=int, default=3, help="Maximum depth for recursive enumeration (default: 3)")
    parser.add_argument("--no-massdns", action="store_true", help="Skip MassDNS verification")
    parser.add_argument("--output-dir", help="Custom output directory")
    parser.add_argument("--wordlist", help="Path to wordlist for dictionary-based subdomain discovery")
    parser.add_argument("--skip-wordlist", action="store_true", help="Skip dictionary-based subdomain discovery")
    parser.add_argument("--check-email-security", action="store_true", help="Check for email security (SPF, DKIM, DMARC) and report if the domain is spoofable")
    parser.add_argument("-v", "--verbose", action="count", default=1, help="Increase verbosity (can be used multiple times, e.g. -vv)")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode, minimal output")
    args = parser.parse_args()
    
    # Set verbosity level
    verbosity = VERBOSE_MINIMAL if args.quiet else min(args.verbose, VERBOSE_DETAILED)
    
    target = args.target.lower()
    is_ip_mode = args.ip or is_ip_address(target)
    
    print_banner(verbosity)
    
    # Check if required tools are available
    missing_tools = check_missing_tools(verbosity)
    has_essential_tools = True
    
    # Check if dig (essential tool) is available
    if "dig" in missing_tools:
        print(f"{Colors.RED}[!] The 'dig' tool is essential and must be installed.{Colors.ENDC}")
        print(f"{Colors.RED}[!] Please install dig (usually part of dnsutils/bind-utils) and try again.{Colors.ENDC}")
        sys.exit(1)
    
    # Print detailed tool information if requested
    if verbosity >= VERBOSE_NORMAL:
        check_tools(verbosity)
        
    if missing_tools:
        print(f"{Colors.YELLOW}[!] Some tools are missing. Functionality will be limited.{Colors.ENDC}")
        print(f"{Colors.YELLOW}[!] Continuing with available tools only...{Colors.ENDC}")
    
    # Initialize results dictionary
    tool_results = {}
    all_subdomains = set()
    recursive_results = None
    
    if is_ip_mode:
        print_section_header(f"IP-based Reconnaissance: {target}", verbosity)
        
        # Get domains associated with the IP address
        domains = get_domains_from_ip(target)
        
        if not domains:
            print(f"{Colors.RED}[!] No domains found for IP address {target}{Colors.ENDC}")
            sys.exit(1)
        
        print(f"\n{Colors.GREEN}[✓] Found {len(domains)} domains associated with {target}:{Colors.ENDC}")
        for domain in domains:
            print(f"{Colors.BLUE}    - {domain}{Colors.ENDC}")
        
        if args.recursive:
            print_section_header(f"Recursive Enumeration for {len(domains)} Domains", verbosity)
            recursive_results = recursive_domain_enumeration(domains, args.max_depth)
            
            # Combine all subdomains from recursive results
            for domain_subs in recursive_results.values():
                all_subdomains.update(domain_subs)
        else:
            # Run standard enumeration on each found domain
            for domain in domains:
                print_section_header(f"Subdomain Enumeration: {domain}", verbosity)
                
                # Run each tool in sequence
                tool_functions = [
                    ("amass", run_amass),
                    ("subfinder", run_subfinder), 
                    ("dnsenum", run_dnsenum),
                    ("sublist3r", run_sublist3r)
                ]
                
                domain_results = {}
                domain_subdomains = set()
                
                for tool_name, tool_func in tool_functions:
                    start_time = time.time()
                    try:
                        subdomains = tool_func(domain)
                        if tool_name not in tool_results:
                            tool_results[tool_name] = set()
                        tool_results[tool_name].update(subdomains)
                        domain_subdomains.update(subdomains)
                        domain_results[tool_name] = subdomains
                        
                        duration = time.time() - start_time
                        print(f"{Colors.GREEN}[✓] {tool_name} found {len(subdomains)} subdomains in {duration:.2f} seconds{Colors.ENDC}")
                    except Exception as e:
                        print(f"{Colors.RED}[!] Error running {tool_name} on {domain}: {str(e)}{Colors.ENDC}")
                
                # MassDNS verification
                if not args.no_massdns and domain_subdomains:
                    print(f"\n{Colors.BLUE}[*] Verifying {len(domain_subdomains)} subdomains with MassDNS...{Colors.ENDC}")
                    start_time = time.time()
                    
                    resolved_subdomains = run_massdns(domain, domain_subdomains)
                    if "massdns" not in tool_results:
                        tool_results["massdns"] = set()
                    tool_results["massdns"].update(resolved_subdomains)
                    
                    duration = time.time() - start_time
                    print(f"{Colors.GREEN}[✓] MassDNS resolved {len(resolved_subdomains)} subdomains in {duration:.2f} seconds{Colors.ENDC}")
                    
                    # Update the domain's subdomains to only include resolved ones
                    if resolved_subdomains:
                        domain_subdomains = resolved_subdomains
                
                all_subdomains.update(domain_subdomains)
    else:
        # Standard domain-based reconnaissance
        domain = target
        print_section_header(f"Domain Reconnaissance: {domain}", verbosity)
        
        # Run each tool in sequence
        tool_functions = [
            ("amass", run_amass),
            ("subfinder", run_subfinder), 
            ("dnsenum", run_dnsenum),
            ("sublist3r", run_sublist3r)
        ]
        
        for tool_name, tool_func in tool_functions:
            start_time = time.time()
            try:
                subdomains = tool_func(domain)
                tool_results[tool_name] = subdomains
                all_subdomains.update(subdomains)
                
                duration = time.time() - start_time
                print(f"{Colors.GREEN}[✓] {tool_name} found {len(subdomains)} subdomains in {duration:.2f} seconds{Colors.ENDC}")
            except Exception as e:
                print(f"{Colors.RED}[!] Error running {tool_name}: {str(e)}{Colors.ENDC}")
        
        # MassDNS verification
        if not args.no_massdns and all_subdomains:
            print_section_header(f"MassDNS Verification: {len(all_subdomains)} Subdomains", verbosity)
            start_time = time.time()
            
            resolved_subdomains = run_massdns(domain, all_subdomains)
            tool_results["massdns"] = resolved_subdomains
            
            duration = time.time() - start_time
            print(f"{Colors.GREEN}[✓] MassDNS resolved {len(resolved_subdomains)} subdomains in {duration:.2f} seconds{Colors.ENDC}")
            
            # Update the final set to only include resolved subdomains
            if resolved_subdomains:
                all_subdomains = resolved_subdomains
        
        # Recursive enumeration if requested
        if args.recursive and all_subdomains:
            print_section_header("Recursive Enumeration", verbosity)
            recursive_results = recursive_domain_enumeration({domain}, args.max_depth)
            # Update all_subdomains with recursive results
            for domain_subs in recursive_results.values():
                all_subdomains.update(domain_subs)
    
    # Print summary
    # Print summary
    print_section_header("Reconnaissance Summary", verbosity)
    print(f"{Colors.GREEN}[✓] Total unique subdomains found: {len(all_subdomains)}{Colors.ENDC}")
    
    # Format the tool results in a table if rich is available
    if RICH_AVAILABLE and verbosity >= VERBOSE_NORMAL:
        table = Table(show_header=True, header_style="bold cyan", box=box.ROUNDED)
        table.add_column("Tool", style="dim")
        table.add_column("Subdomains Found", style="dim")
        
        for tool, subdomains in tool_results.items():
            if tool != "email_security":  # Skip email security as it's not a subdomain list
                table.add_row(tool, str(len(subdomains)))
        
        console.print(table)
    else:
        for tool, subdomains in tool_results.items():
            if tool != "email_security":  # Skip email security as it's not a subdomain list
                print(f"{Colors.BLUE}    - {tool}: {len(subdomains)} subdomains{Colors.ENDC}")
    
    # Resolve IP addresses for all discovered subdomains
    print_section_header("Resolving IP Addresses", verbosity)
    subdomain_to_ips = get_ips_for_subdomains(all_subdomains)
    
    # Build the IP to domains mapping
    print(f"{Colors.BLUE}[*] Building IP to domains mapping...{Colors.ENDC}")
    ip_to_domains_map = build_ip_to_domains_map(subdomain_to_ips)
    print(f"{Colors.GREEN}[✓] Found {len(ip_to_domains_map)} unique IP addresses hosting the discovered domains{Colors.ENDC}")
    
    # Check email security if requested and not in IP mode
    email_security_results = None
    if args.check_email_security and not is_ip_mode:
        email_security_results = check_email_security(domain, verbosity)
        # Add the results to tool_results for inclusion in output
        tool_results["email_security"] = email_security_results
    
    # Save results
    output_files = save_results(
        target, 
        all_subdomains, 
        tool_results, 
        recursive_results, 
        args.output_dir,
        ip_to_domains_map
    )
    # Summary is now printed inside the save_results function
    
    # Clean up any stray IP files
    cleanup_file = f"{target}_ips.txt"
    if os.path.exists(cleanup_file):
        try:
            # Move the file to the output directory instead of deleting it
            dest_path = os.path.join(output_files["directory"], cleanup_file)
            shutil.move(cleanup_file, dest_path)
            print(f"{Colors.YELLOW}[!] Moved stray file {cleanup_file} to output directory{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.RED}[!] Could not move stray file {cleanup_file}: {str(e)}{Colors.ENDC}")
    
    print_section_header(f"Reconnaissance Complete: {target}", verbosity)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Interrupted by user. Exiting...{Colors.ENDC}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.RED}[!] Unhandled error: {str(e)}{Colors.ENDC}")
        sys.exit(1)

