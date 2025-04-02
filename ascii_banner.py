#!/usr/bin/env python3
"""
ASCII Art Banner Module for DSINT Tool
"""

import random
from typing import Dict, List, Optional

# ANSI color codes
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    ENDC = '\033[0m'

# Banners collection with raw strings to avoid escape sequence issues
BANNERS = {
    "standard": f'''
{Colors.CYAN}██████╗{Colors.BLUE} ███████╗{Colors.MAGENTA}██╗███╗   ██╗████████╗{Colors.YELLOW}    ████████╗ ██████╗  ██████╗ ██╗     
{Colors.CYAN}██╔══██╗{Colors.BLUE}██╔════╝{Colors.MAGENTA}██║████╗  ██║╚══██╔══╝{Colors.YELLOW}    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     
{Colors.CYAN}██║  ██║{Colors.BLUE}███████╗{Colors.MAGENTA}██║██╔██╗ ██║   ██║   {Colors.YELLOW}       ██║   ██║   ██║██║   ██║██║     
{Colors.CYAN}██║  ██║{Colors.BLUE}╚════██║{Colors.MAGENTA}██║██║╚██╗██║   ██║   {Colors.YELLOW}       ██║   ██║   ██║██║   ██║██║     
{Colors.CYAN}██████╔╝{Colors.BLUE}███████║{Colors.MAGENTA}██║██║ ╚████║   ██║   {Colors.YELLOW}       ██║   ╚██████╔╝╚██████╔╝███████╗
{Colors.CYAN}╚═════╝ {Colors.BLUE}╚══════╝{Colors.MAGENTA}╚═╝╚═╝  ╚═══╝   ╚═╝   {Colors.YELLOW}       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝
{Colors.GREEN}╔═══════════════════════════════════════════════════════════════════════════╗
║  {Colors.WHITE}{Colors.BOLD}Domain & Subdomain Intelligence Tool{Colors.ENDC}{Colors.GREEN}                                     ║
║  {Colors.WHITE}Advanced reconnaissance for security researchers{Colors.GREEN}                         ║
╚═══════════════════════════════════════════════════════════════════════════╝{Colors.ENDC}
''',

    "minimal": f'''
{Colors.BLUE}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ {Colors.MAGENTA}██████╗ ███████╗██╗███╗   ██╗████████╗{Colors.BLUE} ┃ {Colors.YELLOW}████████╗ ██████╗  ██████╗ ██╗     {Colors.BLUE} ┃
┃ {Colors.MAGENTA}██╔══██╗██╔════╝██║████╗  ██║╚══██╔══╝{Colors.BLUE} ┃ {Colors.YELLOW}╚══██╔══╝██╔═══██╗██╔═══██╗██║     {Colors.BLUE} ┃
┃ {Colors.MAGENTA}██║  ██║███████╗██║██╔██╗ ██║   ██║   {Colors.BLUE} ┃ {Colors.YELLOW}   ██║   ██║   ██║██║   ██║██║     {Colors.BLUE} ┃
┃ {Colors.MAGENTA}██║  ██║╚════██║██║██║╚██╗██║   ██║   {Colors.BLUE} ┃ {Colors.YELLOW}   ██║   ██║   ██║██║   ██║██║     {Colors.BLUE} ┃
┃ {Colors.MAGENTA}██████╔╝███████║██║██║ ╚████║   ██║   {Colors.BLUE} ┃ {Colors.YELLOW}   ██║   ╚██████╔╝╚██████╔╝███████╗{Colors.BLUE} ┃
┃ {Colors.MAGENTA}╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝   {Colors.BLUE} ┃ {Colors.YELLOW}   ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝{Colors.BLUE} ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ {Colors.GREEN}              Domain & Subdomain Intelligence Toolkit {Colors.WHITE}v1.0{Colors.BLUE}                   ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛{Colors.ENDC}
''',
    
    "simple": fr'''
{Colors.BOLD}{Colors.CYAN}
    ____  ____ ___ _   _ _____   _____  ___   ___  _     
   |  _ \/ ___|_ _| \ | |_   _| |_   _|/ _ \ / _ \| |    
   | | | \___ \| ||  \| | | |     | | | | | | | | | |    
   | |_| |___) | || |\  | | |     | | | |_| | |_| | |___ 
   |____/|____/___|_| \_| |_|     |_|  \___/ \___/|_____|
                                                     
{Colors.ENDC}{Colors.GREEN}╔════════════════════════════════════════════════════════════════╗
║  {Colors.WHITE}Domain & Subdomain Intelligence Toolkit{Colors.GREEN}                       ║
║  {Colors.WHITE}Comprehensive OSINT for domain reconnaissance{Colors.GREEN}                 ║
╚════════════════════════════════════════════════════════════════╝{Colors.ENDC}
'''
}

def get_random_banner() -> str:
    """Return a random banner from the collection."""
    return random.choice(list(BANNERS.values()))

def get_banner(style: Optional[str] = None) -> str:
    """
    Return the requested banner style or default to 'standard'.
    
    Args:
        style: The style of banner to return ('standard', 'minimal', 'simple')
        
    Returns:
        The banner as a formatted string
    """
    if style and style in BANNERS:
        return BANNERS[style]
    return BANNERS["standard"]

if __name__ == "__main__":
    # Test all banners when run directly
    for name, banner in BANNERS.items():
        print(f"Banner style: {name}")
        print(banner)
        print("\n" + "="*80 + "\n")
