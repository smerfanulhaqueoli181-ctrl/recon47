"""
modules/banner.py — ASCII art banner
"""

from .utils import Colors


BANNER = r"""
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝ 
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗ 
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝
"""

SUBTITLE = "  Automated Reconnaissance & Vulnerability Scanner"
VERSION  = "  v1.0.0  |  For authorized use only"
DIVIDER  = "  " + "─" * 54


def print_banner():
    print(f"{Colors.RED}{Colors.BOLD}{BANNER}{Colors.RESET}")
    print(f"{Colors.YELLOW}{Colors.BOLD}{SUBTITLE}{Colors.RESET}")
    print(f"{Colors.DIM}{VERSION}{Colors.RESET}")
    print(f"{Colors.DIM}{DIVIDER}{Colors.RESET}")
    print()
