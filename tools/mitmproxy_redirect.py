"""
mitmproxy script to redirect Rust Console Edition localhost requests.

Usage:
    mitmproxy -s mitmproxy_redirect.py
    or
    mitmdump -s mitmproxy_redirect.py

Redirects: http://localhost/* -> http://192.168.0.111:9000/*
"""

from mitmproxy import http
from mitmproxy.proxy.layers import tls
import os

TARGET_HOST = "192.168.0.111"
TARGET_PORT = 9000


# Load blocked domains from hosts.txt
BLOCKED_DOMAINS = set()

def load_blocked_domains():
    """Load domains from hosts.txt file"""
    global BLOCKED_DOMAINS
    hosts_path = os.path.join(os.path.dirname(__file__), "hosts.txt")
    
    try:
        with open(hosts_path, "r") as f:
            for line in f:
                line = line.strip()
                # Skip empty lines and comments
                if line and not line.startswith("#"):
                    # Extract domain (handle format: "0.0.0.0 domain.com" or just "domain.com")
                    parts = line.split()
                    domain = parts[-1] if parts else line
                    BLOCKED_DOMAINS.add(domain.lower())
        print(f"[+] Loaded {len(BLOCKED_DOMAINS)} blocked domains from hosts.txt")
    except FileNotFoundError:
        print(f"[!] WARNING: hosts.txt not found at {hosts_path}")
    except Exception as e:
        print(f"[!] ERROR loading hosts.txt: {e}")

# Load domains when script initializes
load_blocked_domains()

def is_blocked(hostname: str) -> bool:
    """Check if hostname matches any blocked domain"""
    hostname_lower = hostname.lower()
    for blocked in BLOCKED_DOMAINS:
        if blocked in hostname_lower:
            return True
    return False

def tls_clienthello(data: tls.ClientHelloData) -> None:
    if data.context.server.address:
        hostname = data.context.server.address[0]
        
        # Block domains at TLS layer
        if is_blocked(hostname):
            raise ConnectionRefusedError(f"[*] Blocked HTTPS connection to: {hostname}")

def request(flow: http.HTTPFlow) -> None:
    # Block other domains from hosts.txt
    if is_blocked(hostname):
        flow.response = http.Response.make( 
            404,
            b"uwu",
        )
        print(f"[*] Blocked HTTP request to: {hostname}")
        return

    
    if flow.request.host == "localhost" or flow.request.host == "127.0.0.1":
        original = f"{flow.request.host}:{flow.request.port}{flow.request.path}"
        flow.request.host = TARGET_HOST
        flow.request.port = TARGET_PORT
        print(f"[REDIRECT] {original} -> {TARGET_HOST}:{TARGET_PORT}{flow.request.path}")
