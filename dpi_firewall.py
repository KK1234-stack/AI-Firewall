# dpi_firewall.py

from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, UDP, Raw, IPv6
from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.record import TLS # TLS record layer from scapy.all import IP, TCP, UDP, Raw, IPv6, TLS, TLSClientHello # Added TLS for future JA3
import re # For regex pattern matching

# --- Configuration: Define your blocking rules and DPI patterns ---

# Basic IP and Port Filtering Rules
BLOCKED_IPS = [
    "8.8.8.8",         # Example: Google Public DNS
    "192.168.1.100"    # Example: A specific internal IP
]

BLOCKED_PORTS = [
    22,    # SSH
    23,    # Telnet
    8080   # Common proxy/web server port
]

# DPI: Malicious Regex Patterns
# These patterns will be searched within the packet's payload
MALICIOUS_REGEX_PATTERNS = [
    re.compile(r"UNION SELECT", re.IGNORECASE),          # Basic SQL Injection
    re.compile(r"<script>alert\(", re.IGNORECASE),       # Basic XSS
    re.compile(r"exec\s+\(", re.IGNORECASE),             # Command Execution Attempt
    re.compile(r"(\.\.\/){2,}", re.IGNORECASE),           # Directory Traversal
    re.compile(r"wget\s+http", re.IGNORECASE),           # Malicious download attempt
    re.compile(r"powershell\.exe", re.IGNORECASE),       # Windows PowerShell execution
    re.compile(r"nc\s+-l", re.IGNORECASE),               # Netcat listener attempt
    # Add more as you identify common attack signatures
]

# JA3: Known Malicious JA3 Hashes (Conceptual for now, will be populated later)
# These are hashes derived from TLS Client Hello packets of known malicious clients
KNOWN_MALICIOUS_JA3_HASHES = [
    # "d41d8cd98f00b204e9800998ecf8427e", # Example placeholder hash
]


# --- Packet Handling Function ---
def packet_handler(pkt):
    """
    This function is called for every packet redirected to our NetfilterQueue.
    It inspects the packet with DPI capabilities and decides whether to accept or drop it.
    """
    
    # Get the raw payload and convert to Scapy packet
    try:
        scapy_packet = IP(pkt.get_payload())
    except Exception as e:
        # If Scapy can't parse, log and accept to avoid blocking legitimate traffic
        print(f"[-] Error parsing packet payload with Scapy: {e}")
        pkt.accept()
        return

    print(f"\n--- New Packet ({pkt.id}) ---")
    scapy_packet.show() # Display detailed packet layers

    # Extract common network info
    src_ip = scapy_packet[IP].src if IP in scapy_packet else "N/A"
    dst_ip = scapy_packet[IP].dst if IP in scapy_packet else "N/A"
    proto = scapy_packet[IP].proto if IP in scapy_packet else "N/A" # Protocol number (e.g., 6 for TCP, 17 for UDP)

    src_port = None
    dst_port = None
    if TCP in scapy_packet:
        src_port = scapy_packet[TCP].sport
        dst_port = scapy_packet[TCP].dport
        proto = "TCP"
    elif UDP in scapy_packet:
        src_port = scapy_packet[UDP].sport
        dst_port = scapy_packet[UDP].dport
        proto = "UDP"

    payload = b""
    if scapy_packet.haslayer(Raw):
        payload = scapy_packet[Raw].load

    # --- Phase 1: Basic IP and Port Filtering (Moved from basic_firewall.py) ---
    if src_ip in BLOCKED_IPS:
        print(f"BLOCKING (IP): Source IP {src_ip} is on the blacklist.")
        pkt.drop()
        return
    if dst_ip in BLOCKED_IPS:
        print(f"BLOCKING (IP): Destination IP {dst_ip} is on the blacklist.")
        pkt.drop()
        return

    if src_port in BLOCKED_PORTS and (proto == "TCP" or proto == "UDP"):
        print(f"BLOCKING (Port): Source {proto} Port {src_port} is on the blacklist.")
        pkt.drop()
        return
    if dst_port in BLOCKED_PORTS and (proto == "TCP" or proto == "UDP"):
        print(f"BLOCKING (Port): Destination {proto} Port {dst_port} is on the blacklist.")
        pkt.drop()
        return

    # --- Phase 2: DPI - Aggressive Pattern Matching (Regex) ---
    if payload:
        try:
            decoded_payload = payload.decode('utf-8', errors='ignore') # Decode for regex search
            for pattern in MALICIOUS_REGEX_PATTERNS:
                if pattern.search(decoded_payload):
                    print(f"BLOCKING (DPI-Regex): Malicious pattern '{pattern.pattern}' detected in payload.")
                    pkt.drop()
                    return # Drop and exit handler
        except Exception as e:
            print(f"[-] Error decoding payload for regex search: {e}")

    # --- Phase 2: DPI - Basic HTTP Payload Parsing ---
    # This is a very simplistic HTTP detection. For robust parsing, consider dedicated libraries.
    if proto == "TCP" and (dst_port == 80 or src_port == 80): # Standard HTTP port
        try:
            http_data = payload.decode('utf-8', errors='ignore')
            if http_data.startswith("GET ") or http_data.startswith("POST ") or \
               http_data.startswith("HTTP/"): # Basic check for HTTP request/response
                print("[*] Detected HTTP traffic.")
                # Example: Block specific User-Agents or suspicious paths
                if "User-Agent: Nikto" in http_data: # Nikto is a web server scanner
                    print("BLOCKING (DPI-HTTP): Detected Nikto User-Agent.")
                    pkt.drop()
                    return
                if "/admin/login.php?user=" in http_data and "password=" in http_data:
                    print("BLOCKING (DPI-HTTP): Suspicious login attempt pattern.")
                    pkt.drop()
                    return
        except Exception as e:
            print(f"[-] Error parsing HTTP payload: {e}")

    # --- Phase 2: DPI - JA3 TLS Fingerprinting (Conceptual/Placeholder) ---
    # This is a more advanced part and often requires deeper TLS protocol understanding.
    # Scapy can parse some TLS layers, but for full JA3 calculation, it's complex without specialized tools.
    # We will expand on this when we actually implement JA3.
    if TLS in scapy_packet or (proto == "TCP" and (dst_port == 443 or src_port == 443)):
        # Check if it's a TLS Client Hello message (simplified check)
        if scapy_packet.haslayer(TLSClientHello):
            print("[*] Detected TLS Client Hello handshake.")
            # In a real scenario, you'd extract fields and compute JA3 hash here.
            # Example (conceptual):
            # ja3_hash = calculate_ja3_from_scapy_tls_client_hello(scapy_packet[TLSClientHello])
            # if ja3_hash in KNOWN_MALICIOUS_JA3_HASHES:
            #     print(f"BLOCKING (JA3): Detected known malicious JA3 hash: {ja3_hash}")
            #     pkt.drop()
            #     return
            print("[*] JA3 Fingerprinting logic needs full implementation in Phase 2 advanced.")


    # If no blocking rules are matched, accept the packet
    print(f"ACCEPTING packet from {src_ip}:{src_port} to {dst_ip}:{dst_port}.")
    pkt.accept()

# --- Main Firewall Execution Logic ---
def run_firewall():
    nfqueue = NetfilterQueue()
    try:
        nfqueue.bind(0, packet_handler)
        print("[*] DPI Firewall started, listening on NetfilterQueue 0...")
        print("[*] Ensure iptables rules are set: sudo iptables -A INPUT -j NFQUEUE --queue-num 0")
        print("[*]                                sudo iptables -A OUTPUT -j NFQUEUE --queue-num 0")
        print("[*] Press Ctrl+C to stop.")
        nfqueue.run()
    except KeyboardInterrupt:
        print("\n[*] DPI Firewall stopped by user.")
    except Exception as e:
        print(f"[!] An error occurred: {e}")
    finally:
        nfqueue.unbind()
        print("[*] NetfilterQueue unbound.")

if __name__ == "__main__":
    run_firewall()
