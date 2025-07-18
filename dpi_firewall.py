# dpi_firewall.py

from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, UDP, Raw, IPv6 # Keep essential Scapy layers
from scapy.layers.tls.handshake import TLSClientHello # Specific import for ClientHello
from scapy.layers.tls.record import TLS # Specific import for TLS record layer
import re # For regex pattern matching
import hashlib # For MD5 hash calculation (for JA3)

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
    # "2835f8d66572f8a8474d22165f1712a3", # Example: Placeholder for a known malware JA3 (replace with real ones!)
    # "0c9304953997f7d45f7457a4143a41b5", # Another placeholder
]

# --- Helper function to calculate JA3 hash from a Scapy TLSClientHello layer ---
def calculate_ja3_hash(tls_client_hello_layer):
    """
    Calculates the JA3 hash from a Scapy TLSClientHello layer.
    This implementation tries to be accurate but might need adjustments for
    all edge cases of Scapy's TLS parsing.
    """
    try:
        tls_version = int(tls_client_hello_layer.version) if hasattr(tls_client_hello_layer, 'version') else 0
        
        # Cipher Suites (sorted numerically)
        ciphers = sorted([int(c) for c in tls_client_hello_layer.ciphers]) if hasattr(tls_client_hello_layer, 'ciphers') and tls_client_hello_layer.ciphers else []

        # Extensions: Extract relevant data for JA3
        extensions_types = []
        elliptic_curves = []
        elliptic_curve_point_formats = []

        if hasattr(tls_client_hello_layer, 'ext') and tls_client_hello_layer.ext:
            for ext in tls_client_hello_layer.ext:
                if hasattr(ext, 'type'):
                    extensions_types.append(int(ext.type))
                
                # Check for Supported Groups (Elliptic Curves) extension - type 10
                if ext.type == 10 and hasattr(ext, 'groups'):
                    elliptic_curves = sorted([int(g) for g in ext.groups])
                
                # Check for EC Point Formats extension - type 11
                elif ext.type == 11 and hasattr(ext, 'ecpl'):
                    elliptic_curve_point_formats = sorted([int(p) for p in ext.ecpl])
        
        # Sort extension types numerically
        extensions_types = sorted(list(set(extensions_types))) # Use set to handle potential duplicates, then sort

        # Construct the JA3 components string
        ja3_str = []
        ja3_str.append(str(tls_version))
        ja3_str.append("-".join(str(c) for c in ciphers))
        ja3_str.append("-".join(str(t) for t in extensions_types))
        ja3_str.append("-".join(str(ec) for ec in elliptic_curves))
        ja3_str.append("-".join(str(ecpf) for ecpf in elliptic_curve_point_formats))

        final_ja3_string = ",".join(ja3_str)
        ja3_hash = hashlib.md5(final_ja3_string.encode('ascii')).hexdigest()
        return ja3_hash
    except Exception as e:
        print(f"[-] Error in calculate_ja3_hash: {e}")
        return None


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

    # --- Phase 1: Basic IP and Port Filtering ---
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
    if proto == "TCP" and (dst_port == 80 or src_port == 80): # Standard HTTP port
        try:
            http_data = payload.decode('utf-8', errors='ignore')
            if http_data.startswith("GET ") or http_data.startswith("POST ") or \
               http_data.startswith("HTTP/"): # Basic check for HTTP request/response
                print("[*] Detected HTTP traffic.")
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

    # --- Phase 2: DPI - JA3 TLS Fingerprinting ---
    # Scapy's TLS layers must be loaded for TLSClientHello to be recognized.
    # This is done by load_layer("tls") in run_firewall().
    if TLSClientHello in scapy_packet: # Check specifically for the Client Hello layer
        print("[*] Detected TLS Client Hello handshake.")
        try:
            ja3_hash = calculate_ja3_hash(scapy_packet[TLSClientHello])
            if ja3_hash: # Only proceed if hash was calculated successfully
                print(f"[*] Calculated JA3 Hash: {ja3_hash}")
                if ja3_hash in KNOWN_MALICIOUS_JA3_HASHES:
                    print(f"BLOCKING (JA3): Detected known malicious JA3 hash: {ja3_hash}")
                    pkt.drop()
                    return
            else:
                print("[-] JA3 hash calculation failed for this packet.")
        except Exception as e:
            print(f"[-] Error in JA3 processing: {e}")
            # Decide: accept or drop on error? Generally accept to not block good traffic
    elif TLS in scapy_packet: # Other TLS records (not ClientHello)
        print("[*] Detected other TLS traffic.")

    # If no blocking rules are matched, accept the packet
    print(f"ACCEPTING packet from {src_ip}:{src_port} to {dst_ip}:{dst_port}.")
    pkt.accept()


# --- Main Firewall Execution Logic ---
def run_firewall():
    # IMPORTANT: Load the TLS layer for Scapy to recognize TLS packets
    from scapy.all import load_layer # Import load_layer specifically here
    try:
        load_layer("tls")
        print("[*] Scapy TLS layer loaded successfully for JA3.")
    except Exception as e:
        print(f"[-] Warning: Could not load Scapy TLS layer: {e}. TLS/JA3 features might not work correctly.")

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