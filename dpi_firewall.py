from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, UDP, Raw, IPv6
from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.record import TLS
import re
import hashlib
import time

BLOCKED_IPS = [
    "8.8.8.8",
    "192.168.1.100"
]

BLOCKED_PORTS = [
    22,
    23,
    8080
]

MALICIOUS_REGEX_PATTERNS = [
    re.compile(r"UNION SELECT", re.IGNORECASE),
    re.compile(r"<script>alert\(", re.IGNORECASE),
    re.compile(r"exec\s+\(", re.IGNORECASE),
    re.compile(r"(\.\.\/){2,}", re.IGNORECASE),
    re.compile(r"wget\s+http", re.IGNORECASE),
    re.compile(r"powershell\.exe", re.IGNORECASE),
    re.compile(r"nc\s+-l", re.IGNORECASE),
]

KNOWN_MALICIOUS_JA3_HASHES = [
    "60c73e03126780ee6df54162e071ff1e",
    "e270e5b7c7b897f903a45a6c11b0e386",
    "0f878a2e128147d3d23d8393e25b62b1",
    "73b87968e7b172a27572352882a98f1f",
    "f18830113f98e7bb664cc0854d9b626e",
    "9bf75c324c0e6e8e84d4b267104b281f",
]

FRAGMENT_BUFFER = {}
FRAGMENT_TIMEOUT = 5

def calculate_ja3_hash(tls_client_hello_layer):
    try:
        tls_version = int(tls_client_hello_layer.version) if hasattr(tls_client_hello_layer, 'version') else 0
        ciphers = sorted([int(c) for c in tls_client_hello_layer.ciphers]) if hasattr(tls_client_hello_layer, 'ciphers') and tls_client_hello_layer.ciphers else []
        extensions_types = []
        elliptic_curves = []
        elliptic_curve_point_formats = []

        if hasattr(tls_client_hello_layer, 'ext') and tls_client_hello_layer.ext:
            for ext in tls_client_hello_layer.ext:
                if hasattr(ext, 'type'):
                    extensions_types.append(int(ext.type))
                if ext.type == 10 and hasattr(ext, 'groups'):
                    elliptic_curves = sorted([int(g) for g in ext.groups])
                elif ext.type == 11 and hasattr(ext, 'ecpl'):
                    elliptic_curve_point_formats = sorted([int(p) for p in ext.ecpl])
        
        extensions_types = sorted(list(set(extensions_types)))

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

def packet_handler(pkt):
    current_time = time.time()
    try:
        scapy_packet = IP(pkt.get_payload())
    except Exception as e:
        print(f"[-] Error parsing packet payload with Scapy: {e}")
        pkt.accept()
        return

    if scapy_packet.flags & 0x1 or scapy_packet.frag != 0:
        print(f"[*] Detected IP fragment: ID={scapy_packet.id}, Offset={scapy_packet.frag}, Flags={scapy_packet.flags}")
        keys_to_remove = [k for k, v in FRAGMENT_BUFFER.items() if current_time - v['timestamp'] > FRAGMENT_TIMEOUT]
        for k in keys_to_remove:
            print(f"[-] Discarding timed-out fragments for ID: {k[2]}")
            del FRAGMENT_BUFFER[k]

        frag_key = (scapy_packet[IP].src, scapy_packet[IP].dst, scapy_packet.id)
        if frag_key not in FRAGMENT_BUFFER:
            FRAGMENT_BUFFER[frag_key] = {'fragments': [], 'timestamp': current_time}
        
        FRAGMENT_BUFFER[frag_key]['fragments'].append(scapy_packet)
        FRAGMENT_BUFFER[frag_key]['timestamp'] = current_time

        if scapy_packet.frag == 0:
            if scapy_packet.len < 28:
                print(f"BLOCKING (Fragmentation): Detected tiny first fragment (len={scapy_packet.len}) for ID {scapy_packet.id}.")
                pkt.drop()
                del FRAGMENT_BUFFER[frag_key]
                return

        pkt.accept()
        return

    print(f"\n--- New Packet ({pkt.id}) ---")
    scapy_packet.show()

    src_ip = scapy_packet[IP].src if IP in scapy_packet else "N/A"
    dst_ip = scapy_packet[IP].dst if IP in scapy_packet else "N/A"
    proto = scapy_packet[IP].proto if IP in scapy_packet else "N/A"

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

    if payload:
        try:
            decoded_payload = payload.decode('utf-8', errors='ignore')
            for pattern in MALICIOUS_REGEX_PATTERNS:
                if pattern.search(decoded_payload):
                    print(f"BLOCKING (DPI-Regex): Malicious pattern '{pattern.pattern}' detected in payload.")
                    pkt.drop()
                    return
        except Exception as e:
            print(f"[-] Error decoding payload for regex search: {e}")

    if proto == "TCP" and (dst_port == 80 or src_port == 80):
        try:
            http_data = payload.decode('utf-8', errors='ignore')
            if http_data.startswith("GET ") or http_data.startswith("POST ") or \
               http_data.startswith("HTTP/"):
                print("[*] Detected HTTP traffic.")
                if "User-Agent: Nikto" in http_data:
                    print("BLOCKING (DPI-HTTP): Detected Nikto User-Agent.")
                    pkt.drop()
                    return
                if "/admin/login.php?user=" in http_data and "password=" in http_data:
                    print("BLOCKING (DPI-HTTP): Suspicious login attempt pattern.")
                    pkt.drop()
                    return
        except Exception as e:
            print(f"[-] Error parsing HTTP payload: {e}")

    if TLSClientHello in scapy_packet:
        print("[*] Detected TLS Client Hello handshake.")
        try:
            ja3_hash = calculate_ja3_hash(scapy_packet[TLSClientHello])
            if ja3_hash:
                print(f"[*] Calculated JA3 Hash: {ja3_hash}")
                if ja3_hash in KNOWN_MALICIOUS_JA3_HASHES:
                    print(f"BLOCKING (JA3): Detected known malicious JA3 hash: {ja3_hash}")
                    pkt.drop()
                    return
            else:
                print("[-] JA3 hash calculation failed for this packet.")
        except Exception as e:
            print(f"[-] Error in JA3 processing: {e}")
    elif TLS in scapy_packet:
        print("[*] Detected other TLS traffic.")

    print(f"ACCEPTING packet from {src_ip}:{src_port} to {dst_ip}:{dst_port}.")
    pkt.accept()

def run_firewall():
    from scapy.all import load_layer
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
        print("[*] sudo iptables -A OUTPUT -j NFQUEUE --queue-num 0")
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