# dpi_firewall.py - Corrected extract_ml_features

from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, UDP, Raw, IPv6
from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.record import TLS
import re
import hashlib
import time
import joblib
import numpy as np
import pandas as pd
import math  # Make sure this is imported at the top level for calculate_entropy

# --- Configuration (unchanged) ---
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

# --- ML Model Global Variables (Loaded at Firewall Startup) ---
RF_MODEL = None
LR_MODEL = None
SCALER = None

# This MUST be the exact list and order of features your ML models were trained on.
# Copied directly from your train_firewall_model.py output.
ML_FEATURE_COLUMNS = [
    'Dst Port', 'Protocol', 'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts', 'TotLen Fwd Pkts', 'TotLen Bwd Pkts',
    'Fwd Pkt Len Max', 'Fwd Pkt Len Min', 'Fwd Pkt Len Mean', 'Fwd Pkt Len Std', 'Bwd Pkt Len Max', 'Bwd Pkt Len Min',
    'Bwd Pkt Len Mean', 'Bwd Pkt Len Std', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
    'Fwd IAT Tot', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Tot', 'Bwd IAT Mean',
    'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags',
    'Fwd Header Len', 'Bwd Header Len', 'Pkt Len Min', 'Pkt Len Max', 'Pkt Len Mean', 'Pkt Len Std', 'Pkt Len Var',
    'FIN Flag Cnt', 'SYN Flag Cnt', 'RST Flag Cnt', 'PSH Flag Cnt', 'ACK Flag Cnt', 'URG Flag Cnt', 'CWE Flag Count',
    'ECE Flag Cnt', 'Down/Up Ratio', 'Pkt Size Avg', 'Fwd Seg Size Avg', 'Bwd Seg Size Avg', 'Fwd Byts/b Avg',
    'Fwd Pkts/b Avg', 'Fwd Blk Rate Avg', 'Bwd Byts/b Avg', 'Bwd Pkts/b Avg', 'Bwd Blk Rate Avg', 'Init Fwd Win Byts',
    'Init Bwd Win Byts', 'Fwd Act Data Pkts', 'Fwd Seg Size Min', 'Active Mean', 'Active Std', 'Active Max',
    'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
]

# --- Helper Functions (unchanged) ---


def calculate_ja3_hash(tls_client_hello_layer):
    try:
        tls_version = int(tls_client_hello_layer.version) if hasattr(
            tls_client_hello_layer, 'version') else 0
        ciphers = sorted([int(c) for c in tls_client_hello_layer.ciphers]) if hasattr(
            tls_client_hello_layer, 'ciphers') and tls_client_hello_layer.ciphers else []
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
                    elliptic_curve_point_formats = sorted(
                        [int(p) for p in ext.ecpl])

        extensions_types = sorted(list(set(extensions_types)))

        ja3_str = []
        ja3_str.append(str(tls_version))
        ja3_str.append("-".join(str(c) for c in ciphers))
        ja3_str.append("-".join(str(t) for t in extensions_types))
        ja3_str.append("-".join(str(ec) for ec in elliptic_curves))
        ja3_str.append("-".join(str(ecpf)
                       for ecpf in elliptic_curve_point_formats))

        final_ja3_string = ",".join(ja3_str)
        ja3_hash = hashlib.md5(final_ja3_string.encode('ascii')).hexdigest()
        return ja3_hash
    except Exception as e:
        print(f"[-] Error in calculate_ja3_hash: {e}")
        return None


def calculate_entropy(data):
    if not data:
        return 0.0
    frequencies = {}
    for byte in data:
        frequencies[byte] = frequencies.get(byte, 0) + 1
    entropy = 0
    data_len = len(data)
    for freq in frequencies.values():
        p = float(freq) / data_len
        entropy -= p * math.log2(p)
    return entropy


def load_ml_models():
    """Loads the trained ML models and scaler from disk."""
    global RF_MODEL, LR_MODEL, SCALER
    MODEL_DIR = './trained_models'
    try:
        RF_MODEL = joblib.load(os.path.join(
            MODEL_DIR, 'random_forest_model.pkl'))
        LR_MODEL = joblib.load(os.path.join(
            MODEL_DIR, 'logistic_regression_model.pkl'))
        SCALER = joblib.load(os.path.join(MODEL_DIR, 'scaler.pkl'))
        print("[*] ML models and scaler loaded successfully.")
    except Exception as e:
        print(
            f"[!] Error loading ML models: {e}. ML detection will be disabled.")
        RF_MODEL = None
        LR_MODEL = None
        SCALER = None

# --- CRITICALLY UPDATED extract_ml_features function ---


def extract_ml_features(scapy_packet):
    """
    Extracts numerical features from a Scapy packet, matching the format
    expected by the trained ML models. This function must mirror the
    preprocessing logic in train_firewall_model.py exactly.

    Note: Many features are flow-based (e.g., Flow Duration, IATs, Tot Fwd Pkts).
    For a single packet, these will be approximated or set to 0.0/1.0.
    The model's accuracy on real-time single packets will depend on how
    much it relies on these flow-based features vs. packet-level ones.
    """
    # Initialize all features to 0.0 using a Pandas Series for easy column management
    features_dict = {col: 0.0 for col in ML_FEATURE_COLUMNS}

    # Extract IP-layer features
    if IP in scapy_packet:
        features_dict['Protocol'] = scapy_packet[IP].proto
        features_dict['Fwd Header Len'] = scapy_packet[IP].ihl * 4
        features_dict['Pkt Len Min'] = scapy_packet[IP].len
        features_dict['Pkt Len Max'] = scapy_packet[IP].len
        features_dict['Pkt Len Mean'] = scapy_packet[IP].len
        features_dict['Pkt Len Std'] = 0.0
        features_dict['Pkt Len Var'] = 0.0

        # Simple single-packet approximations for flow-based counts/lengths
        features_dict['Tot Fwd Pkts'] = 1.0  # This packet
        features_dict['TotLen Fwd Pkts'] = scapy_packet[IP].len
        features_dict['Fwd Pkt Len Max'] = scapy_packet[IP].len
        features_dict['Fwd Pkt Len Min'] = scapy_packet[IP].len
        features_dict['Fwd Pkt Len Mean'] = scapy_packet[IP].len

        # Initial window bytes are from TCP/UDP, other packet lengths are also based on payload

        # For flow duration and IATs, in a single-packet context, they are often 0 or very small
        # The model was trained on dataset-derived flow durations, so these are approximations.
        features_dict['Flow Duration'] = 0.0
        features_dict['Flow IAT Mean'] = 0.0
        features_dict['Flow IAT Std'] = 0.0
        features_dict['Flow IAT Max'] = 0.0
        features_dict['Flow IAT Min'] = 0.0
        features_dict['Fwd IAT Tot'] = 0.0
        features_dict['Fwd IAT Mean'] = 0.0
        features_dict['Fwd IAT Std'] = 0.0
        features_dict['Fwd IAT Max'] = 0.0
        features_dict['Fwd IAT Min'] = 0.0
        features_dict['Bwd IAT Tot'] = 0.0
        features_dict['Bwd IAT Mean'] = 0.0
        features_dict['Bwd IAT Std'] = 0.0
        features_dict['Bwd IAT Max'] = 0.0
        features_dict['Bwd IAT Min'] = 0.0

        # Other header lengths (Bwd Header Len) are 0 for a forward-only packet
        features_dict['Bwd Header Len'] = 0.0

    # Extract TCP/UDP layer features
    if TCP in scapy_packet:
        features_dict['Dst Port'] = scapy_packet[TCP].dport
        # TCP Flags
        features_dict['FIN Flag Cnt'] = 1.0 if scapy_packet[TCP].flags.F else 0.0
        features_dict['SYN Flag Cnt'] = 1.0 if scapy_packet[TCP].flags.S else 0.0
        features_dict['RST Flag Cnt'] = 1.0 if scapy_packet[TCP].flags.R else 0.0
        features_dict['PSH Flag Cnt'] = 1.0 if scapy_packet[TCP].flags.P else 0.0
        features_dict['ACK Flag Cnt'] = 1.0 if scapy_packet[TCP].flags.A else 0.0
        features_dict['URG Flag Cnt'] = 1.0 if scapy_packet[TCP].flags.U else 0.0
        features_dict['CWE Flag Count'] = 1.0 if scapy_packet[TCP].flags.C else 0.0
        features_dict['ECE Flag Cnt'] = 1.0 if scapy_packet[TCP].flags.E else 0.0
        # Initial Window Bytes
        features_dict['Init Fwd Win Byts'] = scapy_packet[TCP].window

        # Fwd Act Data Pkts for TCP payload
        features_dict['Fwd Act Data Pkts'] = 1.0 if scapy_packet[TCP].payload else 0.0
        features_dict['Fwd Seg Size Min'] = len(
            scapy_packet[TCP].payload) if scapy_packet[TCP].payload else 0.0  # Min segment size from this packet

    elif UDP in scapy_packet:
        features_dict['Dst Port'] = scapy_packet[UDP].dport
        # UDP does not have the flag or window features
        # Assuming Fwd Act Data Pkts is 1 if UDP has payload
        features_dict['Fwd Act Data Pkts'] = 1.0 if scapy_packet[UDP].payload else 0.0
        features_dict['Fwd Seg Size Min'] = len(
            scapy_packet[UDP].payload) if scapy_packet[UDP].payload else 0.0

    # Raw Payload Features
    if scapy_packet.haslayer(Raw):
        payload_load = scapy_packet[Raw].load
        # Approx. packet size average for this packet
        features_dict['Pkt Size Avg'] = len(payload_load)
        # features_dict['payload_entropy'] = calculate_entropy(payload_load) # Add if you implement entropy, ensure 'payload_entropy' is in ML_FEATURE_COLUMNS if used for training
        features_dict['TotLen Fwd Pkts'] = features_dict.get(
            'TotLen Fwd Pkts', 0.0) + len(payload_load)  # Add payload length to total length

    # Down/Up Ratio (can only be known in context of a flow, set to 0 or 1 for single packet)
    # Placeholder, for a single forward packet, ratio is not meaningful
    features_dict['Down/Up Ratio'] = 0.0

    # Fill other flow-based features which are 0 for a single packet
    # These often include: Tot Bwd Pkts, TotLen Bwd Pkts, Bwd Pkt Len Max/Min/Mean/Std
    # Fwd/Bwd Byts/b Avg, Pkts/b Avg, Blk Rate Avg, Init Bwd Win Byts
    # Active/Idle Mean/Std/Max/Min
    for col in features_dict.keys():
        if col not in features_dict:  # Ensure no key errors if col not found, though dict comprehension above covers
            features_dict[col] = 0.0

    # Convert to pandas Series first to ensure correct feature names/order before converting to numpy
    features_series = pd.Series(
        features_dict, index=ML_FEATURE_COLUMNS, dtype=float)

    # --- Replicate the NaN/Inf handling from training ---
    features_series.replace([np.inf, -np.inf], np.nan, inplace=True)
    features_series.fillna(0.0, inplace=True)  # Fill any NaNs with 0.0

    # Return as a 2D numpy array (1 sample, N features)
    return features_series.values.reshape(1, -1)


# --- Packet Handling Function (rest of it unchanged) ---
def packet_handler(pkt):
    current_time = time.time()
    try:
        scapy_packet = IP(pkt.get_payload())
    except Exception as e:
        print(f"[-] Error parsing packet payload with Scapy: {e}")
        pkt.accept()
        return

    # --- Fragmentation Handling ---
    if scapy_packet.flags & 0x1 or scapy_packet.frag != 0:
        print(
            f"[*] Detected IP fragment: ID={scapy_packet.id}, Offset={scapy_packet.frag}, Flags={scapy_packet.flags}")

        keys_to_remove = [k for k, v in FRAGMENT_BUFFER.items(
        ) if current_time - v['timestamp'] > FRAGMENT_TIMEOUT]
        for k in keys_to_remove:
            print(f"[-] Discarding timed-out fragments for ID: {k[2]}")
            del FRAGMENT_BUFFER[k]

        frag_key = (scapy_packet[IP].src,
                    scapy_packet[IP].dst, scapy_packet.id)
        if frag_key not in FRAGMENT_BUFFER:
            FRAGMENT_BUFFER[frag_key] = {
                'fragments': [], 'timestamp': current_time}

        FRAGMENT_BUFFER[frag_key]['fragments'].append(scapy_packet)
        FRAGMENT_BUFFER[frag_key]['timestamp'] = current_time

        if scapy_packet.frag == 0:
            if scapy_packet.len < 28:
                print(
                    f"BLOCKING (Fragmentation): Detected tiny first fragment (len={scapy_packet.len}) for ID {scapy_packet.id}.")
                pkt.drop()
                del FRAGMENT_BUFFER[frag_key]
                return

        pkt.accept()
        return

    print(f"\n--- New Packet ({pkt.id}) ---")
    scapy_packet.show()

    src_ip = scapy_packet[IP].src if IP in scapy_packet else "N/A"
    dst_ip = scapy_packet[IP].dst if IP in scapy_packet else "N/A"
    proto_num = scapy_packet[IP].proto if IP in scapy_packet else "N/A"

    src_port = None
    dst_port = None
    proto_name = "N/A"

    if TCP in scapy_packet:
        src_port = scapy_packet[TCP].sport
        dst_port = scapy_packet[TCP].dport
        proto_name = "TCP"
    elif UDP in scapy_packet:
        src_port = scapy_packet[UDP].sport
        dst_port = scapy_packet[UDP].dport
        proto_name = "UDP"

    payload_bytes = b""
    if scapy_packet.haslayer(Raw):
        payload_bytes = scapy_packet[Raw].load

    # --- Phase 1: Basic IP and Port Filtering ---
    if src_ip in BLOCKED_IPS:
        print(f"BLOCKING (IP): Source IP {src_ip} is on the blacklist.")
        pkt.drop()
        return
    if dst_ip in BLOCKED_IPS:
        print(f"BLOCKING (IP): Destination IP {dst_ip} is on the blacklist.")
        pkt.drop()
        return

    if src_port in BLOCKED_PORTS and (proto_name == "TCP" or proto_name == "UDP"):
        print(
            f"BLOCKING (Port): Source {proto_name} Port {src_port} is on the blacklist.")
        pkt.drop()
        return
    if dst_port in BLOCKED_PORTS and (proto_name == "TCP" or proto_name == "UDP"):
        print(
            f"BLOCKING (Port): Destination {proto_name} Port {dst_port} is on the blacklist.")
        pkt.drop()
        return

    # --- Phase 2: DPI - Aggressive Pattern Matching (Regex) ---
    if payload_bytes:
        try:
            decoded_payload = payload_bytes.decode('utf-8', errors='ignore')
            for pattern in MALICIOUS_REGEX_PATTERNS:
                if pattern.search(decoded_payload):
                    print(
                        f"BLOCKING (DPI-Regex): Malicious pattern '{pattern.pattern}' detected in payload.")
                    pkt.drop()
                    return
        except Exception as e:
            print(f"[-] Error decoding payload for regex search: {e}")

    # --- Phase 2: DPI - Basic HTTP Payload Parsing ---
    if proto_name == "TCP" and (dst_port == 80 or src_port == 80):
        try:
            http_data = payload_bytes.decode('utf-8', errors='ignore')
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

    # --- Phase 2: DPI - JA3 TLS Fingerprinting ---
    if TLSClientHello in scapy_packet:
        print("[*] Detected TLS Client Hello handshake.")
        try:
            ja3_hash = calculate_ja3_hash(scapy_packet[TLSClientHello])
            if ja3_hash:
                print(f"[*] Calculated JA3 Hash: {ja3_hash}")
                if ja3_hash in KNOWN_MALICIOUS_JA3_HASHES:
                    print(
                        f"BLOCKING (JA3): Detected known malicious JA3 hash: {ja3_hash}")
                    pkt.drop()
                    return
            else:
                print("[-] JA3 hash calculation failed for this packet.")
        except Exception as e:
            print(f"[-] Error in JA3 processing: {e}")
    elif TLS in scapy_packet:
        print("[*] Detected other TLS traffic.")

    # --- Phase 3: AI/ML Model Prediction ---
    ml_prediction = "N/A"
    if RF_MODEL and LR_MODEL and SCALER:
        try:
            features_array = extract_ml_features(scapy_packet)

            # Predict with Random Forest
            rf_pred = RF_MODEL.predict(features_array)[0]
            rf_pred_label = "MALICIOUS" if rf_pred == 1 else "BENIGN"

            # Predict with Logistic Regression (requires scaling)
            features_scaled = SCALER.transform(features_array)
            lr_pred = LR_MODEL.predict(features_scaled)[0]
            lr_pred_label = "MALICIOUS" if lr_pred == 1 else "BENIGN"

            print(f"[*] ML Prediction: RF={rf_pred_label}, LR={lr_pred_label}")

            # Define ML blocking policy: Block if either model predicts malicious
            if rf_pred == 1 or lr_pred == 1:
                print(
                    "BLOCKING (ML): At least one ML model predicted malicious traffic.")
                pkt.drop()
                return

        except Exception as e:
            print(f"[!] Error during ML prediction: {e}. Accepting packet.")
            # If ML fails, default to accepting to avoid false positives
    else:
        print("[*] ML models not loaded or available. Skipping ML prediction.")

    # If no blocking rules or ML predictions matched, accept the packet
    print(f"ACCEPTING packet from {src_ip}:{src_port} to {dst_ip}:{dst_port}.")
    pkt.accept()


# --- Main Firewall Execution Logic (unchanged) ---
def run_firewall():
    from scapy.all import load_layer
    try:
        load_layer("tls")
        print("[*] Scapy TLS layer loaded successfully for JA3.")
    except Exception as e:
        print(
            f"[-] Warning: Could not load Scapy TLS layer: {e}. TLS/JA3 features might not work correctly.")

    load_ml_models()

    nfqueue = NetfilterQueue()
    try:
        nfqueue.bind(0, packet_handler)
        print("[*] AI-Enhanced DPI Firewall started, listening on NetfilterQueue 0...")
        print(
            "[*] Ensure iptables rules are set: sudo iptables -A INPUT -j NFQUEUE --queue-num 0")
        print(
            "[*]                                sudo iptables -A OUTPUT -j NFQUEUE --queue-num 0")
        print("[*] Press Ctrl+C to stop.")
        nfqueue.run()
    except KeyboardInterrupt:
        print("\n[*] AI-Enhanced DPI Firewall stopped by user.")
    except Exception as e:
        print(f"[!] An error occurred in main firewall loop: {e}")
    finally:
        nfqueue.unbind()
        print("[*] NetfilterQueue unbound.")


if __name__ == "__main__":
    run_firewall()
