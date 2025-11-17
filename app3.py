from flask import Flask, request, jsonify, render_template, send_file
import pandas as pd
import joblib
import json
import os
from werkzeug.utils import secure_filename
import threading
import time
import socket
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

print("Loading model and rules...")
rf_model = joblib.load('models/rf_apriori_model.joblib')
with open('models/apriori_rules.json', 'r') as f:
    apriori_rules = json.load(f)
print("Model loaded successfully!")
kbd = joblib.load("models/kbd_discretizer.joblib")
model_features = joblib.load("models/model_features.joblib")


live_monitoring = {
    'active': False,
    'predictions': [],
    'capture_mode': 'idle',
    'error_message': '',
    'stats': {
        'total_packets': 0,
        'normal_count': 0,
        'attack_count': 0,
        'start_time': None,
        'websites': {},
        'recent_alerts': []
    }
}

# CACHE FOR HOSTNAME LOOKUPS
hostname_cache = {}
hostname_cache_lock = threading.Lock()

SERVICE_MAP = {
    80: 'http', 443: 'https', 21: 'ftp', 22: 'ssh',
    23: 'telnet', 25: 'smtp', 53: 'domain', 110: 'pop3',
    143: 'imap', 3306: 'mysql', 5432: 'postgresql',
    8080: 'http-alt', 3389: 'rdp'
}

def get_hostname_cached(ip):
    """Get hostname with caching to avoid slow lookups"""
    # Check cache first
    with hostname_cache_lock:
        if ip in hostname_cache:
            return hostname_cache[ip]
    
    # Try to resolve
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        # Cache the result
        with hostname_cache_lock:
            hostname_cache[ip] = hostname
        return hostname
    except:
        # Cache the failure too (use IP as hostname)
        with hostname_cache_lock:
            hostname_cache[ip] = ip
        return ip

def cleanup_old_connections(connection_stats, max_age_seconds=300):
    """Remove connections older than max_age_seconds (default 5 minutes)"""
    current_time = time.time()
    to_remove = []
    
    for conn_key, stats in connection_stats.items():
        if current_time - stats['first_seen'] > max_age_seconds:
            to_remove.append(conn_key)
    
    for key in to_remove:
        del connection_stats[key]
    
    if to_remove:
        print(f"[CLEANUP] Removed {len(to_remove)} old connections")

def parse_tcp_flags(packet):
    """Parse actual TCP flags from packet"""
    try:
        from scapy.all import TCP
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            flags = tcp.flags
            
            # Convert flags to readable format
            if flags == 0x02:  # SYN
                return 'S0'
            elif flags == 0x12:  # SYN-ACK
                return 'S1'
            elif flags == 0x14:  # RST-ACK
                return 'REJ'
            elif flags == 0x18:  # PSH-ACK
                return 'SF'
            elif flags == 0x11:  # FIN-ACK
                return 'SF'
            else:
                return 'SF'
        return 'SF'
    except:
        return 'SF'

def preprocess_input(data):
    """
    Preprocess input data to match the EXACT training pipeline:
    1. Discretize continuous features with KBinsDiscretizer
    2. One-hot encode categorical features
    3. Apply Apriori rules to create rule-based features
    4. Align with saved model features
    """
    df = pd.DataFrame([data] if isinstance(data, dict) else data)
    
    # =====================================================
    # STEP 1: DISCRETIZE CONTINUOUS FEATURES WITH KBD
    # =====================================================
    continuous_features = ['duration', 'src_bytes', 'dst_bytes', 'count', 'srv_count']
    
    # Ensure all continuous features exist
    for col in continuous_features:
        if col not in df.columns:
            df[col] = 0
    
    # Apply KBinsDiscretizer (this bins the values into categories)
    try:
        df_continuous = df[continuous_features].copy()
        df_discretized = kbd.transform(df_continuous)
        
        # Create new column names for binned features
        for i, col in enumerate(continuous_features):
            df[f'{col}_bin'] = df_discretized[:, i]
        
        # Keep original features too (model might use both)
        # df[continuous_features] = df_discretized
        
    except Exception as e:
        print(f"[WARNING] Discretization failed: {e}")
        # Fallback: create bin columns with value 0
        for col in continuous_features:
            df[f'{col}_bin'] = 0
    
    # =====================================================
    # STEP 2: ONE-HOT ENCODE CATEGORICAL FEATURES
    # =====================================================
    categorical_cols = ['protocol_type', 'service', 'flag']
    for col in categorical_cols:
        if col in df.columns:
            df[col] = df[col].astype(str)
    
    df_encoded = pd.get_dummies(df, columns=categorical_cols)
    
    # =====================================================
    # STEP 3: APPLY APRIORI RULES (CREATE RULE FEATURES)
    # =====================================================
    # Rules format: {"antecedents": ["flag=SF", "srv_count_bin=1", "protocol_type=tcp"]}
    # We need to check if conditions match and create binary features
    
    for idx, rule in enumerate(apriori_rules):
        try:
            antecedents = rule.get('antecedents', [])
            
            # Check if ALL antecedent conditions are met
            rule_matches = True
            
            for antecedent in antecedents:
                # Parse the antecedent string: "flag=SF" -> column="flag", value="SF"
                if '=' not in antecedent:
                    rule_matches = False
                    break
                
                col_name, col_value = antecedent.split('=', 1)
                
                # Check if this condition is satisfied
                # For one-hot encoded: check if "flag_SF" column exists and equals 1
                if '_bin' in col_name:
                    # This is a binned feature like "srv_count_bin=1"
                    one_hot_col = f"{col_name}"
                    if one_hot_col in df_encoded.columns:
                        if df_encoded[one_hot_col].iloc[0] != float(col_value):
                            rule_matches = False
                            break
                    else:
                        rule_matches = False
                        break
                else:
                    # This is a categorical feature like "protocol_type=tcp"
                    # After one-hot encoding it becomes "protocol_type_tcp"
                    one_hot_col = f"{col_name}_{col_value}"
                    
                    if one_hot_col in df_encoded.columns:
                        if df_encoded[one_hot_col].iloc[0] == 0:
                            rule_matches = False
                            break
                    else:
                        rule_matches = False
                        break
            
            # Create binary feature for this rule
            rule_feature_name = f"apriori_rule_{idx}"
            df_encoded[rule_feature_name] = 1 if rule_matches else 0
            
        except Exception as e:
            print(f"[WARNING] Rule {idx} processing failed: {e}")
            # Create feature with 0 to avoid missing columns
            df_encoded[f"apriori_rule_{idx}"] = 0
            continue
    
    # =====================================================
    # STEP 4: ALIGN WITH SAVED MODEL FEATURES
    # =====================================================
    # The model expects EXACT features it was trained on
    # Add missing columns with 0s, keep only model features
    
    missing_cols = set(model_features) - set(df_encoded.columns)
    if missing_cols:
        for col in missing_cols:
            df_encoded[col] = 0
    
    # Keep only the features the model expects, in the correct order
    df_encoded = df_encoded[model_features]
    
    return df_encoded

def capture_real_packets():
    """Capture REAL network traffic with IMPROVED Windows interface detection"""
    global live_monitoring
    
    try:
        from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list, conf
        import psutil  # Add this import at top of file
        
        print("\n" + "="*70)
        print("🔴 STARTING REAL PACKET CAPTURE - IMPROVED VERSION")
        print("="*70)
        
        # IMPROVED WINDOWS INTERFACE DETECTION
        try:
            print("🔍 Detecting active network interface...")
            
            # Get active network connections using psutil
            active_interface = None
            net_if_stats = psutil.net_if_stats()
            net_if_addrs = psutil.net_if_addrs()
            
            # Find interface with active connection
            for iface_name, stats in net_if_stats.items():
                if stats.isup:  # Interface is UP
                    # Check if it has a valid IP (not loopback)
                    if iface_name in net_if_addrs:
                        for addr in net_if_addrs[iface_name]:
                            if addr.family == 2:  # AF_INET (IPv4)
                                ip = addr.address
                                # Skip loopback and invalid IPs
                                if not ip.startswith('127.') and not ip.startswith('169.254.'):
                                    active_interface = iface_name
                                    print(f"✅ Found active interface: {iface_name} (IP: {ip})")
                                    break
                if active_interface:
                    break
            
            if not active_interface:
                print("⚠️ No active interface found, using default...")
                interface = None
            else:
                # Try to match with Scapy interface names
                scapy_interfaces = get_if_list()
                print(f"📡 Scapy interfaces: {scapy_interfaces}")
                
                # On Windows, try to find matching device
                interface = None
                for scapy_iface in scapy_interfaces:
                    # Match by name or use default
                    if 'Loopback' not in scapy_iface:
                        interface = scapy_iface
                        print(f"✅ Using Scapy interface: {interface}")
                        break
                
                # If still no match, use None (default)
                if not interface:
                    print("⚠️ Using system default interface")
                    interface = None
                    
        except Exception as e:
            print(f"⚠️ Interface detection failed: {e}")
            print("📡 Using default interface...")
            interface = None
        
        print("🔍 Initializing capture...")
        
        live_monitoring['capture_mode'] = 'real'
        live_monitoring['stats']['start_time'] = time.time()
        
        connection_stats = {}
        packet_count = [0]
        last_cleanup = [time.time()]
        
        def process_packet(packet):
            """Process each captured packet with improved error handling"""
            if not live_monitoring['active']:
                return
            
            try:
                # Only process IP packets
                if not packet.haslayer(IP):
                    return
                
                packet_count[0] += 1
                live_monitoring['stats']['total_packets'] += 1
                
                ip_layer = packet[IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                length = len(packet)
                
                # Skip localhost traffic
                if src_ip.startswith('127.') or dst_ip.startswith('127.'):
                    return
                
                # Determine protocol and ports
                protocol = 'other'
                src_port = 0
                dst_port = 0
                flag = 'SF'
                
                if packet.haslayer(TCP):
                    protocol = 'tcp'
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    flag = parse_tcp_flags(packet)
                elif packet.haslayer(UDP):
                    protocol = 'udp'
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                elif packet.haslayer(ICMP):
                    protocol = 'icmp'
                
                service = SERVICE_MAP.get(dst_port, 'other')
                
                # BIDIRECTIONAL TRACKING
                conn_key = f"{src_ip}:{dst_ip}:{dst_port}"
                reverse_key = f"{dst_ip}:{src_ip}:{src_port}"
                
                if conn_key not in connection_stats:
                    connection_stats[conn_key] = {
                        'count': 0,
                        'src_bytes': 0,
                        'dst_bytes': 0,
                        'first_seen': time.time()
                    }
                
                connection_stats[conn_key]['count'] += 1
                connection_stats[conn_key]['src_bytes'] += length
                
                dst_bytes = 0
                if reverse_key in connection_stats:
                    dst_bytes = connection_stats[reverse_key]['src_bytes']
                
                duration = int(time.time() - connection_stats[conn_key]['first_seen'])
                
                # Prepare data for ML model
                packet_data = {
                    'duration': duration,
                    'protocol_type': protocol,
                    'service': service,
                    'flag': flag,
                    'src_bytes': connection_stats[conn_key]['src_bytes'],
                    'dst_bytes': dst_bytes,
                    'count': connection_stats[conn_key]['count'],
                    'srv_count': len([k for k in connection_stats.keys() if str(dst_port) in k])
                }
                
                # Predict if attack or normal
                X = preprocess_input(packet_data)
                prediction = rf_model.predict(X)[0]
                probability = rf_model.predict_proba(X)[0]
                
                is_attack = prediction == 1
                
                if is_attack:
                    live_monitoring['stats']['attack_count'] += 1
                else:
                    live_monitoring['stats']['normal_count'] += 1
                
                hostname = get_hostname_cached(dst_ip)
                
                if hostname not in live_monitoring['stats']['websites']:
                    live_monitoring['stats']['websites'][hostname] = {
                        'packets': 0,
                        'attacks': 0,
                        'normal': 0,
                        'last_seen': time.time(),
                        'ip': dst_ip,
                        'service': service
                    }
                
                live_monitoring['stats']['websites'][hostname]['packets'] += 1
                live_monitoring['stats']['websites'][hostname]['last_seen'] = time.time()
                
                if is_attack:
                    live_monitoring['stats']['websites'][hostname]['attacks'] += 1
                else:
                    live_monitoring['stats']['websites'][hostname]['normal'] += 1
                
                result = {
                    'timestamp': time.time(),
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'hostname': hostname,
                    'protocol_type': protocol,
                    'service': service,
                    'flag': flag,
                    'src_port': str(src_port),
                    'dst_port': str(dst_port),
                    'length': length,
                    'prediction': 'Attack' if is_attack else 'Normal',
                    'probability': float(probability[1]),
                    'count': connection_stats[conn_key]['count']
                }
                
                live_monitoring['predictions'].append(result)
                
                if len(live_monitoring['predictions']) > 100:
                    live_monitoring['predictions'].pop(0)
                
                if is_attack and probability[1] > 0.7:
                    alert = {
                        'timestamp': time.time(),
                        'type': 'Suspicious Activity',
                        'source': src_ip,
                        'destination': hostname,
                        'severity': 'HIGH' if probability[1] > 0.9 else 'MEDIUM',
                        'probability': float(probability[1]),
                        'details': f"{protocol.upper()} connection to {hostname}:{dst_port}"
                    }
                    live_monitoring['stats']['recent_alerts'].append(alert)
                    
                    if len(live_monitoring['stats']['recent_alerts']) > 10:
                        live_monitoring['stats']['recent_alerts'].pop(0)
                
                # Console output every 10 packets
                if packet_count[0] % 10 == 0:
                    status = '⚠️ ATTACK' if is_attack else '✅ NORMAL'
                    print(f"[PACKET] #{packet_count[0]} | {hostname} [{protocol}:{dst_port}] {status} ({probability[1]*100:.1f}%)")
                
                if time.time() - last_cleanup[0] > 60:
                    cleanup_old_connections(connection_stats)
                    last_cleanup[0] = time.time()
                    
            except Exception as e:
                print(f"[ERROR] Packet processing failed: {e}")
        
        def stop_filter(packet):
            return not live_monitoring['active']
        
        print(f"✅ LIVE CAPTURE ACTIVE")
        print("💡 Browse websites to see REAL traffic!")
        print("🔧 Now capturing on ALL interfaces (promiscuous mode)")
        print("="*70 + "\n")
        
        # SIMPLIFIED: Just sniff without interface specification (captures all)
        sniff(prn=process_packet, stop_filter=stop_filter, store=False)
        
        print("\n🛑 Real capture stopped\n")
        
    except ImportError as e:
        live_monitoring['capture_mode'] = 'error'
        live_monitoring['error_message'] = f'Missing module: {e}. Run: pip install scapy psutil'
        print(f"\n❌ Import error: {e}")
        print("   Install: pip install scapy psutil")
    except PermissionError:
        live_monitoring['capture_mode'] = 'error'
        live_monitoring['error_message'] = 'Permission denied! Run CMD as Administrator'
        print("\n❌ Permission denied!")
        print("   Windows: Run CMD as Administrator")
    except Exception as e:
        live_monitoring['capture_mode'] = 'error'
        live_monitoring['error_message'] = f'Capture error: {str(e)}'
        print(f"\n❌ Capture failed: {e}")
        import traceback
        traceback.print_exc()

        
        def process_packet(packet):
            """Process each captured packet with improved error handling"""
            if not live_monitoring['active']:
                return
            
            try:
                # Only process IP packets
                if not packet.haslayer(IP):
                    return
                
                packet_count[0] += 1
                live_monitoring['stats']['total_packets'] += 1
                
                ip_layer = packet[IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                length = len(packet)
                
                # Skip localhost traffic
                if src_ip.startswith('127.') or dst_ip.startswith('127.'):
                    return
                
                # Determine protocol and ports
                protocol = 'other'
                src_port = 0
                dst_port = 0
                flag = 'SF'
                
                if packet.haslayer(TCP):
                    protocol = 'tcp'
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    flag = parse_tcp_flags(packet)  # Parse real TCP flags
                elif packet.haslayer(UDP):
                    protocol = 'udp'
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                elif packet.haslayer(ICMP):
                    protocol = 'icmp'
                
                service = SERVICE_MAP.get(dst_port, 'other')
                
                # BIDIRECTIONAL TRACKING
                conn_key = f"{src_ip}:{dst_ip}:{dst_port}"
                reverse_key = f"{dst_ip}:{src_ip}:{src_port}"
                
                # Initialize connection stats
                if conn_key not in connection_stats:
                    connection_stats[conn_key] = {
                        'count': 0,
                        'src_bytes': 0,
                        'dst_bytes': 0,
                        'first_seen': time.time()
                    }
                
                connection_stats[conn_key]['count'] += 1
                connection_stats[conn_key]['src_bytes'] += length
                
                # Track reverse direction (destination bytes)
                dst_bytes = 0
                if reverse_key in connection_stats:
                    dst_bytes = connection_stats[reverse_key]['src_bytes']
                
                duration = int(time.time() - connection_stats[conn_key]['first_seen'])
                
                # Prepare data for ML model
                packet_data = {
                    'duration': duration,
                    'protocol_type': protocol,
                    'service': service,
                    'flag': flag,
                    'src_bytes': connection_stats[conn_key]['src_bytes'],
                    'dst_bytes': dst_bytes,  # Now tracks bidirectional!
                    'count': connection_stats[conn_key]['count'],
                    'srv_count': len([k for k in connection_stats.keys() if str(dst_port) in k])
                }
                
                # Predict if attack or normal
                X = preprocess_input(packet_data)
                prediction = rf_model.predict(X)[0]
                probability = rf_model.predict_proba(X)[0]
                
                is_attack = prediction == 1
                
                if is_attack:
                    live_monitoring['stats']['attack_count'] += 1
                else:
                    live_monitoring['stats']['normal_count'] += 1
                
                # Get hostname with caching
                hostname = get_hostname_cached(dst_ip)
                
                # Track websites
                if hostname not in live_monitoring['stats']['websites']:
                    live_monitoring['stats']['websites'][hostname] = {
                        'packets': 0,
                        'attacks': 0,
                        'normal': 0,
                        'last_seen': time.time(),
                        'ip': dst_ip,
                        'service': service
                    }
                
                live_monitoring['stats']['websites'][hostname]['packets'] += 1
                live_monitoring['stats']['websites'][hostname]['last_seen'] = time.time()
                
                if is_attack:
                    live_monitoring['stats']['websites'][hostname]['attacks'] += 1
                else:
                    live_monitoring['stats']['websites'][hostname]['normal'] += 1
                
                # Create result
                result = {
                    'timestamp': time.time(),
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'hostname': hostname,
                    'protocol_type': protocol,
                    'service': service,
                    'flag': flag,
                    'src_port': str(src_port),
                    'dst_port': str(dst_port),
                    'length': length,
                    'prediction': 'Attack' if is_attack else 'Normal',
                    'probability': float(probability[1]),
                    'count': connection_stats[conn_key]['count']
                }
                
                live_monitoring['predictions'].append(result)
                
                # Keep only last 100 packets
                if len(live_monitoring['predictions']) > 100:
                    live_monitoring['predictions'].pop(0)
                
                # Create alerts for suspicious activity
                if is_attack and probability[1] > 0.7:
                    alert = {
                        'timestamp': time.time(),
                        'type': 'Suspicious Activity',
                        'source': src_ip,
                        'destination': hostname,
                        'severity': 'HIGH' if probability[1] > 0.9 else 'MEDIUM',
                        'probability': float(probability[1]),
                        'details': f"{protocol.upper()} connection to {hostname}:{dst_port}"
                    }
                    live_monitoring['stats']['recent_alerts'].append(alert)
                    
                    if len(live_monitoring['stats']['recent_alerts']) > 10:
                        live_monitoring['stats']['recent_alerts'].pop(0)
                
                # Console output every 10 packets
                if packet_count[0] % 10 == 0:
                    status = '⚠️ ATTACK' if is_attack else '✅ NORMAL'
                    iface_name = interface if interface else "default"
                    print(f"[{iface_name}] #{packet_count[0]} | {hostname} [{protocol}:{dst_port}] {status} ({probability[1]*100:.1f}%)")
                
                # Periodic cleanup (every 60 seconds)
                if time.time() - last_cleanup[0] > 60:
                    cleanup_old_connections(connection_stats)
                    last_cleanup[0] = time.time()
                    
            except Exception as e:
                # Log errors instead of silently failing
                print(f"[ERROR] Packet processing failed: {e}")
        
        def stop_filter(packet):
            """Stop sniffing when monitoring is disabled"""
            return not live_monitoring['active']
        
        print(f"✅ LIVE CAPTURE ACTIVE")
        if interface:
            print(f"📡 Interface: {interface}")
        print("💡 Browse websites to see REAL traffic!")
        print("🔧 Improvements: Auto-detect interface, hostname cache, bidirectional tracking, TCP flag parsing")
        print("="*70 + "\n")
        
        # Start sniffing
        if interface:
            sniff(iface=interface, prn=process_packet, stop_filter=stop_filter, store=False)
        else:
            sniff(prn=process_packet, stop_filter=stop_filter, store=False)
        
        print("\n🛑 Real capture stopped\n")
        
    except ImportError:
        live_monitoring['capture_mode'] = 'error'
        live_monitoring['error_message'] = 'Scapy not installed. Run: pip install scapy'
        print("\n❌ Scapy not installed!")
        print("   Install: pip install scapy")
    except PermissionError:
        live_monitoring['capture_mode'] = 'error'
        live_monitoring['error_message'] = 'Permission denied! Run CMD as Administrator (Windows) or use sudo (Linux)'
        print("\n❌ Permission denied!")
        print("   Windows: Run CMD as Administrator")
        print("   Linux/Mac: Use sudo python app.py")
    except Exception as e:
        live_monitoring['capture_mode'] = 'error'
        live_monitoring['error_message'] = f'Capture error: {str(e)}'
        print(f"\n❌ Capture failed: {e}")
        import traceback
        traceback.print_exc()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict_single():
    try:
        data = request.json
        
        required_fields = ['duration', 'protocol_type', 'service', 'flag', 
                          'src_bytes', 'dst_bytes', 'count', 'srv_count']
        
        missing = [f for f in required_fields if f not in data]
        if missing:
            return jsonify({'error': f'Missing fields: {missing}'}), 400
        
        X = preprocess_input(data)
        prediction = rf_model.predict(X)[0]
        probability = rf_model.predict_proba(X)[0]
        
        result = {
            'prediction': 'Attack' if prediction == 1 else 'Normal',
            'attack_probability': float(probability[1]),
            'normal_probability': float(probability[0]),
            'confidence': float(max(probability)),
            'input_data': data
        }
        
        return jsonify(result)
    
    except Exception as e:
        print(f"[ERROR] Prediction failed: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/predict_csv', methods=['POST'])
def predict_csv():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not file.filename.endswith('.csv'):
            return jsonify({'error': 'File must be CSV'}), 400
        
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        df = pd.read_csv(filepath)
        
        required_cols = ['duration', 'protocol_type', 'service', 'flag', 
                        'src_bytes', 'dst_bytes', 'count', 'srv_count']
        missing_cols = [c for c in required_cols if c not in df.columns]
        
        if missing_cols:
            os.remove(filepath)
            return jsonify({'error': f'Missing columns: {missing_cols}'}), 400
        
        X = preprocess_input(df)
        predictions = rf_model.predict(X)
        probabilities = rf_model.predict_proba(X)
        
        df['prediction'] = ['Attack' if p == 1 else 'Normal' for p in predictions]
        df['attack_probability'] = probabilities[:, 1]
        df['confidence'] = probabilities.max(axis=1)
        
        output_filename = f'results_{filename}'
        output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)
        df.to_csv(output_path, index=False)
        
        summary = {
            'total_records': len(df),
            'attacks_detected': int((predictions == 1).sum()),
            'normal_connections': int((predictions == 0).sum()),
            'avg_attack_probability': float(probabilities[:, 1].mean()),
            'download_file': output_filename
        }
        
        os.remove(filepath)
        return jsonify(summary)
    
    except Exception as e:
        print(f"[ERROR] CSV processing failed: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/download/<filename>')
def download_file(filename):
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    return send_file(filepath, as_attachment=True)

@app.route('/start_monitoring', methods=['POST'])
def start_monitoring():
    global live_monitoring
    
    if live_monitoring['active']:
        return jsonify({'message': 'Monitoring already active'})
    
    live_monitoring['active'] = True
    live_monitoring['predictions'] = []
    live_monitoring['capture_mode'] = 'starting'
    live_monitoring['error_message'] = ''
    live_monitoring['stats'] = {
        'total_packets': 0,
        'normal_count': 0,
        'attack_count': 0,
        'start_time': time.time(),
        'websites': {},
        'recent_alerts': []
    }
    
    # Clear hostname cache on new session
    global hostname_cache
    hostname_cache.clear()
    
    thread = threading.Thread(target=capture_real_packets, daemon=True)
    thread.start()
    
    return jsonify({'message': 'Starting real packet capture with improvements...'})

@app.route('/stop_monitoring', methods=['POST'])
def stop_monitoring():
    global live_monitoring
    live_monitoring['active'] = False
    time.sleep(1)
    live_monitoring['capture_mode'] = 'idle'
    return jsonify({'message': 'Monitoring stopped'})

@app.route('/get_dashboard', methods=['GET'])
def get_dashboard():
    try:
        stats = {
            'total_packets': live_monitoring['stats'].get('total_packets', 0),
            'normal_count': live_monitoring['stats'].get('normal_count', 0),
            'attack_count': live_monitoring['stats'].get('attack_count', 0),
            'start_time': live_monitoring['stats'].get('start_time'),
            'websites': live_monitoring['stats'].get('websites', {}),
            'recent_alerts': live_monitoring['stats'].get('recent_alerts', []),
            'capture_mode': live_monitoring.get('capture_mode', 'idle'),
            'error_message': live_monitoring.get('error_message', '')
        }
        
        if stats['start_time']:
            uptime_seconds = int(time.time() - stats['start_time'])
            stats['uptime'] = f"{uptime_seconds // 60}m {uptime_seconds % 60}s"
        else:
            stats['uptime'] = "0m 0s"
        
        websites = stats['websites']
        top_websites = sorted(
            websites.items(),
            key=lambda x: x[1]['packets'],
            reverse=True
        )[:10]
        
        stats['top_websites'] = [
            {
                'hostname': hostname,
                'packets': data['packets'],
                'attacks': data['attacks'],
                'normal': data['normal'],
                'status': 'SAFE' if data['attacks'] == 0 else 'SUSPICIOUS',
                'ip': data.get('ip', 'unknown'),
                'service': data.get('service', 'unknown')
            }
            for hostname, data in top_websites
        ]
        
        if stats['total_packets'] > 0:
            safety_score = (stats['normal_count'] / stats['total_packets']) * 100
            stats['safety_score'] = round(safety_score, 1)
            
            if safety_score > 95:
                stats['status'] = 'PROTECTED'
            elif safety_score > 80:
                stats['status'] = 'WARNING'
            else:
                stats['status'] = 'ALERT'
        else:
            stats['safety_score'] = 100.0
            stats['status'] = 'IDLE'
        
        del stats['websites']
        del stats['start_time']
        
        return jsonify(stats), 200
        
    except Exception as e:
        print(f"[ERROR] Dashboard update failed: {e}")
        return jsonify({
            'total_packets': 0,
            'normal_count': 0,
            'attack_count': 0,
            'uptime': '0m 0s',
            'status': 'IDLE',
            'safety_score': 100.0,
            'top_websites': [],
            'recent_alerts': [],
            'capture_mode': 'idle',
            'error_message': ''
        }), 200

@app.route('/get_live_data', methods=['GET'])
def get_live_data():
    try:
        return jsonify({
            'active': live_monitoring['active'],
            'predictions': live_monitoring['predictions'][-20:],
            'capture_mode': live_monitoring.get('capture_mode', 'idle'),
            'error_message': live_monitoring.get('error_message', '')
        }), 200
    except Exception as e:
        print(f"[ERROR] Live data fetch failed: {e}")
        return jsonify({
            'active': False,
            'predictions': [],
            'capture_mode': 'idle',
            'error_message': str(e)
        }), 200

@app.route('/health')
def health():
    return jsonify({'status': 'healthy', 'model_loaded': True})

if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    print("\n" + "="*70)
    print("🚀 Network Intrusion Detection System - IMPROVED VERSION")
    print("="*70)
    print("📍 Access at: http://localhost:5000")
    print("🔴 REAL packet capture using SCAPY")
    print("✨ NEW: Auto interface detection, hostname caching, bidirectional tracking")
    print("⚠️  MUST run CMD as Administrator!")
    print("="*70 + "\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False, threaded=True)