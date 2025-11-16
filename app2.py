from flask import Flask, request, jsonify, render_template, send_file
import pandas as pd
import joblib
import json
import os
from werkzeug.utils import secure_filename
import threading
import time
import socket

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

print("Loading model and rules...")
rf_model = joblib.load('models/rf_apriori_model.joblib')
with open('models/apriori_rules.json', 'r') as f:
    apriori_rules = json.load(f)
print("Model loaded successfully!")

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

SERVICE_MAP = {
    80: 'http', 443: 'https', 21: 'ftp', 22: 'ssh',
    23: 'telnet', 25: 'smtp', 53: 'domain', 110: 'pop3',
    143: 'imap', 3306: 'mysql', 5432: 'postgresql',
    8080: 'http-alt', 3389: 'rdp'
}

def get_hostname(ip):
    """Try to resolve IP to hostname"""
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return ip

def get_friendly_name(hostname, ip):
    """Convert hostname/IP to friendly website name"""
    hostname_lower = hostname.lower()
    
    # Popular websites mapping
    website_map = {
        'youtube': 'YouTube',
        'googlevideo': 'YouTube',
        'ytimg': 'YouTube',
        'google': 'Google',
        'gstatic': 'Google',
        'googleapis': 'Google',
        'instagram': 'Instagram',
        'cdninstagram': 'Instagram',
        'facebook': 'Facebook',
        'fbcdn': 'Facebook',
        'whatsapp': 'WhatsApp',
        'twitter': 'Twitter (X)',
        'twimg': 'Twitter (X)',
        'reddit': 'Reddit',
        'redd': 'Reddit',
        'github': 'GitHub',
        'githubusercontent': 'GitHub',
        'stackoverflow': 'Stack Overflow',
        'stackexchange': 'Stack Exchange',
        'microsoft': 'Microsoft',
        'live': 'Microsoft',
        'bing': 'Bing',
        'amazon': 'Amazon',
        'amazonaws': 'Amazon AWS',
        'cloudflare': 'Cloudflare',
        'akamai': 'Akamai CDN',
        'netflix': 'Netflix',
        'nflxvideo': 'Netflix',
        'spotify': 'Spotify',
        'apple': 'Apple',
        'icloud': 'iCloud',
        'dropbox': 'Dropbox',
        'zoom': 'Zoom',
        'teams': 'Microsoft Teams',
        'slack': 'Slack',
        'discord': 'Discord',
        'telegram': 'Telegram',
        'tiktok': 'TikTok',
        'linkedin': 'LinkedIn',
        'pinterest': 'Pinterest',
        'tumblr': 'Tumblr',
        'yahoo': 'Yahoo',
        'wikipedia': 'Wikipedia',
        'wikimedia': 'Wikipedia',
        'twitch': 'Twitch',
        'nvidia': 'NVIDIA',
        'steam': 'Steam',
        'epicgames': 'Epic Games',
        'cloudfront': 'Amazon CloudFront',
        'oracle': 'Oracle',
        'adobe': 'Adobe',
        'paypal': 'PayPal',
        'ebay': 'eBay',
        'aliexpress': 'AliExpress',
        'alibaba': 'Alibaba',
        'flipkart': 'Flipkart',
        'myntra': 'Myntra',
        'hotstar': 'Hotstar',
        'primevideo': 'Amazon Prime Video',
        'jio': 'Jio',
        'airtel': 'Airtel',
        'paytm': 'Paytm',
        'zerodha': 'Zerodha',
        'chatgpt': 'ChatGPT',
        'openai': 'OpenAI',
        'claude': 'Claude AI',
        'anthropic': 'Anthropic',
        'gemini': 'Google Gemini'
    }
    
    # Check if hostname contains any known website
    for key, friendly_name in website_map.items():
        if key in hostname_lower:
            return friendly_name
    
    # If hostname is just an IP, return it
    if hostname == ip:
        return f"IP: {ip}"
    
    # Clean up hostname (remove www, subdomains for unknown sites)
    if hostname_lower.startswith('www.'):
        hostname = hostname[4:]
    
    # Extract main domain
    parts = hostname.split('.')
    if len(parts) >= 2:
        main_domain = parts[-2].capitalize()
        return main_domain
    
    return hostname

def preprocess_input(data):
    """Preprocess input data to match model features"""
    df = pd.DataFrame([data] if isinstance(data, dict) else data)
    
    categorical_cols = ['protocol_type', 'service', 'flag']
    for col in categorical_cols:
        if col in df.columns:
            df[col] = df[col].astype(str)
    
    df_encoded = pd.get_dummies(df, columns=categorical_cols)
    model_features = rf_model.feature_names_in_
    
    missing_cols = set(model_features) - set(df_encoded.columns)
    if missing_cols:
        for col in missing_cols:
            df_encoded[col] = 0
    
    df_encoded = df_encoded[model_features]
    return df_encoded

def capture_real_packets():
    """Capture REAL network traffic using SCAPY - NO EVENT LOOP ISSUES!"""
    global live_monitoring
    
    try:
        from scapy.all import sniff, IP, TCP, UDP, ICMP
        
        print("\n" + "="*70)
        print("🔴 STARTING REAL PACKET CAPTURE WITH SCAPY")
        print("="*70)
        
        print(f"📡 Interface: Wi-Fi")
        print("🔍 Initializing capture...")
        
        live_monitoring['capture_mode'] = 'real'
        live_monitoring['stats']['start_time'] = time.time()
        
        connection_stats = {}
        packet_count = [0]  # Use list to modify in nested function
        
        def process_packet(packet):
            """Process each captured packet"""
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
                
                # Determine protocol and ports
                protocol = 'other'
                src_port = 0
                dst_port = 0
                
                if packet.haslayer(TCP):
                    protocol = 'tcp'
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                elif packet.haslayer(UDP):
                    protocol = 'udp'
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                elif packet.haslayer(ICMP):
                    protocol = 'icmp'
                
                service = SERVICE_MAP.get(dst_port, 'other')
                flag = 'SF'
                
                # Connection tracking
                conn_key = f"{src_ip}:{dst_ip}:{dst_port}"
                if conn_key not in connection_stats:
                    connection_stats[conn_key] = {
                        'count': 0,
                        'bytes': 0,
                        'first_seen': time.time()
                    }
                connection_stats[conn_key]['count'] += 1
                connection_stats[conn_key]['bytes'] += length
                
                duration = int(time.time() - connection_stats[conn_key]['first_seen'])
                
                # Prepare data for ML model
                packet_data = {
                    'duration': duration,
                    'protocol_type': protocol,
                    'service': service,
                    'flag': flag,
                    'src_bytes': length,
                    'dst_bytes': 0,
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
                
                # Get hostname
                hostname = get_hostname(dst_ip)
                friendly_name = get_friendly_name(hostname, dst_ip)
                
                # Track websites using friendly name
                if friendly_name not in live_monitoring['stats']['websites']:
                    live_monitoring['stats']['websites'][friendly_name] = {
                        'packets': 0,
                        'attacks': 0,
                        'normal': 0,
                        'last_seen': time.time(),
                        'ip': dst_ip,
                        'service': service
                    }
                
                live_monitoring['stats']['websites'][friendly_name]['packets'] += 1
                live_monitoring['stats']['websites'][friendly_name]['last_seen'] = time.time()
                
                if is_attack:
                    live_monitoring['stats']['websites'][friendly_name]['attacks'] += 1
                else:
                    live_monitoring['stats']['websites'][friendly_name]['normal'] += 1
                
                # Create result
                result = {
                    'timestamp': time.time(),
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'hostname': friendly_name,  # Use friendly name here!
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
                        'destination': friendly_name,  # Use friendly name here!
                        'severity': 'HIGH' if probability[1] > 0.9 else 'MEDIUM',
                        'probability': float(probability[1]),
                        'details': f"{protocol.upper()} connection to {friendly_name}:{dst_port}"
                    }
                    live_monitoring['stats']['recent_alerts'].append(alert)
                    
                    if len(live_monitoring['stats']['recent_alerts']) > 10:
                        live_monitoring['stats']['recent_alerts'].pop(0)
                
                # Console output every 5 packets
                if packet_count[0] % 5 == 0:
                    status = '⚠️ ATTACK' if is_attack else '✅ NORMAL'
                    print(f"[REAL] #{packet_count[0]} | {friendly_name} [{protocol}:{dst_port}] {status} ({probability[1]*100:.1f}%)")
                    
            except Exception as e:
                pass
        
        def stop_filter(packet):
            """Stop sniffing when monitoring is disabled"""
            return not live_monitoring['active']
        
        print(f"✅ LIVE CAPTURE ACTIVE - SCAPY MODE")
        print("💡 Browse websites to see REAL traffic!")
        print("="*70 + "\n")
        
        # Start sniffing - Scapy handles threading perfectly!
        sniff(prn=process_packet, stop_filter=stop_filter, store=False)
        
        print("\n🛑 Real capture stopped\n")
        
    except ImportError:
        live_monitoring['capture_mode'] = 'error'
        live_monitoring['error_message'] = 'Scapy not installed. Run: pip install scapy'
        print("\n❌ Scapy not installed!")
        print("   Run: pip install scapy")
    except PermissionError:
        live_monitoring['capture_mode'] = 'error'
        live_monitoring['error_message'] = 'Permission denied! Run CMD as Administrator'
        print("\n❌ Permission denied! Run as Administrator!")
    except Exception as e:
        live_monitoring['capture_mode'] = 'error'
        live_monitoring['error_message'] = f'Capture error: {str(e)}'
        print(f"\n❌ Capture failed: {e}")

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
    
    thread = threading.Thread(target=capture_real_packets, daemon=True)
    thread.start()
    
    return jsonify({'message': 'Starting real packet capture...'})

@app.route('/stop_monitoring', methods=['POST'])
def stop_monitoring():
    global live_monitoring
    live_monitoring['active'] = False
    time.sleep(1)  # Give thread time to stop
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
        print(f"Dashboard error: {e}")
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
    print("🚀 Network Intrusion Detection System")
    print("="*70)
    print("📍 Access at: http://localhost:5000")
    print("🔴 REAL packet capture using SCAPY")
    print("⚠️  MUST run CMD as Administrator!")
    print("="*70 + "\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False, threaded=True)