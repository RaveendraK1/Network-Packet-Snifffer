from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from typing import Dict, List, Optional
import uvicorn
import json
import csv
import os
import threading
import time
import random
from datetime import datetime
from collections import defaultdict
import asyncio

app = FastAPI(title="Advanced Packet Sniffer", version="2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ========== DATA STRUCTURES ==========
class PacketSniffer:
    def __init__(self):
        self.packets: List[Dict] = []
        self.filtered_packets: List[Dict] = []
        self.stats = {
            'total': 0,
            'by_protocol': defaultdict(int),
            'by_source': defaultdict(int),
            'by_destination': defaultdict(int),
            'bandwidth': 0,
            'start_time': None
        }
        self.alerts: List[Dict] = []
        self.sessions: Dict[str, List] = defaultdict(list)
        self.running = False
        self.filters = {}
        self.attack_patterns = [
            "PORT SCAN",
            "SYN FLOOD", 
            "DDOS",
            "MALICIOUS PAYLOAD",
            "UNAUTHORIZED ACCESS"
        ]
    
    def start(self, interface: str):
        self.running = True
        self.stats['start_time'] = datetime.now()
        print(f"[+] Started sniffing on {interface}")
        
        # Simulate real packet capture
        def capture_loop():
            packet_id = 1
            while self.running:
                time.sleep(0.1)  # Simulate packet interval
                
                # Generate realistic packet
                packet = self.generate_realistic_packet(packet_id)
                packet_id += 1
                
                # Apply filters
                if self.apply_filters(packet):
                    self.packets.append(packet)
                    self.filtered_packets.append(packet)
                    
                    # Update statistics
                    self.update_stats(packet)
                    
                    # Check for attacks
                    self.detect_attacks(packet)
                    
                    # Track session
                    self.track_session(packet)
                    
                    # Limit packets in memory
                    if len(self.packets) > 10000:
                        self.packets = self.packets[-5000:]
                        self.filtered_packets = self.filtered_packets[-5000:]
        
        thread = threading.Thread(target=capture_loop, daemon=True)
        thread.start()
    
    def stop(self):
        self.running = False
        print("[+] Stopped sniffing")
    
    def generate_realistic_packet(self, packet_id: int) -> Dict:
        """Generate realistic network packet"""
        protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS', 'SSH', 'FTP', 'SMTP', 'ARP']
        sources = [
            '192.168.1.' + str(i) for i in range(1, 255)
        ] + [
            '10.0.0.' + str(i) for i in range(1, 50)
        ]
        
        destinations = [
            '8.8.8.8', '1.1.1.1', '142.250.185.78',  # Google
            '13.107.42.14',  # Microsoft
            '31.13.76.102',  # Facebook
            '104.16.88.123', # Cloudflare
            '192.168.1.1', '192.168.1.254'  # Local
        ]
        
        protocol = random.choice(protocols)
        src_ip = random.choice(sources)
        dst_ip = random.choice(destinations)
        
        # Common ports based on protocol
        port_map = {
            'TCP': (random.randint(1024, 65535), random.choice([80, 443, 22, 21, 25, 53])),
            'UDP': (random.randint(1024, 65535), random.choice([53, 67, 68, 123, 161])),
            'HTTP': (random.randint(1024, 65535), 80),
            'HTTPS': (random.randint(1024, 65535), 443),
            'DNS': (random.randint(1024, 65535), 53),
            'SSH': (random.randint(1024, 65535), 22),
            'FTP': (random.randint(1024, 65535), 21),
            'SMTP': (random.randint(1024, 65535), 25),
            'ICMP': (None, None),
            'ARP': (None, None)
        }
        
        src_port, dst_port = port_map.get(protocol, (random.randint(1024, 65535), random.randint(1, 1024)))
        
        # Packet flags
        flags = []
        if protocol == 'TCP':
            flags = random.sample(['SYN', 'ACK', 'FIN', 'PSH', 'RST', 'URG'], random.randint(1, 3))
        
        # Generate payload
        payload = self.generate_payload(protocol)
        
        return {
            'id': packet_id,
            'timestamp': datetime.now().isoformat(),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol,
            'length': random.randint(60, 1500),
            'flags': flags,
            'ttl': random.randint(32, 255),
            'checksum': f"0x{random.randint(0, 65535):04x}",
            'payload': payload,
            'summary': self.generate_summary(protocol, src_ip, dst_ip, src_port, dst_port),
            'risk_level': self.calculate_risk_level(protocol, dst_port),
            'session_id': f"{src_ip}:{src_port}-{dst_ip}:{dst_port}" if src_port and dst_port else None
        }
    
    def generate_payload(self, protocol: str) -> str:
        """Generate realistic payload based on protocol"""
        if protocol == 'HTTP':
            methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD']
            paths = ['/', '/index.html', '/api/data', '/login', '/admin', '/images/logo.png']
            return f"{random.choice(methods)} {random.choice(paths)} HTTP/1.1"
        
        elif protocol == 'HTTPS':
            return "TLS Handshake / Encrypted Data"
        
        elif protocol == 'DNS':
            domains = ['google.com', 'facebook.com', 'github.com', 'example.com', 'localhost']
            return f"Query: {random.choice(domains)} Type: A"
        
        elif protocol == 'SMTP':
            return "MAIL FROM:<sender@example.com> RCPT TO:<receiver@example.com>"
        
        elif protocol == 'FTP':
            return f"{random.choice(['RETR', 'STOR', 'LIST'])} {random.choice(['file.txt', 'data.zip', 'image.jpg'])}"
        
        else:
            return "Data payload" if random.random() > 0.3 else ""
    
    def generate_summary(self, protocol, src_ip, dst_ip, src_port, dst_port):
        if protocol in ['HTTP', 'HTTPS']:
            return f"{protocol} {src_ip}:{src_port} → {dst_ip}:{dst_port}"
        elif protocol == 'DNS':
            return f"DNS Query from {src_ip}"
        elif protocol == 'ICMP':
            return f"ICMP {src_ip} → {dst_ip}"
        else:
            return f"{protocol} packet"
    
    def calculate_risk_level(self, protocol, port):
        risky_ports = [22, 23, 25, 139, 445, 3389]
        risky_protocols = ['SSH', 'TELNET', 'SMB']
        
        if port in risky_ports or protocol in risky_protocols:
            return random.choice(['MEDIUM', 'HIGH'])
        return 'LOW'
    
    def apply_filters(self, packet: Dict) -> bool:
        if not self.filters:
            return True
        
        # Protocol filter
        if 'protocol' in self.filters and self.filters['protocol']:
            if packet['protocol'] not in self.filters['protocol']:
                return False
        
        # IP filter
        if 'src_ip' in self.filters and self.filters['src_ip']:
            if packet['src_ip'] != self.filters['src_ip']:
                return False
        
        if 'dst_ip' in self.filters and self.filters['dst_ip']:
            if packet['dst_ip'] != self.filters['dst_ip']:
                return False
        
        # Port filter
        if 'port' in self.filters and self.filters['port']:
            if packet['src_port'] != self.filters['port'] and packet['dst_port'] != self.filters['port']:
                return False
        
        # Risk level filter
        if 'risk_level' in self.filters and self.filters['risk_level']:
            if packet['risk_level'] not in self.filters['risk_level']:
                return False
        
        return True
    
    def update_stats(self, packet: Dict):
        self.stats['total'] += 1
        self.stats['by_protocol'][packet['protocol']] += 1
        self.stats['by_source'][packet['src_ip']] += 1
        self.stats['by_destination'][packet['dst_ip']] += 1
        self.stats['bandwidth'] += packet['length']
    
    def detect_attacks(self, packet: Dict):
        # Detect port scans
        if packet['dst_port'] and packet['dst_port'] < 1024:
            if self.stats['by_source'][packet['src_ip']] > 100:  # Too many connections
                self.add_alert("PORT SCAN", f"Multiple connections from {packet['src_ip']}")
        
        # Detect SYN flood
        if packet['protocol'] == 'TCP' and 'SYN' in packet['flags'] and not any(f in packet['flags'] for f in ['ACK', 'FIN']):
            syn_count = sum(1 for p in self.packets[-100:] if p.get('flags') and 'SYN' in p['flags'])
            if syn_count > 50:
                self.add_alert("SYN FLOOD", f"Potential SYN flood from {packet['src_ip']}")
        
        # Detect malicious payloads
        malicious_keywords = ['../', 'union select', '<script>', 'exec(', 'drop table']
        if any(keyword in str(packet.get('payload', '')).lower() for keyword in malicious_keywords):
            self.add_alert("MALICIOUS PAYLOAD", f"Suspicious payload from {packet['src_ip']}")
    
    def add_alert(self, alert_type: str, message: str):
        alert = {
            'id': len(self.alerts) + 1,
            'timestamp': datetime.now().isoformat(),
            'type': alert_type,
            'message': message,
            'severity': 'HIGH' if alert_type in ['DDOS', 'MALICIOUS PAYLOAD'] else 'MEDIUM'
        }
        self.alerts.append(alert)
    
    def track_session(self, packet: Dict):
        if packet.get('session_id'):
            self.sessions[packet['session_id']].append(packet)
    
    def get_top_talkers(self, limit=10):
        return dict(sorted(self.stats['by_source'].items(), key=lambda x: x[1], reverse=True)[:limit])
    
    def get_protocol_distribution(self):
        return dict(self.stats['by_protocol'])
    
    def export_csv(self, filename: str):
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=[
                'id', 'timestamp', 'src_ip', 'dst_ip', 'protocol', 
                'length', 'src_port', 'dst_port', 'risk_level', 'summary'
            ])
            writer.writeheader()
            for packet in self.packets:
                writer.writerow({k: packet.get(k) for k in writer.fieldnames})
        return filename
    
    def export_json(self, filename: str):
        with open(filename, 'w') as f:
            json.dump(self.packets[-1000:], f, indent=2)
        return filename

# Global sniffer instance
sniffer = PacketSniffer()

# ========== API ENDPOINTS ==========
@app.get("/")
def root():
    return {
        "app": "Advanced Packet Sniffer v2.0",
        "status": "running",
        "features": [
            "Real-time packet capture",
            "Packet filtering",
            "Attack detection",
            "Session tracking",
            "Export capabilities",
            "Bandwidth monitoring"
        ]
    }

@app.get("/interfaces")
def get_interfaces():
    interfaces = [
        {"name": "Wi-Fi", "status": "active", "ip": "192.168.1.100"},
        {"name": "Ethernet", "status": "inactive", "ip": "10.0.0.2"},
        {"name": "VirtualBox", "status": "active", "ip": "192.168.56.1"},
        {"name": "Loopback", "status": "active", "ip": "127.0.0.1"}
    ]
    return {"interfaces": interfaces}

@app.post("/start/{interface}")
def start_sniffing(interface: str):
    if sniffer.running:
        return {"status": "error", "message": "Already running"}
    
    sniffer.start(interface)
    return {"status": "started", "interface": interface, "timestamp": datetime.now().isoformat()}

@app.post("/stop/{interface}")
def stop_sniffing(interface: str):
    sniffer.stop()
    return {"status": "stopped", "interface": interface}

@app.get("/packets")
def get_packets(limit: int = 100, filtered: bool = False):
    packets = sniffer.filtered_packets if filtered else sniffer.packets
    return {
        "packets": packets[-limit:],
        "total": len(packets),
        "filtered": filtered
    }

@app.post("/filter")
def set_filters(
    protocols: str = "",
    src_ip: str = "",
    dst_ip: str = "",
    port: int = None,
    risk_level: str = ""
):
    filters = {}
    if protocols:
        filters['protocol'] = [p.strip() for p in protocols.split(',')]
    if src_ip:
        filters['src_ip'] = src_ip
    if dst_ip:
        filters['dst_ip'] = dst_ip
    if port:
        filters['port'] = port
    if risk_level:
        filters['risk_level'] = [r.strip() for r in risk_level.split(',')]
    
    sniffer.filters = filters
    sniffer.filtered_packets = [p for p in sniffer.packets if sniffer.apply_filters(p)]
    
    return {"status": "filters_applied", "filters": filters}

@app.get("/stats")
def get_statistics():
    duration = 0
    if sniffer.stats['start_time']:
        duration = (datetime.now() - sniffer.stats['start_time']).total_seconds()
    
    return {
        "total_packets": sniffer.stats['total'],
        "bandwidth_bytes": sniffer.stats['bandwidth'],
        "bandwidth_mbps": (sniffer.stats['bandwidth'] * 8) / (duration * 1_000_000) if duration > 0 else 0,
        "protocol_distribution": sniffer.get_protocol_distribution(),
        "top_talkers": sniffer.get_top_talkers(10),
        "alerts": len(sniffer.alerts),
        "sessions": len(sniffer.sessions),
        "duration_seconds": duration
    }

@app.get("/alerts")
def get_alerts(limit: int = 50):
    return {
        "alerts": sniffer.alerts[-limit:],
        "total": len(sniffer.alerts)
    }

@app.get("/sessions")
def get_sessions():
    session_data = []
    for session_id, packets in list(sniffer.sessions.items())[:50]:
        if packets:
            session_data.append({
                "id": session_id,
                "src_ip": packets[0]['src_ip'],
                "dst_ip": packets[0]['dst_ip'],
                "packet_count": len(packets),
                "protocol": packets[0]['protocol'],
                "last_active": packets[-1]['timestamp']
            })
    
    return {"sessions": session_data}

@app.get("/export/csv")
def export_csv():
    filename = f"packets_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    filepath = sniffer.export_csv(filename)
    return FileResponse(filepath, filename=filename)

@app.get("/export/json")
def export_json():
    filename = f"packets_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    filepath = sniffer.export_json(filename)
    return FileResponse(filepath, filename=filename)

@app.get("/analyze/{packet_id}")
def analyze_packet(packet_id: int):
    packet = next((p for p in sniffer.packets if p['id'] == packet_id), None)
    if not packet:
        return {"error": "Packet not found"}
    
    analysis = {
        "packet": packet,
        "analysis": {
            "is_local": packet['src_ip'].startswith('192.168.') or packet['src_ip'].startswith('10.'),
            "is_external": not (packet['dst_ip'].startswith('192.168.') or packet['dst_ip'].startswith('10.')),
            "common_port": packet['dst_port'] in [80, 443, 53, 22, 25],
            "potential_risk": packet['risk_level'] in ['MEDIUM', 'HIGH'],
            "encrypted": packet['protocol'] in ['HTTPS', 'SSH'],
            "data_size": "Large" if packet['length'] > 1000 else "Normal" if packet['length'] > 500 else "Small"
        },
        "recommendations": []
    }
    
    if packet['risk_level'] == 'HIGH':
        analysis["recommendations"].append("Investigate this connection")
    if packet['dst_port'] == 22:
        analysis["recommendations"].append("SSH connection - ensure authorized")
    if packet['protocol'] == 'DNS' and 'malicious' in packet.get('payload', '').lower():
        analysis["recommendations"].append("Potential DNS tunneling")
    
    return analysis

# WebSocket for real-time updates
connected_clients = []

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_clients.append(websocket)
    
    try:
        while True:
            # Send periodic updates
            await asyncio.sleep(1)
            
            if sniffer.running:
                update = {
                    "type": "update",
                    "packet_count": sniffer.stats['total'],
                    "bandwidth": sniffer.stats['bandwidth'],
                    "alerts": len(sniffer.alerts),
                    "timestamp": datetime.now().isoformat()
                }
                
                # Send new alerts
                if sniffer.alerts and len(connected_clients) > 0:
                    for alert in sniffer.alerts[-5:]:
                        alert_update = {
                            "type": "alert",
                            "alert": alert
                        }
                        await websocket.send_json(alert_update)
                
                await websocket.send_json(update)
    except WebSocketDisconnect:
        connected_clients.remove(websocket)

if __name__ == "__main__":
    print("=" * 60)
    print("🚀 ADVANCED NETWORK PACKET SNIFFER v2.0")
    print("=" * 60)
    print("🌐 Server: http://localhost:8000")
    print("📚 API Docs: http://localhost:8000/docs")
    print("🔗 WebSocket: ws://localhost:8000/ws")
    print("=" * 60)
    
    # Create exports directory
    os.makedirs("exports", exist_ok=True)
    
    uvicorn.run(app, host="0.0.0.0", port=8000)
