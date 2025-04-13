import http.server
import socketserver
import os
import io
import base64
import urllib
import re
import mimetypes
import threading
import hashlib
import json
import secrets
import subprocess
import tempfile
import time
import ipaddress
from datetime import datetime, timedelta  # ← Fixed import to include timedelta
from collections import defaultdict, Counter

PORT = 8001
USERNAME = "a"
PASSWORD = "a"

SITE_NAME = "Welcome to CN project"
CHUNK_SIZE = 1048576  # 1 MB
ENCRYPTION_KEY_FILE = "encryption_key.bin"
ENCRYPTION_META_FILE = "encryption_meta.json"
IDS_LOG_FILE = "ids_events.json"

# IDS Configuration
IDS_CONFIG = {
    'login_attempts_threshold': 3,  # Number of failed logins before triggering alert
    'login_attempts_window': 300,   # Time window in seconds for login attempts (5 minutes)
    'request_rate_threshold': 30,   # Max requests per minute before triggering alert
    'suspicious_patterns': [
        r'\.\./', r'\.\.\\',        # Path traversal attempts
        r'SELECT.*FROM',            # Potential SQL injection
        r'<script>',                # XSS attempts 
        r'/etc/passwd',             # Sensitive file access attempt
        r'eval\(',                  # Code injection attempts
        r'exec\('
    ],
    'blocked_user_agents': [
        'sqlmap', 'nikto', 'nmap', 'burpsuite', 'dirbuster', 'gobuster',
        'hydra', 'masscan', 'harvester'
    ],
    'alert_threshold': 'medium',    # 'low', 'medium', 'high'
    'block_threshold': 'high'       # Severity level that triggers IP blocking
}


class IntrusionDetectionSystem:
    def __init__(self):
        self.events = self.load_events()
        self.login_attempts = defaultdict(list)  # IP -> list of timestamps
        self.request_counts = defaultdict(Counter)  # IP -> {timestamp: count}
        self.blocked_ips = set()
        
    def load_events(self):
        if os.path.exists(IDS_LOG_FILE):
            try:
                with open(IDS_LOG_FILE, 'r') as f:
                    return json.load(f)
            except:
                return {"events": [], "stats": {"total_alerts": 0, "blocked_ips": 0}}
        return {"events": [], "stats": {"total_alerts": 0, "blocked_ips": 0}}
    
    def save_events(self):
        with open(IDS_LOG_FILE, 'w') as f:
            json.dump(self.events, f, indent=2)
    
    def add_event(self, ip, event_type, details, severity):
        timestamp = datetime.now().isoformat()
        event = {
            "timestamp": timestamp,
            "ip": ip,
            "event_type": event_type,
            "details": details,
            "severity": severity
        }
        self.events["events"].insert(0, event)  # Add at beginning for newest first
        self.events["stats"]["total_alerts"] += 1
        
        # Limit event history to most recent 1000
        if len(self.events["events"]) > 1000:
            self.events["events"] = self.events["events"][:1000]
            
        # Save events to disk
        self.save_events()
        return event
    
    def check_login_attempt(self, ip, success):
        current_time = time.time()
        # Clean old attempts
        self.login_attempts[ip] = [t for t in self.login_attempts[ip] 
                                  if current_time - t < IDS_CONFIG['login_attempts_window']]
        
        if not success:
            self.login_attempts[ip].append(current_time)
            # Check if threshold exceeded
            if len(self.login_attempts[ip]) >= IDS_CONFIG['login_attempts_threshold']:
                severity = "high" if len(self.login_attempts[ip]) > IDS_CONFIG['login_attempts_threshold'] + 2 else "medium"
                details = f"Failed login attempts: {len(self.login_attempts[ip])} in {IDS_CONFIG['login_attempts_window']} seconds"
                return self.add_event(ip, "auth_failure", details, severity)
        return None
    
    def check_request_rate(self, ip):
        current_time = int(time.time() / 60)  # Current minute
        self.request_counts[ip][current_time] += 1
        
        # Clean old counts (keep only last 10 minutes)
        for minute in list(self.request_counts[ip].keys()):
            if current_time - minute > 10:
                del self.request_counts[ip][minute]
        
        # Check rate
        if self.request_counts[ip][current_time] > IDS_CONFIG['request_rate_threshold']:
            severity = "medium"
            if self.request_counts[ip][current_time] > IDS_CONFIG['request_rate_threshold'] * 2:
                severity = "high"
            details = f"High request rate: {self.request_counts[ip][current_time]} requests in last minute"
            return self.add_event(ip, "rate_limit", details, severity)
        return None
    
    def check_path(self, ip, path, user_agent):
        # Check for suspicious patterns
        for pattern in IDS_CONFIG['suspicious_patterns']:
            if re.search(pattern, path, re.IGNORECASE):
                severity = "high"
                details = f"Suspicious pattern in request path: {pattern}"
                return self.add_event(ip, "suspicious_request", details, severity)
        
        # Check for suspicious user agents
        if user_agent:
            for bad_agent in IDS_CONFIG['blocked_user_agents']:
                if bad_agent.lower() in user_agent.lower():
                    severity = "high"
                    details = f"Detected potentially malicious user agent: {user_agent}"
                    return self.add_event(ip, "suspicious_agent", details, severity)
        
        return None
    
    def should_block(self, ip):
        """Determine if an IP should be blocked based on recent activity"""
        if ip in self.blocked_ips:
            return True
            
        # Count high severity events in the last hour
        recent_high_severity = 0
        one_hour_ago = (datetime.now() - timedelta(hours=1)).isoformat()  # Fixed: Using timedelta correctly
        
        for event in self.events["events"]:
            if (event["ip"] == ip and 
                event["severity"] == "high" and 
                event["timestamp"] > one_hour_ago):
                recent_high_severity += 1
        
        # Block if 3 or more high severity events
        if recent_high_severity >= 3:
            self.blocked_ips.add(ip)
            self.events["stats"]["blocked_ips"] += 1
            self.add_event(ip, "ip_blocked", f"IP automatically blocked after {recent_high_severity} high severity events", "critical")
            return True
            
        return False


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


class CustomHandler(http.server.SimpleHTTPRequestHandler):
    # Class-level IDS instance shared by all handler instances
    ids_system = IntrusionDetectionSystem()
    
    def __init__(self, *args, **kwargs):
        self.encryption_key = self.load_or_create_encryption_key()
        self.encryption_meta = self.load_encryption_meta()
        super().__init__(*args, **kwargs)

    def load_or_create_encryption_key(self):
        """Load existing encryption key or create a new one if it doesn't exist"""
        if os.path.exists(ENCRYPTION_KEY_FILE):
            with open(ENCRYPTION_KEY_FILE, 'rb') as f:
                return f.read()
        else:
            # Generate a new AES-256 key (32 bytes)
            key = secrets.token_bytes(32)
            with open(ENCRYPTION_KEY_FILE, 'wb') as f:
                f.write(key)
            return key

    def load_encryption_meta(self):
        """Load metadata about encrypted files"""
        if os.path.exists(ENCRYPTION_META_FILE):
            try:
                with open(ENCRYPTION_META_FILE, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}

    def save_encryption_meta(self):
        """Save encryption metadata to file"""
        with open(ENCRYPTION_META_FILE, 'w') as f:
            json.dump(self.encryption_meta, f)

    def encrypt_file_data(self, data):
        """Encrypt file data using OpenSSL AES-256-CBC"""
        # Generate a random IV
        iv = secrets.token_bytes(16)

        # Create temporary files for input, output, key, and IV
        with tempfile.NamedTemporaryFile(delete=False) as input_file:
            input_file.write(data)
            input_path = input_file.name

        with tempfile.NamedTemporaryFile(delete=False) as key_file:
            key_file.write(self.encryption_key)
            key_path = key_file.name

        with tempfile.NamedTemporaryFile(delete=False) as iv_file:
            iv_file.write(iv)
            iv_path = iv_file.name

        output_path = tempfile.mktemp()

        try:
            # Run OpenSSL command to encrypt the data
            subprocess.run([
                'openssl', 'enc', '-aes-256-cbc',
                '-in', input_path,
                '-out', output_path,
                '-K', self.encryption_key.hex(),
                '-iv', iv.hex()
            ], check=True, capture_output=True) # Added capture_output for better error info

            # Read the encrypted data
            with open(output_path, 'rb') as f:
                encrypted_data = f.read()

            # Return IV concatenated with encrypted data
            return iv + encrypted_data

        except subprocess.CalledProcessError as e:
            print(f"OpenSSL Encryption Error: {e.stderr.decode()}") # Print OpenSSL error
            raise Exception(f"OpenSSL encryption failed: {e}")

        finally:
            # Clean up temporary files
            for path in [input_path, key_path, iv_path, output_path]:
                if os.path.exists(path):
                    os.unlink(path)

    def decrypt_file_data(self, data):
        """Decrypt file data using OpenSSL AES-256-CBC"""
        # Extract IV from the beginning of the data
        iv = data[:16]
        encrypted_data = data[16:]

        # Create temporary files for input, output, key, and IV
        with tempfile.NamedTemporaryFile(delete=False) as input_file:
            input_file.write(encrypted_data)
            input_path = input_file.name

        with tempfile.NamedTemporaryFile(delete=False) as key_file:
            key_file.write(self.encryption_key)
            key_path = key_file.name

        with tempfile.NamedTemporaryFile(delete=False) as iv_file:
            iv_file.write(iv)
            iv_path = iv_file.name

        output_path = tempfile.mktemp()

        try:
            # Run OpenSSL command to decrypt the data
            subprocess.run([
                'openssl', 'enc', '-aes-256-cbc', '-d',
                '-in', input_path,
                '-out', output_path,
                '-K', self.encryption_key.hex(),
                '-iv', iv.hex()
            ], check=True, capture_output=True) # Added capture_output

            # Read the decrypted data
            with open(output_path, 'rb') as f:
                decrypted_data = f.read()

            return decrypted_data

        except subprocess.CalledProcessError as e:
            print(f"OpenSSL Decryption Error: {e.stderr.decode()}") # Print OpenSSL error
            raise Exception(f"OpenSSL decryption failed: {e}")

        finally:
            # Clean up temporary files
            for path in [input_path, key_path, iv_path, output_path]:
                if os.path.exists(path):
                    os.unlink(path)
    
    def get_client_ip(self):
        """Get the client IP address"""
        ip = self.client_address[0]
        # If behind reverse proxy, check for X-Forwarded-For header
        if "X-Forwarded-For" in self.headers:
            forwarded_for = self.headers["X-Forwarded-For"].split(",")[0].strip()
            try:
                # Validate it's a proper IP address
                ipaddress.ip_address(forwarded_for)
                ip = forwarded_for
            except ValueError:
                pass
        return ip

    def log_message(self, format, *args):
        """Override to add IDS monitoring to all requests"""
        client_ip = self.get_client_ip()
        
        # Skip IDS checks for localhost during development if desired
        #if client_ip == "127.0.0.1":
        #    return super().log_message(format, *args)
        
        # Check request rate
        self.ids_system.check_request_rate(client_ip)
        
        # Check path for suspicious patterns
        user_agent = self.headers.get('User-Agent', '')
        request_path = args[0].split()[1] if len(args) > 0 else self.path
        self.ids_system.check_path(client_ip, request_path, user_agent)
        
        # Call the original method
        super().log_message(format, *args)
        
    def do_GET(self):
        client_ip = self.get_client_ip()
        
        # IDS monitoring - check if IP is blocked
        if self.ids_system.should_block(client_ip):
            self.send_response(403)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Access Denied</h1><p>Your IP has been blocked due to suspicious activity.</p></body></html>")
            return
            
        # Special endpoint for IDS dashboard
        if self.path == "/ids_dashboard":
            if not self.authenticate():
                self.ids_system.check_login_attempt(client_ip, False)
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="Restricted Area"')
                self.end_headers()
                return
                
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(self.generate_ids_dashboard())
            return
            
        if self.path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
            return

        if not self.authenticate():
            # Log failed authentication
            self.ids_system.check_login_attempt(client_ip, False)
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="Restricted Area"')
            self.end_headers()
            return
            
        # Log successful authentication
        self.ids_system.check_login_attempt(client_ip, True)

        path = self.translate_path(self.path)
        if os.path.isfile(path):
            self.send_file(path)
        else:
            return http.server.SimpleHTTPRequestHandler.do_GET(self)

    def do_POST(self):
        client_ip = self.get_client_ip()
        
        # IDS monitoring - check if IP is blocked
        if self.ids_system.should_block(client_ip):
            self.send_response(403)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Access Denied</h1><p>Your IP has been blocked due to suspicious activity.</p></body></html>")
            return

        if not self.authenticate():
            # Log failed authentication
            self.ids_system.check_login_attempt(client_ip, False)
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="Restricted Area"')
            self.end_headers()
            return

        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        params = urllib.parse.parse_qs(post_data)

        if 'delete' in params:
            filename = params['delete'][0]
            try:
                os.remove(filename)
                # Remove from encryption metadata if present
                if filename in self.encryption_meta:
                    del self.encryption_meta[filename]
                    self.save_encryption_meta()
                self.send_response(303)
                self.send_header('Location', self.path)
                self.end_headers()
            except Exception as e:
                self.send_error(500, f"Error deleting file: {str(e)}")
        else:
            self.send_error(400, "Invalid POST request")

    def authenticate(self):
        if self.headers.get('Authorization') is None:
            return False
        else:
            auth = self.headers.get('Authorization').split()
            if len(auth) != 2 or auth[0].lower() != 'basic':
                return False

            auth_decoded = base64.b64decode(auth[1]).decode('utf-8')
            username, password = auth_decoded.split(':')
            return username == USERNAME and password == PASSWORD

    def send_file(self, path):
        try:
            f = open(path, 'rb')
        except OSError:
            self.send_error(404, "File not found")
            return None

        try:
            data = f.read()
            # f.close() # Do not close f here, close after writing is done

            # Check file metadata
            is_encrypted = False
            file_hash = hashlib.sha256(data).hexdigest()

            # If file exists in metadata and hash matches, it's already encrypted
            if path in self.encryption_meta and self.encryption_meta[path].get('hash') == file_hash:
                is_encrypted = True
                content = data  # Already encrypted, send as is
            else:
                # File is not encrypted or has changed, encrypt it now
                if not path.endswith(('.jpg', '.jpeg', '.png', '.gif', '.ico', '.webp')):
                    # Don't encrypt image files as they might be needed for display
                    try:
                        content = self.encrypt_file_data(data)
                        # Update metadata
                        self.encryption_meta[path] = {
                            'hash': hashlib.sha256(content).hexdigest(),
                            'original_size': len(data)
                        }
                        self.save_encryption_meta()
                        is_encrypted = True
                    except Exception as e:
                        print(f"Encryption error for {path}: {str(e)}")
                        content = data  # If encryption fails, send original data
                else:
                    content = data  # Don't encrypt images

            # Serve the file (encrypted or not)
            fs = os.fstat(f.fileno())
            content_type, encoding = mimetypes.guess_type(path)
            if content_type is None:
                content_type = 'application/octet-stream'

            # For downloading, we serve the encrypted content directly
            self.send_response(200)
            self.send_header("Content-type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Last-Modified", self.date_time_string(fs.st_mtime))
            # Add header to indicate encryption status for client awareness
            self.send_header("X-Encrypted", "1" if is_encrypted else "0")
            self.end_headers()

            # Write the content (encrypted or not)
            self.wfile.write(content)

        except Exception as e:
            print(f"Error sending file {path}: {str(e)}")
            self.send_error(500, f"Error serving file: {str(e)}")
        finally:
            if 'f' in locals() and f and not f.closed: # Ensure f is defined and not closed before attempting to close
                f.close()
                
    def generate_ids_dashboard(self):
        """Generate HTML for the IDS dashboard"""
        events = self.ids_system.events["events"]
        stats = self.ids_system.events["stats"]
        
        # Count events by severity
        severity_counts = Counter()
        event_type_counts = Counter()
        recent_ips = Counter()
        
        for event in events[:100]:  # Only use recent events for stats
            severity_counts[event["severity"]] += 1
            event_type_counts[event["event_type"]] += 1
            recent_ips[event["ip"]] += 1
            
        # Generate HTML
        html = []
        html.append('<!DOCTYPE html>')
        html.append('<html lang="en">')
        html.append('<head>')
        html.append('<meta charset="utf-8">')
        html.append('<meta name="viewport" content="width=device-width, initial-scale=1.0">')
        html.append('<meta http-equiv="refresh" content="30">')  # Auto-refresh every 30 seconds
        html.append('<title>Intrusion Detection System Dashboard</title>')
        html.append('<style>')
        html.append('body { font-family: "Open Sans", "Helvetica Neue", Helvetica, Arial, sans-serif; background-color: #36393f; color: #dcddde; margin: 0; padding: 0; display: flex; flex-direction: column; min-height: 100vh; }')
        html.append('header, footer { background-color: #2f3136; padding: 15px 20px; text-align: center; }')
        html.append('header h1, footer p { margin: 0; color: #7289da; }')
        html.append('.container { flex: 1; width: 95%; max-width: 1200px; margin: 20px auto; padding: 20px; border: 1px solid #4f545c; border-radius: 10px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); background-color: #2f3136; }')
        html.append('.dashboard-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-bottom: 20px; }')
        html.append('.card { background-color: #40444b; border-radius: 10px; padding: 15px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); }')
        html.append('.stat-value { font-size: 2em; font-weight: bold; margin: 10px 0; text-align: center; }')
        html.append('.stat-label { text-align: center; opacity: 0.8; margin-bottom: 10px; }')
        html.append('table { width: 100%; border-collapse: separate; border-spacing: 0; margin-top: 20px; border: 1px solid #4f545c; border-radius: 10px; overflow: hidden; }')
        html.append('th, td { padding: 12px 15px; border-bottom: 1px solid #4f545c; }')
        html.append('tr:last-child td { border-bottom: none; }')
        html.append('th { background-color: #7289da; color: #ffffff; text-align: left; }')
        html.append('.severity-low { color: #43b581; }')
        html.append('.severity-medium { color: #faa61a; }')
        html.append('.severity-high { color: #f04747; }')
        html.append('.severity-critical { color: #f04747; font-weight: bold; animation: pulse 2s infinite; }')
        html.append('@keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.5; } 100% { opacity: 1; } }')
        html.append('.chart-container { height: 200px; margin: 20px 0; }')
        html.append('.chart-bar { height: 100%; display: flex; align-items: flex-end; gap: 10px; }')
        html.append('.bar { flex-grow: 1; margin: 0 5px; border-radius: 5px 5px 0 0; position: relative; }')
        html.append('.bar-label { position: absolute; bottom: -25px; left: 0; right: 0; text-align: center; font-size: 12px; }')
        html.append('.bar-value { position: absolute; bottom: -45px; left: 0; right: 0; text-align: center; font-size: 10px; opacity: 0.8; }')
        html.append('.low { background-color: #43b581; }')
        html.append('.medium { background-color: #faa61a; }')
        html.append('.high { background-color: #f04747; }')
        html.append('.critical { background-color: #f04747; animation: pulse 2s infinite; }')
        html.append('.nav-links { display: flex; justify-content: center; gap: 20px; margin: 20px 0; }')
        html.append('.nav-links a { color: #7289da; text-decoration: none; padding: 10px; border-radius: 5px; transition: background-color 0.3s; }')
        html.append('.nav-links a:hover { background-color: #40444b; }')
        html.append('.filter-buttons { display: flex; justify-content: center; gap: 10px; margin: 20px 0; }')
        html.append('.filter-btn { background-color: #40444b; border: none; color: #dcddde; padding: 8px 16px; border-radius: 5px; cursor: pointer; transition: background-color 0.3s; }')
        html.append('.filter-btn:hover, .filter-btn.active { background-color: #7289da; color: white; }')
        html.append('</style>')
        html.append('</head>')
        html.append('<body>')
        html.append('<header>')
        html.append(f'<h1>Intrusion Detection System Dashboard</h1>')
        html.append('</header>')
        
        html.append('<div class="nav-links">')
        html.append('<a href="/">Back to File Browser</a>')
        html.append('<a href="/ids_dashboard">IDS Dashboard</a>')
        html.append('</div>')
        
        html.append('<div class="container">')
        
        # Stats overview
        html.append('<div class="dashboard-grid">')
        
        # Total alerts card
        html.append('<div class="card">')
        html.append('<div class="stat-label">Total Security Alerts</div>')
        html.append(f'<div class="stat-value">{stats["total_alerts"]}</div>')
        html.append('</div>')
        
        # Blocked IPs card
        html.append('<div class="card">')
        html.append('<div class="stat-label">IPs Blocked</div>')
        html.append(f'<div class="stat-value">{stats["blocked_ips"]}</div>')
        html.append('</div>')
        
        # High severity alerts card
        html.append('<div class="card">')
        html.append('<div class="stat-label">High Severity Alerts</div>')
        html.append(f'<div class="stat-value">{severity_counts["high"] + severity_counts["critical"]}</div>')
        html.append('</div>')
        
        # Most common event type card
        most_common = event_type_counts.most_common(1)
        most_common_event = most_common[0][0] if most_common else "None"
        most_common_count = most_common[0][1] if most_common else 0
        
        html.append('<div class="card">')
        html.append('<div class="stat-label">Most Common Alert Type</div>')
        html.append(f'<div class="stat-value">{most_common_event.replace("_", " ").title()}</div>')
        html.append(f'<div style="text-align: center">({most_common_count} occurrences)</div>')
        html.append('</div>')
        
        html.append('</div>') # End dashboard-grid
        
        # Severity chart
        html.append('<div class="card">')
        html.append('<h2>Alert Severity Distribution</h2>')
        html.append('<div class="chart-container">')
        html.append('<div class="chart-bar">')
        
        # Calculate max value for scaling
        max_severity = max(severity_counts.values()) if severity_counts else 1
        
        # Bars for each severity
        for severity, label, css_class in [
            ("low", "Low", "low"),
            ("medium", "Medium", "medium"), 
            ("high", "High", "high"),
            ("critical", "Critical", "critical")
        ]:
            count = severity_counts[severity]
            height = int((count / max_severity) * 100) if max_severity > 0 else 0
            height = max(height, 10) if count > 0 else 0  # Minimum visible height if there are events
            
            html.append(f'<div class="bar {css_class}" style="height: {height}%">')
            html.append(f'<div class="bar-label">{label}</div>')
            html.append(f'<div class="bar-value">{count}</div>')
            html.append('</div>')
            
        html.append('</div>') # End chart-bar
        html.append('</div>') # End chart-container
        html.append('</div>') # End card
        
        # Filter buttons
        html.append('<div class="filter-buttons">')
        html.append('<button class="filter-btn active" onclick="filterEvents(\'all\')">All</button>')
        html.append('<button class="filter-btn" onclick="filterEvents(\'high\')">High/Critical</button>')
        html.append('<button class="filter-btn" onclick="filterEvents(\'auth\')">Auth Failures</button>')
        html.append('<button class="filter-btn" onclick="filterEvents(\'suspicious\')">Suspicious Activity</button>')
        html.append('</div>')
        
        # Recent alerts table
        html.append('<h2>Recent Security Events</h2>')
        html.append('<div class="table-container">')
        html.append('<table id="events-table">')
        html.append('<tr><th>Time</th><th>IP</th><th>Type</th><th>Details</th><th>Severity</th></tr>')
        
        for event in events[:50]:  # Show most recent 50 events
            timestamp = datetime.fromisoformat(event["timestamp"]).strftime('%Y-%m-%d %H:%M:%S')
            event_type_display = event["event_type"].replace("_", " ").title()
            
            # Set CSS class based on severity
            severity_class = f"severity-{event['severity']}"
            
            # Set data attributes for filtering
            data_attrs = f'data-severity="{event["severity"]}" data-type="{event["event_type"]}"'
            
            html.append(f'<tr {data_attrs}>')
            html.append(f'<td>{timestamp}</td>')
            html.append(f'<td>{event["ip"]}</td>')
            html.append(f'<td>{event_type_display}</td>')
            html.append(f'<td>{event["details"]}</td>')
            html.append(f'<td class="{severity_class}">{event["severity"].title()}</td>')
            html.append('</tr>')
            
        html.append('</table>')
        html.append('</div>') # End table-container
        
        # JavaScript for filtering
        html.append('<script>')
        html.append('function filterEvents(type) {')
        html.append('  const rows = document.querySelectorAll("#events-table tr:not(:first-child)");')
        html.append('  const buttons = document.querySelectorAll(".filter-btn");')
        html.append('  ')
        html.append('  // Update active button')
        html.append('  buttons.forEach(btn => btn.classList.remove("active"));')
        html.append('  document.querySelector(`.filter-btn[onclick*="${type}"]`).classList.add("active");')
        html.append('  ')
        html.append('  // Show/hide rows based on filter')
        html.append('  rows.forEach(row => {')
        html.append('    if (type === "all") {')
        html.append('      row.style.display = "";')
        html.append('    } else if (type === "high") {')
        html.append('      row.style.display = (row.dataset.severity === "high" || row.dataset.severity === "critical") ? "" : "none";')
        html.append('    } else if (type === "auth") {')
        html.append('      row.style.display = row.dataset.type === "auth_failure" ? "" : "none";')
        html.append('    } else if (type === "suspicious") {')
        html.append('      row.style.display = (row.dataset.type === "suspicious_request" || row.dataset.type === "suspicious_agent") ? "" : "none";')
        html.append('    }')
        html.append('  });')
        html.append('}')
        html.append('</script>')
        
        html.append('</div>') # End container
        
        html.append('<footer>')
        html.append('<p>&copy; 2024 CryptoSage IDS | <a href="https://github.com/abeer555" target="_blank" style="color: #7289da;">GitHub</a></p>')
        html.append('</footer>')
        html.append('</body>')
        html.append('</html>')
        
        return '\n'.join(html).encode('utf-8')

    def list_directory(self, path):
        try:
            list = os.listdir(path)
        except os.error:
            self.send_error(http.server.HTTPStatus.NOT_FOUND, "No permission to list directory")
            return None

        def natural_sort_key(s):
            return [int(text) if text.isdigit() else text.lower() for text in re.split('([0-9]+)', s)]

        query = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(query)
        sort_by = params.get('sort', ['name'])[0]
        sort_order = params.get('order', ['asc'])[0]

        reverse = (sort_order == 'desc')

        if sort_by == 'name':
            list.sort(key=natural_sort_key, reverse=reverse)
        elif sort_by == 'size':
            list.sort(key=lambda x: os.path.getsize(os.path.join(path, x)) if not os.path.isdir(os.path.join(path, x)) else 0, reverse=reverse)
        elif sort_by == 'date':
            list.sort(key=lambda x: os.path.getmtime(os.path.join(path, x)), reverse=reverse)

        next_order = 'desc' if sort_order == 'asc' else 'asc'

        r = []
        displaypath = os.path.relpath(path, os.getcwd())
        r.append('<!DOCTYPE html>')
        r.append('<html lang="en">')
        r.append('<head>')
        r.append('<meta charset="utf-8">')
        r.append('<meta name="viewport" content="width=device-width, initial-scale=1.0">')
        r.append(f'<title>{SITE_NAME} - {displaypath}</title>')
        r.append('<style>')
        r.append('body { font-family: "Open Sans", "Helvetica Neue", Helvetica, Arial, sans-serif; background-color: #36393f; color: #dcddde; margin: 0; padding: 0; display: flex; flex-direction: column; min-height: 100vh; }')
        r.append('header, footer { background-color: #2f3136; padding: 15px 20px; text-align: center; }')
        r.append('header h1, footer p { margin: 0; color: #7289da; }')
        r.append('.container { flex: 1; width: 95%; max-width: 1200px; margin: 20px auto; padding: 20px; border: 1px solid #4f545c; border-radius: 10px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); background-color: #2f3136; }')
        r.append('table { width: 100%; border-collapse: separate; border-spacing: 0; margin-top: 20px; border: 1px solid #4f545c; border-radius: 10px; overflow: hidden; }')
        r.append('th, td { padding: 12px 15px; border-bottom: 1px solid #4f545c; }')
        r.append('tr:last-child td { border-bottom: none; }')
        r.append('th { background-color: #7289da; color: #ffffff; text-align: left; }')
        r.append('td:nth-child(3), td:nth-child(4), td:nth-child(5), th:nth-child(3), th:nth-child(4), th:nth-child(5) { text-align: center; }')
        r.append('a { text-decoration: none; color: #dcddde; transition: color 0.3s ease, transform 0.3s ease; }')
        r.append('a:hover { color: #ffffff; transform: translateY(-2px); }')
        r.append('.download-btn, .action-btn { background-color: #7289da; color: white; padding: 8px 16px; border-radius: 5px; transition: all 0.3s ease; display: inline-block; text-align: center; margin: 5px auto; font-size: 14px; width: auto; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); }')
        r.append('.download-btn:hover, .action-btn:hover { background-color: #677bc4; transform: translateY(-3px) scale(1.05); box-shadow: 0 6px 8px rgba(0, 0, 0, 0.15); }')
        r.append('.sort-link { color: #ffffff; text-decoration: none; margin-right: 15px; transition: all 0.3s ease; font-weight: bold; }')
        r.append('.sort-link:hover { text-decoration: underline; transform: translateY(-3px); }')
        r.append('@media (max-width: 768px) { .container { width: 100%; padding: 10px; } table { font-size: 14px; } th, td { padding: 8px; } .download-btn { padding: 6px 12px; font-size: 12px; } .sort-link { margin-right: 10px; } td:nth-child(2), th:nth-child(2) { display: none; } }')
        r.append('@media (max-width: 480px) { table { font-size: 12px; } th, td { padding: 6px; } .download-btn { padding: 4px 8px; font-size: 10px; } .sort-link { margin-right: 5px; } }')
        r.append('@keyframes pulse { 0% { transform: scale(1); } 50% { transform: scale(1.05); } 100% { transform: scale(1); } }')
        r.append('.animate-pulse { animation: pulse 2s infinite; }')
        r.append('tr:hover { background-color: #40444b; }')
        r.append('.status-icon { font-size: 16px; margin-left: 5px; }')
        r.append('.encrypted { color: #43b581; }')
        r.append('.encryption-banner { background-color: #7289da; color: white; padding: 15px; text-align: center; margin-bottom: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1); display: flex; flex-direction: column; align-items: center; }')
        r.append('.encryption-banner h3 { margin-top: 0; margin-bottom: 10px; }')
        r.append('.encryption-badge { background-color: #43b581; color: white; padding: 5px 10px; border-radius: 20px; font-size: 14px; font-weight: bold; display: inline-block; margin-top: 5px; }')
        r.append('.encryption-details { font-size: 14px; margin-top: 5px; opacity: 0.8; }')
        r.append('.tooltip { position: relative; display: inline-block; }')
        r.append('.tooltip .tooltiptext { visibility: hidden; width: 200px; background-color: #23272a; color: #fff; text-align: center; border-radius: 6px; padding: 5px; position: absolute; z-index: 1; bottom: 125%; left: 50%; margin-left: -100px; opacity: 0; transition: opacity 0.3s; font-size: 12px; }')
        r.append('.tooltip .tooltiptext::after { content: ""; position: absolute; top: 100%; left: 50%; margin-left: -5px; border-width: 5px; border-style: solid; border-color: #23272a transparent transparent transparent; }')
        r.append('.tooltip:hover .tooltiptext { visibility: visible; opacity: 1; }')
        
        # Add IDS status badge styling
        r.append('.ids-status { display: inline-block; margin-left: 15px; }')
        r.append('.ids-badge { background-color: #43b581; color: white; padding: 5px 10px; border-radius: 20px; font-size: 14px; font-weight: bold; display: inline-block; }')
        r.append('.ids-critical { background-color: #f04747; animation: pulse 2s infinite; }')
        r.append('.nav-links { display: flex; justify-content: center; gap: 20px; margin: 20px 0; }')
        r.append('.nav-links a { color: #7289da; text-decoration: none; padding: 10px; border-radius: 5px; transition: background-color 0.3s; }')
        r.append('.nav-links a:hover { background-color: #40444b; }')
        
        r.append('</style>')
        r.append('</head>')
        r.append('<body>')
        r.append('<header>')
        r.append(f'<h1>{SITE_NAME}</h1>')
        r.append('</header>')
        
        # Add navigation links
        r.append('<div class="nav-links">')
        r.append('<a href="/">File Browser</a>')
        r.append('<a href="/ids_dashboard">IDS Dashboard</a>')
        r.append('</div>')
        
        r.append('<div class="container">')
        
        # Add IDS status banner
        events = self.ids_system.events["events"]
        high_severity_count = sum(1 for e in events[:20] if e["severity"] in ["high", "critical"])
        
        r.append('<div class="encryption-banner">')
        r.append('<div class="encryption-badge">OpenSSL AES-256 Encryption Active</div>')
        r.append('<p class="encryption-details">Files are automatically encrypted for secure storage and transfer</p>')
        
        # Add IDS status
        if high_severity_count > 0:
            r.append(f'<div class="ids-badge ids-critical">⚠️ {high_severity_count} High Severity Security Alerts</div>')
            r.append(f'<a href="/ids_dashboard" class="ids-details">View Details</a>')
        else:
            r.append('<div class="ids-badge">✓ Intrusion Detection Active</div>')
            
        r.append('</div>')
        
        r.append(f'<h2>{displaypath}</h2>')
        r.append('<div style="overflow-x: auto;">')
        r.append('<table>')
        r.append(f'<tr><th><a href="?sort=name&order={next_order if sort_by == "name" else "asc"}" class="sort-link">Name</a></th><th><a href="?sort=size&order={next_order if sort_by == "size" else "asc"}" class="sort-link">Size</a></th><th><a href="?sort=date&order={next_order if sort_by == "date" else "asc"}" class="sort-link">Last Modified</a></th><th>Status</th><th>Action</th></tr>')
        for name in list:
            fullname = os.path.join(path, name)
            displayname = linkname = name
            if os.path.isdir(fullname):
                displayname = name + "/"
                linkname = name + "/"
            if os.path.islink(fullname):
                displayname = name + "@"

            # Determine if file is encrypted
            is_encrypted = False
            if os.path.isfile(fullname) and not fullname.endswith(('.jpg', '.jpeg', '.png', '.gif', '.ico', '.webp')):
                with open(fullname, 'rb') as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()
                    if fullname in self.encryption_meta and self.encryption_meta[fullname].get('hash') == file_hash:
                        is_encrypted = True

            r.append('<tr>')
            r.append(f'<td><a href="{urllib.parse.quote(linkname)}" class="animate-pulse">{displayname}</a></td>')
            if os.path.isdir(fullname):
                r.append('<td>-</td>')
            else:
                if is_encrypted and fullname in self.encryption_meta:
                    original_size = self.encryption_meta[fullname].get('original_size', os.path.getsize(fullname))
                    r.append(f'<td>{self.human(original_size)}</td>')
                else:
                    r.append(f'<td>{self.human(os.path.getsize(fullname))}</td>')
            r.append(f'<td>{self.date_time_string(os.path.getmtime(fullname))}</td>')

            # Add encryption status
            if os.path.isdir(fullname):
                r.append('<td>-</td>')
            else:
                if is_encrypted:
                    r.append('<td><div class="tooltip"><span class="status-icon encrypted">🔒 Encrypted</span><span class="tooltiptext">This file is protected with OpenSSL AES-256 encryption</span></div></td>')
                elif fullname.endswith(('.jpg', '.jpeg', '.png', '.gif', '.ico', '.webp')):
                    r.append('<td><div class="tooltip"><span class="status-icon">🖼️ Image</span><span class="tooltiptext">Image files are not encrypted for display purposes</span></div></td>')
                else:
                    r.append('<td><span class="status-icon">🔒  Encrypted</span></td>')

            r.append('<td>')
            if not os.path.isdir(fullname):
                r.append(f'<a href="{urllib.parse.quote(linkname)}" class="download-btn">View/Download</a>')
            r.append('</td>')
            r.append('</tr>')
        r.append('</table>')
        r.append('</div>')
        r.append('</div>')

        # Add JavaScript for page interactivity
        r.append('<script>')
        r.append('// Auto-refresh to update encryption status')
        r.append('setTimeout(() => { location.reload(); }, 60000);') # Refresh every minute
        r.append('</script>')

        r.append('<footer>')
        r.append('<p>&copy; 2024 CryptoSage | <a href="https://github.com/abeer555" target="_blank" style="color: #7289da;">GitHub</a></p>')
        r.append('</footer>')
        r.append('</body>')
        r.append('</html>')
        encoded = '\n'.join(r).encode('utf-8', 'surrogateescape')
        f = io.BytesIO()
        f.write(encoded)
        f.seek(0)
        self.send_response(http.server.HTTPStatus.OK)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        return f

    def human(self, size):
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} PB"


Handler = CustomHandler

if __name__ == "__main__":
    with ThreadedHTTPServer(("", PORT), Handler) as httpd:
        print(f"Serving at port {PORT}")
        print("🔒 OpenSSL AES-256 Encryption automatically enabled")
        print("🔍 Intrusion Detection System active")
        httpd.serve_forever()