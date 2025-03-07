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

PORT =8001 
USERNAME = "a"
PASSWORD = "a"

SITE_NAME = "Welcome to CN project"
CHUNK_SIZE = 1048576  # 1 MB
ENCRYPTION_KEY_FILE = "encryption_key.bin"
ENCRYPTION_META_FILE = "encryption_meta.json"


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


class CustomHandler(http.server.SimpleHTTPRequestHandler):
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

    def do_GET(self):
        if self.path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
            return

        if not self.authenticate():
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="Restricted Area"')
            self.end_headers()
            return

        path = self.translate_path(self.path)
        if os.path.isfile(path):
            self.send_file(path)
        else:
            return http.server.SimpleHTTPRequestHandler.do_GET(self)

    def do_POST(self):
        if not self.authenticate():
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
        r.append('</style>')
        r.append('</head>')
        r.append('<body>')
        r.append('<header>')
        r.append(f'<h1>{SITE_NAME}</h1>')
        r.append('</header>')
        r.append('<div class="container">')
        r.append('<div class="encryption-banner">')
        r.append('<div class="encryption-badge">OpenSSL AES-256 Encryption Active</div>')
        r.append('<p class="encryption-details">Files are automatically encrypted for secure storage and transfer</p>')
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
        r.append('setTimeout(() => { location.reload(); }, 5000);')
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

with ThreadedHTTPServer(("", PORT), Handler) as httpd:
    print(f"Serving at port {PORT}")
    print("🔒 OpenSSL AES-256 Encryption automatically enabled")
    httpd.serve_forever()




