import http.server
import socketserver
import os
import io
import base64
import urllib
import re
import mimetypes

PORT = 8000
USERNAME = "username"
PASSWORD = "password"
SITE_NAME = "CryptoSage's Room"

class CustomTCPServer(socketserver.TCPServer):
    allow_reuse_address = True

class CustomHandler(http.server.SimpleHTTPRequestHandler):
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
            fs = os.fstat(f.fileno())
            content_type, encoding = mimetypes.guess_type(path)
            if content_type is None:
                content_type = 'application/octet-stream'
            self.send_response(200)
            self.send_header("Content-type", content_type)
            self.send_header("Content-Length", str(fs[6]))
            self.send_header("Last-Modified", self.date_time_string(fs.st_mtime))
            self.end_headers()
            self.copyfile(f, self.wfile)
        finally:
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
        r.append('td:nth-child(3), td:nth-child(4), th:nth-child(3), th:nth-child(4) { text-align: center; }')
        r.append('a { text-decoration: none; color: #dcddde; transition: color 0.3s ease, transform 0.3s ease; }')
        r.append('a:hover { color: #ffffff; transform: translateY(-2px); }')
        r.append('.download-btn { background-color: #7289da; color: white; padding: 8px 16px; border-radius: 5px; transition: all 0.3s ease; display: inline-block; text-align: center; margin: 5px auto; font-size: 14px; width: auto; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); }')
        r.append('.download-btn:hover { background-color: #677bc4; transform: translateY(-3px) scale(1.05); box-shadow: 0 6px 8px rgba(0, 0, 0, 0.15); }')
        r.append('.sort-link { color: #ffffff; text-decoration: none; margin-right: 15px; transition: all 0.3s ease; font-weight: bold; }')
        r.append('.sort-link:hover { text-decoration: underline; transform: translateY(-3px); }')
        r.append('@media (max-width: 768px) { .container { width: 100%; padding: 10px; } table { font-size: 14px; } th, td { padding: 8px; } .download-btn { padding: 6px 12px; font-size: 12px; } .sort-link { margin-right: 10px; } td:nth-child(2), th:nth-child(2) { display: none; } }')
        r.append('@media (max-width: 480px) { table { font-size: 12px; } th, td { padding: 6px; } .download-btn { padding: 4px 8px; font-size: 10px; } .sort-link { margin-right: 5px; } }')
        r.append('@keyframes pulse { 0% { transform: scale(1); } 50% { transform: scale(1.05); } 100% { transform: scale(1); } }')
        r.append('.animate-pulse { animation: pulse 2s infinite; }')
        r.append('tr:hover { background-color: #40444b; }')
        r.append('</style>')
        r.append('</head>')
        r.append('<body>')
        r.append('<header>')
        r.append(f'<h1>{SITE_NAME}</h1>')
        r.append('</header>')
        r.append('<div class="container">')
        r.append(f'<h2>{displaypath}</h2>')
        r.append('<div style="overflow-x: auto;">')
        r.append('<table>')
        r.append(f'<tr><th><a href="?sort=name&order={next_order if sort_by == "name" else "asc"}" class="sort-link">Name</a></th><th><a href="?sort=size&order={next_order if sort_by == "size" else "asc"}" class="sort-link">Size</a></th><th><a href="?sort=date&order={next_order if sort_by == "date" else "asc"}" class="sort-link">Last Modified</a></th><th>Action</th></tr>')
        for name in list:
            fullname = os.path.join(path, name)
            displayname = linkname = name
            if os.path.isdir(fullname):
                displayname = name + "/"
                linkname = name + "/"
            if os.path.islink(fullname):
                displayname = name + "@"
            r.append('<tr>')
            r.append(f'<td><a href="{urllib.parse.quote(linkname)}" class="animate-pulse">{displayname}</a></td>')
            if os.path.isdir(fullname):
                r.append('<td>-</td>')
            else:
                r.append(f'<td>{self.human(os.path.getsize(fullname))}</td>')
            r.append(f'<td>{self.date_time_string(os.path.getmtime(fullname))}</td>')
            r.append('<td>')
            if not os.path.isdir(fullname):
                r.append(f'<a href="{urllib.parse.quote(linkname)}" class="download-btn">View/Download</a>')
            r.append('</td>')
            r.append('</tr>')
        r.append('</table>')
        r.append('</div>')
        r.append('</div>')
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

with CustomTCPServer(("", PORT), Handler) as httpd:
    print(f"Serving at port {PORT}")
    httpd.serve_forever()
