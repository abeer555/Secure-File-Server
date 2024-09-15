import http.server
import socketserver
import os
import io
import base64
import urllib
import re

PORT = 8000
USERNAME = "your_username"
PASSWORD = "your_password"
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

    def list_directory(self, path):
        try:
            list = os.listdir(path)
        except os.error:
            self.send_error(http.server.HTTPStatus.NOT_FOUND, "No permission to list directory")
            return None
        
        def natural_sort_key(s):
            return [int(text) if text.isdigit() else text.lower() for text in re.split('([0-9]+)', s)]
        
        # Get sorting parameters from query
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

        # Toggle sort order for next click
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
        r.append('header, footer { background-color: #2f3136; padding: 10px 20px; text-align: center; }')
        r.append('header h1, footer p { margin: 0; color: #7289da; }')
        r.append('.container { flex: 1; width: 80%; margin: 20px auto; padding: 20px; border: 1px solid #ddd; border-radius: 10px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); background-color: #2f3136; }')
        r.append('table { width: 100%; border-collapse: collapse; margin-top: 20px; }')
        r.append('th, td { padding: 12px 15px; border: 1px solid #2f3136; }')
        r.append('th { background-color: #7289da; color: #ffffff; }')
        r.append('a { text-decoration: none; color: inherit; transition: color 0.3s ease, transform 0.3s ease; }')
        r.append('a:hover { text-decoration: underline; color: inherit; transform: translateY(-2px); }')
        r.append('.download-btn { background-color: #7289da; color: white; padding: 8px 16px; border-radius: 5px; transition: background-color 0.3s ease, transform 0.3s ease; display: inline-block; text-align: center; margin: 10px auto; font-size: 14px; width: auto; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); }')
        r.append('.download-btn:hover { background-color: #677bc4; transform: translateY(-3px); box-shadow: 0 6px 8px rgba(0, 0, 0, 0.15); }')
        r.append('.sort-link { color: #ffffff; text-decoration: none; margin-right: 15px; transition: color 0.3s ease, transform 0.3s ease; font-weight: bold; }')
        r.append('.sort-link:hover { text-decoration: underline; transform: translateY(-3px); color: #ffffff; }')
        r.append('</style>')
        r.append('</head>')
        r.append('<body>')
        r.append('<header>')
        r.append(f'<h1>{SITE_NAME}</h1>')
        r.append('</header>')
        r.append('<div class="container">')
        r.append(f'<h2>{displaypath}</h2>')
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
            r.append(f'<td><a href="{urllib.parse.quote(linkname)}">{displayname}</a></td>')
            if os.path.isdir(fullname):
                r.append('<td>-</td>')
            else:
                r.append(f'<td>{self.human_readable_size(os.path.getsize(fullname))}</td>')
            r.append(f'<td>{self.date_time_string(os.path.getmtime(fullname))}</td>')
            r.append('<td>')
            if not os.path.isdir(fullname):
                r.append(f'<a href="{urllib.parse.quote(linkname)}" class="download-btn" download>Download</a>')
            r.append('</td>')
            r.append('</tr>')
        r.append('</table>')
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

    def human_readable_size(self, size):
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} PB"

Handler = CustomHandler

with CustomTCPServer(("", PORT), Handler) as httpd:
    print(f"Serving at port {PORT}")
    httpd.serve_forever()