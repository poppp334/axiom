#!/usr/bin/env python3
"""
Lightweight HTTP server for testing axiom locally.
Serves specific endpoints that exercise all four modules:
  - Fingerprinting (headers, cookies)
  - JS route extraction (script tags with API routes)
  - Secret patterns in exposed files
  - Soft-404 templates

Run: python tests/test_server.py
Then: python axiom.py http://127.0.0.1:8080 --scope "127.0.0.1"
"""

import http.server
import json
import os
import socketserver
from urllib.parse import urlparse

PORT = 8080

# Simulated secret file content
SECRET_JS = """
// app.js — exposed source
const API_KEY = "AKIA1234567890ABCDE";
const MONGO_URI = "mongodb://admin:secret123@localhost:27017/prod";
const TOKEN = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.sig";
fetch("/api/v1/users").then(r => r.json());
fetch("/api/graphql", { method: "POST" });
console.log("/webhook/stripe");
//# sourceMappingURL=app.js.map
"""

BACKUP_CONTENT = """password="SuperSecret2024"
db_host=localhost
api_key="FAKE_SECRET_KEY_12345678901234567890"
"""


class AxiomTestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # ── Fingerprint signals ──
        if path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Server", "Apache/2.4.41 (Ubuntu)")
            self.send_header("X-Powered-By", "PHP/8.1")
            self.send_header("Set-Cookie", "PHPSESSID=abc123xyz; path=/")
            self.end_headers()
            html = """<!DOCTYPE html>
<html>
<head>
    <title>Test Corp</title>
    <script src="/static/js/app.js"></script>
    <script src="/static/js/chunk-vendors.js"></script>
</head>
<body>
    <h1>Welcome to Test Corp</h1>
    <a href="/admin">Admin Panel</a>
    <a href="/api/docs">API Docs</a>
    <script>
        const routes = ["/api/v1/secret-endpoint", "/api/graphql", "/webhook/slack"];
    </script>
</body>
</html>"""
            self.wfile.write(html.encode())
            return

        # ── JS bundle with secrets & routes ──
        if path == "/static/js/app.js":
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.end_headers()
            self.wfile.write(SECRET_JS.encode())
            return

        if path == "/static/js/chunk-vendors.js":
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.end_headers()
            self.wfile.write(b'console.log("/api/v2/internal");')
            return

        # ── Admin panel (200, triggers recursive descent) ──
        if path == "/admin":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<h1>Admin Panel</h1>")
            return

        if path == "/admin/login":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<form>Login</form>")
            return

        if path == "/admin/config":
            self.send_response(403)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"Forbidden")
            return

        # ── API endpoints ──
        if path == "/api/v1/users":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"users": [{"id": 1, "name": "Alice"}]}')
            return

        if path == "/api/graphql":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"data": {"__schema": {}}}')
            return

        if path == "/api/v1/secret-endpoint":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"secret": "data"}')
            return

        # ── Exposed backup file with secrets ──
        if path == "/backup/config.old":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(BACKUP_CONTENT.encode())
            return

        # ── .env file ──
        if path == "/.env":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b'DB_PASSWORD="ProdPass2024"\nJWT_SECRET="eyJhbGciOiJIUzI1NiJ9.supersecret"\n')
            return

        # ── Soft-404 template (generic 404 page) ──
        if path == "/swagger" or path.startswith("/v1/") or path.startswith("/api/v2"):
            self.send_response(404)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>404 Not Found</h1><p>The page you requested does not exist.</p></body></html>")
            return

        if path == "/api/docs":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<h1>API Documentation</h1>")
            return

        # ── Default: generic soft-404 ──
        self.send_response(404)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body><h1>404 Not Found</h1><p>The page you requested does not exist.</p></body></html>")


if __name__ == "__main__":
    with socketserver.TCPServer(("", PORT), AxiomTestHandler) as httpd:
        print(f"axiom test server running on http://127.0.0.1:{PORT}")
        print("Endpoints:")
        print("  /                       — HTML with PHP headers, script tags")
        print("  /static/js/app.js       — JS with secrets + API routes")
        print("  /static/js/chunk-vendors.js — JS with internal route")
        print("  /admin                  — 200 (triggers recursion)")
        print("  /admin/login            — 200 (recursion hit)")
        print("  /admin/config           — 403")
        print("  /api/v1/users           — 200 JSON")
        print("  /api/graphql            — 200 GraphQL")
        print("  /api/v1/secret-endpoint — 200 JSON")
        print("  /api/docs               — 200 HTML")
        print("  /backup/config.old      — 200 with password + API key")
        print("  /.env                   — 200 with DB password + JWT")
        print("  /swagger, /v1/*, /api/v2/* — 404 (soft-404 cluster)")
        print("\nPress Ctrl+C to stop")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nServer stopped.")
