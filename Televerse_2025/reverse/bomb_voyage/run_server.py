import http.server, socketserver, os

PORT=10002
print(f"Serving bomb binary on :{PORT}")
handler = http.server.SimpleHTTPRequestHandler
with socketserver.TCPServer(("https://breadcrumbs.eteteleverse.com/", PORT), handler) as httpd:
    httpd.serve_forever()
