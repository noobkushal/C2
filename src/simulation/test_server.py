"""
SAFE SIMULATION — NOT MALWARE
Local benign test server on 127.0.0.1:8888 for detector validation.
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import sys

class BenignRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(b"SAFE SIMULATION - NOT MALWARE - OK\n")

    def log_message(self, format, *args):
        # Suppress verbose HTTP log output
        pass

def run_test_server(host: str = "127.0.0.1", port: int = 8888):
    print("=" * 60)
    print("SAFE SIMULATION — NOT MALWARE")
    print(f"Starting local benign HTTP test server on http://{host}:{port}")
    print("=" * 60)
    server_address = (host, port)
    httpd = HTTPServer(server_address, BenignRequestHandler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping test server...")
        httpd.server_close()

if __name__ == "__main__":
    run_test_server()
