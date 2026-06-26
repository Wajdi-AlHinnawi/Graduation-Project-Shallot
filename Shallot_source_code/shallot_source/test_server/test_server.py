"""test_server/test_server.py

A very small local HTTP server used as the destination website for milestone 1.
"""

from http.server import BaseHTTPRequestHandler, HTTPServer
from shared.config import TEST_SERVER_HOST, TEST_SERVER_PORT


class DemoHandler(BaseHTTPRequestHandler):
    """Simple handler that returns a small HTML page."""

    def do_GET(self):
        print("-" * 90)
        print(f"[TEST_SERVER] GET request received for path: {self.path}")
        print(f"[TEST_SERVER] Client address = {self.client_address}")
        print("[TEST_SERVER] Request headers:")
        for header_name, header_value in self.headers.items():
            print(f"[TEST_SERVER]   {header_name}: {header_value}")

        body = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset=\"utf-8\">
    <title>Senior Project Onion Test Server</title>
</head>
<body>
    <h1>Hello from the destination test server</h1>
    <p>You reached path: <strong>{self.path}</strong></p>
    <p>If you see this page through the browser proxy, your onion path worked.</p>
</body>
</html>
""".strip().encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

        print(f"[TEST_SERVER] Response sent successfully ({len(body)} bytes)")
        print("-" * 90)

    def log_message(self, format, *args):
        print(f"[TEST_SERVER] {self.address_string()} - {format % args}")


def main() -> None:
    server = HTTPServer((TEST_SERVER_HOST, TEST_SERVER_PORT), DemoHandler)
    print(f"[TEST_SERVER] Listening on http://{TEST_SERVER_HOST}:{TEST_SERVER_PORT}")
    print("[TEST_SERVER] Waiting for destination requests...")
    server.serve_forever()


if __name__ == "__main__":
    main()
