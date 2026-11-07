"""Tiny HTTP server that redirects all requests to HTTPS on port 8750."""
import http.server
import os

HTTPS_PORT = os.environ.get("CSFV2_PORT", "8750")


class RedirectHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        host = self.headers.get("Host", "").split(":")[0]
        target = f"https://{host}:{HTTPS_PORT}{self.path}"
        self.send_response(301)
        self.send_header("Location", target)
        self.end_headers()

    do_POST = do_GET
    do_HEAD = do_GET

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    port = int(os.environ.get("CSFV2_HTTP_PORT", "8080"))
    server = http.server.HTTPServer(("0.0.0.0", port), RedirectHandler)
    print(f"HTTP redirect server on :{port} -> https://HOST:{HTTPS_PORT}")
    server.serve_forever()
