#!/usr/bin/env python3
"""
Astra Mock Lab - Local Multi-Proxy Benchmarking Testbed
======================================================
Simulates a high-performance backend server and multiple forwarder proxies
with realistic behaviors (Healthy, 429 Rate-Limited, and Transient Errors)
to test Astra's load balancing, circuit breaking, and retry failover locally.
"""

import http.server
import socketserver
import threading
import urllib.request
import time
import sys
import subprocess
import os

TARGET_PORT = 18080
PROXIES = [
    {"port": 18081, "name": "Proxy-Alpha (Fast & Healthy)", "behavior": "healthy"},
    {"port": 18082, "name": "Proxy-Beta (Simulates 429 Rate-Limiting)", "behavior": "rate_limit"},
    {"port": 18083, "name": "Proxy-Gamma (Fast & Healthy)", "behavior": "healthy"},
]

class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

class TargetHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'{"status":"ok","engine":"astra-mock-backend"}'
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass

def make_proxy_handler(behavior):
    request_counter = [0]
    lock = threading.Lock()

    class ProxyHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            with lock:
                request_counter[0] += 1
                count = request_counter[0]

            # Behavior simulation
            if behavior == "rate_limit" and count % 4 == 0:
                body = b'{"error":"Too Many Requests","retry_after":2}'
                self.send_response(429)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.send_header('Retry-After', '2')
                self.end_headers()
                self.wfile.write(body)
                return

            # Forward to target
            if self.path.startswith("http://") or self.path.startswith("https://"):
                target_url = self.path
            else:
                target_url = f"http://127.0.0.1:{TARGET_PORT}{self.path}"
            try:
                req = urllib.request.Request(target_url)
                with urllib.request.urlopen(req, timeout=2.0) as resp:
                    resp_body = resp.read()
                    self.send_response(resp.status)
                    for k, v in resp.headers.items():
                        self.send_header(k, v)
                    self.end_headers()
                    self.wfile.write(resp_body)
            except Exception:
                self.send_response(502)
                self.end_headers()

        def log_message(self, format, *args):
            pass

    return ProxyHandler

def start_servers():
    target_server = ThreadingTCPServer(('127.0.0.1', TARGET_PORT), TargetHandler)
    threading.Thread(target=target_server.serve_forever, daemon=True).start()

    proxy_servers = []
    for p in PROXIES:
        handler = make_proxy_handler(p["behavior"])
        server = ThreadingTCPServer(('127.0.0.1', p["port"]), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        proxy_servers.append(server)

    time.sleep(0.3)
    return target_server, proxy_servers

def create_mock_proxy_file(filename="mock_proxies.txt"):
    with open(filename, "w") as f:
        f.write("# Astra Mock Lab Proxies\n")
        for p in PROXIES:
            f.write(f"http://127.0.0.1:{p['port']}\n")
    return filename

def main():
    target_server, proxy_servers = start_servers()
    proxy_file = create_mock_proxy_file("mock_proxies.txt")

    print("═════════════════════════════════════════════════════════════════════")
    print("  🚀 Astra Local Mock Lab is READY")
    print("═════════════════════════════════════════════════════════════════════")
    print(f"  • Target Backend Server:  http://127.0.0.1:{TARGET_PORT}/")
    for p in PROXIES:
        print(f"  • {p['name']:<40} -> http://127.0.0.1:{p['port']}")
    print(f"  • Proxy List Saved to:   {proxy_file}")
    print("─────────────────────────────────────────────────────────────────────\n")

    if len(sys.argv) > 1 and sys.argv[1] == "--server-only":
        print("Servers are running in background. You can run Astra in another terminal:")
        print(f"  ./target/release/astra --url http://127.0.0.1:{TARGET_PORT}/api --proxy-file {proxy_file} -n 50000 --concurrency 50 --pipeline 3\n")
        print("Press Ctrl+C to stop the mock servers.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nShutting down mock lab.")
            return

    # Default: Run automated benchmark to demonstrate 100% success rate
    req_count = 5000
    if len(sys.argv) > 2 and sys.argv[1] == "--benchmark":
        req_count = int(sys.argv[2])

    print(f"▶ Running Astra Automated Benchmark ({req_count} requests)...")
    cmd = [
        "./target/release/astra",
        "--url", f"http://127.0.0.1:{TARGET_PORT}/api",
        "--proxy-file", proxy_file,
        "-n", str(req_count),
        "--concurrency", "25",
        "--pipeline", "2",
        "--retries", "3",
        "--retry-backoff", "15",
        "--proxy-fail-threshold", "2",
        "--proxy-cooldown", "3",
        "--no-tui"
    ]
    subprocess.run(cmd)

if __name__ == "__main__":
    main()
