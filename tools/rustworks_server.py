#!/usr/bin/env python3
"""
Simple mock Rustworks API server for Rust Console Edition
Run with: python3 rustworks_server.py
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import os
import ssl

# Map file configuration
MAP_FILE_PATH = "/home/ryan/code/ps4/reversing/maps/proceduralmap.3000.806.17179869055.174.map"
MAP_FILE_NAME = os.path.basename(MAP_FILE_PATH)

class RustworksHandler(BaseHTTPRequestHandler):
    # Use HTTP/1.1 instead of default HTTP/1.0
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        print(f"[{self.address_string()}] {args[0]}")

    def send_json(self, data, status=200):
        try:
            response = json.dumps(data).encode('utf-8')
            print(f"  Response ({status}): {response[:500]}")
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', len(response))
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(response)
            print(f"  Response sent successfully")
        except Exception as e:
            print(f"  ERROR sending response: {e}")

    def do_GET(self):
        print(f"GET {self.path}")

        # Maintenance status - disabled
        if self.path == '/maintenance.json':
            self.send_json({
                "enabled": False,
                "error": "",
                "next_scheduled_whats_new_iso8601_utc": "2025-12-31T00:00:00.000Z",
                "server_list_delay_in_seconds": "5.0",
                "loc_sig": ""
            })

        # Localization/updates
        elif self.path.endswith('.json') and 'en-' in self.path:
            self.send_json({
                "revision": "20251201",
                "description": "Custom Server",
                "changes": [
                    {"type": "added", "change": "Custom server support enabled"},
                    {"type": "added", "change": "Hello world! From EarthOnion"}
                ]
            })

        # Promo videos
        elif '/skins/promo_videos' in self.path:
            self.send_json({"videos": []})

        # Region list - regions is an array of strings (region names)
        elif '/region/list' in self.path:
            self.send_json({
                "regions": ["us-east", "us-west", "eu", "asia"]
            })

        # Server list (GET)
        elif '/servers' in self.path or '/serverlist' in self.path or '/server/list' in self.path:
            # Response format from real servers.json
            self.send_json({
                "servers": [
                    {
                        "server_id": 1,
                        "name": "HelloYunho Server",
                        "seed": "12345",
                        "world_size": "3000",
                        "max_players": 100,
                        "platform": "psn",
                        "region": "US | East",
                        "stable": True
                    }
                ],
                "last_updated": "Mon, 08 Dec 2025 00:00:00 GMT"
            })

        # Skin data
        elif '/skins' in self.path:
            self.send_json({"skins": []})

        # User stats
        elif '/stats' in self.path:
            self.send_json({})

        # Login/auth
        elif '/login' in self.path or '/auth' in self.path:
            self.send_json({
                "success": True,
                "token": "fake_token_12345",
                "user_id": 12345
            })

        # Serve map file
        elif '/maps/' in self.path or self.path.endswith('.map'):
            self.serve_map_file()

        # Default - return empty success
        else:
            print(f"  -> Unknown endpoint, returning empty response")
            self.send_json({})

    def serve_map_file(self):
        """Serve the custom map file"""
        try:
            if not os.path.exists(MAP_FILE_PATH):
                print(f"  ERROR: Map file not found: {MAP_FILE_PATH}")
                self.send_error(404, "Map file not found")
                return

            file_size = os.path.getsize(MAP_FILE_PATH)
            print(f"  Serving map file: {MAP_FILE_NAME} ({file_size} bytes)")

            self.send_response(200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Length', file_size)
            self.send_header('Content-Disposition', f'attachment; filename="{MAP_FILE_NAME}"')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Connection', 'close')
            self.end_headers()

            # Stream the file in chunks
            with open(MAP_FILE_PATH, 'rb') as f:
                while True:
                    chunk = f.read(65536)  # 64KB chunks
                    if not chunk:
                        break
                    self.wfile.write(chunk)

            print(f"  Map file sent successfully")
        except Exception as e:
            print(f"  ERROR serving map: {e}")
            self.send_error(500, str(e))

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length > 0 else b''

        print(f"POST {self.path}")
        print(f"  Headers: {dict(self.headers)}")
        if body:
            try:
                print(f"  Body: {body.decode('utf-8')}")
            except:
                print(f"  Body (raw): {body[:500]}")

        # Login endpoint
        if '/login' in self.path:
            self.send_json({
                "success": True,
                "access_token": "fake_access_token",
                "user_id": 12345,
                "network_protocol": 1
            })

        # Server list endpoint (POST)
        elif '/server/list' in self.path:
            # Parse request to get page info
            page = 1
            try:
                if body:
                    req_data = json.loads(body.decode('utf-8'))
                    page = req_data.get('page', 1)
            except:
                pass

            # Response format from decompiled b__99_0 lambda (server entry parser):
            # JSON keys found by tracing string literal addresses in disassembly:
            # server_id, name, description, owner_id, type (string: "community"/"official"),
            # next_save_wipe, next_blueprint_wipe, region_code, platform, password (bool),
            # worldsize (not world_size!), seed, max_players, active_players,
            # game_time, up_since, public_ip (not ip_address!), ping_port
            #
            # LOCAL SERVER CONFIG: Point to local Python LiteNetLib server for packet analysis
            # Change LOCAL_SERVER_IP to your PC's IP address on the network
            LOCAL_SERVER_IP = "192.168.0.111"  # Local Python server IP
            RUSTWORKS_IP = "192.168.0.111"    # This server's IP (rustworks)
            MAP_URL = f"http://{RUSTWORKS_IP}:9000/maps/{MAP_FILE_NAME}"

            self.send_json({
                "servers": [
                    {
                        "server_id": 1,
                        "name": "Local LiteNetLib Test Server",
                        "description": "Testing unencrypted connection",
                        "owner_id": 12345,
                        "type": "community",
                        "next_save_wipe": "",
                        "next_blueprint_wipe": "",
                        "region_code": "us-east",
                        "platform": "crossplay",
                        "password": False,
                        "worldsize": 3000,
                        "seed": 806,
                        "levelurl": MAP_URL,
                        "max_players": 100,
                        "active_players": 0,
                        "game_time": "12:00",
                        "up_since": "2025-12-09T00:00:00Z",
                        "public_ip": LOCAL_SERVER_IP,
                        "port": 28915,
                        "ping_port": 28915
                        # No dtls field - server list entry doesn't need it
                    },
                    {
                        "server_id": 2,
                        "name": "G-Portal Server (DTLS Encrypted)",
                        "description": "Original G-Portal server - requires DTLS",
                        "owner_id": 12345,
                        "type": "community",
                        "next_save_wipe": "",
                        "next_blueprint_wipe": "",
                        "region_code": "us-east",
                        "platform": "crossplay",
                        "password": False,
                        "worldsize": 1500,
                        "seed": 1647828828,
                        "max_players": 100,
                        "active_players": 0,
                        "game_time": "12:00",
                        "up_since": "2025-12-09T00:00:00Z",
                        "public_ip": "209.126.13.95",
                        "ping_port": 28915
                    }
                ],
                "meta": {
                    "page": page,
                    "page_size": 50,
                    "results": 1
                }
            })

        # Region list endpoint (POST)
        elif '/region/list' in self.path:
            self.send_json({
                "regions": ["us-east", "us-west", "eu", "asia"]
            })

        # Connect endpoint - returns connection credentials
        # Endpoint format: /server/{server_id}/connect
        elif '/connect' in self.path:
            # Parse request to get server_id (might also be in URL path)
            server_id = 1
            try:
                if body:
                    req_data = json.loads(body.decode('utf-8'))
                    server_id = req_data.get('server_id', 1)
                    print(f"  Connect request for server_id: {server_id}")
            except:
                pass

            # Response format based on string literals found in binary:
            # Field names at indexes: ip (10004), full (10005), dtls (10006), port (5010)
            #
            # LOCAL SERVER CONFIG
            LOCAL_SERVER_IP = "192.168.0.111"  # Local Python server IP
            RUSTWORKS_IP = "192.168.0.111"    # This server's IP (rustworks)
            MAP_URL = f"http://{RUSTWORKS_IP}:9000/maps/{MAP_FILE_NAME}"

            if server_id == 1:
                # Local LiteNetLib server - no DTLS
                # JSON keys from stringliteral.json:
                #   ip (10004), full (10005), port (5010)
                #   dtls (10006) - MUST be omitted for non-DTLS, or a nested dict with:
                #     root (2541), client (2508), key (479)
                #
                # IMPORTANT: Do NOT include "dtls" key when DTLS is disabled!
                # The game expects dtls to be a nested dict, not a boolean.
                # If dtls key exists, it tries to read sub-keys from it and crashes.
                self.send_json({
                    "ip": LOCAL_SERVER_IP,
                    "port": 28915,  # Local Python LiteNetLib server port
                    "full": False,
                    "levelurl": MAP_URL
                    # No "dtls" key = DTLS disabled
                })
            else:
                # G-Portal server - DTLS enabled
                # When DTLS is enabled, "dtls" must be a nested object with certificates
                self.send_json({
                    "ip": "209.126.13.95",
                    "port": 28915,
                    "full": False,
                    "dtls": {
                        "root": "",      # DTLSRootCertificate
                        "client": "",    # DTLSClientCertificate
                        "key": ""        # DTLSClientKey
                    }
                })

        # Default response
        else:
            self.send_json({"success": True})

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', '*')
        self.end_headers()

def run_server(port=9000, https_port=443):
    # Start HTTP server
    http_server = HTTPServer(('0.0.0.0', port), RustworksHandler)

    # Start HTTPS server
    https_server = HTTPServer(('0.0.0.0', https_port), RustworksHandler)
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(
        '/home/ryan/code/ps4/reversing/server.crt',
        '/home/ryan/code/ps4/reversing/server.key'
    )
    https_server.socket = ssl_context.wrap_socket(https_server.socket, server_side=True)

    print(f"Starting Rustworks mock server")
    print(f"  HTTP:  http://0.0.0.0:{port}")
    print(f"  HTTPS: https://0.0.0.0:{https_port}")
    print("Press Ctrl+C to stop")

    import threading
    http_thread = threading.Thread(target=http_server.serve_forever)
    http_thread.daemon = True
    http_thread.start()

    try:
        https_server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        http_server.shutdown()
        https_server.shutdown()

if __name__ == '__main__':
    run_server()
