#!/usr/bin/env python3
"""
Rust Console Edition Server - LiteNetLib based
Implements Facepunch's LiteNetLib variant + Rust game protocol
"""

import socket
import struct
import time
import threading
import json
from enum import IntEnum
from dataclasses import dataclass
from typing import Dict, Optional
import traceback

# =============================================================================
# LiteNetLib Protocol
# =============================================================================

class PacketProperty(IntEnum):
    """LiteNetLib packet types"""
    Unreliable = 0
    Channeled = 1
    Ack = 2
    Ping = 3
    Pong = 4
    ConnectRequest = 5
    ConnectAccept = 6
    Disconnect = 7
    UnconnectedMessage = 8
    MtuCheck = 9
    MtuOk = 10
    Broadcast = 11
    Merged = 12
    ShutdownOk = 13
    PeerNotFound = 14
    InvalidProtocol = 15
    NatMessage = 16
    Empty = 17

# =============================================================================
# Rust Console Edition Message Types (from reverse engineering)
# =============================================================================

class Message(IntEnum):
    """Rust network message types - matches PC Rust server"""
    First = 0
    Welcome = 1
    Auth = 2
    Approved = 3
    Ready = 4
    Entities = 5
    EntityDestroy = 6
    GroupChange = 7
    GroupDestroy = 8
    RPCMessage = 9
    EntityPosition = 10
    ConsoleMessage = 11
    ConsoleCommand = 12
    Effect = 13
    DisconnectReason = 14
    Tick = 15
    Message_ = 16  # Renamed to avoid conflict with class name
    RequestUserInformation = 17
    GiveUserInformation = 18
    GroupEnter = 19
    GroupLeave = 20
    VoiceData = 21
    EAC = 22
    EntityFlags = 23
    World = 24
    ConsoleReplicatedVars = 25
    QueueUpdate = 26
    SyncVar = 27
    PackedSyncVar = 28

# =============================================================================
# DTLS.prx Hash Calculation (for Console Edition packet validation)
# =============================================================================

def calculate_dtls_hash(payload: bytes) -> int:
    """
    Calculate DTLS.prx hash checksum for Console Edition packets.

    This matches the algorithm in DTLS.prx FUN_01040b70:
    - Start with seed 0x743eb7
    - For each byte: seed = seed * 3 + byte
    - Add packet length
    - Return bottom 4 bits
    """
    seed = 0x743eb7
    for byte in payload:
        seed = (seed * 3 + byte) & 0xFFFFFFFF  # Keep as 32-bit

    checksum = (len(payload) + seed) & 0xF  # Bottom 4 bits
    return checksum

def inject_dtls_hash(packet: bytearray) -> bytearray:
    """
    Inject DTLS.prx hash into packet header.

    DTLS.prx validates ALL packets by checking:
    - Top 4 bits of byte 3 must match hash(entire_packet) & 0xF

    For Channeled packets, byte 3 format is: [Hash(4 bits)][Channel(4 bits)]
    For Ping/Pong packets, byte 3 format is: [Hash(4 bits)][Data(4 bits)]
    """
    if len(packet) < 4:
        return packet  # Too short, can't inject hash

    # Calculate hash with byte 3 top bits cleared (PS4 approach)
    original_byte3 = packet[3]
    packet[3] = packet[3] & 0x0F  # Clear top 4 bits
    checksum = calculate_dtls_hash(packet)

    # Inject hash into top 4 bits of byte 3, preserving bottom 4 bits (channel/data)
    packet[3] = (packet[3] & 0x0F) | (checksum << 4)

    # Debug: verify hash
    if len(packet) <= 16:
        verify_hash = calculate_dtls_hash(packet)
        if verify_hash != checksum:
            print(f"[HASH] WARNING: Hash mismatch! Calculated: 0x{checksum:x}, Verify: 0x{verify_hash:x}")
        print(f"[HASH] Packet: {packet.hex()} | Hash: 0x{checksum:x} | Byte3: 0x{original_byte3:02x}->0x{packet[3]:02x}")

    return packet

# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class Peer:
    """Connected peer information"""
    id: int
    addr: tuple
    state: str
    connect_time: float
    username: str = ""
    user_id: int = 0
    sequence_out: int = 0x420  # Start at 1056 to pass DTLS.prx validation (bits[5:9]=0, bits[10:14]=8)
    sequence_in: int = 0
    connection_number: int = 0  # LiteNetLib ConnectionNumber (0-3)

# =============================================================================
# Server Implementation
# =============================================================================

class RustConsoleServer:
    def __init__(self, host='0.0.0.0', port=28915):
        self.host = host
        self.port = port
        self.sock = None
        self.running = False
        self.peers: Dict[tuple, Peer] = {}
        self.next_peer_id = 1

        # Server info
        self.server_name = "PS4 Test Server"
        self.max_players = 100
        self.world_size = 3000
        self.seed = 12345
        self.protocol_version = 2615  # Rust protocol version

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.settimeout(0.5)
        self.running = True

        print(f"=" * 60)
        print(f"Rust Console Edition Server")
        print(f"=" * 60)
        print(f"Listening: {self.host}:{self.port}")
        print(f"Server: {self.server_name}")
        print(f"=" * 60)

        # Start keepalive thread
        keepalive_thread = threading.Thread(target=self.keepalive_loop, daemon=True)
        keepalive_thread.start()

        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
                self.handle_packet(data, addr)
            except socket.timeout:
                continue
            except Exception as e:
                print(f"[ERROR] {e}")
                traceback.print_exc()

    def stop(self):
        self.running = False
        if self.sock:
            self.sock.close()

    def keepalive_loop(self):
        """Send periodic pings to keep connections alive"""
        while self.running:
            time.sleep(5)
            for addr, peer in list(self.peers.items()):
                if peer.state == 'connected':
                    # Could send ping here if needed
                    pass

    # =========================================================================
    # Send Functions
    # =========================================================================

    def send_packet(self, packet: bytes, addr: tuple, description: str = ""):
        """
        Send a packet with DTLS.prx hash injection for Console Edition.

        All outgoing packets must have the hash checksum injected into
        the top 4 bits of byte 3, otherwise PS4 DTLS.prx will reject them.
        """
        packet = bytearray(packet)

        # Inject DTLS.prx hash checksum
        packet = inject_dtls_hash(packet)

        if description:
            print(f"[SEND] {description} ({len(packet)}B): {packet.hex()}")

        self.sock.sendto(bytes(packet), addr)

    def send_channeled(self, addr: tuple, channel: int, payload: bytes):
        """Send a reliable channeled packet"""
        peer = self.peers.get(addr)
        if not peer:
            return

        # CRITICAL: Use sequence 0x0420 which passes bit sequence validation
        # The validation checks (uint32 >> 5 & 0x1f) < (uint32 >> 10 & 0x1f)
        # With seq=0x0420, this passes regardless of hash value in byte 3
        seq = 0x0420

        # Build header with ConnectionNumber
        header = PacketProperty.Channeled | (peer.connection_number << 5)

        packet = bytearray()
        packet.append(header)                     # Header with ConnectionNumber
        packet.extend(struct.pack('<H', seq))    # Sequence (2 bytes)
        packet.append(channel)                    # Channel (1 byte)
        packet.extend(payload)                    # Payload

        self.send_packet(packet, addr, f"Channeled Seq={seq} Ch={channel} ConnNum={peer.connection_number} Payload={len(payload)}B")

    def send_as_ping(self, addr: tuple, payload: bytes):
        """Send payload disguised as a Ping packet - gets queued directly without filtering"""
        peer = self.peers.get(addr)
        if not peer:
            return

        seq = peer.sequence_out
        peer.sequence_out = (peer.sequence_out + 1) & 0xFFFF

        # Ping packet header
        header = PacketProperty.Ping | (peer.connection_number << 5)

        packet = bytearray()
        packet.append(header)                     # Header with ConnectionNumber
        packet.extend(struct.pack('<H', seq))    # Sequence (2 bytes)
        packet.append(0)                          # Byte 3 (will get hash injected)
        packet.extend(payload)                    # Payload

        self.send_packet(packet, addr, f"Ping(game message) Seq={seq} ConnNum={peer.connection_number} Payload={len(payload)}B")

    def send_fragment_ack_ordered(self, addr: tuple, payload: bytes):
        """Send a FragmentAckOrdered packet using Pong packet type (ReliableOrdered delivery)"""
        peer = self.peers.get(addr)
        if not peer:
            return

        seq = peer.sequence_out
        peer.sequence_out = (peer.sequence_out + 1) & 0xFFFF

        # Use Pong packet type (4) - DTLS.prx interprets this as FRAGMENT_ACK_ORDERED delivery
        header = PacketProperty.Pong | (peer.connection_number << 5)

        packet = bytearray()
        packet.append(header)                     # Header with ConnectionNumber
        packet.extend(struct.pack('<H', seq))    # Sequence (2 bytes)

        # For Pong packets, byte 3 is part of timestamp structure, not fragment info
        # Pad to 11 bytes like real Pong packets to ensure correct DTLS interpretation
        # Structure: [header(1)][seq(2)][timestamp(8)]
        ticks = int(time.time() * 10000000) + 621355968000000000  # .NET ticks
        packet.extend(struct.pack('<q', ticks))   # 8-byte timestamp

        # Now append payload AFTER the timestamp structure
        # This makes it 11+ bytes, matching Pong packet structure
        packet.extend(payload)                    # Payload

        print(f"[FRAG] Pre-hash packet: {packet.hex()} | byte3={packet[3]:02x} bottom4={packet[3]&0xF}")
        self.send_packet(packet, addr, f"Pong/FragmentAckOrdered Seq={seq} ConnNum={peer.connection_number} Payload={len(payload)}B")
        print(f"[FRAG] Post-hash packet: {packet.hex()} | byte3={packet[3]:02x} bottom4={packet[3]&0xF}")

    def send_rust_message(self, addr: tuple, msg_type: int, payload: bytes = b''):
        """Send a Rust game message using Channeled packet - DTLS.prx hook redirects to Ping queue"""
        # Rust message format: type byte + payload
        rust_msg = bytearray()
        rust_msg.append(msg_type)
        rust_msg.extend(payload)

        print(f"[RUST] Sending {Message(msg_type).name} ({msg_type}): {rust_msg.hex()}")
        # Use Channeled packet type (1) - DTLS.prx hook will redirect to Ping queue!
        # send_channeled(addr, channel, payload)
        self.send_channeled(addr, 0, bytes(rust_msg))

    def send_request_user_info(self, addr: tuple):
        """Send RequestUserInformation message to client"""
        print(f"[RUST] >>> Sending RequestUserInformation to {addr}")
        self.send_rust_message(addr, Message.RequestUserInformation)

    # =========================================================================
    # Packet Handling
    # =========================================================================

    def handle_packet(self, data: bytes, addr: tuple):
        if len(data) < 1:
            return

        # Log ALL incoming data for debugging
        print(f"\n[RAW] {addr[0]}:{addr[1]} | {len(data)}B | {data[:64].hex()}")
        if all(32 <= b < 127 or b in (10, 13) for b in data[:20]):
            print(f"       ASCII: {data[:64]}")

        # Check for CONN magic
        if len(data) >= 4 and data[:4] == b'CONN':
            self.handle_conn(data, addr)
            return

        # Parse LiteNetLib header
        header = data[0]
        packet_type = header & 0x1F
        conn_num = (header >> 5) & 0x03
        is_frag = (header >> 7) & 0x01

        type_name = PacketProperty(packet_type).name if packet_type <= 17 else f"Unknown({packet_type})"

        # Log ALL packets for debugging
        print(f"[LNL] {addr[0]}:{addr[1]} | {type_name} | connNum={conn_num} frag={is_frag} | {len(data)}B")
        if packet_type not in [PacketProperty.Ping, PacketProperty.Pong]:
            print(f"       Hex: {data[:48].hex()}")

        # Handle by type
        handlers = {
            PacketProperty.ConnectRequest: self.handle_connect_request,
            PacketProperty.ConnectAccept: self.handle_connect_accept,
            PacketProperty.Ping: self.handle_ping,
            PacketProperty.Pong: self.handle_pong,
            PacketProperty.Disconnect: self.handle_disconnect,
            PacketProperty.Channeled: self.handle_channeled,
            PacketProperty.Unreliable: self.handle_unreliable,
            PacketProperty.MtuCheck: self.handle_mtu_check,
            PacketProperty.Ack: self.handle_ack,
        }

        handler = handlers.get(packet_type)
        if handler:
            handler(data, addr)

    def handle_conn(self, data: bytes, addr: tuple):
        """Handle Facepunch CONN magic packet"""
        print(f"\n{'='*60}")
        print(f"[CONN] New connection from {addr}")
        print(f"       Full data ({len(data)} bytes): {data.hex()}")
        print(f"       ASCII: {data}")
        print(f"{'='*60}")

        # Create peer
        peer_id = self.next_peer_id
        self.next_peer_id += 1

        # Generate connect_time - use .NET ticks (100ns intervals since 0001-01-01)
        connect_time = int(time.time() * 10000000) + 621355968000000000
        print(f"[CONN] Generated connect_time: {connect_time}")

        self.peers[addr] = Peer(
            id=peer_id,
            addr=addr,
            state='connecting',
            connect_time=connect_time
        )

        # DON'T echo CONN! The CONN handshake is handled by DTLS.prx natively
        # The PS4 will move on to LiteNetLib Ping packets after CONN
        # We just track that we saw CONN and wait for the first Ping
        self.peers[addr].state = 'conn_received'
        print(f"[CONN] CONN received from native DTLS layer, waiting for LiteNetLib Ping...")

    def handle_connect_request(self, data: bytes, addr: tuple):
        """Handle standard LiteNetLib ConnectRequest"""
        print(f"[ConnectRequest] from {addr}")
        if len(data) >= 18:
            protocol_id = struct.unpack('<Q', data[1:9])[0]
            connect_time = struct.unpack('<Q', data[9:17])[0]
            print(f"  Protocol: {protocol_id}, ConnectTime: {connect_time}")

        # Accept connection
        peer_id = self.next_peer_id
        self.next_peer_id += 1

        self.peers[addr] = Peer(
            id=peer_id,
            addr=addr,
            state='connected',
            connect_time=time.time()
        )

        # Send accept
        response = bytearray()
        response.append(PacketProperty.ConnectAccept)
        response.extend(struct.pack('<Q', int(time.time() * 1000)))
        response.append(peer_id & 0xFF)

        self.send_packet(response, addr, "ConnectAccept")

    def handle_ping(self, data: bytes, addr: tuple):
        """Handle ping, send pong"""
        if len(data) < 3:
            print(f"[PING] Too short: {len(data)}B")
            return

        # Parse ping sequence
        seq = struct.unpack('<H', data[1:3])[0]

        # Extract and store ConnectionNumber
        ping_header = data[0]
        conn_num = (ping_header >> 5) & 0x03

        peer = self.peers.get(addr)
        ping_count = getattr(peer, 'ping_count', 0) + 1 if peer else 1
        if peer:
            peer.ping_count = ping_count
            # Store ConnectionNumber from first ping
            if peer.connection_number == 0:
                peer.connection_number = conn_num
                print(f"[PING] Stored ConnectionNumber={conn_num} for {addr}")

            # Send ConnectAccept to complete LiteNetLib handshake
            # DISABLED: Causing bad packet issues
            # if peer.state == 'conn_received':
            #     print(f"[PING] First ping after CONN - sending ConnectAccept")
            #     # Send ConnectAccept
            #     response = bytearray()
            #     response.append(PacketProperty.ConnectAccept | (peer.connection_number << 5))
            #     response.extend(struct.pack('<Q', int(time.time() * 1000)))  # Timestamp
            #     response.append(peer.id & 0xFF)  # Peer ID
            #     self.send_packet(response, addr, "ConnectAccept")
            #     peer.state = 'awaiting_rtt'

            # Transition state manually after first ping
            if peer.state == 'conn_received':
                peer.state = 'awaiting_rtt'

        print(f"[PING #{ping_count}] Seq={seq} connNum={conn_num} from {addr}")
        print(f"       Ping hex: {data.hex()}")

        # Send 11-byte Pong with timestamp (standard LiteNetLib format)
        # IMPORTANT: Preserve ConnectionNumber from ping header!
        pong_header = PacketProperty.Pong | (conn_num << 5)

        pong = bytearray()
        pong.append(pong_header)  # Header with ConnectionNumber preserved
        pong.extend(data[1:3])  # Sequence (2 bytes)
        ticks = int(time.time() * 10000000) + 621355968000000000  # .NET ticks
        pong.extend(struct.pack('<q', ticks))
        print(f"[PONG] Sending 11B (connNum={conn_num} seq={seq}):")
        print(f"       Header: 0x{pong_header:02x} | Seq: {seq} | Ticks: {ticks}")
        print(f"       Hex: {pong.hex()}")
        self.send_packet(pong, addr)

        # After 3rd ping, start sending our own pings and then RequestUserInformation
        if peer and peer.state == 'awaiting_rtt' and ping_count == 3:
            print(f"[RTT] Client RTT measured, now sending server Pings...")
            peer.state = 'server_ping'
            # Send server-initiated ping with correct ConnectionNumber
            # IMPORTANT: Must be at least 4 bytes for DTLS.prx validation!
            # Use different sequence than Channeled packets to avoid collision
            server_ping_header = PacketProperty.Ping | (peer.connection_number << 5)
            server_ping = bytearray()
            server_ping.append(server_ping_header)
            server_ping.extend(struct.pack('<H', 0x440))  # Sequence 0x440 (different from Channeled seq 0x420)
            server_ping.append(0)  # Padding byte to make it 4 bytes minimum
            print(f"[PING] Server sending 4B (connNum={peer.connection_number}): {server_ping.hex()}")
            self.send_packet(server_ping, addr, "ServerPing")


    def handle_pong(self, data: bytes, addr: tuple):
        """Handle pong response from client (may contain FragmentAckOrdered with payload)"""
        if len(data) >= 3:
            seq = struct.unpack('<H', data[1:3])[0]
            print(f"[PONG RECV] Seq={seq} from {addr} | Full data ({len(data)}B): {data.hex()}")

            # Send ACK back to the client for this packet
            peer = self.peers.get(addr)
            if peer and len(data) > 3:
                channel = data[3] if len(data) > 3 else 0
                ack_packet = bytearray()
                ack_packet.append(PacketProperty.Ack | (peer.connection_number << 5))
                ack_packet.extend(struct.pack('<H', seq))
                ack_packet.append(channel)
                self.send_packet(ack_packet, addr, f"ACK seq={seq}")

            # Check if there's payload data beyond the header (FragmentAckOrdered)
            if len(data) > 11:  # Pong header + timestamp = 11 bytes
                payload = data[11:]
                print(f"[PONG] Has payload ({len(payload)}B): {payload.hex()}")
                print(f"[PONG] Possible message type: {payload[0] if len(payload) > 0 else 'N/A'}")
                # Try to process as Rust message
                if len(payload) > 0:
                    self.handle_rust_message(payload, addr)

    def handle_disconnect(self, data: bytes, addr: tuple):
        """Handle disconnect"""
        print(f"[DISCONNECT] {addr}")

        if addr in self.peers:
            del self.peers[addr]

        # Send ShutdownOk
        self.send_packet(bytes([PacketProperty.ShutdownOk]), addr, "ShutdownOk")

    def handle_mtu_check(self, data: bytes, addr: tuple):
        """Handle MTU check"""
        print(f"[MTU] Check size={len(data)}")

        mtu_ok = bytearray([PacketProperty.MtuOk])
        mtu_ok.extend(data[1:])

        self.send_packet(mtu_ok, addr, "MtuOk")

    def handle_connect_accept(self, data: bytes, addr: tuple):
        """Handle ConnectAccept from client (Facepunch custom handshake)"""
        print(f"[ConnectAccept] Received from client: {data.hex()}")
        print(f"[ConnectAccept] Client acknowledging CONN handshake")

        # Send ConnectAccept back to complete bidirectional handshake
        peer = self.peers.get(addr)
        if peer:
            response = bytearray()
            response.append(PacketProperty.ConnectAccept | (peer.connection_number << 5))
            response.extend(struct.pack('<Q', int(time.time() * 1000)))  # Timestamp
            response.append(peer.id & 0xFF)  # Peer ID
            # Pad to 4 bytes minimum
            while len(response) < 4:
                response.append(0)
            self.send_packet(response, addr, "ConnectAccept (server)")
            print(f"[ConnectAccept] Sent ConnectAccept to client - handshake complete!")

            # Now that handshake is complete, send RequestUserInformation
            peer.state = 'connected'
            print(f"[GAME] Handshake complete, sending RequestUserInformation")
            self.send_request_user_info(addr)

    def handle_ack(self, data: bytes, addr: tuple):
        """Handle ACK"""
        if len(data) >= 4:
            seq = struct.unpack('<H', data[1:3])[0]
            channel = data[3]
            print(f"[ACK] Seq={seq} Ch={channel} | Data: {data.hex()}")

    def handle_unreliable(self, data: bytes, addr: tuple):
        """Handle unreliable packet"""
        payload = data[1:]
        print(f"[UNRELIABLE] {len(payload)}B: {payload[:32].hex()}")
        self.handle_rust_message(payload, addr)

    def handle_channeled(self, data: bytes, addr: tuple):
        """Handle reliable channeled packet"""
        if len(data) < 4:
            return

        seq = struct.unpack('<H', data[1:3])[0]
        channel = data[3]
        payload = data[4:]

        print(f"[CHANNELED] Seq={seq} Ch={channel} Payload={len(payload)}B")
        print(f"            Data: {payload[:64].hex()}")

        # Send ACK with same ConnectionNumber as received packet
        received_header = data[0]
        conn_num = (received_header >> 5) & 0x03
        ack_header = PacketProperty.Ack | (conn_num << 5)

        ack = bytearray()
        ack.append(ack_header)
        ack.extend(struct.pack('<H', seq))
        ack.append(channel)
        self.send_packet(ack, addr, "Ack")

        # Process game message
        self.handle_rust_message(payload, addr)

    # =========================================================================
    # Rust Game Protocol
    # =========================================================================

    def handle_rust_message(self, data: bytes, addr: tuple):
        """Parse and handle Rust game message"""
        if len(data) < 1:
            return

        msg_type = data[0]
        msg_data = data[1:]

        try:
            msg_name = Message(msg_type).name
        except ValueError:
            msg_name = f"Unknown({msg_type})"

        print(f"[RUST] Message: {msg_name} ({msg_type})")
        print(f"       Payload ({len(msg_data)}B): {msg_data[:48].hex()}")

        # Handle specific message types
        if msg_type == Message.Ready:
            self.handle_ready(msg_data, addr)
        elif msg_type == Message.Auth:
            self.handle_auth(msg_data, addr)
        elif msg_type == Message.GiveUserInformation:
            self.handle_user_info(msg_data, addr)
        elif msg_type == Message.ConsoleCommand:
            self.handle_console_command(msg_data, addr)
        elif msg_type == Message.Tick:
            self.handle_tick(msg_data, addr)

    def handle_ready(self, data: bytes, addr: tuple):
        """Client says it's ready"""
        print(f"[RUST] Client {addr} is READY")

        # Send Welcome message
        self.send_welcome(addr)

    def handle_auth(self, data: bytes, addr: tuple):
        """Handle auth packet from client"""
        print(f"[RUST] Auth from {addr}")
        print(f"       Data: {data[:64].hex()}")

        # Try to parse auth data
        # Format may include: token, user ID, username, etc.

        # Send Approved
        self.send_approved(addr)

    def handle_user_info(self, data: bytes, addr: tuple):
        """Handle user information response (GiveUserInformation)"""
        print(f"[RUST] *** GiveUserInformation from {addr} ***")
        print(f"       Raw ({len(data)}B): {data.hex()}")

        # Expected format from PC Rust:
        # - Magic byte: 228 (0xE4)
        # - userid: UInt64
        # - protocol: UInt32
        # - os: String (length-prefixed)
        # - username: String
        # etc.

        if len(data) < 1:
            print(f"       ERROR: Empty data")
            return

        magic = data[0]
        print(f"       Magic: {magic} (expected 228/0xE4)")

        if len(data) >= 13:
            userid = struct.unpack('<Q', data[1:9])[0]
            protocol = struct.unpack('<I', data[9:13])[0]
            print(f"       UserID: {userid}")
            print(f"       Protocol: {protocol}")

            # Try to parse strings after fixed header
            pos = 13
            if pos < len(data):
                # OS string (length-prefixed)
                remaining = data[pos:]
                print(f"       Remaining: {remaining[:64].hex()}")

        # Update peer info
        peer = self.peers.get(addr)
        if peer:
            peer.state = 'authenticated'
            print(f"[RUST] Client authenticated, sending Approved...")

    def handle_console_command(self, data: bytes, addr: tuple):
        """Handle console command from client"""
        try:
            cmd = data.decode('utf-8', errors='ignore')
            print(f"[RUST] ConsoleCommand: {cmd}")
        except:
            print(f"[RUST] ConsoleCommand (binary): {data.hex()}")

    def handle_tick(self, data: bytes, addr: tuple):
        """Handle tick/heartbeat"""
        pass  # Just acknowledge

    # =========================================================================
    # Send Messages
    # =========================================================================

    def send_reliable(self, addr: tuple, data: bytes, channel: int = 0):
        """Send reliable channeled message"""
        peer = self.peers.get(addr)
        if not peer:
            return

        # Build header with ConnectionNumber
        header = PacketProperty.Channeled | (peer.connection_number << 5)

        packet = bytearray()
        packet.append(header)
        packet.extend(struct.pack('<H', peer.sequence_out))  # Use current sequence
        packet.append(channel)
        packet.extend(data)

        print(f"[SEND] Reliable Seq={peer.sequence_out} connNum={peer.connection_number}: {packet.hex()}")
        self.send_packet(packet, addr)

        peer.sequence_out += 1  # Increment for next packet

    def send_all_message_types(self, addr: tuple):
        """Send all common message types to test which ones trigger Unity handlers"""
        print(f"\n[TEST] Sending all message types to {addr}")
        print("=" * 60)

        # List of message types to test
        test_messages = [
            (Message.Welcome, "Welcome", b'\x01\x37\x0a\x00\x00'),  # Type 1 + protocol
            (Message.Auth, "Auth", b'\x02'),  # Type 2
            (Message.Approved, "Approved", b'\x03\x01\x00\x00\x00\x00\x00\x00\x00'),  # Type 3 + ID
            (Message.Ready, "Ready", b'\x04'),  # Type 4
            (Message.ConsoleMessage, "ConsoleMessage", b'\x0b' + b'Test\x00'),  # Type 11 + string
            (Message.RequestUserInformation, "RequestUserInformation", b'\x11'),  # Type 17
            (Message.Tick, "Tick", b'\x0f\x00\x00\x00\x00'),  # Type 15 + tick data
        ]

        import time
        for msg_type, name, payload in test_messages:
            print(f"[TEST] Sending {name} (type {msg_type})...")
            self.send_reliable(addr, payload)
            time.sleep(0.1)  # Small delay between messages

        print("=" * 60)
        print("[TEST] All message types sent\n")

    def send_welcome(self, addr: tuple):
        """Send Welcome message with server info"""
        print(f"[RUST] Sending Welcome to {addr}")

        # Build Welcome message
        # Format: message_type (1) + protocol (4) + ... (varies)
        msg = bytearray()
        msg.append(Message.Welcome)
        msg.extend(struct.pack('<I', self.protocol_version))  # Protocol version

        self.send_reliable(addr, bytes(msg))

    def send_approved(self, addr: tuple):
        """Send Approved message"""
        print(f"[RUST] Sending Approved to {addr}")

        peer = self.peers.get(addr)
        if not peer:
            return

        # Build Approved message
        msg = bytearray()
        msg.append(Message.Approved)

        # Approved packet typically contains:
        # - Network ID (8 bytes)
        # - Server info
        msg.extend(struct.pack('<Q', peer.id))  # Network ID

        self.send_reliable(addr, bytes(msg))

        # After approved, might need to send world info
        self.send_world_info(addr)

    def send_world_info(self, addr: tuple):
        """Send world/level information"""
        print(f"[RUST] Sending World info to {addr}")

        msg = bytearray()
        msg.append(Message.World)
        msg.extend(struct.pack('<I', self.world_size))  # World size
        msg.extend(struct.pack('<I', self.seed))  # Seed
        # More world data...

        self.send_reliable(addr, bytes(msg))

    def send_console_message(self, addr: tuple, message: str):
        """Send console message to client"""
        msg = bytearray()
        msg.append(Message.ConsoleMessage)
        msg.extend(message.encode('utf-8'))

        self.send_reliable(addr, bytes(msg))

# =============================================================================
# Main
# =============================================================================

def main():
    server = RustConsoleServer(port=28915)

    try:
        server.start()
    except KeyboardInterrupt:
        print("\n[SHUTDOWN] Stopping server...")
        server.stop()

if __name__ == '__main__':
    main()
