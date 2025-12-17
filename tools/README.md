# Tools

Development and analysis tools for RustCERevive.

## Files

### mitmproxy_redirect.py
Man-in-the-middle proxy script for intercepting and analyzing Rust Console Edition network traffic.

**Purpose**: Used during initial reverse engineering to capture and modify packets between game and official servers.

**Usage**:
```bash
mitmproxy -s mitmproxy_redirect.py
```

### rustworks_server.py
Early prototype server implementation - intercepts at Rustworks API level.

**Note**: Superseded by `../server/rust_console_server.py` which implements the full DTLS protocol.

## Current Production Tools

The active server implementation is in `../server/rust_console_server.py` which includes:
- Full LiteNetLib protocol support
- DTLS.prx hash validation
- Proper packet structuring for PS4
