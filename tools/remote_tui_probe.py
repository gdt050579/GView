#!/usr/bin/env python3
"""
Reference client of the GView remote TUI protocol v1 (docs/source/remote_protocol.rst).

Independent of the C++ implementation: connects to `GView serve` with mutual TLS 1.3, sends Hello, decodes every
frame (0x81 full frames and 0x82 optimized full / delta frames), optionally sends keys and prints the remote screen
as text. Used for end-to-end tests and to measure the bandwidth of a session.

Examples:
    python tools/remote_tui_probe.py 127.0.0.1 --pki ./pki --name analyst
    python tools/remote_tui_probe.py 127.0.0.1 --pki ./pki --name analyst --keys "Alt+F" "Down" "Enter" --dump
    python tools/remote_tui_probe.py 0.0.0.0 --listen --pki ./pki --name analyst      (reverse mode)
"""

import argparse
import socket
import ssl
import struct
import sys
import time

VERSION = 1
CAP_OPTIMIZED_FRAMES = 1
T_KEY, T_MOUSE, T_RESIZE, T_HELLO, T_CLOSE = 0x01, 0x02, 0x03, 0x10, 0x7F
T_FRAME, T_OPT_FRAME, T_CURSOR, T_WELCOME = 0x81, 0x82, 0x83, 0x90
MAX_SERVER_PAYLOAD = 4 + 1024 * 512 * 4
MOD_ALT, MOD_CTRL, MOD_SHIFT, MOD_UNICODE = 0x1, 0x2, 0x4, 0x8000

# AppCUI key codes (AppCUI::Input::Key)
KEYS = {f"F{i}": i for i in range(1, 13)}
for i, name in enumerate(["Enter", "Escape", "Insert", "Delete", "Backspace", "Tab", "Left", "Up", "Down", "Right",
                          "PageUp", "PageDown", "Home", "End", "Space"]):
    KEYS[name] = 13 + i
for i in range(26):
    KEYS[chr(ord("A") + i)] = 28 + i
for i in range(10):
    KEYS[str(i)] = 54 + i


class ProtocolError(Exception):
    pass


class Screen:
    def __init__(self):
        self.width = self.height = 0
        self.cells = []  # (code, fg, bg)
        self.frame_id = 0
        self.cursor = (0, 0, False)

    def text(self):
        rows = []
        for y in range(self.height):
            row = "".join(chr(c[0]) if 0x20 <= c[0] < 0xD800 else "?" for c in self.cells[y * self.width:(y + 1) * self.width])
            rows.append(row.rstrip())
        return "\n".join(rows)


def read_cells(data, pos, count, out):
    decoded = 0
    while decoded < count:
        if pos + 2 > len(data):
            raise ProtocolError("truncated run")
        tag, = struct.unpack_from("<H", data, pos)
        pos += 2
        n = tag & 0x7FFF
        if n == 0 or n > count - decoded:
            raise ProtocolError("invalid run length")
        if tag & 0x8000:
            if pos + 4 > len(data):
                raise ProtocolError("truncated cell")
            code, fg, bg = struct.unpack_from("<HBB", data, pos)
            pos += 4
            out.extend([(code, fg, bg)] * n)
        else:
            if pos + 4 * n > len(data):
                raise ProtocolError("truncated literal run")
            for i in range(n):
                out.append(struct.unpack_from("<HBB", data, pos + 4 * i))
            pos += 4 * n
        decoded += n
    return pos


def apply_logical_frame(screen, frame_id, data):
    if len(data) < 9:
        raise ProtocolError("truncated frame header")
    kind, width, height, base = struct.unpack_from("<BHHI", data, 0)
    pos = 9
    if not (1 <= width <= 1024 and 1 <= height <= 512):
        raise ProtocolError("invalid screen size")
    count = width * height
    if kind == 0:
        cells = []
        pos = read_cells(data, pos, count, cells)
        if pos != len(data) or base != 0:
            raise ProtocolError("malformed full frame")
        screen.width, screen.height, screen.cells = width, height, cells
    elif kind == 1:
        if (width, height) != (screen.width, screen.height) or base != screen.frame_id or base == 0:
            raise ProtocolError("delta does not match the current screen")
        spans, = struct.unpack_from("<I", data, pos)
        pos += 4
        cells = list(screen.cells)
        minimum = 0
        for _ in range(spans):
            offset, n = struct.unpack_from("<II", data, pos)
            pos += 8
            if n == 0 or offset < minimum or offset + n > count:
                raise ProtocolError("invalid span")
            decoded = []
            pos = read_cells(data, pos, n, decoded)
            cells[offset:offset + n] = decoded
            minimum = offset + n
        if pos != len(data):
            raise ProtocolError("trailing data")
        screen.cells = cells
    else:
        raise ProtocolError("unknown frame kind")
    screen.frame_id = frame_id


def message(type_, payload=b""):
    return struct.pack("<BI", type_, len(payload)) + payload


def key_message(spec):
    """'Enter', 'Alt+F', 'Ctrl+Shift+F5', or text:'abc' (one message per character)"""
    if spec.startswith("text:"):
        return b"".join(message(T_KEY, struct.pack("<BHH", 1, ord(ch), MOD_UNICODE)) for ch in spec[5:])
    mods = 0
    parts = spec.split("+")
    for p in parts[:-1]:
        mods |= {"Alt": MOD_ALT, "Ctrl": MOD_CTRL, "Shift": MOD_SHIFT}[p]
    return message(T_KEY, struct.pack("<BHH", 1, KEYS[parts[-1]], mods))


class Connection:
    def __init__(self, sock):
        self.sock = sock
        self.buffer = b""
        self.received = 0

    def recv_message(self, timeout):
        self.sock.settimeout(timeout)
        while True:
            if len(self.buffer) >= 5:
                type_, length = struct.unpack_from("<BI", self.buffer, 0)
                if length > MAX_SERVER_PAYLOAD:
                    raise ProtocolError("payload too large")
                if len(self.buffer) >= 5 + length:
                    payload = self.buffer[5:5 + length]
                    self.buffer = self.buffer[5 + length:]
                    return type_, payload
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("connection closed")
            self.received += len(chunk)
            self.buffer += chunk


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("host")
    ap.add_argument("--port", type=int, default=18262)
    ap.add_argument("--listen", action="store_true", help="reverse mode: wait for 'GView serve --reverse'")
    ap.add_argument("--pki", help="folder created by 'GView remote-certs' (uses <name>.crt/.key and gview-ca.crt)")
    ap.add_argument("--name", default="analyst")
    ap.add_argument("--cert"), ap.add_argument("--key"), ap.add_argument("--ca")
    ap.add_argument("--server-name")
    ap.add_argument("--alpn", default="gview/1")
    ap.add_argument("--size", default="120x40")
    ap.add_argument("--legacy", action="store_true", help="do not announce optimized frames (server sends 0x81)")
    ap.add_argument("--keys", nargs="*", default=[], help="keys sent once the first screen arrived")
    ap.add_argument("--settle", type=float, default=1.5, help="seconds without traffic before printing")
    ap.add_argument("--dump", action="store_true", help="print the final screen")
    args = ap.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # box drawing characters on any console

    cert = args.cert or f"{args.pki}/{args.name}.crt"
    key = args.key or f"{args.pki}/{args.name}.key"
    ca = args.ca or f"{args.pki}/gview-ca.crt"
    width, height = (int(v) for v in args.size.lower().split("x"))

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if args.listen else ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(cert, key)
    ctx.load_verify_locations(ca)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.set_alpn_protocols([args.alpn])

    if args.listen:
        server = socket.create_server((args.host, args.port))
        raw, peer = server.accept()
        server.close()
        sock = ctx.wrap_socket(raw, server_side=True)
    else:
        raw = socket.create_connection((args.host, args.port), timeout=10)
        sock = ctx.wrap_socket(raw, server_hostname=args.server_name or args.host)
    if sock.selected_alpn_protocol() != args.alpn:
        sys.exit("ALPN not negotiated")
    print(f"# {sock.version()} {sock.cipher()[0]} peer={dict(x[0] for x in sock.getpeercert()['subject'])}", file=sys.stderr)

    conn = Connection(sock)
    sent = message(T_HELLO, struct.pack("<HIHH", VERSION, 0 if args.legacy else CAP_OPTIMIZED_FRAMES, width, height))
    sock.sendall(sent)
    sent_bytes = len(sent)
    screen = Screen()
    chunks, chunk_frame, chunk_total = b"", 0, 0
    frames = 0
    pending_keys = list(args.keys)
    start = time.time()
    while True:
        try:
            type_, payload = conn.recv_message(args.settle)
        except socket.timeout:
            if pending_keys and screen.width:
                data = key_message(pending_keys.pop(0))
                sock.sendall(data)
                sent_bytes += len(data)
                continue
            break
        if type_ == T_WELCOME:
            version, caps, w, h = struct.unpack("<HIHH", payload)
            print(f"# welcome v{version} caps={caps} screen={w}x{h}", file=sys.stderr)
        elif type_ == T_FRAME:
            w, h = struct.unpack_from("<HH", payload)
            if len(payload) != 4 + 4 * w * h:
                raise ProtocolError("bad 0x81 frame")
            screen.width, screen.height = w, h
            screen.cells = [struct.unpack_from("<HBB", payload, 4 + 4 * i) for i in range(w * h)]
            frames += 1
        elif type_ == T_OPT_FRAME:
            fid, total, index, length = struct.unpack_from("<IQII", payload)
            data = payload[20:]
            if len(data) != length:
                raise ProtocolError("bad chunk length")
            if index == 0:
                chunks, chunk_frame, chunk_total = b"", fid, total
            elif fid != chunk_frame:
                raise ProtocolError("interleaved frames")
            chunks += data
            if len(chunks) == chunk_total:
                apply_logical_frame(screen, fid, chunks)
                frames += 1
        elif type_ == T_CURSOR:
            screen.cursor = struct.unpack("<HHB", payload)
        elif type_ == T_CLOSE:
            reason, n = struct.unpack_from("<HH", payload)
            print(f"# closed by server: reason={reason} {payload[4:4 + n].decode('ascii', 'replace')}", file=sys.stderr)
            break
        else:
            raise ProtocolError(f"unexpected message 0x{type_:02x}")

    elapsed = time.time() - start
    print(f"# frames={frames} received={conn.received} bytes sent={sent_bytes} bytes in {elapsed:.1f}s; "
          f"screen={screen.width}x{screen.height} cursor={screen.cursor}", file=sys.stderr)
    if args.dump:
        print(screen.text())
    try:
        sock.sendall(message(T_CLOSE, struct.pack("<HH", 0, 0)))
        sock.close()
    except OSError:
        pass


if __name__ == "__main__":
    main()
