#!/usr/bin/env python3
"""
MITM tampering experiment for the GView remote TUI (docs/source/remote_protocol.rst, "Security model").

A TCP proxy between `GView connect` and `GView serve` that flips one bit inside the N-th TLS application data record
of the chosen direction. TLS 1.3 protects every record with an AEAD cipher, so the receiver must reject the record
(bad_record_mac) and terminate the session: no tampered key, mouse event or screen update is ever applied.

    python tools/remote_tamper_proxy.py --listen 127.0.0.1:18263 --target 127.0.0.1:18262 --direction s2c --record 5
    GView connect 127.0.0.1:18263 --server-name 127.0.0.1
"""

import argparse
import socket
import threading


def parse(address):
    host, _, port = address.rpartition(":")
    return host.strip("[]"), int(port)


def pump(src, dst, name, tamper_record, log):
    """forwards TLS records; flips one bit of application data record number `tamper_record` (1-based, 0 = never)"""
    buffer = b""
    application_records = 0
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            buffer += data
            out = b""
            while len(buffer) >= 5:
                length = int.from_bytes(buffer[3:5], "big")
                if len(buffer) < 5 + length:
                    break
                record = bytearray(buffer[:5 + length])
                buffer = buffer[5 + length:]
                if record[0] == 23:  # application_data (every encrypted TLS 1.3 record)
                    application_records += 1
                    if application_records == tamper_record and length > 0:
                        record[5 + length // 2] ^= 0x01
                        log(f"{name}: flipped one bit in application data record #{application_records} ({length} bytes)")
                out += bytes(record)
            if out:
                dst.sendall(out)
    except OSError:
        pass
    finally:
        log(f"{name}: stream closed after {application_records} application data records")
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--listen", required=True, help="address:port the client connects to")
    ap.add_argument("--target", required=True, help="address:port of the GView server")
    ap.add_argument("--direction", choices=["c2s", "s2c"], default="s2c")
    ap.add_argument("--record", type=int, default=5, help="1-based application data record to tamper with")
    args = ap.parse_args()

    lock = threading.Lock()

    def log(text):
        with lock:
            print(text, flush=True)

    server = socket.create_server(parse(args.listen))
    log(f"listening on {args.listen}, forwarding to {args.target}")
    while True:
        client, peer = server.accept()
        upstream = socket.create_connection(parse(args.target))
        log(f"connection from {peer[0]}:{peer[1]}")
        c2s = args.record if args.direction == "c2s" else 0
        s2c = args.record if args.direction == "s2c" else 0
        threading.Thread(target=pump, args=(client, upstream, "client->server", c2s, log), daemon=True).start()
        threading.Thread(target=pump, args=(upstream, client, "server->client", s2c, log), daemon=True).start()


if __name__ == "__main__":
    main()
