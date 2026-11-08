#!/usr/bin/env python3
"""Reference course server (stub) for GView Learning and Evaluation Mode, protocol v2.

Implements the server side of docs/source/learning_mode_protocol.rst for end-to-end tests of the desktop client
(GViewCore/src/Security/Learning/tests_learning.cpp, "[integration]" / "[integration-hostile]") and of the web
(WebAssembly) client:

  POST /GView/Connect                 signed policy (Ed25519 over the exact bytes, schema 2, digest, subject, server)
  POST /GView/GetWeeks                catalogue: week 1 (problems + resources); a disabled item and a week that is not
                                      visible yet are never sent
  POST /GView/GetProblems/<name>      task content with the delivery headers (GVE1 = HKDF + AES-256-GCM in memory mode)
  POST /GView/GetResource/<name>      resource content
  POST /GView/SubmitFlag              grading with idempotency keys (a resent clientSubmissionId answers duplicate:true)
  POST /GView/Telemetry               batches, de-duplicated on (sessionId, seq): {"accepted": n, "duplicates": m}
  POST /GView/WebLaunch               one-click launch of the web build (--launch-code): {"code"} -> the connection
                                      string, once; 401 afterwards; 403 without an allowed Origin; 426 below protocol 2
  POST /GView/GetNotes                course notes (spec §10.11): the student's own notes + the teacher notes for them
  POST /GView/SaveNote                compare-and-set on "revision"; a retried create / update is answered 200
  POST /GView/DeleteNote              unknown id => 404
  POST /GView/SaveTeacherNote         course staff only (--staff), else 403
  POST /GView/DeleteTeacherNote       course staff only
  OPTIONS *                           CORS preflight for browser clients (--cors-origin)

Transport: HTTPS by default, with a self-signed certificate generated at start-up; the printed connection string
carries it as extra.caPem (the only trust anchor of the desktop client). Browsers can not pin a certificate (the web
client refuses caPem): for them use --tls-cert/--tls-key with a certificate the browser trusts, or --http for local
development (plain HTTP on the loopback, client setting [GView] LearningAllowPlainHttpLocalhost=true).

Browser clients need CORS: every --cors-origin is answered with Access-Control-Allow-Origin, the request headers of the
protocol are allowed and the X-GView-* response headers are exposed. The X-GView-Platform request header
("web-wasm32" for the browser) selects the policy: web clients get one without screen protection (a page can not
prevent screenshots), or a 426 UNSUPPORTED_CLIENT with --refuse-platform web-wasm32.

  python tools/learning_mode_stub_server.py --quiet --require-explanation          # desktop end-to-end tests
  python tools/learning_mode_stub_server.py --http --cors-origin http://127.0.0.1:8765 --storage-mode file   # web
  python tools/learning_mode_stub_server.py --http --cors-origin http://127.0.0.1:8765 --launch-code <32-64 chars>
      then open http://127.0.0.1:8765/GView.html#launch=<code>&server=http%3A%2F%2F127.0.0.1%3A8443

Fault injection: --tamper-policy (signature does not verify), --corrupt-blob (GCM tag fails), --delay-ms (slow
server: responsiveness and cancellation). The signing key is derived from a public seed: FOR TESTS ONLY.

Course notes: --notes on|off|absent (the policy's "notes" object; off = the student note endpoints answer 403, absent =
a server without notes), --notes-forbidden (the policy says on, the endpoints answer 403: notes turned off after
connect), --staff (the token is course staff: every teacher note, SaveTeacherNote / DeleteTeacherNote allowed),
--group G1|G2 (the student's lab group), --notes-max-chars, --notes-rate-limit (requests per minute).

Requires: Python 3.9+, cryptography.
"""

import argparse
import base64
import collections
import datetime
import hashlib
import hmac
import ipaddress
import json
import os
import re
import ssl
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509.oid import NameOID

DEFAULT_TOKEN = "tok_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcd"
# deterministic key: the connection string stays the same between runs (test fixture, NOT a secret)
SIGNING_SEED = hashlib.sha256(b"GView learning mode stub server - test key").digest()

ALLOWED_REQUEST_HEADERS = ("XAppUserID, X-GView-Client, X-GView-Protocol, X-GView-Policy, X-GView-Platform, Content-Type, "
                           "Accept")
NOTE_ENDPOINTS = ("/GView/GetNotes", "/GView/SaveNote", "/GView/DeleteNote", "/GView/SaveTeacherNote",
                  "/GView/DeleteTeacherNote")
EXPOSED_RESPONSE_HEADERS = ("X-GView-Delivery, X-GView-SHA256, X-GView-Encrypted, X-GView-Filename, X-GView-Item-Version, "
                            "Retry-After, Content-Length")


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def subject_of(token: str) -> str:
    """Policy subject of an access token (hex(sha256(token))[0:16]); also what the log shows instead of the token."""
    return hashlib.sha256(token.encode()).hexdigest()[:16]


def make_mz(label: str, sections: int) -> bytes:
    """A small, harmless, deterministic "MZ" image (a DOS stub that only prints a message)."""
    header = bytearray(64)
    header[0:2] = b"MZ"
    header[0x3C:0x40] = (64).to_bytes(4, "little")
    stub = f"GView course task {label}: {sections} sections. This program cannot be run in DOS mode.\r\n$".encode()
    body = bytearray()
    for i in range(sections):
        body += f".sect{i}".encode().ljust(8, b"\x00") + bytes((i * 37 + k) & 0xFF for k in range(56))
    return bytes(header) + stub + bytes(body)


def self_signed_certificate(host: str):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "GView learning stub server")])
    now = datetime.datetime.now(datetime.timezone.utc)
    alt = [x509.DNSName("localhost")]
    try:
        alt.append(x509.IPAddress(ipaddress.ip_address(host)))
    except ValueError:
        alt.append(x509.DNSName(host))
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=7))
            .add_extension(x509.SubjectAlternativeName(alt), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return cert_pem, key_pem


class StubState:
    def __init__(self, args):
        self.args = args
        self.lock = threading.Lock()
        self.key = Ed25519PrivateKey.from_private_bytes(SIGNING_SEED)
        self.public_hex = self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        self.token = args.token
        # the student of --launch-code may be another one (--launch-token): both access tokens are accepted
        self.launch_token = args.launch_token or args.token
        self.tokens = {self.token, self.launch_token}
        self.launch_used = False     # --launch-code is single use
        self.server_url = args.server_url
        self.ca_pem = None  # set when the server uses its own self-signed certificate
        self.attempts = {}           # problem -> attempts
        self.solved = set()
        self.submissions = {}        # clientSubmissionId -> response
        self.telemetry_seen = set()  # (sessionId, seq)
        self.telemetry_events = 0
        self.score = 0
        # week 1 (visible) + an item that is disabled; week 2 is not visible yet and is never sent
        self.items = {
            "w1_stack_var": {"problem": True, "mode": "memory", "flag": "3", "points": 100, "fileName": "stack_var.exe",
                             "content": make_mz("w1_stack_var", 3), "title": "Count the stack variables", "explain": True},
            "w1_xor_key": {"problem": True, "mode": "file", "flag": "0x5a", "points": 50, "fileName": "xor_key.exe",
                           "content": make_mz("w1_xor_key", 2), "title": "Find the XOR key"},
            "w1_notes": {"problem": False, "kind": "text", "mode": "file", "fileName": "notes.md",
                         "content": b"# Lab notes\n\nWeek 1: the stack, the heap and the first sections of a PE file.\n",
                         "title": "Lab notes"},
        }
        self.disabled = {"w1_hidden", "w2_problem"}
        self.visible_weeks = {"Week 1"}
        self.all_weeks = {"Week 1", "Week 2"}
        # course notes (spec §10.11)
        self.student_notes = {}       # id -> note
        self.last_update = {}         # id -> (base revision, title, body, scope) of the last applied update
        self.teacher_notes = [
            {"id": 1, "title": "Conditional jumps", "body": "jle / jg compare signed values; jbe / ja unsigned ones.",
             "scope": {"kind": "general"}, "audience": "all", "enabled": True, "order": 1},
            {"id": 2, "title": "Stack frames", "body": "Locals live below rbp: [rbp-4], [rbp-8], ...",
             "scope": {"kind": "problem", "name": "w1_stack_var"}, "audience": "all", "enabled": True, "order": 2},
            {"id": 3, "title": "Draft (hidden)", "body": "not published yet", "scope": {"kind": "general"},
             "audience": "all", "enabled": False, "order": 3},
            {"id": 4, "title": "Lab group G2", "body": "Room 204 for G2.", "scope": {"kind": "general"},
             "audience": "G2", "enabled": True, "order": 4},
            {"id": 5, "title": "Reading for week 1", "body": "PE format chapter.", "scope": {"kind": "week", "name": "Week 1"},
             "audience": "all", "enabled": True, "order": 5},
            {"id": 6, "title": "Week 2 preview", "body": "not visible yet", "scope": {"kind": "problem", "name": "w2_problem"},
             "audience": "all", "enabled": True, "order": 6},
        ]
        now = int(time.time())
        for t in self.teacher_notes:
            t.update({"revision": 1, "createdAt": now, "updatedAt": now})
        self.next_teacher_id = 7
        self.notes_requests = collections.deque()  # timestamps of note requests (rate limit)

    # ------------------------------------------------------------------ policy
    def policy_id(self, token: str) -> str:
        return "pol_stub_" + hashlib.sha256((token + self.server_url).encode()).hexdigest()[:8]

    def content_key(self, token: str) -> bytes:
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=self.policy_id(token).encode(),
                    info=b"GView-Content-v1").derive(token.encode())

    def policy_bytes(self, platform: str, token: str) -> bytes:
        web = platform.startswith("web-")
        now = int(time.time())
        policy = {
            "schema": 2,
            "id": self.policy_id(token),
            "digest": "",
            "purpose": "GView learning stub server",
            "issuedAt": now,
            "startsAt": now - 60,
            "endsAt": now + self.args.policy_minutes * 60,
            "subject": subject_of(token),
            "serverUrl": self.server_url,
            "disabledFeatures": ["Copy", "Export", "Clipboard", "LLMHints"],
            "storageMode": self.args.storage_mode,
            "watermark": "stub-course",
            # a web page can not exclude itself from screen capture: the server decides what web clients get
            "bestEffortScreenProtect": not web,
            "requireScreenProtect": self.args.require_screen_protect,
            "telemetry": {"enabled": True, "flushIntervalSeconds": self.args.flush_interval, "maxBatchEvents": 500,
                          "idleThresholdSeconds": 120, "eventLevel": True},
            "submission": {"allowInTool": True, "requireExplanation": False, "explanationMaxChars": 2000},
            "contentEncryption": "aes-256-gcm-hkdf-v1",
            "contentKeyId": hashlib.sha256(self.content_key(token)).hexdigest()[:16],
        }
        if self.args.notes != "absent":
            policy["notes"] = {"enabled": self.args.notes == "on", "maxChars": self.args.notes_max_chars}
        canonical = json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()
        policy["digest"] = hashlib.sha256(canonical).hexdigest()
        return json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()

    def connect_response(self, platform: str, token: str) -> dict:
        data = self.policy_bytes(platform, token)
        signature = self.key.sign(data)
        if self.args.tamper_policy:
            data = data.replace(b'"stub-course"', b'"stub-coursX"')  # one byte changed after signing
        return {"status": "ok", "protocolVersion": 2, "serverVersion": "2.0.0-stub", "serverTime": int(time.time()),
                "policy": b64(data), "policySignature": b64(signature),
                "user": {"displayName": "Stub Student", "score": self.score}}

    # ------------------------------------------------------------------ catalogue
    def weeks(self) -> dict:
        problems, resources = [], []
        for order, (name, it) in enumerate(self.items.items()):
            entry = {"name": name, "title": it["title"], "order": order, "deliveryMode": it["mode"],
                     "fileName": it["fileName"], "size": len(it["content"]),
                     "sha256": hashlib.sha256(it["content"]).hexdigest()}
            if it["problem"]:
                entry.update({"pointsMax": it["points"], "pointsCurrent": it["points"],
                              "submission": {"requireExplanation": self.args.require_explanation and it.get("explain", False)},
                              "me": {"solved": name in self.solved, "attempts": self.attempts.get(name, 0)}})
                problems.append(entry)
            else:
                entry["kind"] = it["kind"]
                resources.append(entry)
        resources.append({"name": "w1_reading", "title": "GView documentation", "kind": "link", "order": 99,
                          "url": "https://gdt050579.github.io/GView/"})
        return {"status": "ok", "weeks": [{"id": 1, "name": "Week 1", "title": "Getting started", "order": 1,
                                           "problems": problems, "resources": resources}]}

    def delivery(self, name: str, token: str):
        it = self.items[name]
        plaintext = it["content"]
        memory = it["mode"] == "memory" or self.args.storage_mode == "memory"
        headers = {"X-GView-Delivery": "memory" if memory else "file",
                   "X-GView-SHA256": hashlib.sha256(plaintext).hexdigest(),
                   "X-GView-Filename": it["fileName"], "X-GView-Item-Version": "1"}
        if memory:
            iv = os.urandom(12)
            aad = name.encode() + b"\x00" + self.policy_id(token).encode()
            body = b"GVE1" + iv + AESGCM(self.content_key(token)).encrypt(iv, plaintext, aad)
            if self.args.corrupt_blob:
                body = body[:-1] + bytes([body[-1] ^ 0x01])
            headers["X-GView-Encrypted"] = "1"
        else:
            body = plaintext
            headers["X-GView-Encrypted"] = "0"
        return body, headers

    def connection_string(self, token: str = None, server_url: str = None) -> str:
        parts = [b64((token or self.token).encode()), b64((server_url or self.server_url).encode()),
                 b64(self.public_hex.encode())]
        extra = {"label": "GView stub course"}
        if self.ca_pem:
            extra["caPem"] = b64(self.ca_pem)
        parts.append(b64(json.dumps(extra, separators=(",", ":")).encode()))
        return b64("#".join(parts).encode())


class Handler(BaseHTTPRequestHandler):
    server_version = "GViewLearningStub/2.0"
    protocol_version = "HTTP/1.1"
    state: StubState = None  # set in main()

    def log_message(self, fmt, *args):
        if not self.state.args.quiet:
            sys.stderr.write("[stub] %s - %s\n" % (self.address_string(), fmt % args))

    def note(self, text: str):
        if not self.state.args.quiet:
            print("[stub] " + text, flush=True)

    @staticmethod
    def _sanitize_header_component(value):
        return str(value).replace("\r", "").replace("\n", "")

    def cors_headers(self):
        origin = self.headers.get("Origin")
        if origin and origin in self.state.args.cors_origin:
            self.send_header("Access-Control-Allow-Origin", self._sanitize_header_component(origin))
            self.send_header("Vary", "Origin")
            self.send_header("Access-Control-Expose-Headers", EXPOSED_RESPONSE_HEADERS)

    def reply(self, status: int, body: bytes, content_type="application/json", extra=None):
        self.send_response(status)
        self.cors_headers()
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(self._sanitize_header_component(k), self._sanitize_header_component(v))
        self.end_headers()
        self.wfile.write(body)

    def reply_json(self, status: int, obj: dict, extra=None):
        self.reply(status, json.dumps(obj).encode(), extra=extra)

    def error(self, status: int, code: str, details: str, retryable=False):
        self.reply_json(status, {"status": "error", "code": code, "details": details, "retryable": retryable})

    def do_OPTIONS(self):
        origin = self.headers.get("Origin")
        if not origin or origin not in self.state.args.cors_origin:
            self.send_response(403)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", self._sanitize_header_component(origin))
        self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "POST")
        self.send_header("Access-Control-Allow-Headers", ALLOWED_REQUEST_HEADERS)
        self.send_header("Access-Control-Max-Age", "600")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        self.error(405, "BAD_REQUEST", "use POST")

    def do_POST(self):
        st = self.state
        length = int(self.headers.get("Content-Length") or 0)
        if length > 2 * 1024 * 1024:
            self.error(413, "BAD_REQUEST", "body too large")
            return
        if self.path in NOTE_ENDPOINTS:
            cap = 256 * 1024 if self.path in ("/GView/SaveNote", "/GView/SaveTeacherNote") else 64 * 1024
            if length > cap:
                self.rfile.read(length)
                self.error(413, "PAYLOAD_TOO_LARGE", f"request body above {cap} bytes")
                return
        raw = self.rfile.read(length) if length else b""
        if st.args.delay_ms > 0:
            time.sleep(st.args.delay_ms / 1000.0)
        if self.path == "/GView/WebLaunch":
            self.web_launch(raw)
            return
        token = self.headers.get("XAppUserID")
        if token not in st.tokens:
            self.error(401, "UNAUTHORIZED", "invalid access token")
            return
        platform = self.headers.get("X-GView-Platform", "")
        if platform and platform in st.args.refuse_platform:
            self.error(426, "UNSUPPORTED_CLIENT", f"this course is not available on {platform}")
            return
        try:
            body = json.loads(raw.decode("utf-8")) if raw else {}
        except ValueError:
            self.error(400, "BAD_REQUEST", "body is not JSON")
            return
        path = self.path
        with st.lock:
            if path == "/GView/Connect":
                self.note(f"connect from client={self.headers.get('X-GView-Client')} platform={platform or '?'} "
                          f"subject={subject_of(token)}")
                self.reply_json(200, st.connect_response(platform, token))
            elif path == "/GView/GetWeeks":
                self.reply_json(200, st.weeks())
            elif path.startswith("/GView/GetProblems/") or path.startswith("/GView/GetResource/"):
                name = path.rsplit("/", 1)[1]
                it = st.items.get(name)
                if it is None or name in st.disabled or it["problem"] != path.startswith("/GView/GetProblems/"):
                    self.error(404, "NOT_FOUND", "no such item")
                    return
                data, headers = st.delivery(name, token)
                self.reply(200, data, content_type="application/octet-stream", extra=headers)
            elif path == "/GView/SubmitFlag":
                self.submit(body)
            elif path == "/GView/Telemetry":
                self.telemetry(body, token)
            elif path in NOTE_ENDPOINTS and st.args.notes != "absent":
                self.notes_endpoint(path, body)
            else:
                self.error(404, "NOT_FOUND", "unknown endpoint")

    # ------------------------------------------------------------------ course notes (spec §10.11)
    def notes_endpoint(self, path, body):
        st = self.state
        args = st.args
        now = time.time()
        while st.notes_requests and now - st.notes_requests[0] >= 60:
            st.notes_requests.popleft()
        if len(st.notes_requests) >= args.notes_rate_limit:
            retry = max(1, int(60 - (now - st.notes_requests[0])) + 1)
            self.reply_json(429, {"status": "error", "code": "RATE_LIMITED", "details": "too many note requests",
                                  "retryable": True}, extra={"Retry-After": str(retry)})
            return
        st.notes_requests.append(now)
        if not isinstance(body, dict):
            self.error(400, "BAD_REQUEST", "body must be a JSON object")
            return
        teacher_endpoint = path in ("/GView/SaveTeacherNote", "/GView/DeleteTeacherNote")
        if teacher_endpoint and not args.staff:
            self.error(403, "FORBIDDEN", "Only course staff can edit course notes.")
            return
        if not teacher_endpoint and not args.staff and (args.notes == "off" or args.notes_forbidden):
            self.error(403, "FORBIDDEN", "Course notes are disabled for this week.")
            return
        handler = {"/GView/GetNotes": self.get_notes, "/GView/SaveNote": self.save_note,
                   "/GView/DeleteNote": self.delete_note, "/GView/SaveTeacherNote": self.save_teacher_note,
                   "/GView/DeleteTeacherNote": self.delete_teacher_note}[path]
        handler(body)

    def item_visible(self, scope):
        st = self.state
        kind = scope["kind"]
        if kind == "general":
            return True
        if kind == "week":
            return scope["name"] in st.visible_weeks
        it = st.items.get(scope["name"])
        return it is not None and scope["name"] not in st.disabled and it["problem"] == (kind == "problem")

    def item_exists(self, scope):
        st = self.state
        kind = scope["kind"]
        if kind == "general":
            return True
        if kind == "week":
            return scope["name"] in st.all_weeks
        return scope["name"] in st.items or scope["name"] in st.disabled

    def parse_scope(self, value):
        """None/missing => general; returns (scope, error)"""
        if value is None:
            return {"kind": "general"}, None
        if not isinstance(value, dict) or value.get("kind") not in ("general", "week", "problem", "resource"):
            return None, "invalid scope"
        if value["kind"] == "general":
            return {"kind": "general"}, None
        name = value.get("name")
        if not isinstance(name, str) or not name:
            return None, "scope.name is required"
        return {"kind": value["kind"], "name": name}, None

    def normalize_text(self, body):
        """returns (title, text, error) following the server limits"""
        title, text = body.get("title", ""), body.get("body", "")
        if not isinstance(title, str) or not isinstance(text, str):
            return None, None, "title and body must be strings"
        if "\x00" in title or "\x00" in text:
            return None, None, "NUL characters are not allowed"
        title = "".join(" " if ord(c) < 32 or ord(c) == 127 else c for c in title)
        if len(title) > 200:
            return None, None, "title is longer than 200 characters"
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        if len(text) > self.state.args.notes_max_chars:
            return None, None, f"body is longer than {self.state.args.notes_max_chars} characters"
        return title, text, None

    def teacher_view(self, t, staff):
        r = {"id": t["id"], "title": t["title"], "body": t["body"], "scope": t["scope"], "audience": t["audience"],
             "updatedAt": t["updatedAt"]}
        if staff:
            r.update({"enabled": t["enabled"], "order": t["order"], "revision": t["revision"], "createdAt": t["createdAt"]})
        return r

    def get_notes(self, body):
        st = self.state
        staff = st.args.staff
        mine = sorted(st.student_notes.values(), key=lambda n: (n["updatedAt"], n["revision"]), reverse=True)
        teacher = []
        for t in sorted(st.teacher_notes, key=lambda t: (t["order"], t["id"])):
            if not staff and (not t["enabled"] or t["audience"] not in ("all", st.args.group) or not self.item_visible(t["scope"])):
                continue
            teacher.append(self.teacher_view(t, staff))
        self.reply_json(200, {"status": "ok", "maxChars": st.args.notes_max_chars, "serverTime": int(time.time()),
                              "canEditTeacherNotes": staff, "mine": [dict(n) for n in mine], "teacher": teacher})

    def save_note(self, body):
        st = self.state
        note_id = body.get("id")
        if not isinstance(note_id, str) or not note_id or len(note_id) > 64:
            self.error(400, "BAD_REQUEST", "id must be a non-empty string")
            return
        revision = body.get("revision")
        if revision is not None and (not isinstance(revision, int) or isinstance(revision, bool)):
            self.error(400, "BAD_REQUEST", "revision must be an integer")
            return
        title, text, err = self.normalize_text(body)
        if err:
            self.error(400, "BAD_REQUEST", err)
            return
        scope, err = self.parse_scope(body.get("scope"))
        if err:
            self.error(400, "BAD_REQUEST", err)
            return
        if not st.args.staff and not self.item_visible(scope):
            self.error(404, "NOT_FOUND", "no such item")  # hidden items can not be probed
            return
        existing = st.student_notes.get(note_id)
        now = int(time.time())
        if revision is None:
            if existing is not None:
                if (existing["title"], existing["body"], existing["scope"]) == (title, text, scope):
                    self.reply_json(200, {"status": "ok", "id": note_id, "revision": existing["revision"],
                                          "updatedAt": existing["updatedAt"], "created": False})
                else:
                    self.error(409, "CONFLICT", "a different note with this id exists")
                return
            if len(st.student_notes) >= 500:
                self.error(400, "BAD_REQUEST", "at most 500 notes per student")
                return
            st.student_notes[note_id] = {"id": note_id, "title": title, "body": text, "scope": scope, "revision": 1,
                                         "createdAt": now, "updatedAt": now}
            self.note(f"note {note_id[:8]} created")
            self.reply_json(200, {"status": "ok", "id": note_id, "revision": 1, "updatedAt": now, "created": True})
            return
        if existing is None:
            self.error(404, "NOT_FOUND", "no such note")
            return
        if existing["revision"] == revision:
            existing.update({"title": title, "body": text, "scope": scope, "revision": revision + 1, "updatedAt": now})
            st.last_update[note_id] = (revision, title, text, scope)
            self.note(f"note {note_id[:8]} revision {revision + 1}")
            self.reply_json(200, {"status": "ok", "id": note_id, "revision": revision + 1, "updatedAt": now, "created": False})
            return
        if existing["revision"] == revision + 1 and st.last_update.get(note_id) == (revision, title, text, scope):
            # the same update retried after a lost answer
            self.reply_json(200, {"status": "ok", "id": note_id, "revision": revision + 1,
                                  "updatedAt": existing["updatedAt"], "created": False})
            return
        self.error(409, "CONFLICT", "the note was changed in the meantime")

    def delete_note(self, body):
        st = self.state
        note_id = body.get("id")
        if not isinstance(note_id, str) or note_id not in st.student_notes:
            self.error(404, "NOT_FOUND", "no such note")
            return
        del st.student_notes[note_id]
        st.last_update.pop(note_id, None)
        self.reply_json(200, {"status": "ok"})

    def save_teacher_note(self, body):
        st = self.state
        title, text, err = self.normalize_text(body)
        if err:
            self.error(400, "BAD_REQUEST", err)
            return
        scope = None
        if "scope" in body:
            scope, err = self.parse_scope(body.get("scope"))
            if err:
                self.error(400, "BAD_REQUEST", err)
                return
            if not self.item_exists(scope):
                self.error(404, "NOT_FOUND", "no such item")
                return
        audience = body.get("audience")
        if audience is not None and audience not in ("all", "G1", "G2"):
            self.error(400, "BAD_REQUEST", "audience must be all, G1 or G2")
            return
        enabled, order = body.get("enabled"), body.get("order")
        if enabled is not None and not isinstance(enabled, bool):
            self.error(400, "BAD_REQUEST", "enabled must be a boolean")
            return
        if order is not None and (not isinstance(order, int) or isinstance(order, bool)):
            self.error(400, "BAD_REQUEST", "order must be an integer")
            return
        now = int(time.time())
        note_id = body.get("id")
        if note_id is None:
            t = {"id": st.next_teacher_id, "title": title, "body": text, "scope": scope or {"kind": "general"},
                 "audience": audience or "all", "enabled": True if enabled is None else enabled,
                 "order": order or 0, "revision": 1, "createdAt": now, "updatedAt": now}
            st.next_teacher_id += 1
            st.teacher_notes.append(t)
            self.reply_json(200, {"status": "ok", "id": t["id"], "revision": 1, "updatedAt": now, "created": True})
            return
        revision = body.get("revision")
        if not isinstance(note_id, int) or isinstance(note_id, bool) or not isinstance(revision, int) or isinstance(revision, bool):
            self.error(400, "BAD_REQUEST", "id and revision must be integers")
            return
        t = next((t for t in st.teacher_notes if t["id"] == note_id), None)
        if t is None:
            self.error(404, "NOT_FOUND", "no such course note")
            return
        if t["revision"] != revision:
            self.error(409, "CONFLICT", "the course note was changed in the meantime")
            return
        t.update({"title": title, "body": text, "revision": revision + 1, "updatedAt": now})
        if "scope" in body:
            t["scope"] = scope
        if audience is not None:
            t["audience"] = audience
        if enabled is not None:
            t["enabled"] = enabled
        if order is not None:
            t["order"] = order
        self.reply_json(200, {"status": "ok", "id": note_id, "revision": revision + 1, "updatedAt": now, "created": False})

    def delete_teacher_note(self, body):
        st = self.state
        note_id = body.get("id")
        t = next((t for t in st.teacher_notes if t["id"] == note_id), None) if isinstance(note_id, int) else None
        if t is None:
            self.error(404, "NOT_FOUND", "no such course note")
            return
        st.teacher_notes.remove(t)
        self.reply_json(200, {"status": "ok"})

    def web_launch(self, raw: bytes):
        """POST /GView/WebLaunch {"code"}: one-click launch of the web build. --launch-code is answered once with the
        connection string of --launch-token (and --launch-server-url), then with 401 like an expired / used code."""
        st = self.state
        origin = self.headers.get("Origin")
        if not origin or origin not in st.args.cors_origin:
            self.error(403, "FORBIDDEN", "This GView page is not allowed by the course server (origin not allowed).")
            return
        try:
            protocol = int(self.headers.get("X-GView-Protocol") or "0")
        except ValueError:
            protocol = 0
        if protocol < 2:
            self.error(426, "UNSUPPORTED_CLIENT", "X-GView-Protocol 2 is required")
            return
        try:
            body = json.loads(raw.decode("utf-8")) if raw else {}
        except ValueError:
            body = None
        code = body.get("code") if isinstance(body, dict) else None
        if not isinstance(code, str) or not code:
            self.error(400, "BAD_REQUEST", "code is required")
            return
        if st.args.launch_delay_ms > 0:
            time.sleep(st.args.launch_delay_ms / 1000.0)
        with st.lock:
            valid = (st.args.launch_code is not None and not st.launch_used and
                     hmac.compare_digest(code.encode(), st.args.launch_code.encode()))
            if valid:
                st.launch_used = True
        if not valid:
            self.note(f"web launch refused (unknown, used or expired code) origin={origin}")
            self.error(401, "UNAUTHORIZED", "invalid or expired launch code")
            return
        # the code and the connection string are never logged
        self.note(f"web launch redeemed origin={origin} platform={self.headers.get('X-GView-Platform', '?')} "
                  f"client={self.headers.get('X-GView-Client', '?')} subject={subject_of(st.launch_token)}")
        self.reply_json(200, {"status": "ok", "connectionString": st.connection_string(
            st.launch_token, st.args.launch_server_url or st.server_url)})

    def submit(self, body):
        st = self.state
        sid = body.get("clientSubmissionId", "")
        if sid and sid in st.submissions:
            resp = dict(st.submissions[sid])
            resp["duplicate"] = True
            self.reply_json(200, resp)
            return
        problem = body.get("problem", "")
        it = st.items.get(problem)
        if it is None or not it["problem"] or problem in st.disabled:
            self.error(404, "NOT_FOUND", "no such problem")
            return
        # --require-explanation: the problems marked "explain" need one (announced per item in the catalogue)
        if st.args.require_explanation and it.get("explain", False) and not str(body.get("explanation", "")).strip():
            self.error(400, "BAD_REQUEST", "an explanation is required")
            return
        already = problem in st.solved
        attempts = st.attempts.get(problem, 0) + 1
        st.attempts[problem] = attempts
        correct = str(body.get("flag", "")).strip() == it["flag"]
        points = 0
        if correct and not already:
            points = it["points"]
            st.score += points
            st.solved.add(problem)
        resp = {"status": "ok", "correct": correct, "points": points, "attempts": attempts, "alreadySolved": already,
                "duplicate": False, "details": "Correct!" if correct else "Wrong flag", "totalScore": st.score}
        if sid:
            st.submissions[sid] = resp
        self.reply_json(200, resp)

    def telemetry(self, body, token):
        st = self.state
        session = body.get("sessionId", "?")
        fresh = duplicates = 0
        for ev in body.get("events", []):
            key = (session, ev.get("seq"))
            if key in st.telemetry_seen:
                duplicates += 1
                continue
            st.telemetry_seen.add(key)
            fresh += 1
            self.note(f"telemetry {session[:8]} #{ev.get('seq')} {ev.get('type')} {ev.get('item', '')}")
        st.telemetry_events += fresh
        self.note(f"telemetry batch platform={body.get('platform')} subject={subject_of(token)} new={fresh} "
                  f"duplicates={duplicates} total={st.telemetry_events}")
        self.reply_json(200, {"status": "ok", "accepted": fresh, "duplicates": duplicates})


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--server-url", help="URL the clients use (default http(s)://<host>:<port>)")
    ap.add_argument("--token", default=DEFAULT_TOKEN)
    ap.add_argument("--http", action="store_true", help="plain HTTP (local development of the web client)")
    ap.add_argument("--tls-cert", help="PEM certificate trusted by the clients (default: a generated self-signed one)")
    ap.add_argument("--tls-key", help="PEM private key of --tls-cert")
    ap.add_argument("--cors-origin", action="append", default=[],
                    help="web origin allowed to call the server (e.g. http://127.0.0.1:8765); repeatable")
    ap.add_argument("--storage-mode", choices=["file", "memory"], default="memory")
    ap.add_argument("--require-explanation", action="store_true")
    ap.add_argument("--require-screen-protect", action="store_true")
    ap.add_argument("--refuse-platform", action="append", default=[], help="answer 426 to this X-GView-Platform")
    ap.add_argument("--policy-minutes", type=int, default=240)
    ap.add_argument("--flush-interval", type=int, default=15, help="telemetry.flushIntervalSeconds of the policy")
    ap.add_argument("--tamper-policy", action="store_true", help="send a policy whose signature does not verify")
    ap.add_argument("--corrupt-blob", action="store_true", help="flip a bit in encrypted deliveries")
    ap.add_argument("--delay-ms", type=int, default=0, help="wait this long before answering every POST")
    ap.add_argument("--launch-code", help="one-time code of POST /GView/WebLaunch (one-click launch of the web build): "
                                          "answered once with a connection string, then with 401")
    ap.add_argument("--launch-token", help="access token of the student of --launch-code (default: --token); "
                                           "both tokens are accepted")
    ap.add_argument("--launch-server-url", help="server URL put in the connection string of --launch-code (default: "
                                                "--server-url; another value tests the client's origin check)")
    ap.add_argument("--launch-delay-ms", type=int, default=0, help="extra wait before answering /GView/WebLaunch")
    ap.add_argument("--notes", choices=["on", "off", "absent"], default="on",
                    help="course notes in the policy: on, off (student note endpoints answer 403) or absent (no notes)")
    ap.add_argument("--notes-forbidden", action="store_true",
                    help="the policy says notes are on, but the student note endpoints answer 403 (turned off later)")
    ap.add_argument("--staff", action="store_true", help="the token is course staff (may edit teacher notes)")
    ap.add_argument("--group", choices=["G1", "G2"], default="G1", help="lab group of the student")
    ap.add_argument("--notes-max-chars", type=int, default=20000)
    ap.add_argument("--notes-rate-limit", type=int, default=60, help="note requests per minute (429 above)")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()
    if args.launch_code is not None and not re.fullmatch(r"[A-Za-z0-9_-]{32,64}", args.launch_code):
        ap.error("--launch-code must match ^[A-Za-z0-9_-]{32,64}$ (the client ignores any other code)")
    if args.launch_server_url:
        args.launch_server_url = args.launch_server_url.rstrip("/").lower()

    tls = not args.http
    if args.server_url is None:
        args.server_url = f"{'https' if tls else 'http'}://{args.host}:{args.port}"
    args.server_url = args.server_url.rstrip("/").lower()

    state = StubState(args)
    Handler.state = state
    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    if tls:
        cert_file, key_file = args.tls_cert, args.tls_key
        if not cert_file:
            cert_pem, key_pem = self_signed_certificate(args.host)
            state.ca_pem = cert_pem  # the clients pin it (extra.caPem of the connection string)
            folder = tempfile.mkdtemp(prefix="gview-stub-")
            cert_file, key_file = os.path.join(folder, "cert.pem"), os.path.join(folder, "key.pem")
            with open(cert_file, "wb") as f:
                f.write(cert_pem)
            with open(key_file, "wb") as f:
                f.write(key_pem)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(cert_file, key_file)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

    print(f"GView learning stub server on {args.server_url} (CORS origins: {', '.join(args.cors_origin) or 'none'})")
    print(f"policy public key : {state.public_hex}")
    print(f"connection string : {state.connection_string()}")
    if args.launch_code is not None:
        print(f"web launch        : POST /GView/WebLaunch answers once (student {subject_of(state.launch_token)}"
              f"{', server ' + args.launch_server_url if args.launch_server_url else ''})")
    if not tls:
        print("plain HTTP: the client needs [GView] LearningAllowPlainHttpLocalhost=true (and a page served from localhost)")
    elif state.ca_pem:
        print("self-signed certificate pinned through extra.caPem (desktop clients; browsers refuse pinned CAs)")
    sys.stdout.flush()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
