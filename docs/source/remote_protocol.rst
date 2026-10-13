Remote TUI
==========

GView can run on one machine (the **server**: where the files are and where every parser and plugin runs) and be
used from another one (the **client**: the analyst). Only the characters of the text user interface travel over the
network, never the analysed data itself. The protocol is a small, purpose-built RPC-style protocol on top of
**TLS 1.3 with mutual authentication**.

The remote mode is optional. It is compiled only when CMake is configured with ``-DGVIEW_ENABLE_REMOTE=ON``
(default ``OFF``); without it, GView contains no networking code for this feature and the commands below report
that the build does not support them.

.. code-block:: bash

   cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DGVIEW_ENABLE_REMOTE=ON
   cmake --build build --config Release --parallel


Quick start
-----------

1. Create a private CA and one short-lived certificate per GView instance (run it on a trusted machine; the CA
   private key ``gview-ca.key`` never leaves it):

   .. code-block:: bash

      GView remote-certs ./pki --name server.lab      # certificate of the server (host name or IP address)
      GView remote-certs ./pki --name analyst1        # certificate of an analyst

   Each instance receives its own ``<name>.crt`` / ``<name>.key`` and ``gview-ca.crt``. Running the command again
   for the same name rotates that certificate (the CA is reused). Certificates are valid for 14 days by default
   (``--days``), the CA for 365 days (``--ca-days``).

2. Start the server (headless: it does not use the local terminal). Every option can also be set in the
   ``[Remote]`` section of ``gview.ini``:

   .. code-block:: bash

      GView serve --bind 0.0.0.0 --cert pki/server.lab.crt --key pki/server.lab.key --ca pki/gview-ca.crt sample.exe

   By default the server only listens on ``127.0.0.1``: exposing it to other machines is an explicit decision
   (``--bind``). ``Ctrl+C`` (or *Exit* from a connected analyst) stops it. Every connection, authenticated identity
   (subject and SHA-256 fingerprint of the certificate) and disconnection is logged on stderr.

3. Connect from the analyst machine, either from the command line or with *File / Connect to a remote GView*:

   .. code-block:: bash

      GView connect server.lab --cert pki/analyst1.crt --key pki/analyst1.key --ca pki/gview-ca.crt

   The remote screen opens in a GView window; several windows (several servers) can be open at the same time and
   arranged like any other window. Every key goes to the remote GView; press **Ctrl+F12** (configurable,
   *RemoteLocalKey*) and the next key is handled by the local GView instead (for example ``Ctrl+F12`` then
   ``Alt+0`` opens the local windows manager). ``Escape`` closes a disconnected window.

Reverse connection
~~~~~~~~~~~~~~~~~~

When the analysed host can not accept inbound connections, the analyst waits for it and the server connects out
(and reconnects with an exponential back-off when the session ends):

.. code-block:: bash

   GView listen 0.0.0.0:18262 --cert pki/analyst1.crt --key pki/analyst1.key --ca pki/gview-ca.crt   # analyst
   GView serve --reverse analyst1.lab:18262 --server-name analyst1 --cert ... --key ... --ca ...      # server

In reverse mode the TCP/TLS roles are swapped (the analyst is the TLS server) but the protocol roles are not: the
server still sends the screen and the analyst still sends the input. ``--server-name`` is the name that must appear
in the analyst certificate (default: the host given to ``--reverse``).

Multiple analysts
~~~~~~~~~~~~~~~~~

Several analysts can be connected to the same server (``--max-clients``, default 4, at most 32). They share one
GView instance: their key and mouse events are queued in a single FIFO and executed in the order they were received,
and everybody sees the same screen. Like ``tmux``, the shared screen has the size of the smallest connected
analyst so that everybody sees the whole interface.

Configuration
~~~~~~~~~~~~~

.. code-block:: ini

   [Remote]
   Certificate = "pki/server.lab.crt"      ; PEM, this instance (+ optional intermediate certificates)
   PrivateKey = "pki/server.lab.key"       ; PEM, unencrypted (protect it with file permissions)
   TrustedCA = "pki/gview-ca.crt"          ; CA(s) that must have issued the peer certificate
   ALPN = "gview/1"
   BindAddress = "127.0.0.1"
   Port = 18262
   MaxClients = 4
   MaxPeerCertificateLifetimeDays = 30     ; 0 = no limit

Relative paths are resolved against the folder of ``gview.ini`` (portable deployments keep everything next to the
binaries). Command line options (``--cert``, ``--key``, ``--ca``, ``--alpn``, ``--max-cert-days``, ``--bind``,
``--port``, ``--max-clients``, ``--size``) override the file.


Security model
--------------

**Threat model.** The network is hostile: an attacker may eavesdrop, replay, reorder, delay or modify traffic
(man-in-the-middle). Both peers are also untrusted input sources: the server renders attacker-controlled files
(malware) and a client may be compromised. The protocol must provide confidentiality, integrity, replay protection
and mutual authentication, and each side must survive arbitrary bytes from the other.

**Transport.** TLS 1.3 only, with the AEAD suites ``TLS_AES_256_GCM_SHA384`` and
``TLS_CHACHA20_POLY1305_SHA256`` and the ``X25519`` key exchange; OpenSSL security level 3 (at least 128-bit
security for every key and signature). Session tickets, resumption and 0-RTT early data are disabled (early data can
be replayed), as are compression and renegotiation.

**Mutual authentication.** Both ends present an X.509 certificate that must chain to the configured CA bundle; the
system trust store is never used (a certificate from any public CA is rejected). The client verifies that the
server certificate was issued for the host it connected to (DNS or IP subject alternative name; ``--server-name``
overrides it). A peer certificate whose lifetime exceeds ``MaxPeerCertificateLifetimeDays`` is rejected, so stolen
or forgotten long-lived certificates are useless. The server re-reads its certificate, key and CA bundle when the
files change (checked at most every 2 s, applied to new connections), so certificates can be rotated by a scheduler
or by an ACME / private-CA agent without restarting GView; an inconsistent intermediate state (new certificate, old
key) keeps the previous identity in use.

**ALPN.** ``gview/1`` (configurable) is mandatory: a peer that does not negotiate it is refused, which keeps other
TLS clients (and cross-protocol attacks) out.

**MITM resistance.** Any modification of a record makes its AEAD authentication fail and the session ends (see the
tampering experiment below); no tampered key or screen update is ever applied.

**Hostile input handling.** Every message size is capped per type and direction before anything is buffered (a
client may not send more than 260 bytes per message), every count, offset, size and code is validated, delta frames
must reference the frame the client actually holds, frame chunks must arrive strictly in order with increasing
frame ids, and a malformed message closes the connection. Characters received from a server are sanitized before
they reach the local terminal (C0/C1 control characters, lone surrogates and non-characters are replaced), so a
malicious screen can not inject terminal escape sequences.

**Resource limits.** At most ``MaxClients`` authenticated analysts plus 8 connections in the handshake phase; the
TLS handshake and the protocol handshake each have a 10 s deadline; a peer that stops reading for 30 s is
disconnected; the input queue is bounded (mouse moves are coalesced) and a slow client never makes the server buffer
frames (each client receives the most recent screen when it can, encoded against the last frame *it* received).

**Data exposure.** Only screen characters leave the server. The server's OS clipboard is never read or written in
server mode (copy / paste work through a clipboard private to the GView process). A connected analyst has the same
abilities as a local GView user on the server (open files, plugins, exit GView); Learning and Evaluation Mode
policies apply unchanged.


Wire protocol (version 1)
-------------------------

All integers are **little endian**. Every message is framed as::

   u8  Type
   u32 PayloadLength
   u8  Payload[PayloadLength]

===========  ======================  =========  ==========================================================
Type         Name                    Direction  Payload
===========  ======================  =========  ==========================================================
``0x01``     KeyEvent                C → S      ``u8 pressed, u16 keyCode, u16 modifiers`` (5 bytes)
``0x02``     MouseEvent              C → S      ``u8 event, u16 x, u16 y, u8 button, u8 modifiers`` (7 bytes)
``0x03``     Resize                  C → S      ``u16 width, u16 height``
``0x10``     Hello                   C → S      ``u16 version, u32 capabilities, u16 width, u16 height``
``0x7F``     Close                   both       ``u16 reason, u16 textLength, u8 text[textLength]`` (≤ 256)
``0x81``     TuiFrame                S → C      ``u16 width, u16 height, cell[width*height]``
``0x82``     TuiOptimizedFrame       S → C      one chunk of a logical frame (below)
``0x83``     Cursor                  S → C      ``u16 x, u16 y, u8 visible``
``0x90``     Welcome                 S → C      ``u16 version, u32 capabilities, u16 width, u16 height``
===========  ======================  =========  ==========================================================

A cell is ``u16 characterCode, u8 foreground, u8 background`` (the 16 AppCUI colors, ``0x10`` = transparent): the
"u16 color" of the original design with the foreground in the low byte. The 0x81 payload size is therefore
``4 + width × height × 4`` bytes.

**Session.** After the TLS handshake the client sends ``Hello`` (its screen size and capabilities; capability
``0x1`` = understands ``0x82``). The server answers ``Welcome`` and then streams the screen: a full frame first,
then only changes, and ``Cursor`` whenever the cursor moves. Nothing is sent while the screen does not change.
Either side may end the session with ``Close`` (reasons: 0 normal, 1 protocol error, 2 unsupported version,
3 server full, 4 timeout, 5 shutdown, 6 internal error).

**Keys.** ``modifiers`` bits: ``0x1`` Alt, ``0x2`` Ctrl, ``0x4`` Shift, ``0x8000`` *unicode* (other bits must be 0).
Without the unicode bit ``keyCode`` is an ``AppCUI::Input::Key`` code (``< Key::Count``) and the receiver derives the
character (letters, digits, space; none with Ctrl/Alt). With the unicode bit ``keyCode`` is a printable UTF-16 code
unit and the receiver derives the key code (letters, digits, space). ``keyCode = 0`` without the unicode bit reports a
new modifier (shift) state. AppCUI only processes presses; releases are accepted and ignored.

**Mouse.** ``event``: 0 release, 1 press, 2 move, 3 wheel. ``button`` flags: ``0x1`` left, ``0x2`` right, ``0x4``
middle, ``0x8`` double click; for a wheel event it is the direction (1 up, 2 down, 3 left, 4 right). ``modifiers``
uses the Alt / Ctrl / Shift bits above. Events outside the current screen are dropped.

**Optimized frames (0x82).** A logical frame is split in chunks of at most 32 KB::

   u32 frameId      strictly increasing, starts at 1
   u64 totalBytes   size of the logical frame (≤ 4 MB)
   u32 chunkIndex   0, 1, 2 ... (in order, one frame at a time)
   u32 dataLength   1 .. 32768
   u8  data[dataLength]

The reassembled logical frame is::

   u8  kind          0 = full, 1 = delta
   u16 width, u16 height
   u32 baseFrameId   delta: id of the frame it applies to (the one the client holds); full: 0
   full : runs covering width × height cells
   delta: u32 spanCount, then spanCount × { u32 offset, u32 count, runs covering count cells }
          (offset = y × width + x, spans strictly increasing and non overlapping)

Runs use a ``u16`` tag: ``0x8000 | n`` = *n* repetitions of the single cell that follows, otherwise *n* literal
cells follow (1 ≤ n ≤ 32767). The server sends whichever of full / delta is smaller and merges changed cells that
are separated by at most two unchanged cells into one span.

Limits: screens are 20×6 … 1024×512 cells (the requested sizes are clamped).


Tools and evaluation
--------------------

``tools/remote_tui_probe.py`` is an independent reference client (Python, standard library only): it connects with
mutual TLS, decodes every frame, can send keys and prints the remote screen and the number of bytes exchanged.

.. code-block:: bash

   python tools/remote_tui_probe.py server.lab --pki ./pki --name analyst1 --keys Down Down F4 --dump

``tools/remote_tamper_proxy.py`` is the MITM tampering experiment: a TCP proxy that flips one bit of the N-th TLS
record of one direction. The receiving end reports ``bad record mac`` and terminates the session.

.. code-block:: bash

   python tools/remote_tamper_proxy.py --listen 127.0.0.1:18263 --target 127.0.0.1:18262 --direction c2s --record 6


Notes on the design
-------------------

Points where the implementation makes the original design precise:

* The key event keeps its 5-byte layout; the ``0x8000`` modifier bit tells whether ``keyCode`` is an AppCUI key or a
  character (both can not fit in 5 bytes). A shifted punctuation key (e.g. ``Shift+1`` → ``!``) is transmitted as
  its character.
* The mouse event carries a modifiers byte (7 bytes in total) and a wheel event type.
* ``Hello`` / ``Welcome`` (version and capability negotiation, initial size), ``Resize``, ``Cursor`` and ``Close``
  complete the message set; the logical content of ``0x82`` (run-length encoded full and delta frames) is specified
  above.
* Frames are not compressed (no zlib): compressing attacker-influenced content together with confidential content
  under the same encryption leaks information through the record sizes (CRIME / BREACH class).

Known limitations: the client does not forward pure modifier changes (AppCUI controls are not notified of them), so
the remote command bar does not switch to its Alt / Ctrl variants while a modifier is held; the shared screen uses
the special character set of the server (Unicode).
