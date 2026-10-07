// Unit tests of the remote TUI (docs/source/remote_protocol.rst): wire format, input mapping, frame encoding /
// decoding (including hostile inputs) and loopback TLS 1.3 + mutual TLS integration tests with generated certificates.

#include <catch.hpp>

#include "RemoteChannel.hpp"
#include "RemoteClient.hpp"
#include "RemoteServer.hpp"

#include <filesystem>
#include <random>
#include <thread>

using namespace GView::Remote;
using namespace GView::Remote::Protocol;
using AppCUI::Graphics::Character;
using AppCUI::Graphics::Color;
using AppCUI::Input::Key;
using AppCUI::Input::MouseButton;

namespace
{
Character Cell(char16 code, Color fg = Color::White, Color bg = Color::Black)
{
    Character c{};
    c.Code             = code;
    c.Color.Foreground = fg;
    c.Color.Background = bg;
    return c;
}
Screen MakeScreen(uint32 w, uint32 h, std::mt19937& rng)
{
    Screen s;
    s.width  = w;
    s.height = h;
    s.cells.resize(static_cast<size_t>(w) * h);
    std::uniform_int_distribution<int> run(1, 40), ch(0x20, 0x7E), col(0, 15);
    size_t i = 0;
    while (i < s.cells.size()) {
        // runs of identical cells mixed with text, like a real TUI screen
        const auto c   = Cell(static_cast<char16>(ch(rng)), static_cast<Color>(col(rng)), static_cast<Color>(col(rng)));
        const size_t n = static_cast<size_t>(run(rng));
        for (size_t k = 0; k < n && i < s.cells.size(); k++, i++)
            s.cells[i] = (rng() & 1) ? c : Cell(static_cast<char16>(ch(rng)), c.Color.Foreground, c.Color.Background);
    }
    return s;
}
std::vector<uint8> Payload(const std::vector<uint8>& message)
{
    REQUIRE(message.size() >= HEADER_SIZE);
    return std::vector<uint8>(message.begin() + HEADER_SIZE, message.end());
}
bool KeyRoundTrip(Key key, char16 ch, Key& outKey, char16& outCh)
{
    bool shiftState = false;
    std::vector<uint8> m;
    AppendKeyEvent(m, EncodeKeyEvent(key, ch));
    KeyEvent parsed;
    return ParseKeyEvent(Payload(m), parsed) && DecodeKeyEvent(parsed, outKey, outCh, shiftState) && !shiftState;
}
} // namespace

TEST_CASE("Message framing and per-direction size caps", "[Remote]")
{
    std::vector<uint8> stream;
    AppendResize(stream, 120, 40);
    AppendKeyEvent(stream, EncodeKeyEvent(Key::Enter, 0));

    // fed one byte at a time
    MessageParser parser(true);
    std::vector<MessageType> types;
    for (auto b : stream) {
        parser.Append(&b, 1);
        MessageType t;
        std::span<const uint8> p;
        while (parser.Next(t, p) == MessageParser::Result::Message)
            types.push_back(t);
    }
    REQUIRE(types == std::vector<MessageType>{ MessageType::Resize, MessageType::KeyEvent });

    SECTION("a server message is refused by the server side parser")
    {
        std::vector<uint8> m;
        AppendCursor(m, CursorState{ 1, 2, true });
        MessageParser p(true);
        p.Append(m.data(), m.size());
        MessageType t;
        std::span<const uint8> payload;
        REQUIRE(p.Next(t, payload) == MessageParser::Result::Error);
    }
    SECTION("an oversized payload is refused before it is buffered")
    {
        const uint8 header[] = { static_cast<uint8>(MessageType::KeyEvent), 0xFF, 0xFF, 0xFF, 0x7F };
        MessageParser p(true);
        p.Append(header, sizeof(header));
        MessageType t;
        std::span<const uint8> payload;
        REQUIRE(p.Next(t, payload) == MessageParser::Result::Error);
        // the parser stays poisoned
        REQUIRE(p.Next(t, payload) == MessageParser::Result::Error);
    }
    SECTION("unknown types are refused")
    {
        const uint8 header[] = { 0x55, 0, 0, 0, 0 };
        MessageParser p(false);
        p.Append(header, sizeof(header));
        MessageType t;
        std::span<const uint8> payload;
        REQUIRE(p.Next(t, payload) == MessageParser::Result::Error);
    }
}

TEST_CASE("Handshake and small messages", "[Remote]")
{
    std::vector<uint8> m;
    AppendHello(m, Hello{ VERSION, CAP_OPTIMIZED_FRAMES, 200, 60 });
    Hello h;
    REQUIRE(DecodeHello(Payload(m), h));
    REQUIRE(h.width == 200);
    REQUIRE(h.height == 60);
    REQUIRE(h.capabilities == CAP_OPTIMIZED_FRAMES);
    auto p = Payload(m);
    p.push_back(0);
    REQUIRE_FALSE(DecodeHello(p, h)); // trailing byte

    m.clear();
    AppendWelcome(m, Welcome{ VERSION, 0, 0, 10 });
    Welcome w;
    REQUIRE_FALSE(DecodeWelcome(Payload(m), w)); // zero width

    m.clear();
    AppendClose(m, CloseReason::ServerFull, std::string("bad\x1B[2Jtext") + std::string(400, 'x'));
    CloseMessage c;
    REQUIRE(DecodeClose(Payload(m), c));
    REQUIRE(c.reason == CloseReason::ServerFull);
    REQUIRE(c.text.size() == MAX_CLOSE_TEXT_SIZE);
    REQUIRE(c.text.find('\x1B') == std::string::npos); // no escape sequence reaches the local terminal

    uint32 cw = 5, ch = 100000;
    ClampScreenSize(cw, ch);
    REQUIRE(cw == MIN_SCREEN_WIDTH);
    REQUIRE(ch == MAX_SCREEN_HEIGHT);
}

TEST_CASE("Keyboard events keep AppCUI semantics", "[Remote]")
{
    Key k;
    char16 c;
    REQUIRE(KeyRoundTrip(Key::A, u'a', k, c));
    REQUIRE((k == Key::A && c == u'a'));
    REQUIRE(KeyRoundTrip(Key::A | Key::Shift, u'A', k, c));
    REQUIRE((k == (Key::A | Key::Shift) && c == u'A'));
    REQUIRE(KeyRoundTrip(Key::N7, u'7', k, c));
    REQUIRE((k == Key::N7 && c == u'7'));
    REQUIRE(KeyRoundTrip(Key::Space, u' ', k, c));
    REQUIRE((k == Key::Space && c == u' '));
    REQUIRE(KeyRoundTrip(Key::Ctrl | Key::C, 0, k, c));
    REQUIRE((k == (Key::Ctrl | Key::C) && c == 0));
    REQUIRE(KeyRoundTrip(Key::Alt | Key::F, u'f', k, c));
    REQUIRE((k == (Key::Alt | Key::F) && c == u'f'));
    REQUIRE(KeyRoundTrip(Key::F5 | Key::Shift, 0, k, c));
    REQUIRE((k == (Key::F5 | Key::Shift) && c == 0));
    REQUIRE(KeyRoundTrip(Key::Enter, 0, k, c));
    REQUIRE((k == Key::Enter && c == 0));
    // characters without an AppCUI key keep the character
    REQUIRE(KeyRoundTrip(Key::N1 | Key::Shift, u'!', k, c));
    REQUIRE((k == Key::None && c == u'!'));
    REQUIRE(KeyRoundTrip(Key::None, static_cast<char16>(0x0103), k, c));
    REQUIRE((k == Key::None && c == static_cast<char16>(0x0103)));

    bool shiftState = false;
    KeyEvent e;
    e.code      = 0;
    e.modifiers = KEY_MOD_CTRL | KEY_MOD_ALT;
    REQUIRE(DecodeKeyEvent(e, k, c, shiftState));
    REQUIRE(shiftState);
    REQUIRE(k == (Key::Ctrl | Key::Alt));

    e.code      = 0x1B; // ESC as a "character"
    e.modifiers = KEY_MOD_UNICODE;
    REQUIRE_FALSE(DecodeKeyEvent(e, k, c, shiftState));
    e.code = 0xD800; // lone surrogate
    REQUIRE_FALSE(DecodeKeyEvent(e, k, c, shiftState));
    e.code      = static_cast<uint16>(Key::Count);
    e.modifiers = 0;
    REQUIRE_FALSE(DecodeKeyEvent(e, k, c, shiftState));
    e.code      = static_cast<uint16>(Key::A);
    e.modifiers = 0x0100; // reserved bit
    REQUIRE_FALSE(DecodeKeyEvent(e, k, c, shiftState));
    e.modifiers = 0;
    e.pressed   = 2;
    REQUIRE_FALSE(DecodeKeyEvent(e, k, c, shiftState));
}

TEST_CASE("Mouse events are validated and mapped", "[Remote]")
{
    REQUIRE(DecodeMouseButtons(EncodeMouseButtons(MouseButton::Right)) == MouseButton::Right);
    REQUIRE(EncodeMouseButtons(MouseButton::Right) == MOUSE_BUTTON_RIGHT);
    REQUIRE(EncodeMouseButtons(MouseButton::Center) == MOUSE_BUTTON_MIDDLE);

    MouseEvent e{ MouseEventKind::Press, 10, 4, MOUSE_BUTTON_LEFT | MOUSE_BUTTON_DOUBLE_CLICK, KEY_MOD_SHIFT };
    std::vector<uint8> m;
    AppendMouseEvent(m, e);
    REQUIRE(m.size() == HEADER_SIZE + MOUSE_EVENT_PAYLOAD_SIZE);
    MouseEvent parsed;
    REQUIRE(ParseMouseEvent(Payload(m), parsed));
    AppCUI::Application::FrontendEvent f;
    REQUIRE(ToFrontendEvent(parsed, f));
    REQUIRE(f.Type == AppCUI::Application::FrontendEventType::MouseDown);
    REQUIRE((f.X == 10 && f.Y == 4));
    REQUIRE(f.Button == (MouseButton::Left | MouseButton::DoubleClicked));
    REQUIRE(f.Key == Key::Shift);

    auto bad = [](MouseEvent ev) {
        std::vector<uint8> msg;
        AppendMouseEvent(msg, ev);
        MouseEvent out;
        return !ParseMouseEvent(Payload(msg), out);
    };
    REQUIRE(bad(MouseEvent{ MouseEventKind::Press, 0, 0, MOUSE_BUTTON_DOUBLE_CLICK, 0 }));
    REQUIRE(bad(MouseEvent{ MouseEventKind::Wheel, 0, 0, 9, 0 }));
    REQUIRE(bad(MouseEvent{ MouseEventKind::Move, 0, 0, 0x10, 0 }));
    REQUIRE(bad(MouseEvent{ MouseEventKind::Move, 0, 0, 0, 0x80 }));
    REQUIRE(bad(MouseEvent{ static_cast<MouseEventKind>(7), 0, 0, 0, 0 }));
}

TEST_CASE("Frames: full and delta encoding round trip", "[Remote]")
{
    std::mt19937 rng(20251006);
    auto s1 = MakeScreen(160, 50, rng);

    Screen client;
    uint32 clientFrameId = 0;
    std::string error;

    auto full = EncodeFrame(nullptr, 0, s1);
    REQUIRE(full[0] == FRAME_KIND_FULL);
    REQUIRE(full.size() < s1.cells.size() * WIRE_CELL_SIZE); // run length encoding helps on TUI screens
    REQUIRE(ApplyFrame(client, clientFrameId, 1, full, error));
    REQUIRE(client.SameContent(s1));

    // unchanged screen -> nothing to send
    REQUIRE(EncodeFrame(&s1, 1, s1).empty());

    // sparse changes -> small delta
    auto s2        = s1;
    s2.cells[0]    = Cell(u'X');
    s2.cells[1234] = Cell(u'Y', Color::Red);
    s2.cells[1236] = Cell(u'Z', Color::Green);
    for (uint32 x = 0; x < 160; x++)
        s2.cells[49 * 160 + x] = Cell(u'-', Color::Yellow, Color::DarkBlue);
    auto delta = EncodeFrame(&s1, 1, s2);
    REQUIRE(delta[0] == FRAME_KIND_DELTA);
    REQUIRE(delta.size() < 100);
    REQUIRE(ApplyFrame(client, clientFrameId, 2, delta, error));
    REQUIRE(clientFrameId == 2);
    REQUIRE(client.SameContent(s2));

    // many random rounds (deterministic)
    auto previous     = s2;
    uint32 previousId = 2;
    for (uint32 round = 0; round < 200; round++) {
        auto next          = previous;
        const auto changes = rng() % 300;
        for (uint32 i = 0; i < changes; i++)
            next.cells[rng() % next.cells.size()] = Cell(static_cast<char16>(0x20 + rng() % 0x5F), static_cast<Color>(rng() % 16));
        auto f = EncodeFrame(&previous, previousId, next);
        if (changes == 0 || f.empty())
            continue;
        REQUIRE(ApplyFrame(client, clientFrameId, previousId + 1, f, error));
        REQUIRE(client.SameContent(next));
        previous = next;
        previousId++;
    }

    // a resize always produces a full frame
    auto resized = MakeScreen(80, 25, rng);
    auto rf      = EncodeFrame(&previous, previousId, resized);
    REQUIRE(rf[0] == FRAME_KIND_FULL);
    REQUIRE(ApplyFrame(client, clientFrameId, previousId + 1, rf, error));
    REQUIRE(client.SameContent(resized));
}

TEST_CASE("Frames: hostile input never corrupts the client screen", "[Remote]")
{
    std::mt19937 rng(7);
    auto s1 = MakeScreen(100, 30, rng);
    auto s2 = s1;
    for (uint32 i = 0; i < 40; i++)
        s2.cells[rng() % s2.cells.size()] = Cell(u'#');
    const auto full  = EncodeFrame(nullptr, 0, s1);
    const auto delta = EncodeFrame(&s1, 1, s2);

    Screen base;
    uint32 baseId = 0;
    std::string error;
    REQUIRE(ApplyFrame(base, baseId, 1, full, error));

    SECTION("delta with a wrong base frame")
    {
        auto copy = base;
        uint32 id = 5; // the client did not apply frame 1
        REQUIRE_FALSE(ApplyFrame(copy, id, 6, delta, error));
        REQUIRE(copy.SameContent(base));
    }
    SECTION("truncated frames")
    {
        for (size_t len = 0; len < delta.size(); len++) {
            auto copy = base;
            uint32 id = 1;
            REQUIRE_FALSE(ApplyFrame(copy, id, 2, std::span<const uint8>(delta.data(), len), error));
            REQUIRE(copy.SameContent(base));
            REQUIRE(id == 1);
        }
    }
    SECTION("random mutations")
    {
        for (uint32 round = 0; round < 3000; round++) {
            auto mutated     = (round & 1) ? delta : full;
            const auto flips = 1 + rng() % 4;
            for (uint32 i = 0; i < flips; i++)
                mutated[rng() % mutated.size()] ^= static_cast<uint8>(1u << (rng() % 8));
            auto copy = base;
            uint32 id = 1;
            if (ApplyFrame(copy, id, 2, mutated, error)) {
                // accepted -> must still be a coherent screen
                REQUIRE(copy.IsValid());
                REQUIRE(id == 2);
            } else {
                REQUIRE(copy.SameContent(base));
                REQUIRE(id == 1);
            }
        }
    }
    SECTION("a span outside of the screen")
    {
        std::vector<uint8> f;
        ByteWriter w(f);
        w.U8(FRAME_KIND_DELTA);
        w.U16(100);
        w.U16(30);
        w.U32(1);
        w.U32(1);        // one span
        w.U32(100 * 30); // offset == cell count
        w.U32(1);
        w.U16(1);
        w.U16(u'A');
        w.U8(15);
        w.U8(0);
        auto copy = base;
        uint32 id = 1;
        REQUIRE_FALSE(ApplyFrame(copy, id, 2, f, error));
    }
    SECTION("an invalid color")
    {
        std::vector<uint8> f;
        ByteWriter w(f);
        w.U8(FRAME_KIND_FULL);
        w.U16(1);
        w.U16(1);
        w.U32(0);
        w.U16(1);
        w.U16(u'A');
        w.U8(0x11); // > Transparent
        w.U8(0);
        Screen s;
        uint32 id = 0;
        REQUIRE_FALSE(ApplyFrame(s, id, 1, f, error));
    }
}

TEST_CASE("Optimized frame chunks are reassembled strictly in order", "[Remote]")
{
    std::vector<uint8> logical(MAX_CHUNK_DATA_SIZE * 2 + 100, 0x41);
    logical[0] = FRAME_KIND_FULL;
    std::vector<uint8> stream;
    AppendOptimizedFrame(stream, 7, logical);

    // split the message stream
    std::vector<std::vector<uint8>> chunks;
    MessageParser parser(false);
    parser.Append(stream.data(), stream.size());
    MessageType t;
    std::span<const uint8> p;
    while (parser.Next(t, p) == MessageParser::Result::Message) {
        REQUIRE(t == MessageType::TuiOptimizedFrame);
        chunks.emplace_back(p.begin(), p.end());
    }
    REQUIRE(chunks.size() == 3);

    SECTION("in order")
    {
        FrameAssembler a;
        REQUIRE(a.AddChunk(chunks[0]) == FrameAssembler::Result::NeedMore);
        REQUIRE(a.AddChunk(chunks[1]) == FrameAssembler::Result::NeedMore);
        REQUIRE(a.AddChunk(chunks[2]) == FrameAssembler::Result::Complete);
        REQUIRE(a.GetFrameId() == 7);
        REQUIRE(std::vector<uint8>(a.GetFrame().begin(), a.GetFrame().end()) == logical);
        // replayed / older frame ids are refused
        FrameAssembler b = a;
        REQUIRE(b.AddChunk(chunks[0]) == FrameAssembler::Result::Error);
    }
    SECTION("out of order")
    {
        FrameAssembler a;
        REQUIRE(a.AddChunk(chunks[0]) == FrameAssembler::Result::NeedMore);
        REQUIRE(a.AddChunk(chunks[2]) == FrameAssembler::Result::Error);
    }
    SECTION("a chunk that does not start a frame")
    {
        FrameAssembler a;
        REQUIRE(a.AddChunk(chunks[1]) == FrameAssembler::Result::Error);
    }
    SECTION("announced size above the cap")
    {
        auto c = chunks[0];
        c[4]   = 0xFF; // total size (u64) low byte
        c[8]   = 0x10; // -> far above MAX_LOGICAL_FRAME_SIZE
        FrameAssembler a;
        REQUIRE(a.AddChunk(c) == FrameAssembler::Result::Error);
    }
}

TEST_CASE("Legacy full frame (0x81)", "[Remote]")
{
    std::mt19937 rng(3);
    auto s = MakeScreen(40, 10, rng);
    std::vector<uint8> m;
    AppendTuiFrame(m, s);
    REQUIRE(m.size() == HEADER_SIZE + 4 + 40 * 10 * WIRE_CELL_SIZE);
    Screen out;
    REQUIRE(DecodeTuiFrame(Payload(m), out));
    REQUIRE(out.SameContent(s));
    auto p = Payload(m);
    p.pop_back();
    REQUIRE_FALSE(DecodeTuiFrame(p, out));
}

TEST_CASE("Remote cells are sanitized before reaching the local terminal", "[Remote]")
{
    REQUIRE(SanitizeCell(Cell(0x1B)).Code == u'?');
    REQUIRE(SanitizeCell(Cell(0x9B)).Code == u'?'); // C1 CSI
    REQUIRE(SanitizeCell(Cell(0xDC00)).Code == u'?');
    REQUIRE(SanitizeCell(Cell(0)).Code == u' ');
    REQUIRE(SanitizeCell(Cell(static_cast<char16>(0x2500))).Code == static_cast<char16>(0x2500)); // box drawing kept
    auto c = SanitizeCell(Cell(u'a', Color::Transparent, Color::Transparent));
    REQUIRE(c.Color.Foreground == Color::Silver);
    REQUIRE(c.Color.Background == Color::Black);
}

TEST_CASE("Host and port parsing", "[Remote]")
{
    std::string host;
    uint16 port = 0;
    REQUIRE(Net::ParseHostPort("server.lab", host, port, 18262));
    REQUIRE((host == "server.lab" && port == 18262));
    REQUIRE(Net::ParseHostPort("10.0.0.5:9000", host, port, 18262));
    REQUIRE((host == "10.0.0.5" && port == 9000));
    REQUIRE(Net::ParseHostPort("[::1]:9001", host, port, 18262));
    REQUIRE((host == "::1" && port == 9001));
    REQUIRE(Net::ParseHostPort("fe80::1", host, port, 18262));
    REQUIRE((host == "fe80::1" && port == 18262));
    REQUIRE_FALSE(Net::ParseHostPort("host:0", host, port, 1));
    REQUIRE_FALSE(Net::ParseHostPort("host:70000", host, port, 1));
    REQUIRE_FALSE(Net::ParseHostPort("bad host", host, port, 1));
    REQUIRE_FALSE(Net::ParseHostPort("[::1", host, port, 1));
    REQUIRE_FALSE(Net::ParseHostPort("", host, port, 1));
}

// ------------------------------------------------------------------ TLS loopback integration
namespace
{
struct TempFolder {
    std::filesystem::path path;
    explicit TempFolder(std::string_view name)
    {
        std::random_device rd;
        path = std::filesystem::temp_directory_path() / (std::string("gview-remote-test-") + std::string(name) + "-" + std::to_string(rd()));
        std::filesystem::create_directories(path);
    }
    ~TempFolder()
    {
        std::error_code ec;
        std::filesystem::remove_all(path, ec);
    }
};

Tls::Settings Identity(const TempFolder& pki, const std::string& name, const TempFolder* caFolder = nullptr)
{
    Tls::Settings s;
    s.certificate = pki.path / (name + ".crt");
    s.privateKey  = pki.path / (name + ".key");
    s.trustedCA   = (caFolder ? caFolder->path : pki.path) / "gview-ca.crt";
    return s;
}

struct HandshakeResult {
    bool serverOk{ false };
    bool clientOk{ false };
    std::string serverError;
    std::string clientError;
    std::unique_ptr<Channel> server;
    std::unique_ptr<Channel> client;
};

HandshakeResult Handshake(const Tls::Settings& serverSettings, const Tls::Settings& clientSettings, const std::string& serverName = "127.0.0.1")
{
    HandshakeResult r;
    std::string error;
    REQUIRE(Net::Startup(error));
    auto serverContext = Tls::Context::Create(serverSettings, Tls::Role::Server, error);
    INFO(error);
    REQUIRE(serverContext);
    auto clientContext = Tls::Context::Create(clientSettings, Tls::Role::Client, error);
    INFO(error);
    REQUIRE(clientContext);

    Net::Socket listener;
    REQUIRE(Net::Listen("127.0.0.1", 0, listener, error));
    const auto port = Net::LocalPort(listener);
    REQUIRE(port != 0);

    std::thread serverThread([&]() {
        Net::Socket accepted;
        std::string peer, e;
        for (int i = 0; i < 100 && !accepted.IsValid(); i++) {
            Net::PollRequest req{};
            req.socket   = listener.Get();
            req.wantRead = true;
            Net::Poll(&req, 1, 50);
            Net::Accept(listener, accepted, peer, e);
        }
        if (!accepted.IsValid() || !Net::ConfigureStream(accepted, e)) {
            r.serverError = "accept failed: " + e;
            return;
        }
        auto stream = Tls::Stream::Create(serverContext, std::move(accepted), "", e);
        if (!stream) {
            r.serverError = e;
            return;
        }
        r.server      = std::make_unique<Channel>(std::move(stream), true);
        r.serverOk    = r.server->Init(e) && r.server->Handshake(std::chrono::milliseconds(5000), e);
        r.serverError = e;
    });

    Net::Socket socket;
    std::string e;
    if (Net::Connect("127.0.0.1", port, 5000, nullptr, socket, e) && Net::ConfigureStream(socket, e)) {
        auto stream = Tls::Stream::Create(clientContext, std::move(socket), serverName, e);
        if (stream) {
            r.client   = std::make_unique<Channel>(std::move(stream), false);
            r.clientOk = r.client->Init(e) && r.client->Handshake(std::chrono::milliseconds(5000), e);
        }
    }
    r.clientError = e;
    serverThread.join();
    return r;
}

// minimal protocol peers driven by Channel::Run
class TestServerHandler : public Channel::Handler
{
  public:
    Channel* channel{ nullptr };
    Screen screen;
    bool hello{ false };
    bool sent{ false };
    std::vector<Key> keys;
    bool OnMessage(MessageType type, std::span<const uint8> payload, CloseReason& reason, std::string&) override
    {
        reason = CloseReason::ProtocolError;
        if (type == MessageType::Hello) {
            Hello h;
            hello = DecodeHello(payload, h);
            channel->Wake();
            return hello;
        }
        if (type == MessageType::KeyEvent) {
            KeyEvent e;
            Key k;
            char16 c;
            bool s;
            if (!ParseKeyEvent(payload, e) || !DecodeKeyEvent(e, k, c, s))
                return false;
            keys.push_back(k);
            channel->Stop(CloseReason::Normal); // test done
            return true;
        }
        return false;
    }
    void ProduceOutgoing(std::vector<uint8>& out) override
    {
        if (!hello || sent)
            return;
        AppendWelcome(out, Welcome{ VERSION, CAP_OPTIMIZED_FRAMES, static_cast<uint16>(screen.width), static_cast<uint16>(screen.height) });
        AppendOptimizedFrame(out, 1, EncodeFrame(nullptr, 0, screen));
        AppendCursor(out, CursorState{ 3, 4, true });
        sent = true;
    }
};
class TestClientHandler : public Channel::Handler
{
  public:
    Channel* channel{ nullptr };
    FrameAssembler assembler;
    Screen screen;
    uint32 frameId{ 0 };
    bool welcome{ false };
    bool helloSent{ false };
    bool keySent{ false };
    CursorState cursor;
    bool OnMessage(MessageType type, std::span<const uint8> payload, CloseReason& reason, std::string& text) override
    {
        reason = CloseReason::ProtocolError;
        switch (type) {
        case MessageType::Welcome: {
            Welcome w;
            welcome = DecodeWelcome(payload, w);
            return welcome;
        }
        case MessageType::TuiOptimizedFrame: {
            const auto r = assembler.AddChunk(payload);
            if (r == FrameAssembler::Result::Error)
                return false;
            if (r == FrameAssembler::Result::Complete)
                return ApplyFrame(screen, frameId, assembler.GetFrameId(), assembler.GetFrame(), text);
            return true;
        }
        case MessageType::Cursor:
            if (!DecodeCursor(payload, cursor))
                return false;
            channel->Wake(); // the screen is complete -> send a key
            return true;
        default:
            return false;
        }
    }
    void ProduceOutgoing(std::vector<uint8>& out) override
    {
        if (!helloSent) {
            AppendHello(out, Hello{ VERSION, CAP_OPTIMIZED_FRAMES, 90, 30 });
            helloSent = true;
        }
        if (cursor.visible && !keySent) {
            AppendKeyEvent(out, EncodeKeyEvent(Key::Ctrl | Key::Q, 0));
            keySent = true;
        }
    }
};
} // namespace

TEST_CASE("TLS 1.3 mutual authentication over loopback", "[Remote][TLS]")
{
    TempFolder pki("pki");
    std::string report, error;
    REQUIRE(Tls::GenerateCertificates(pki.path, "127.0.0.1", 7, 30, report, error));
    REQUIRE(Tls::GenerateCertificates(pki.path, "analyst", 7, 30, report, error));
    REQUIRE(report.find("(reused)") != std::string::npos); // the CA created by the first call was reused

    const auto serverIdentity = Identity(pki, "127.0.0.1");
    const auto clientIdentity = Identity(pki, "analyst");

    SECTION("a full protocol exchange")
    {
        auto r = Handshake(serverIdentity, clientIdentity);
        INFO(r.serverError << " / " << r.clientError);
        REQUIRE(r.serverOk);
        REQUIRE(r.clientOk);
        REQUIRE(r.server->GetPeer().subject.find("CN=analyst") != std::string::npos);
        REQUIRE(r.client->GetPeer().subject.find("CN=127.0.0.1") != std::string::npos);
        REQUIRE((r.client->GetPeer().cipher == "TLS_AES_256_GCM_SHA384" || r.client->GetPeer().cipher == "TLS_CHACHA20_POLY1305_SHA256"));

        std::mt19937 rng(11);
        TestServerHandler sh;
        sh.channel = r.server.get();
        sh.screen  = MakeScreen(90, 30, rng);
        TestClientHandler ch;
        ch.channel = r.client.get();

        Channel::Result serverResult, clientResult;
        std::thread st([&]() { serverResult = r.server->Run(sh); });
        clientResult = r.client->Run(ch);
        st.join();

        REQUIRE(ch.welcome);
        REQUIRE(ch.screen.SameContent(sh.screen));
        REQUIRE((ch.cursor.x == 3 && ch.cursor.y == 4 && ch.cursor.visible));
        REQUIRE(sh.keys == std::vector<Key>{ Key::Ctrl | Key::Q });
        REQUIRE(clientResult.closedByPeer); // the server closed the session with a Close message
    }
    SECTION("a peer certificate from another CA is refused")
    {
        TempFolder other("other");
        REQUIRE(Tls::GenerateCertificates(other.path, "intruder", 7, 30, report, error));
        auto intruder = Identity(other, "intruder", &pki); // trusts our CA but presents a foreign certificate
        auto r        = Handshake(serverIdentity, intruder);
        REQUIRE_FALSE(r.serverOk);
    }
    SECTION("the server name is verified")
    {
        auto r = Handshake(serverIdentity, clientIdentity, "server.example");
        REQUIRE_FALSE(r.clientOk);
    }
    SECTION("ALPN is mandatory")
    {
        auto client = clientIdentity;
        client.alpn = "other/1";
        auto r      = Handshake(serverIdentity, client);
        REQUIRE_FALSE(r.serverOk);
        REQUIRE_FALSE(r.clientOk);
    }
    SECTION("long-lived peer certificates are refused")
    {
        auto server                           = serverIdentity;
        server.maxPeerCertificateLifetimeDays = 1; // the analyst certificate is valid for 7 days
        auto r                                = Handshake(server, clientIdentity);
        REQUIRE_FALSE(r.serverOk);
    }
}

TEST_CASE("ClientSession end to end (TLS, Hello/Welcome, frames, cursor, keys)", "[Remote][TLS]")
{
    TempFolder pki("session");
    std::string report, error;
    REQUIRE(Tls::GenerateCertificates(pki.path, "127.0.0.1", 7, 30, report, error));
    REQUIRE(Tls::GenerateCertificates(pki.path, "analyst", 7, 30, report, error));
    REQUIRE(Net::Startup(error));
    auto serverContext = Tls::Context::Create(Identity(pki, "127.0.0.1"), Tls::Role::Server, error);
    REQUIRE(serverContext);
    Net::Socket listener;
    REQUIRE(Net::Listen("127.0.0.1", 0, listener, error));
    const auto port = Net::LocalPort(listener);

    std::mt19937 rng(5);
    TestServerHandler handler;
    handler.screen = MakeScreen(90, 30, rng);
    std::thread serverThread([&]() {
        Net::Socket accepted;
        std::string peer, e;
        for (int i = 0; i < 100 && !accepted.IsValid(); i++) {
            Net::PollRequest req{};
            req.socket   = listener.Get();
            req.wantRead = true;
            Net::Poll(&req, 1, 50);
            Net::Accept(listener, accepted, peer, e);
        }
        if (!accepted.IsValid() || !Net::ConfigureStream(accepted, e))
            return;
        auto stream = Tls::Stream::Create(serverContext, std::move(accepted), "", e);
        if (!stream)
            return;
        Channel channel(std::move(stream), true);
        if (!channel.Init(e) || !channel.Handshake(std::chrono::milliseconds(5000), e))
            return;
        handler.channel = &channel;
        channel.Run(handler);
    });

    ClientOptions options;
    options.mode = ClientOptions::Mode::Connect;
    options.host = "127.0.0.1";
    options.port = port;
    options.tls  = Identity(pki, "analyst");
    {
        ClientSession session(options);
        session.Start(90, 30);
        Screen screen;
        CursorState cursor;
        bool complete = false;
        for (int i = 0; i < 400 && !complete; i++) {
            Screen s;
            CursorState c;
            if (session.TakeScreen(s, c)) {
                if (s.IsValid())
                    screen = std::move(s);
                cursor = c;
            }
            complete = screen.IsValid() && cursor.visible;
            if (!complete)
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        std::string status;
        INFO(status);
        REQUIRE(complete);
        REQUIRE(screen.SameContent(handler.screen));
        REQUIRE(session.GetState(status) == ClientSession::State::Connected);

        session.SendKey(Key::Ctrl | Key::Q, 0); // the test server ends the session when it receives a key
        auto state = ClientSession::State::Connected;
        for (int i = 0; i < 400 && state != ClientSession::State::Closed; i++) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            state = session.GetState(status);
        }
        REQUIRE(state == ClientSession::State::Closed);
    }
    serverThread.join();
    REQUIRE(handler.keys == std::vector<Key>{ Key::Ctrl | Key::Q });
}
