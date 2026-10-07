#include "RemoteProtocol.hpp"

#include <algorithm>
#include <cstring>

namespace GView::Remote::Protocol
{
using AppCUI::Graphics::Color;
using AppCUI::Input::Key;
using AppCUI::Input::MouseButton;
using AppCUI::Input::MouseWheel;

namespace
{
    constexpr uint32 KEY_BASE_MASK      = 0x0FFF;
    constexpr uint32 KEY_MODIFIERS_MASK = static_cast<uint32>(Key::Alt) | static_cast<uint32>(Key::Ctrl) | static_cast<uint32>(Key::Shift);
    constexpr uint32 MERGE_GAP          = 2; // unchanged cells absorbed into a delta span (cheaper than a new span header)
    constexpr uint32 MIN_REPEAT_RUN     = 3; // shorter runs are emitted as literals

    inline bool HasFlag(Key key, Key flag)
    {
        return (static_cast<uint32>(key) & static_cast<uint32>(flag)) != 0;
    }
    inline bool SameCell(const Character& a, const Character& b)
    {
        return a.Code == b.Code && a.Color.Foreground == b.Color.Foreground && a.Color.Background == b.Color.Background;
    }
    inline bool IsValidColor(uint8 c)
    {
        return c <= static_cast<uint8>(Color::Transparent);
    }
    // characters that can be transmitted inside a key event
    inline bool IsTransmittableCharacter(char16 ch)
    {
        if (ch < 0x20 || (ch >= 0x7F && ch <= 0x9F))
            return false; // C0 / DEL / C1 control characters
        if (ch >= 0xD800 && ch <= 0xDFFF)
            return false; // surrogates (AppCUI works with UCS-2 code units)
        return ch != 0xFFFE && ch != 0xFFFF;
    }
    // printable character produced by an (unmodified or shifted) AppCUI key, 0 if none
    char16 KeyToCharacter(uint32 base, bool shift)
    {
        if (base >= static_cast<uint32>(Key::A) && base <= static_cast<uint32>(Key::Z))
            return static_cast<char16>((shift ? u'A' : u'a') + (base - static_cast<uint32>(Key::A)));
        if (base >= static_cast<uint32>(Key::N0) && base <= static_cast<uint32>(Key::N9))
            return shift ? 0 : static_cast<char16>(u'0' + (base - static_cast<uint32>(Key::N0)));
        if (base == static_cast<uint32>(Key::Space))
            return u' ';
        return 0;
    }
    // AppCUI key produced by a character (letters, digits and space), Key::None otherwise
    Key CharacterToKey(char16 ch)
    {
        if (ch >= u'a' && ch <= u'z')
            return static_cast<Key>(static_cast<uint32>(Key::A) + (ch - u'a'));
        if (ch >= u'A' && ch <= u'Z')
            return static_cast<Key>((static_cast<uint32>(Key::A) + (ch - u'A')) | static_cast<uint32>(Key::Shift));
        if (ch >= u'0' && ch <= u'9')
            return static_cast<Key>(static_cast<uint32>(Key::N0) + (ch - u'0'));
        if (ch == u' ')
            return Key::Space;
        return Key::None;
    }
    uint16 ModifiersToWire(Key key)
    {
        uint16 m = 0;
        if (HasFlag(key, Key::Alt))
            m |= KEY_MOD_ALT;
        if (HasFlag(key, Key::Ctrl))
            m |= KEY_MOD_CTRL;
        if (HasFlag(key, Key::Shift))
            m |= KEY_MOD_SHIFT;
        return m;
    }
    uint32 WireToModifiers(uint16 m)
    {
        uint32 k = 0;
        if (m & KEY_MOD_ALT)
            k |= static_cast<uint32>(Key::Alt);
        if (m & KEY_MOD_CTRL)
            k |= static_cast<uint32>(Key::Ctrl);
        if (m & KEY_MOD_SHIFT)
            k |= static_cast<uint32>(Key::Shift);
        return k;
    }

    void WriteCell(ByteWriter& w, const Character& c)
    {
        w.U16(c.Code);
        w.U8(static_cast<uint8>(c.Color.Foreground));
        w.U8(static_cast<uint8>(c.Color.Background));
    }
    bool ReadCell(ByteReader& r, Character& c)
    {
        uint16 code;
        uint8 fg, bg;
        if (!r.U16(code) || !r.U8(fg) || !r.U8(bg))
            return false;
        if (!IsValidColor(fg) || !IsValidColor(bg))
            return false;
        c.Code             = code;
        c.Color.Foreground = static_cast<Color>(fg);
        c.Color.Background = static_cast<Color>(bg);
        return true;
    }

    size_t RepeatRunAt(const Character* p, const Character* end)
    {
        size_t n = 1;
        while (p + n < end && n < MAX_RUN_LENGTH && SameCell(p[n], p[0]))
            n++;
        return n;
    }
    // true when a repeat run worth encoding (>= MIN_REPEAT_RUN identical cells) starts at p
    bool StartsRepeatRun(const Character* p, const Character* end)
    {
        return (end - p) >= static_cast<std::ptrdiff_t>(MIN_REPEAT_RUN) && SameCell(p[1], p[0]) && SameCell(p[2], p[0]);
    }
    // run-length encoding of [begin, end): literal runs (u16 n, n cells) and repeat runs (u16 0x8000|n, one cell)
    void EncodeCells(ByteWriter& w, const Character* begin, const Character* end)
    {
        auto p = begin;
        while (p < end) {
            const auto repeat = RepeatRunAt(p, end);
            if (repeat >= MIN_REPEAT_RUN) {
                w.U16(static_cast<uint16>(RUN_REPEAT_FLAG | repeat));
                WriteCell(w, *p);
                p += repeat;
                continue;
            }
            auto q = p;
            while (q < end && static_cast<size_t>(q - p) < MAX_RUN_LENGTH && !StartsRepeatRun(q, end))
                q++;
            if (q == p) // defensive: never emit an empty literal
                q++;
            w.U16(static_cast<uint16>(q - p));
            for (auto c = p; c < q; c++)
                WriteCell(w, *c);
            p = q;
        }
    }
    // decodes exactly `count` cells into out (appended)
    bool DecodeCells(ByteReader& r, size_t count, std::vector<Character>& out)
    {
        size_t decoded = 0;
        while (decoded < count) {
            uint16 tag;
            if (!r.U16(tag))
                return false;
            const size_t n = tag & MAX_RUN_LENGTH;
            if (n == 0 || n > count - decoded)
                return false;
            if (tag & RUN_REPEAT_FLAG) {
                Character c;
                if (!ReadCell(r, c))
                    return false;
                out.insert(out.end(), n, c);
            } else {
                // a literal run needs n * 4 bytes: check before touching the output (bounded allocation)
                if (r.Remaining() / WIRE_CELL_SIZE < n)
                    return false;
                for (size_t i = 0; i < n; i++) {
                    Character c;
                    if (!ReadCell(r, c))
                        return false;
                    out.push_back(c);
                }
            }
            decoded += n;
        }
        return true;
    }
    void WriteLogicalHeader(ByteWriter& w, uint8 kind, const Screen& s, uint32 baseFrameId)
    {
        w.U8(kind);
        w.U16(static_cast<uint16>(s.width));
        w.U16(static_cast<uint16>(s.height));
        w.U32(baseFrameId);
    }
    bool IsValidScreenSize(uint32 width, uint32 height)
    {
        return width >= 1 && height >= 1 && width <= MAX_SCREEN_WIDTH && height <= MAX_SCREEN_HEIGHT;
    }
} // namespace

std::string_view CloseReasonToString(CloseReason reason)
{
    switch (reason) {
    case CloseReason::Normal:
        return "closed";
    case CloseReason::ProtocolError:
        return "protocol error";
    case CloseReason::UnsupportedVersion:
        return "unsupported protocol version";
    case CloseReason::ServerFull:
        return "server is full";
    case CloseReason::Timeout:
        return "timeout";
    case CloseReason::Shutdown:
        return "shutdown";
    case CloseReason::InternalError:
        return "internal error";
    }
    return "unknown reason";
}

// ------------------------------------------------------------------ framing
void AppendMessage(std::vector<uint8>& out, MessageType type, std::span<const uint8> payload)
{
    ByteWriter w(out);
    w.U8(static_cast<uint8>(type));
    w.U32(static_cast<uint32>(payload.size()));
    w.Bytes(payload);
}

uint32 MaxPayloadSize(MessageType type, bool sentByClient)
{
    if (sentByClient) {
        switch (type) {
        case MessageType::KeyEvent:
            return KEY_EVENT_PAYLOAD_SIZE;
        case MessageType::MouseEvent:
            return MOUSE_EVENT_PAYLOAD_SIZE;
        case MessageType::Resize:
            return RESIZE_PAYLOAD_SIZE;
        case MessageType::Hello:
            return HELLO_PAYLOAD_SIZE;
        case MessageType::Close:
            return MAX_CLOSE_PAYLOAD_SIZE;
        default:
            return 0;
        }
    }
    switch (type) {
    case MessageType::TuiFrame:
        return MAX_TUI_FRAME_PAYLOAD_SIZE;
    case MessageType::TuiOptimizedFrame:
        return OPTIMIZED_CHUNK_HEADER + MAX_CHUNK_DATA_SIZE;
    case MessageType::Cursor:
        return CURSOR_PAYLOAD_SIZE;
    case MessageType::Welcome:
        return WELCOME_PAYLOAD_SIZE;
    case MessageType::Close:
        return MAX_CLOSE_PAYLOAD_SIZE;
    default:
        return 0;
    }
}

void MessageParser::Append(const uint8* data, size_t size)
{
    if (failed || data == nullptr || size == 0)
        return;
    if (consumed > 0) {
        buffer.erase(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(consumed));
        consumed = 0;
    }
    buffer.insert(buffer.end(), data, data + size);
}

MessageParser::Result MessageParser::Next(MessageType& type, std::span<const uint8>& payload)
{
    if (failed)
        return Result::Error;
    const size_t available = buffer.size() - consumed;
    if (available < HEADER_SIZE)
        return Result::NeedMoreData;
    ByteReader r(buffer.data() + consumed, available);
    uint8 t;
    uint32 length;
    r.U8(t);
    r.U32(length);
    const auto maxSize = MaxPayloadSize(static_cast<MessageType>(t), parsesClientMessages);
    if (maxSize == 0) {
        failed = true;
        error  = "unexpected message type 0x" + std::to_string(t);
        return Result::Error;
    }
    if (length > maxSize) {
        failed = true;
        error  = "payload too large for message type 0x" + std::to_string(t) + " (" + std::to_string(length) + " bytes)";
        return Result::Error;
    }
    if (available - HEADER_SIZE < length)
        return Result::NeedMoreData;
    type    = static_cast<MessageType>(t);
    payload = std::span<const uint8>(buffer.data() + consumed + HEADER_SIZE, length);
    consumed += HEADER_SIZE + length;
    return Result::Message;
}

// ------------------------------------------------------------------ small messages
void AppendHello(std::vector<uint8>& out, const Hello& hello)
{
    std::vector<uint8> p;
    ByteWriter w(p);
    w.U16(hello.version);
    w.U32(hello.capabilities);
    w.U16(hello.width);
    w.U16(hello.height);
    AppendMessage(out, MessageType::Hello, p);
}
void AppendWelcome(std::vector<uint8>& out, const Welcome& welcome)
{
    std::vector<uint8> p;
    ByteWriter w(p);
    w.U16(welcome.version);
    w.U32(welcome.capabilities);
    w.U16(welcome.width);
    w.U16(welcome.height);
    AppendMessage(out, MessageType::Welcome, p);
}
void AppendResize(std::vector<uint8>& out, uint16 width, uint16 height)
{
    std::vector<uint8> p;
    ByteWriter w(p);
    w.U16(width);
    w.U16(height);
    AppendMessage(out, MessageType::Resize, p);
}
void AppendCursor(std::vector<uint8>& out, const CursorState& cursor)
{
    std::vector<uint8> p;
    ByteWriter w(p);
    w.U16(cursor.x);
    w.U16(cursor.y);
    w.U8(cursor.visible ? 1 : 0);
    AppendMessage(out, MessageType::Cursor, p);
}
void AppendClose(std::vector<uint8>& out, CloseReason reason, std::string_view text)
{
    if (text.size() > MAX_CLOSE_TEXT_SIZE)
        text = text.substr(0, MAX_CLOSE_TEXT_SIZE);
    std::vector<uint8> p;
    ByteWriter w(p);
    w.U16(static_cast<uint16>(reason));
    w.U16(static_cast<uint16>(text.size()));
    w.Bytes(std::span<const uint8>(reinterpret_cast<const uint8*>(text.data()), text.size()));
    AppendMessage(out, MessageType::Close, p);
}

bool DecodeHello(std::span<const uint8> payload, Hello& hello)
{
    ByteReader r(payload);
    Hello h;
    if (!r.U16(h.version) || !r.U32(h.capabilities) || !r.U16(h.width) || !r.U16(h.height) || !r.AtEnd())
        return false;
    if (h.width == 0 || h.height == 0)
        return false;
    hello = h;
    return true;
}
bool DecodeWelcome(std::span<const uint8> payload, Welcome& welcome)
{
    ByteReader r(payload);
    Welcome h;
    if (!r.U16(h.version) || !r.U32(h.capabilities) || !r.U16(h.width) || !r.U16(h.height) || !r.AtEnd())
        return false;
    if (!IsValidScreenSize(h.width, h.height))
        return false;
    welcome = h;
    return true;
}
bool DecodeResize(std::span<const uint8> payload, uint16& width, uint16& height)
{
    ByteReader r(payload);
    uint16 w, h;
    if (!r.U16(w) || !r.U16(h) || !r.AtEnd() || w == 0 || h == 0)
        return false;
    width  = w;
    height = h;
    return true;
}
bool DecodeCursor(std::span<const uint8> payload, CursorState& cursor)
{
    ByteReader r(payload);
    CursorState c;
    uint8 visible;
    if (!r.U16(c.x) || !r.U16(c.y) || !r.U8(visible) || !r.AtEnd() || visible > 1)
        return false;
    c.visible = visible == 1;
    cursor    = c;
    return true;
}
bool DecodeClose(std::span<const uint8> payload, CloseMessage& close)
{
    ByteReader r(payload);
    uint16 reason, length;
    std::span<const uint8> text;
    if (!r.U16(reason) || !r.U16(length) || length > MAX_CLOSE_TEXT_SIZE || !r.Bytes(length, text) || !r.AtEnd())
        return false;
    close.reason = static_cast<CloseReason>(reason);
    close.text.clear();
    close.text.reserve(text.size());
    // the text is displayed locally: keep printable ASCII only
    for (auto b : text)
        close.text.push_back((b >= 0x20 && b < 0x7F) ? static_cast<char>(b) : '?');
    return true;
}

void ClampScreenSize(uint32& width, uint32& height)
{
    width  = std::clamp(width, MIN_SCREEN_WIDTH, MAX_SCREEN_WIDTH);
    height = std::clamp(height, MIN_SCREEN_HEIGHT, MAX_SCREEN_HEIGHT);
}

// ------------------------------------------------------------------ keyboard
KeyEvent EncodeKeyEvent(Key key, char16 unicodeCharacter)
{
    const uint32 base    = static_cast<uint32>(key) & KEY_BASE_MASK;
    const uint16 mods    = ModifiersToWire(key);
    const bool shift     = HasFlag(key, Key::Shift);
    const bool ctrlOrAlt = HasFlag(key, Key::Ctrl) || HasFlag(key, Key::Alt);

    KeyEvent e;
    e.pressed = 1;
    if (IsTransmittableCharacter(unicodeCharacter)) {
        // the key code form is used when the receiver rebuilds exactly the same character from it
        if (base != 0 && base < static_cast<uint32>(Key::Count) && !ctrlOrAlt && KeyToCharacter(base, shift) == unicodeCharacter) {
            e.code      = static_cast<uint16>(base);
            e.modifiers = mods;
            return e;
        }
        e.code      = unicodeCharacter;
        e.modifiers = static_cast<uint16>(mods | KEY_MOD_UNICODE);
        return e;
    }
    e.code      = base < static_cast<uint32>(Key::Count) ? static_cast<uint16>(base) : 0;
    e.modifiers = mods;
    return e;
}

bool DecodeKeyEvent(const KeyEvent& e, Key& key, char16& unicodeCharacter, bool& isShiftState)
{
    if (e.pressed > 1 || (e.modifiers & ~KEY_MOD_MASK) != 0)
        return false;
    const uint32 mods = WireToModifiers(e.modifiers);
    isShiftState      = false;
    if (e.modifiers & KEY_MOD_UNICODE) {
        const char16 ch = static_cast<char16>(e.code);
        if (!IsTransmittableCharacter(ch))
            return false;
        auto k = CharacterToKey(ch);
        if (k != Key::None)
            k = static_cast<Key>(static_cast<uint32>(k) | (mods & (static_cast<uint32>(Key::Alt) | static_cast<uint32>(Key::Ctrl))));
        key              = k;
        unicodeCharacter = ch;
        return true;
    }
    if (e.code >= static_cast<uint32>(Key::Count))
        return false;
    if (e.code == 0) {
        // modifier only event -> new shift state
        isShiftState     = true;
        key              = static_cast<Key>(mods);
        unicodeCharacter = 0;
        return true;
    }
    const bool ctrlOrAlt = (mods & (static_cast<uint32>(Key::Alt) | static_cast<uint32>(Key::Ctrl))) != 0;
    key                  = static_cast<Key>(e.code | mods);
    unicodeCharacter     = ctrlOrAlt ? 0 : KeyToCharacter(e.code, (mods & static_cast<uint32>(Key::Shift)) != 0);
    return true;
}

void AppendKeyEvent(std::vector<uint8>& out, const KeyEvent& e)
{
    std::vector<uint8> p;
    ByteWriter w(p);
    w.U8(e.pressed);
    w.U16(e.code);
    w.U16(e.modifiers);
    AppendMessage(out, MessageType::KeyEvent, p);
}
bool ParseKeyEvent(std::span<const uint8> payload, KeyEvent& e)
{
    ByteReader r(payload);
    KeyEvent k;
    if (!r.U8(k.pressed) || !r.U16(k.code) || !r.U16(k.modifiers) || !r.AtEnd())
        return false;
    e = k;
    return true;
}

// ------------------------------------------------------------------ mouse
uint8 EncodeMouseButtons(MouseButton button)
{
    const auto b = static_cast<uint32>(button);
    uint8 r      = 0;
    if (b & static_cast<uint32>(MouseButton::Left))
        r |= MOUSE_BUTTON_LEFT;
    if (b & static_cast<uint32>(MouseButton::Right))
        r |= MOUSE_BUTTON_RIGHT;
    if (b & static_cast<uint32>(MouseButton::Center))
        r |= MOUSE_BUTTON_MIDDLE;
    if (b & static_cast<uint32>(MouseButton::DoubleClicked))
        r |= MOUSE_BUTTON_DOUBLE_CLICK;
    return r;
}
MouseButton DecodeMouseButtons(uint8 button)
{
    uint32 r = 0;
    if (button & MOUSE_BUTTON_LEFT)
        r |= static_cast<uint32>(MouseButton::Left);
    if (button & MOUSE_BUTTON_RIGHT)
        r |= static_cast<uint32>(MouseButton::Right);
    if (button & MOUSE_BUTTON_MIDDLE)
        r |= static_cast<uint32>(MouseButton::Center);
    if (button & MOUSE_BUTTON_DOUBLE_CLICK)
        r |= static_cast<uint32>(MouseButton::DoubleClicked);
    return static_cast<MouseButton>(r);
}
uint8 EncodeMouseWheel(MouseWheel wheel)
{
    switch (wheel) {
    case MouseWheel::Up:
        return MOUSE_WHEEL_UP;
    case MouseWheel::Down:
        return MOUSE_WHEEL_DOWN;
    case MouseWheel::Left:
        return MOUSE_WHEEL_LEFT;
    case MouseWheel::Right:
        return MOUSE_WHEEL_RIGHT;
    default:
        return 0;
    }
}
uint8 EncodeModifiers8(Key key)
{
    return static_cast<uint8>(ModifiersToWire(key));
}
Key DecodeModifiers8(uint8 modifiers)
{
    return static_cast<Key>(WireToModifiers(modifiers & (KEY_MOD_ALT | KEY_MOD_CTRL | KEY_MOD_SHIFT)));
}
void AppendMouseEvent(std::vector<uint8>& out, const MouseEvent& e)
{
    std::vector<uint8> p;
    ByteWriter w(p);
    w.U8(static_cast<uint8>(e.kind));
    w.U16(e.x);
    w.U16(e.y);
    w.U8(e.button);
    w.U8(e.modifiers);
    AppendMessage(out, MessageType::MouseEvent, p);
}
bool ParseMouseEvent(std::span<const uint8> payload, MouseEvent& e)
{
    ByteReader r(payload);
    uint8 kind;
    MouseEvent m;
    if (!r.U8(kind) || !r.U16(m.x) || !r.U16(m.y) || !r.U8(m.button) || !r.U8(m.modifiers) || !r.AtEnd())
        return false;
    if (kind > static_cast<uint8>(MouseEventKind::Wheel) || (m.modifiers & ~(KEY_MOD_ALT | KEY_MOD_CTRL | KEY_MOD_SHIFT)) != 0)
        return false;
    m.kind = static_cast<MouseEventKind>(kind);
    switch (m.kind) {
    case MouseEventKind::Wheel:
        if (m.button < MOUSE_WHEEL_UP || m.button > MOUSE_WHEEL_RIGHT)
            return false;
        break;
    case MouseEventKind::Press:
        // at least one real button (the double click flag alone is meaningless)
        if ((m.button & ~MOUSE_BUTTON_MASK) != 0 || (m.button & (MOUSE_BUTTON_LEFT | MOUSE_BUTTON_RIGHT | MOUSE_BUTTON_MIDDLE)) == 0)
            return false;
        break;
    default:
        if ((m.button & ~MOUSE_BUTTON_MASK) != 0)
            return false;
        break;
    }
    e = m;
    return true;
}
bool ToFrontendEvent(const MouseEvent& e, AppCUI::Application::FrontendEvent& out)
{
    using AppCUI::Application::FrontendEventType;
    AppCUI::Application::FrontendEvent f;
    f.X   = e.x;
    f.Y   = e.y;
    f.Key = DecodeModifiers8(e.modifiers);
    switch (e.kind) {
    case MouseEventKind::Press:
        f.Type   = FrontendEventType::MouseDown;
        f.Button = DecodeMouseButtons(e.button);
        break;
    case MouseEventKind::Release:
        f.Type   = FrontendEventType::MouseUp;
        f.Button = DecodeMouseButtons(e.button);
        break;
    case MouseEventKind::Move:
        f.Type   = FrontendEventType::MouseMove;
        f.Button = DecodeMouseButtons(e.button);
        break;
    case MouseEventKind::Wheel:
        f.Type = FrontendEventType::MouseWheel;
        switch (e.button) {
        case MOUSE_WHEEL_UP:
            f.Wheel = MouseWheel::Up;
            break;
        case MOUSE_WHEEL_DOWN:
            f.Wheel = MouseWheel::Down;
            break;
        case MOUSE_WHEEL_LEFT:
            f.Wheel = MouseWheel::Left;
            break;
        case MOUSE_WHEEL_RIGHT:
            f.Wheel = MouseWheel::Right;
            break;
        default:
            return false;
        }
        break;
    default:
        return false;
    }
    out = f;
    return true;
}

// ------------------------------------------------------------------ frames
bool Screen::SameContent(const Screen& other) const
{
    if (width != other.width || height != other.height || cells.size() != other.cells.size())
        return false;
    static_assert(sizeof(Character) == 4, "Character is expected to be packed in 4 bytes");
    return cells.empty() || std::memcmp(cells.data(), other.cells.data(), cells.size() * sizeof(Character)) == 0;
}

void AppendTuiFrame(std::vector<uint8>& out, const Screen& screen)
{
    std::vector<uint8> p;
    p.reserve(4 + screen.cells.size() * WIRE_CELL_SIZE);
    ByteWriter w(p);
    w.U16(static_cast<uint16>(screen.width));
    w.U16(static_cast<uint16>(screen.height));
    for (const auto& c : screen.cells)
        WriteCell(w, c);
    AppendMessage(out, MessageType::TuiFrame, p);
}

bool DecodeTuiFrame(std::span<const uint8> payload, Screen& screen)
{
    ByteReader r(payload);
    uint16 width, height;
    if (!r.U16(width) || !r.U16(height) || !IsValidScreenSize(width, height))
        return false;
    const size_t count = static_cast<size_t>(width) * height;
    if (r.Remaining() != count * WIRE_CELL_SIZE)
        return false;
    std::vector<Character> cells;
    cells.reserve(count);
    for (size_t i = 0; i < count; i++) {
        Character c;
        if (!ReadCell(r, c))
            return false;
        cells.push_back(c);
    }
    screen.width  = width;
    screen.height = height;
    screen.cells  = std::move(cells);
    return true;
}

std::vector<uint8> EncodeFullFrame(const Screen& screen)
{
    std::vector<uint8> out;
    out.reserve(LOGICAL_FRAME_HEADER_SIZE + screen.cells.size() * WIRE_CELL_SIZE / 2);
    ByteWriter w(out);
    WriteLogicalHeader(w, FRAME_KIND_FULL, screen, 0);
    EncodeCells(w, screen.cells.data(), screen.cells.data() + screen.cells.size());
    return out;
}

std::vector<uint8> EncodeFrame(const Screen* previous, uint32 previousFrameId, const Screen& current)
{
    if (previous == nullptr || !previous->IsValid() || previous->width != current.width || previous->height != current.height || previousFrameId == 0)
        return EncodeFullFrame(current);

    std::vector<uint8> out;
    ByteWriter w(out);
    WriteLogicalHeader(w, FRAME_KIND_DELTA, current, previousFrameId);
    const size_t countOffset = out.size();
    w.U32(0); // span count (patched below)

    const auto* prev = previous->cells.data();
    const auto* cur  = current.cells.data();
    const size_t n   = current.cells.size();
    uint32 spans     = 0;
    size_t i         = 0;
    while (i < n) {
        if (SameCell(prev[i], cur[i])) {
            i++;
            continue;
        }
        const size_t start = i;
        size_t last        = i;
        size_t j           = i + 1;
        while (j < n && j - last <= MERGE_GAP) {
            if (!SameCell(prev[j], cur[j]))
                last = j;
            j++;
        }
        const size_t count = last + 1 - start;
        w.U32(static_cast<uint32>(start));
        w.U32(static_cast<uint32>(count));
        EncodeCells(w, cur + start, cur + start + count);
        spans++;
        i = last + 1;
    }
    if (spans == 0)
        return {};
    for (uint32 b = 0; b < 4; b++)
        out[countOffset + b] = static_cast<uint8>(spans >> (b * 8));

    auto full = EncodeFullFrame(current);
    if (full.size() <= out.size())
        return full;
    return out;
}

void AppendOptimizedFrame(std::vector<uint8>& out, uint32 frameId, std::span<const uint8> logicalFrame)
{
    const uint64 total = logicalFrame.size();
    uint32 index       = 0;
    size_t offset      = 0;
    std::vector<uint8> p;
    while (offset < logicalFrame.size()) {
        const size_t len = std::min<size_t>(MAX_CHUNK_DATA_SIZE, logicalFrame.size() - offset);
        p.clear();
        ByteWriter w(p);
        w.U32(frameId);
        w.U64(total);
        w.U32(index);
        w.U32(static_cast<uint32>(len));
        w.Bytes(logicalFrame.subspan(offset, len));
        AppendMessage(out, MessageType::TuiOptimizedFrame, p);
        offset += len;
        index++;
    }
}

FrameAssembler::Result FrameAssembler::AddChunk(std::span<const uint8> payload)
{
    ByteReader r(payload);
    uint32 id, index, length;
    uint64 total;
    std::span<const uint8> chunk;
    if (!r.U32(id) || !r.U64(total) || !r.U32(index) || !r.U32(length) || length == 0 || length > MAX_CHUNK_DATA_SIZE || !r.Bytes(length, chunk) ||
        !r.AtEnd()) {
        error = "malformed frame chunk";
        return Result::Error;
    }
    if (total < LOGICAL_FRAME_HEADER_SIZE || total > MAX_LOGICAL_FRAME_SIZE) {
        error = "invalid frame size";
        return Result::Error;
    }
    if (index == 0) {
        if (inProgress) {
            error = "a new frame started before the previous one was complete";
            return Result::Error;
        }
        if (id == 0 || id <= lastCompletedFrameId) {
            error = "frame ids must be strictly increasing";
            return Result::Error;
        }
        data.clear();
        data.reserve(static_cast<size_t>(total));
        expectedSize = total;
        frameId      = id;
        nextChunk    = 0;
        inProgress   = true;
    } else if (!inProgress || id != frameId || index != nextChunk || total != expectedSize) {
        error = "out of order frame chunk";
        return Result::Error;
    }
    if (length > expectedSize - data.size()) {
        error = "frame chunk exceeds the announced frame size";
        return Result::Error;
    }
    data.insert(data.end(), chunk.begin(), chunk.end());
    nextChunk++;
    if (data.size() < expectedSize)
        return Result::NeedMore;
    inProgress           = false;
    lastCompletedFrameId = frameId;
    return Result::Complete;
}

bool ApplyFrame(Screen& screen, uint32& screenFrameId, uint32 frameId, std::span<const uint8> logicalFrame, std::string& error)
{
    ByteReader r(logicalFrame);
    uint8 kind;
    uint16 width, height;
    uint32 baseFrameId;
    if (!r.U8(kind) || !r.U16(width) || !r.U16(height) || !r.U32(baseFrameId)) {
        error = "truncated frame header";
        return false;
    }
    if (!IsValidScreenSize(width, height)) {
        error = "invalid screen size";
        return false;
    }
    const size_t count = static_cast<size_t>(width) * height;

    if (kind == FRAME_KIND_FULL) {
        std::vector<Character> cells;
        cells.reserve(count);
        if (baseFrameId != 0 || !DecodeCells(r, count, cells) || !r.AtEnd()) {
            error = "malformed full frame";
            return false;
        }
        screen.width  = width;
        screen.height = height;
        screen.cells  = std::move(cells);
        screenFrameId = frameId;
        return true;
    }
    if (kind != FRAME_KIND_DELTA) {
        error = "unknown frame kind";
        return false;
    }
    if (!screen.IsValid() || screen.width != width || screen.height != height || baseFrameId != screenFrameId || baseFrameId == 0) {
        error = "delta frame does not match the current screen";
        return false;
    }
    uint32 spanCount;
    if (!r.U32(spanCount) || spanCount == 0 || spanCount > count) {
        error = "invalid span count";
        return false;
    }
    // decode and validate everything first; the screen is changed only if the whole frame is valid
    struct Span {
        size_t offset, count, first;
    };
    std::vector<Span> spans;
    std::vector<Character> cells;
    size_t minOffset = 0;
    for (uint32 s = 0; s < spanCount; s++) {
        uint32 offset, n;
        if (!r.U32(offset) || !r.U32(n) || n == 0 || offset < minOffset || offset >= count || n > count - offset) {
            error = "invalid span";
            return false;
        }
        const size_t first = cells.size();
        if (!DecodeCells(r, n, cells)) {
            error = "malformed span content";
            return false;
        }
        spans.push_back({ offset, n, first });
        minOffset = static_cast<size_t>(offset) + n;
    }
    if (!r.AtEnd()) {
        error = "trailing data after the last span";
        return false;
    }
    for (const auto& s : spans)
        std::copy_n(cells.begin() + static_cast<std::ptrdiff_t>(s.first), s.count, screen.cells.begin() + static_cast<std::ptrdiff_t>(s.offset));
    screenFrameId = frameId;
    return true;
}

Character SanitizeCell(Character c)
{
    const char16 ch = c.Code;
    if (ch == 0)
        c.Code = u' ';
    else if (!IsTransmittableCharacter(ch))
        c.Code = u'?';
    if (!IsValidColor(static_cast<uint8>(c.Color.Foreground)) || c.Color.Foreground == Color::Transparent)
        c.Color.Foreground = Color::Silver;
    if (!IsValidColor(static_cast<uint8>(c.Color.Background)) || c.Color.Background == Color::Transparent)
        c.Color.Background = Color::Black;
    return c;
}
} // namespace GView::Remote::Protocol
