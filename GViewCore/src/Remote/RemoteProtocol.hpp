#pragma once

// Wire contract of the GView remote TUI protocol (docs/source/remote_protocol.rst, protocol version 1).
//
// Everything in here is pure (no I/O, no globals, no threads) so it can be unit tested exhaustively. Every byte that
// comes from the network is hostile - on the server it comes from a (possibly compromised) client, on the client it
// comes from a server that renders attacker controlled files - so every size, count, offset and code is validated
// against hard caps before it is used, and integer arithmetic on wire values is overflow safe.
//
// Message framing (all integers little endian):
//     u8  Type
//     u32 PayloadLength
//     u8  Payload[PayloadLength]

#include "GView.hpp"

#include <array>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace GView::Remote::Protocol
{
using AppCUI::Graphics::Character;

constexpr uint16 VERSION     = 1;
constexpr uint32 HEADER_SIZE = 5; // u8 type + u32 payload length

enum class MessageType : uint8 {
    // client -> server
    KeyEvent   = 0x01,
    MouseEvent = 0x02,
    Resize     = 0x03,
    Hello      = 0x10,
    // both directions
    Close = 0x7F,
    // server -> client
    TuiFrame          = 0x81,
    TuiOptimizedFrame = 0x82,
    Cursor            = 0x83,
    Welcome           = 0x90,
};

// capabilities (Hello / Welcome)
constexpr uint32 CAP_OPTIMIZED_FRAMES   = 0x00000001; // the client understands TuiOptimizedFrame (0x82)
constexpr uint32 SUPPORTED_CAPABILITIES = CAP_OPTIMIZED_FRAMES;

// screen limits (a frame never has more than MAX_SCREEN_CELLS cells -> at most 2 MB per raw frame)
constexpr uint32 MIN_SCREEN_WIDTH  = 20;
constexpr uint32 MIN_SCREEN_HEIGHT = 6;
constexpr uint32 MAX_SCREEN_WIDTH  = 1024;
constexpr uint32 MAX_SCREEN_HEIGHT = 512;
constexpr uint32 MAX_SCREEN_CELLS  = MAX_SCREEN_WIDTH * MAX_SCREEN_HEIGHT;
constexpr uint32 WIRE_CELL_SIZE    = 4; // u16 character code + u8 foreground + u8 background

// payload sizes / caps
constexpr uint32 KEY_EVENT_PAYLOAD_SIZE     = 5;
constexpr uint32 MOUSE_EVENT_PAYLOAD_SIZE   = 7;
constexpr uint32 RESIZE_PAYLOAD_SIZE        = 4;
constexpr uint32 HELLO_PAYLOAD_SIZE         = 10;
constexpr uint32 WELCOME_PAYLOAD_SIZE       = 10;
constexpr uint32 CURSOR_PAYLOAD_SIZE        = 5;
constexpr uint32 MAX_CLOSE_TEXT_SIZE        = 256;
constexpr uint32 MAX_CLOSE_PAYLOAD_SIZE     = 4 + MAX_CLOSE_TEXT_SIZE;
constexpr uint32 MAX_CLIENT_PAYLOAD_SIZE    = MAX_CLOSE_PAYLOAD_SIZE; // largest message a client may send
constexpr uint32 OPTIMIZED_CHUNK_HEADER     = 20;                     // u32 frameId, u64 total, u32 index, u32 length
constexpr uint32 MAX_CHUNK_DATA_SIZE        = 32 * 1024;
constexpr uint32 MAX_TUI_FRAME_PAYLOAD_SIZE = 4 + MAX_SCREEN_CELLS * WIRE_CELL_SIZE;
constexpr uint32 MAX_SERVER_PAYLOAD_SIZE    = MAX_TUI_FRAME_PAYLOAD_SIZE; // largest message a server may send

// logical (reassembled) optimized frame
constexpr uint8 FRAME_KIND_FULL            = 0;
constexpr uint8 FRAME_KIND_DELTA           = 1;
constexpr uint32 LOGICAL_FRAME_HEADER_SIZE = 9; // u8 kind, u16 width, u16 height, u32 base frame id
constexpr uint64 MAX_LOGICAL_FRAME_SIZE    = 4ull * 1024ull * 1024ull;
constexpr uint32 MAX_RUN_LENGTH            = 0x7FFF;
constexpr uint16 RUN_REPEAT_FLAG           = 0x8000;

// key event modifiers (wire)
constexpr uint16 KEY_MOD_ALT     = 0x0001;
constexpr uint16 KEY_MOD_CTRL    = 0x0002;
constexpr uint16 KEY_MOD_SHIFT   = 0x0004;
constexpr uint16 KEY_MOD_UNICODE = 0x8000; // KeyCode carries a UTF-16 character instead of an AppCUI key code
constexpr uint16 KEY_MOD_MASK    = KEY_MOD_ALT | KEY_MOD_CTRL | KEY_MOD_SHIFT | KEY_MOD_UNICODE;

// mouse events (wire)
enum class MouseEventKind : uint8 {
    Release = 0,
    Press   = 1,
    Move    = 2,
    Wheel   = 3,
};
constexpr uint8 MOUSE_BUTTON_LEFT         = 0x01;
constexpr uint8 MOUSE_BUTTON_RIGHT        = 0x02;
constexpr uint8 MOUSE_BUTTON_MIDDLE       = 0x04;
constexpr uint8 MOUSE_BUTTON_DOUBLE_CLICK = 0x08;
constexpr uint8 MOUSE_BUTTON_MASK         = 0x0F;
constexpr uint8 MOUSE_WHEEL_UP            = 1;
constexpr uint8 MOUSE_WHEEL_DOWN          = 2;
constexpr uint8 MOUSE_WHEEL_LEFT          = 3;
constexpr uint8 MOUSE_WHEEL_RIGHT         = 4;

enum class CloseReason : uint16 {
    Normal             = 0,
    ProtocolError      = 1,
    UnsupportedVersion = 2,
    ServerFull         = 3,
    Timeout            = 4,
    Shutdown           = 5,
    InternalError      = 6,
};
std::string_view CloseReasonToString(CloseReason reason);

inline constexpr bool IsClientMessage(MessageType t)
{
    return t == MessageType::KeyEvent || t == MessageType::MouseEvent || t == MessageType::Resize || t == MessageType::Hello || t == MessageType::Close;
}
inline constexpr bool IsServerMessage(MessageType t)
{
    return t == MessageType::TuiFrame || t == MessageType::TuiOptimizedFrame || t == MessageType::Cursor || t == MessageType::Welcome ||
           t == MessageType::Close;
}

// ------------------------------------------------------------------ byte helpers
class ByteWriter
{
    std::vector<uint8>& out;

  public:
    explicit ByteWriter(std::vector<uint8>& output) : out(output)
    {
    }
    void U8(uint8 v)
    {
        out.push_back(v);
    }
    void U16(uint16 v)
    {
        out.push_back(static_cast<uint8>(v));
        out.push_back(static_cast<uint8>(v >> 8));
    }
    void U32(uint32 v)
    {
        for (uint32 i = 0; i < 4; i++)
            out.push_back(static_cast<uint8>(v >> (i * 8)));
    }
    void U64(uint64 v)
    {
        for (uint32 i = 0; i < 8; i++)
            out.push_back(static_cast<uint8>(v >> (i * 8)));
    }
    void Bytes(std::span<const uint8> data)
    {
        out.insert(out.end(), data.begin(), data.end());
    }
};

// Bounded reader: every read fails (and the reader stays failed) once the data is exhausted.
class ByteReader
{
    const uint8* data;
    size_t size;
    size_t pos{ 0 };
    bool failed{ false };

    bool Need(size_t n)
    {
        if (failed || n > size - pos) {
            failed = true;
            return false;
        }
        return true;
    }

  public:
    ByteReader(const uint8* d, size_t s) : data(d), size(d ? s : 0)
    {
    }
    explicit ByteReader(std::span<const uint8> s) : ByteReader(s.data(), s.size())
    {
    }
    bool U8(uint8& v)
    {
        if (!Need(1))
            return false;
        v = data[pos++];
        return true;
    }
    bool U16(uint16& v)
    {
        if (!Need(2))
            return false;
        v = static_cast<uint16>(data[pos] | (data[pos + 1] << 8));
        pos += 2;
        return true;
    }
    bool U32(uint32& v)
    {
        if (!Need(4))
            return false;
        v = 0;
        for (uint32 i = 0; i < 4; i++)
            v |= static_cast<uint32>(data[pos + i]) << (i * 8);
        pos += 4;
        return true;
    }
    bool U64(uint64& v)
    {
        if (!Need(8))
            return false;
        v = 0;
        for (uint32 i = 0; i < 8; i++)
            v |= static_cast<uint64>(data[pos + i]) << (i * 8);
        pos += 8;
        return true;
    }
    bool Bytes(size_t n, std::span<const uint8>& result)
    {
        if (!Need(n))
            return false;
        result = std::span<const uint8>(data + pos, n);
        pos += n;
        return true;
    }
    size_t Remaining() const
    {
        return failed ? 0 : size - pos;
    }
    bool AtEnd() const
    {
        return !failed && pos == size;
    }
    bool Failed() const
    {
        return failed;
    }
};

// ------------------------------------------------------------------ framing
void AppendMessage(std::vector<uint8>& out, MessageType type, std::span<const uint8> payload);

// Incremental parser for a byte stream of messages. A message whose type is not allowed for this direction, or whose
// payload exceeds the cap of its type, poisons the parser (the connection must be closed).
class MessageParser
{
  public:
    enum class Result {
        NeedMoreData,
        Message,
        Error,
    };
    // isServer == true -> parses messages sent by a client (and the other way around)
    explicit MessageParser(bool isServer) : parsesClientMessages(isServer)
    {
    }
    void Append(const uint8* data, size_t size);
    // on Result::Message, type / payload describe the message (payload is valid until the next call)
    Result Next(MessageType& type, std::span<const uint8>& payload);
    const std::string& GetError() const
    {
        return error;
    }

  private:
    std::vector<uint8> buffer;
    size_t consumed{ 0 };
    bool parsesClientMessages;
    bool failed{ false };
    std::string error;
};
// maximum payload accepted for a message type (0 = the type is not allowed in that direction)
uint32 MaxPayloadSize(MessageType type, bool sentByClient);

// ------------------------------------------------------------------ handshake / small messages
struct Hello {
    uint16 version{ VERSION };
    uint32 capabilities{ 0 };
    uint16 width{ 0 };
    uint16 height{ 0 };
};
struct Welcome {
    uint16 version{ VERSION };
    uint32 capabilities{ 0 };
    uint16 width{ 0 };
    uint16 height{ 0 };
};
struct CursorState {
    uint16 x{ 0 };
    uint16 y{ 0 };
    bool visible{ false };
    bool operator==(const CursorState&) const = default;
};
struct CloseMessage {
    CloseReason reason{ CloseReason::Normal };
    std::string text; // UTF-8, at most MAX_CLOSE_TEXT_SIZE bytes, control characters removed
};

void AppendHello(std::vector<uint8>& out, const Hello& hello);
void AppendWelcome(std::vector<uint8>& out, const Welcome& welcome);
void AppendResize(std::vector<uint8>& out, uint16 width, uint16 height);
void AppendCursor(std::vector<uint8>& out, const CursorState& cursor);
void AppendClose(std::vector<uint8>& out, CloseReason reason, std::string_view text);

bool DecodeHello(std::span<const uint8> payload, Hello& hello);
bool DecodeWelcome(std::span<const uint8> payload, Welcome& welcome);
bool DecodeResize(std::span<const uint8> payload, uint16& width, uint16& height);
bool DecodeCursor(std::span<const uint8> payload, CursorState& cursor);
bool DecodeClose(std::span<const uint8> payload, CloseMessage& close);

// clamps a requested screen size to [MIN, MAX]
void ClampScreenSize(uint32& width, uint32& height);

// ------------------------------------------------------------------ keyboard
struct KeyEvent {
    uint8 pressed{ 1 };
    uint16 code{ 0 };
    uint16 modifiers{ 0 };
};
// AppCUI key event (key code + modifiers, unicode character) -> wire
KeyEvent EncodeKeyEvent(AppCUI::Input::Key key, char16 unicodeCharacter);
// wire -> AppCUI key event; returns false for a malformed event. isShiftState is set for a modifier-only event
// (KeyCode == 0, no unicode flag) which reports the new Alt/Ctrl/Shift state.
bool DecodeKeyEvent(const KeyEvent& e, AppCUI::Input::Key& key, char16& unicodeCharacter, bool& isShiftState);
void AppendKeyEvent(std::vector<uint8>& out, const KeyEvent& e);
bool ParseKeyEvent(std::span<const uint8> payload, KeyEvent& e);

// ------------------------------------------------------------------ mouse
struct MouseEvent {
    MouseEventKind kind{ MouseEventKind::Move };
    uint16 x{ 0 };
    uint16 y{ 0 };
    uint8 button{ 0 }; // button flags (press / release / move) or wheel direction (wheel)
    uint8 modifiers{ 0 };
};
uint8 EncodeMouseButtons(AppCUI::Input::MouseButton button);
AppCUI::Input::MouseButton DecodeMouseButtons(uint8 button);
uint8 EncodeMouseWheel(AppCUI::Input::MouseWheel wheel);
uint8 EncodeModifiers8(AppCUI::Input::Key key); // Alt / Ctrl / Shift bits of an AppCUI key -> wire bits
AppCUI::Input::Key DecodeModifiers8(uint8 modifiers);
void AppendMouseEvent(std::vector<uint8>& out, const MouseEvent& e);
// validates the event (kind, flags, wheel direction, reserved modifier bits)
bool ParseMouseEvent(std::span<const uint8> payload, MouseEvent& e);
// wire mouse event -> AppCUI frontend event
bool ToFrontendEvent(const MouseEvent& e, AppCUI::Application::FrontendEvent& out);

// ------------------------------------------------------------------ screen frames
struct Screen {
    uint32 width{ 0 };
    uint32 height{ 0 };
    std::vector<Character> cells; // width * height, row major

    bool IsValid() const
    {
        return width > 0 && height > 0 && cells.size() == static_cast<size_t>(width) * height;
    }
    bool SameContent(const Screen& other) const;
};

// legacy full frame (0x81)
void AppendTuiFrame(std::vector<uint8>& out, const Screen& screen);
bool DecodeTuiFrame(std::span<const uint8> payload, Screen& screen);

// logical optimized frames (the content transported by 0x82 chunks)
std::vector<uint8> EncodeFullFrame(const Screen& screen);
// delta between two screens of the same size; returns an empty vector when nothing changed. If the delta is not
// smaller than the full frame, the full frame is returned instead (the decoder handles both kinds).
std::vector<uint8> EncodeFrame(const Screen* previous, uint32 previousFrameId, const Screen& current);
// splits a logical frame in 0x82 chunks
void AppendOptimizedFrame(std::vector<uint8>& out, uint32 frameId, std::span<const uint8> logicalFrame);

// Client side: reassembles 0x82 chunks (strictly sequential, one frame at a time, increasing frame ids)
class FrameAssembler
{
  public:
    enum class Result {
        NeedMore,
        Complete,
        Error,
    };
    Result AddChunk(std::span<const uint8> payload);
    // valid after Result::Complete (until the next AddChunk)
    uint32 GetFrameId() const
    {
        return frameId;
    }
    std::span<const uint8> GetFrame() const
    {
        return data;
    }
    const std::string& GetError() const
    {
        return error;
    }

  private:
    std::vector<uint8> data;
    uint64 expectedSize{ 0 };
    uint32 frameId{ 0 };
    uint32 lastCompletedFrameId{ 0 };
    uint32 nextChunk{ 0 };
    bool inProgress{ false };
    std::string error;
};

// Applies a logical frame to a screen. A delta frame must reference the frame id that produced the current screen
// and keep its size. On failure the screen is left unchanged.
bool ApplyFrame(Screen& screen, uint32& screenFrameId, uint32 frameId, std::span<const uint8> logicalFrame, std::string& error);

// Characters received from a server are rendered by the local terminal: control characters (C0 / C1 / DEL),
// lone surrogates and non-characters are replaced so that a malicious screen can never inject terminal escape
// sequences, and transparent colors are replaced with opaque ones.
Character SanitizeCell(Character c);
} // namespace GView::Remote::Protocol
