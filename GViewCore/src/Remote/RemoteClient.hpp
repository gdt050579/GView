#pragma once

// Client side of the remote TUI: a ClientSession runs the connection on its own thread and keeps the last decoded
// remote screen; the UI thread (RemoteWindow) only takes snapshots of it and queues input events.
//
//   connect mode : the analyst connects to a GView server (TLS client)
//   listen mode  : reverse connection - the analyst waits for a GView server to connect (TLS server)

#include "RemoteChannel.hpp"
#include "RemoteServer.hpp"

#include <deque>
#include <memory>
#include <mutex>
#include <thread>

namespace GView::Remote
{
struct ClientOptions {
    enum class Mode {
        Connect,
        Listen,
    };
    Mode mode{ Mode::Connect };
    std::string host; // connect: server host; listen: bind address
    uint16 port{ DEFAULT_PORT };
    std::string serverName; // connect: name expected in the server certificate (default: host)
    Tls::Settings tls;

    std::string Describe() const;
};

class ClientSession : public Channel::Handler
{
  public:
    enum class State {
        Connecting,
        Listening,
        Handshaking,
        Connected,
        Closed,
    };

    explicit ClientSession(ClientOptions options);
    ~ClientSession() override;
    ClientSession(const ClientSession&)            = delete;
    ClientSession& operator=(const ClientSession&) = delete;

    // ---- UI thread
    void Start(uint32 width, uint32 height);
    void Stop(); // asynchronous (the destructor joins the thread)
    void SendKey(AppCUI::Input::Key key, char16 unicodeCharacter);
    void SendMouse(const Protocol::MouseEvent& e);
    void Resize(uint32 width, uint32 height);
    // copies the remote screen if it changed since the previous call
    bool TakeScreen(Protocol::Screen& screen, Protocol::CursorState& cursor);
    State GetState(std::string& status);
    const ClientOptions& GetOptions() const
    {
        return options;
    }

    // ---- Channel::Handler (I/O thread)
    bool OnMessage(Protocol::MessageType type, std::span<const uint8> payload, Protocol::CloseReason& reason, std::string& text) override;
    void ProduceOutgoing(std::vector<uint8>& out) override;

  private:
    void Run();
    void SetState(State s, std::string status);
    bool Establish(std::unique_ptr<Tls::Stream>& stream, std::string& error);

    ClientOptions options;
    std::thread thread;
    std::atomic<bool> stopRequested{ false };
    Net::Waker connectWaker; // interrupts the listen / connect phase

    std::mutex lock; // protects everything below
    Channel* channel{ nullptr };
    State state{ State::Connecting };
    std::string status;
    std::deque<std::vector<uint8>> outgoing; // encoded input messages
    bool helloSent{ false };
    uint32 width{ 0 };
    uint32 height{ 0 };
    bool resizePending{ false };
    Protocol::Screen screen;
    uint32 screenFrameId{ 0 };
    Protocol::CursorState cursor;
    bool screenChanged{ false };

    // I/O thread only
    Protocol::FrameAssembler assembler;
    bool welcomeReceived{ false };
};

// Window hosting a remote GView screen (created from the File menu or from the command line)
bool OpenRemoteWindow(const ClientOptions& options);
} // namespace GView::Remote
