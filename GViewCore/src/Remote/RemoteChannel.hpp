#pragma once

// One established remote TUI connection: a single I/O thread owns the TLS stream (an SSL object is never used by
// two threads), reads and dispatches messages and writes whatever the handler produces. Other threads only call
// Wake() / Stop(), which interrupt the poll through a loopback wake-up socket.
//
// Back-pressure: the handler is asked for new output only when everything produced before has been written. A slow
// peer therefore never makes the sender buffer frames - it simply receives the most recent screen when it can.

#include "RemoteProtocol.hpp"
#include "RemoteTls.hpp"

#include <atomic>
#include <chrono>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace GView::Remote
{
class Channel
{
  public:
    class Handler
    {
      public:
        virtual ~Handler() = default;
        // A received message (already checked against the size cap of its type). Return false to close the
        // connection with `reason` / `text` (sent to the peer in a Close message).
        virtual bool OnMessage(Protocol::MessageType type, std::span<const uint8> payload, Protocol::CloseReason& reason, std::string& text) = 0;
        // Appends the next messages to send (called on the I/O thread whenever all previous output was written).
        virtual void ProduceOutgoing(std::vector<uint8>& out) = 0;
    };
    struct Result {
        Protocol::CloseReason reason{ Protocol::CloseReason::Normal };
        std::string text;
        bool closedByPeer{ false };
    };

    // isServer: the local end is the GView server (it receives client messages)
    Channel(std::unique_ptr<Tls::Stream> stream, bool isServer);
    bool Init(std::string& error);

    // ---- thread safe
    void Wake();
    void Stop(Protocol::CloseReason reason);
    bool IsStopRequested() const
    {
        return stopRequested.load();
    }

    // ---- I/O thread
    bool Handshake(std::chrono::milliseconds timeout, std::string& error);
    Result Run(Handler& handler);
    // the connection is closed with CloseReason::Timeout if no deadline cancellation happened before `deadline`
    void SetDeadline(std::chrono::steady_clock::time_point deadline)
    {
        this->deadline = deadline;
        hasDeadline    = true;
    }
    void ClearDeadline()
    {
        hasDeadline = false;
    }
    const Tls::PeerInfo& GetPeer() const
    {
        return stream->GetPeer();
    }

  private:
    enum class FlushResult {
        Done,
        Pending,
        Failed,
    };
    FlushResult Flush(bool& wantRead, bool& wantWrite, std::string& error);
    void SendCloseBestEffort(Protocol::CloseReason reason, std::string_view text);

    std::unique_ptr<Tls::Stream> stream;
    Net::Waker waker;
    Protocol::MessageParser parser;
    std::vector<uint8> pending;
    size_t pendingOffset{ 0 };
    std::vector<uint8> readBuffer;
    std::atomic<bool> stopRequested{ false };
    std::atomic<uint16> stopReason{ 0 };
    std::chrono::steady_clock::time_point deadline;
    std::chrono::steady_clock::time_point lastWriteProgress;
    bool hasDeadline{ false };
};
} // namespace GView::Remote
