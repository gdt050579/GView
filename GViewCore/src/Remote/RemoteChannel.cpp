#include "RemoteChannel.hpp"

namespace GView::Remote
{
using namespace Protocol;

namespace
{
    constexpr size_t READ_BUFFER_SIZE        = 16 * 1024;
    constexpr uint32 MAX_READS_PER_ITERATION = 64; // fairness between reading and writing
    constexpr int IDLE_POLL_MS               = 500;
    constexpr auto WRITE_STALL_TIMEOUT       = std::chrono::seconds(30);
    constexpr auto CLOSE_FLUSH_TIMEOUT       = std::chrono::milliseconds(500);
} // namespace

Channel::Channel(std::unique_ptr<Tls::Stream> s, bool isServer) : stream(std::move(s)), parser(isServer)
{
    readBuffer.resize(READ_BUFFER_SIZE);
}

bool Channel::Init(std::string& error)
{
    return waker.Create(error);
}

void Channel::Wake()
{
    waker.Signal();
}

void Channel::Stop(CloseReason reason)
{
    stopReason.store(static_cast<uint16>(reason));
    stopRequested.store(true);
    waker.Signal();
}

bool Channel::Handshake(std::chrono::milliseconds timeout, std::string& error)
{
    return stream->Handshake(std::chrono::steady_clock::now() + timeout, stopRequested, waker, error);
}

Channel::FlushResult Channel::Flush(bool& wantRead, bool& wantWrite, std::string& error)
{
    while (pendingOffset < pending.size()) {
        size_t written = 0;
        switch (stream->Write(pending.data() + pendingOffset, pending.size() - pendingOffset, written)) {
        case Tls::Stream::Io::Ok:
            pendingOffset += written;
            lastWriteProgress = std::chrono::steady_clock::now();
            break;
        case Tls::Stream::Io::WantWrite:
            wantWrite = true;
            return FlushResult::Pending;
        case Tls::Stream::Io::WantRead:
            wantRead = true;
            return FlushResult::Pending;
        default:
            error = stream->GetLastError();
            return FlushResult::Failed;
        }
    }
    pending.clear();
    pendingOffset = 0;
    return FlushResult::Done;
}

void Channel::SendCloseBestEffort(CloseReason reason, std::string_view text)
{
    // finish the message in progress (a TLS record can not be abandoned half written), then say goodbye
    AppendClose(pending, reason, text);
    const auto until = std::chrono::steady_clock::now() + CLOSE_FLUSH_TIMEOUT;
    while (std::chrono::steady_clock::now() < until) {
        bool wantRead = false, wantWrite = false;
        std::string error;
        const auto r = Flush(wantRead, wantWrite, error);
        if (r != FlushResult::Pending)
            break;
        Net::PollRequest req{};
        req.socket    = stream->GetSocket();
        req.wantRead  = wantRead;
        req.wantWrite = wantWrite;
        Net::Poll(&req, 1, 50);
    }
    stream->Shutdown();
}

Channel::Result Channel::Run(Handler& handler)
{
    Result result;
    lastWriteProgress = std::chrono::steady_clock::now();

    while (true) {
        if (stopRequested.load()) {
            result.reason = static_cast<CloseReason>(stopReason.load());
            result.text   = std::string(CloseReasonToString(result.reason));
            SendCloseBestEffort(result.reason, result.text);
            return result;
        }
        if (hasDeadline && std::chrono::steady_clock::now() >= deadline) {
            result.reason = CloseReason::Timeout;
            result.text   = "the remote end did not complete the protocol handshake in time";
            SendCloseBestEffort(result.reason, result.text);
            return result;
        }

        bool wantRead  = false;
        bool wantWrite = false;
        bool progress  = false;
        std::string error;

        // ---- write
        if (pending.empty()) {
            handler.ProduceOutgoing(pending);
            if (!pending.empty())
                lastWriteProgress = std::chrono::steady_clock::now(); // the stall timer starts with new output
        }
        if (!pending.empty()) {
            const auto before = pendingOffset;
            const auto r      = Flush(wantRead, wantWrite, error);
            if (r == FlushResult::Failed) {
                result.reason = CloseReason::Normal;
                result.text   = error;
                return result;
            }
            progress = r == FlushResult::Done || pendingOffset != before;
            if (r == FlushResult::Pending && std::chrono::steady_clock::now() - lastWriteProgress > WRITE_STALL_TIMEOUT) {
                // the peer stopped reading: drop it instead of holding a session (and its resources) forever
                result.reason = CloseReason::Timeout;
                result.text   = "the remote end stopped reading";
                stream->Shutdown();
                return result;
            }
        }

        // ---- read (drain everything TLS has buffered)
        for (uint32 i = 0; i < MAX_READS_PER_ITERATION; i++) {
            size_t read  = 0;
            const auto r = stream->Read(readBuffer.data(), readBuffer.size(), read);
            if (r == Tls::Stream::Io::WantRead) {
                wantRead = true;
                break;
            }
            if (r == Tls::Stream::Io::WantWrite) {
                wantWrite = true;
                break;
            }
            if (r != Tls::Stream::Io::Ok) {
                result.reason       = CloseReason::Normal;
                result.text         = stream->GetLastError();
                result.closedByPeer = r == Tls::Stream::Io::Closed;
                return result;
            }
            progress = true;
            parser.Append(readBuffer.data(), read);
            while (true) {
                MessageType type;
                std::span<const uint8> payload;
                const auto pr = parser.Next(type, payload);
                if (pr == MessageParser::Result::NeedMoreData)
                    break;
                if (pr == MessageParser::Result::Error) {
                    result.reason = CloseReason::ProtocolError;
                    result.text   = parser.GetError();
                    SendCloseBestEffort(result.reason, result.text);
                    return result;
                }
                if (type == MessageType::Close) {
                    CloseMessage close;
                    if (!DecodeClose(payload, close)) {
                        result.reason = CloseReason::ProtocolError;
                        result.text   = "malformed close message";
                        SendCloseBestEffort(result.reason, result.text);
                        return result;
                    }
                    result.reason       = close.reason;
                    result.text         = close.text.empty() ? std::string(CloseReasonToString(close.reason)) : close.text;
                    result.closedByPeer = true;
                    stream->Shutdown();
                    return result;
                }
                CloseReason reason = CloseReason::ProtocolError;
                std::string text;
                if (!handler.OnMessage(type, payload, reason, text)) {
                    result.reason = reason;
                    result.text   = text.empty() ? std::string(CloseReasonToString(reason)) : text;
                    SendCloseBestEffort(result.reason, result.text);
                    return result;
                }
            }
        }
        if (progress)
            continue; // handled data may have produced output -> try again before sleeping

        Net::PollRequest req[2] = {};
        req[0].socket           = stream->GetSocket();
        req[0].wantRead         = true; // input is processed even while output is blocked
        req[0].wantWrite        = wantWrite;
        req[1].socket           = waker.Get();
        req[1].wantRead         = true;
        if (!Net::Poll(req, 2, IDLE_POLL_MS)) {
            result.reason = CloseReason::InternalError;
            result.text   = "poll: " + Net::LastErrorText();
            return result;
        }
        if (req[1].readable)
            waker.Drain();
        if (req[0].failed && !req[0].readable) {
            result.reason       = CloseReason::Normal;
            result.text         = "connection lost";
            result.closedByPeer = true;
            return result;
        }
    }
}
} // namespace GView::Remote
