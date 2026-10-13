#pragma once

// Minimal cross-platform TCP layer for the remote TUI (Winsock2 on Windows, BSD sockets elsewhere).
// All stream sockets are non-blocking, not inherited by child processes, use TCP_NODELAY (interactive traffic) and
// TCP keep-alive (dead peer detection), and never raise SIGPIPE.

#include "GView.hpp"

#include <atomic>
#include <string>
#include <string_view>

namespace GView::Remote::Net
{
#ifdef BUILD_FOR_WINDOWS
using SocketHandle                           = uintptr_t; // SOCKET
constexpr SocketHandle INVALID_SOCKET_HANDLE = ~static_cast<uintptr_t>(0);
#else
using SocketHandle                           = int;
constexpr SocketHandle INVALID_SOCKET_HANDLE = -1;
#endif

// Initializes the socket library once per process (WSAStartup on Windows, SIGPIPE ignored on POSIX).
bool Startup(std::string& error);

class Socket
{
    SocketHandle handle{ INVALID_SOCKET_HANDLE };

  public:
    Socket() = default;
    explicit Socket(SocketHandle h) : handle(h)
    {
    }
    ~Socket();
    Socket(const Socket&)            = delete;
    Socket& operator=(const Socket&) = delete;
    Socket(Socket&& other) noexcept;
    Socket& operator=(Socket&& other) noexcept;

    bool IsValid() const
    {
        return handle != INVALID_SOCKET_HANDLE;
    }
    SocketHandle Get() const
    {
        return handle;
    }
    void Close();
};

struct PollRequest {
    SocketHandle socket{ INVALID_SOCKET_HANDLE };
    bool wantRead{ false };
    bool wantWrite{ false };
    // results
    bool readable{ false }; // includes hang-up (a read will report the end of the stream)
    bool writable{ false };
    bool failed{ false };
};
// Waits until at least one request is ready or timeoutMs elapses. Returns false on a poll error.
bool Poll(PollRequest* requests, size_t count, int timeoutMs);

// Listening socket bound to bindAddress:port (empty address = every interface)
bool Listen(const std::string& bindAddress, uint16 port, Socket& listener, std::string& error);
// Accepts one pending connection. Returns false when none is pending (error stays empty) or on failure.
bool Accept(const Socket& listener, Socket& client, std::string& peerAddress, std::string& error);
// Connects with a timeout; when cancel becomes true the attempt is aborted (checked every ~100 ms)
bool Connect(const std::string& host, uint16 port, uint32 timeoutMs, const std::atomic<bool>* cancel, Socket& out, std::string& error);
// non-blocking, TCP_NODELAY, keep-alive, no SIGPIPE, not inheritable
bool ConfigureStream(Socket& s, std::string& error);
// address of the remote peer ("ip:port")
std::string PeerAddress(const Socket& s);
// local port of a bound socket (0 on error) - useful after binding port 0
uint16 LocalPort(const Socket& s);

// Cross-thread wake-up that can be waited for with Poll: a loopback datagram socket connected to itself.
class Waker
{
    Socket socket;

  public:
    bool Create(std::string& error);
    void Signal(); // thread safe, never blocks
    void Drain();  // owner thread
    SocketHandle Get() const
    {
        return socket.Get();
    }
};

// "host", "host:port", "[ipv6]:port" or a bare IPv6 address. Returns false for an invalid text.
bool ParseHostPort(std::string_view text, std::string& host, uint16& port, uint16 defaultPort);
bool IsIpAddress(const std::string& host);
std::string LastErrorText();
} // namespace GView::Remote::Net
