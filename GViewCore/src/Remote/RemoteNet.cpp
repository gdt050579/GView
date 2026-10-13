// Winsock headers must be included before anything that may pull <windows.h>
#ifdef BUILD_FOR_WINDOWS
#    ifndef WIN32_LEAN_AND_MEAN
#        define WIN32_LEAN_AND_MEAN
#    endif
#    ifndef NOMINMAX
#        define NOMINMAX
#    endif
#    include <winsock2.h>
#    include <ws2tcpip.h>
#else
#    include <arpa/inet.h>
#    include <fcntl.h>
#    include <netdb.h>
#    include <netinet/in.h>
#    include <netinet/tcp.h>
#    include <poll.h>
#    include <signal.h>
#    include <sys/socket.h>
#    include <sys/types.h>
#    include <unistd.h>
#    include <cerrno>
#endif

#include "RemoteNet.hpp"

#include <chrono>
#include <mutex>
#include <system_error>
#include <vector>

namespace GView::Remote::Net
{
namespace
{
#ifdef BUILD_FOR_WINDOWS
    inline SOCKET Native(SocketHandle h)
    {
        return static_cast<SOCKET>(h);
    }
    inline int LastError()
    {
        return WSAGetLastError();
    }
    inline bool IsWouldBlock(int e)
    {
        return e == WSAEWOULDBLOCK;
    }
    inline bool IsInProgress(int e)
    {
        return e == WSAEWOULDBLOCK || e == WSAEINPROGRESS;
    }
    inline void CloseNative(SocketHandle h)
    {
        closesocket(Native(h));
    }
    SocketHandle CreateSocket(int family, int type, int protocol)
    {
        // WSA_FLAG_NO_HANDLE_INHERIT: the socket is not inherited by processes spawned by GView
        const SOCKET s = WSASocketW(family, type, protocol, nullptr, 0, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);
        return s == INVALID_SOCKET ? INVALID_SOCKET_HANDLE : static_cast<SocketHandle>(s);
    }
    bool SetNonBlocking(SocketHandle h)
    {
        u_long mode = 1;
        return ioctlsocket(Native(h), FIONBIO, &mode) == 0;
    }
    bool SetNoInherit(SocketHandle h)
    {
        // sockets are handles: never let a process spawned by GView inherit them
        return SetHandleInformation(reinterpret_cast<HANDLE>(Native(h)), HANDLE_FLAG_INHERIT, 0) != FALSE;
    }
#else
    inline int Native(SocketHandle h)
    {
        return h;
    }
    inline int LastError()
    {
        return errno;
    }
    inline bool IsWouldBlock(int e)
    {
        return e == EWOULDBLOCK || e == EAGAIN;
    }
    inline bool IsInProgress(int e)
    {
        return e == EINPROGRESS || e == EWOULDBLOCK || e == EAGAIN || e == EINTR;
    }
    inline void CloseNative(SocketHandle h)
    {
        close(h);
    }
    bool SetNoInherit(SocketHandle h)
    {
        const int flags = fcntl(h, F_GETFD);
        return flags >= 0 && fcntl(h, F_SETFD, flags | FD_CLOEXEC) == 0;
    }
    SocketHandle CreateSocket(int family, int type, int protocol)
    {
        const int s = socket(family, type, protocol);
        if (s < 0)
            return INVALID_SOCKET_HANDLE;
        SetNoInherit(s);
        return s;
    }
    bool SetNonBlocking(SocketHandle h)
    {
        const int flags = fcntl(h, F_GETFL, 0);
        return flags >= 0 && fcntl(h, F_SETFL, flags | O_NONBLOCK) == 0;
    }
#endif
    std::string ErrorText(int code)
    {
#ifdef BUILD_FOR_WINDOWS
        return std::error_code(code, std::system_category()).message();
#else
        return std::error_code(code, std::generic_category()).message();
#endif
    }
    std::string AddressToString(const sockaddr* addr, socklen_t len)
    {
        char host[NI_MAXHOST]    = {};
        char service[NI_MAXSERV] = {};
        if (getnameinfo(addr, len, host, sizeof(host), service, sizeof(service), NI_NUMERICHOST | NI_NUMERICSERV) != 0)
            return "?";
        if (addr->sa_family == AF_INET6)
            return std::string("[") + host + "]:" + service;
        return std::string(host) + ":" + service;
    }
    struct AddrInfo {
        addrinfo* list{ nullptr };
        ~AddrInfo()
        {
            if (list)
                freeaddrinfo(list);
        }
    };
    bool Resolve(const std::string& host, uint16 port, bool passive, AddrInfo& result, std::string& error)
    {
        addrinfo hints{};
        hints.ai_family   = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        if (passive)
            hints.ai_flags = AI_PASSIVE;
        const auto service = std::to_string(port);
        const int rc       = getaddrinfo(host.empty() ? nullptr : host.c_str(), service.c_str(), &hints, &result.list);
        if (rc != 0 || result.list == nullptr) {
#ifdef BUILD_FOR_WINDOWS
            error = "cannot resolve '" + host + "': " + ErrorText(rc);
#else
            error = "cannot resolve '" + host + "': " + gai_strerror(rc);
#endif
            return false;
        }
        return true;
    }
    // waits for a non-blocking connect to complete (true = connected)
    bool WaitForConnect(SocketHandle s, std::chrono::steady_clock::time_point deadline, const std::atomic<bool>* cancel, std::string& error)
    {
        while (true) {
            if (cancel && cancel->load()) {
                error = "cancelled";
                return false;
            }
            const auto now = std::chrono::steady_clock::now();
            if (now >= deadline) {
                error = "connection timed out";
                return false;
            }
            const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
            const int slice = static_cast<int>(std::min<long long>(left, 100));
#ifdef BUILD_FOR_WINDOWS
            // select (not WSAPoll): WSAPoll does not report a failed connect on older Windows versions
            fd_set writeSet, errorSet;
            FD_ZERO(&writeSet);
            FD_ZERO(&errorSet);
            FD_SET(Native(s), &writeSet);
            FD_SET(Native(s), &errorSet);
            timeval tv{ 0, slice * 1000 };
            const int rc = select(0, nullptr, &writeSet, &errorSet, &tv);
            if (rc == SOCKET_ERROR) {
                error = ErrorText(LastError());
                return false;
            }
            if (rc == 0)
                continue;
#else
            pollfd p{ s, POLLOUT, 0 };
            const int rc = poll(&p, 1, slice);
            if (rc < 0) {
                if (errno == EINTR)
                    continue;
                {
                    error = ErrorText(errno);
                    return false;
                }
            }
            if (rc == 0)
                continue;
#endif
            int soError   = 0;
            socklen_t len = sizeof(soError);
            if (getsockopt(Native(s), SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&soError), &len) != 0) {
                error = ErrorText(LastError());
                return false;
            }
            if (soError != 0) {
                error = ErrorText(soError);
                return false;
            }
            return true;
        }
    }
} // namespace

bool Startup(std::string& error)
{
    static std::once_flag once;
    static bool ok = false;
    static std::string startupError;
    std::call_once(once, []() {
#ifdef BUILD_FOR_WINDOWS
        WSADATA data;
        const int rc = WSAStartup(MAKEWORD(2, 2), &data);
        ok           = rc == 0;
        if (!ok)
            startupError = "WSAStartup failed: " + ErrorText(rc);
#else
        // a write on a socket closed by the peer must fail with EPIPE instead of killing the process
        signal(SIGPIPE, SIG_IGN);
        ok = true;
#endif
    });
    if (!ok)
        error = startupError;
    return ok;
}

std::string LastErrorText()
{
    return ErrorText(LastError());
}

Socket::~Socket()
{
    Close();
}
Socket::Socket(Socket&& other) noexcept : handle(other.handle)
{
    other.handle = INVALID_SOCKET_HANDLE;
}
Socket& Socket::operator=(Socket&& other) noexcept
{
    if (this != &other) {
        Close();
        handle       = other.handle;
        other.handle = INVALID_SOCKET_HANDLE;
    }
    return *this;
}
void Socket::Close()
{
    if (handle != INVALID_SOCKET_HANDLE) {
        CloseNative(handle);
        handle = INVALID_SOCKET_HANDLE;
    }
}

bool Poll(PollRequest* requests, size_t count, int timeoutMs)
{
#ifdef BUILD_FOR_WINDOWS
    std::vector<WSAPOLLFD> fds(count);
    for (size_t i = 0; i < count; i++) {
        fds[i].fd     = Native(requests[i].socket);
        fds[i].events = static_cast<SHORT>((requests[i].wantRead ? POLLRDNORM : 0) | (requests[i].wantWrite ? POLLWRNORM : 0));
    }
    const int rc = WSAPoll(fds.data(), static_cast<ULONG>(count), timeoutMs);
    if (rc == SOCKET_ERROR)
        return false;
    for (size_t i = 0; i < count; i++) {
        const auto r         = fds[i].revents;
        requests[i].readable = (r & (POLLRDNORM | POLLHUP)) != 0;
        requests[i].writable = (r & POLLWRNORM) != 0;
        requests[i].failed   = (r & (POLLERR | POLLNVAL)) != 0;
    }
    return true;
#else
    std::vector<pollfd> fds(count);
    for (size_t i = 0; i < count; i++) {
        fds[i].fd     = requests[i].socket;
        fds[i].events = static_cast<short>((requests[i].wantRead ? POLLIN : 0) | (requests[i].wantWrite ? POLLOUT : 0));
    }
    const int rc = poll(fds.data(), static_cast<nfds_t>(count), timeoutMs);
    if (rc < 0 && errno != EINTR)
        return false;
    for (size_t i = 0; i < count; i++) {
        const auto r         = rc > 0 ? fds[i].revents : 0;
        requests[i].readable = (r & (POLLIN | POLLHUP)) != 0;
        requests[i].writable = (r & POLLOUT) != 0;
        requests[i].failed   = (r & (POLLERR | POLLNVAL)) != 0;
    }
    return true;
#endif
}

bool Listen(const std::string& bindAddress, uint16 port, Socket& listener, std::string& error)
{
    AddrInfo info;
    if (!Resolve(bindAddress, port, true, info, error))
        return false;
    for (auto ai = info.list; ai != nullptr; ai = ai->ai_next) {
        Socket s(CreateSocket(ai->ai_family, ai->ai_socktype, ai->ai_protocol));
        if (!s.IsValid()) {
            error = "socket: " + LastErrorText();
            continue;
        }
        int one = 1;
#ifdef BUILD_FOR_WINDOWS
        // no other process can bind the same port while GView listens on it (port hijacking)
        setsockopt(Native(s.Get()), SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&one), sizeof(one));
#else
        setsockopt(s.Get(), SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
#endif
        if (bind(Native(s.Get()), ai->ai_addr, static_cast<int>(ai->ai_addrlen)) != 0) {
            error = "cannot bind " + AddressToString(ai->ai_addr, static_cast<socklen_t>(ai->ai_addrlen)) + ": " + LastErrorText();
            continue;
        }
        if (listen(Native(s.Get()), 16) != 0) {
            error = "listen: " + LastErrorText();
            continue;
        }
        if (!SetNonBlocking(s.Get())) {
            error = "cannot make the listening socket non-blocking: " + LastErrorText();
            continue;
        }
        listener = std::move(s);
        error.clear();
        return true;
    }
    if (error.empty())
        error = "no usable address for '" + bindAddress + "'";
    return false;
}

bool Accept(const Socket& listener, Socket& client, std::string& peerAddress, std::string& error)
{
    error.clear();
    sockaddr_storage addr{};
    socklen_t len = sizeof(addr);
#ifdef BUILD_FOR_WINDOWS
    const SOCKET s = accept(Native(listener.Get()), reinterpret_cast<sockaddr*>(&addr), &len);
    if (s == INVALID_SOCKET) {
#else
    const int s = accept(listener.Get(), reinterpret_cast<sockaddr*>(&addr), &len);
    if (s < 0) {
#endif
        const int e = LastError();
#ifndef BUILD_FOR_WINDOWS
        if (e == EINTR || e == ECONNABORTED)
            return false;
#endif
        if (!IsWouldBlock(e))
            error = "accept: " + ErrorText(e);
        return false;
    }
    client = Socket(static_cast<SocketHandle>(s));
    SetNoInherit(client.Get());
    peerAddress = AddressToString(reinterpret_cast<sockaddr*>(&addr), len);
    return true;
}

bool Connect(const std::string& host, uint16 port, uint32 timeoutMs, const std::atomic<bool>* cancel, Socket& out, std::string& error)
{
    AddrInfo info;
    if (!Resolve(host, port, false, info, error))
        return false;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    for (auto ai = info.list; ai != nullptr; ai = ai->ai_next) {
        if (cancel && cancel->load()) {
            error = "cancelled";
            return false;
        }
        Socket s(CreateSocket(ai->ai_family, ai->ai_socktype, ai->ai_protocol));
        if (!s.IsValid() || !SetNonBlocking(s.Get())) {
            error = "socket: " + LastErrorText();
            continue;
        }
        if (connect(Native(s.Get()), ai->ai_addr, static_cast<int>(ai->ai_addrlen)) != 0) {
            const int e = LastError();
            if (!IsInProgress(e)) {
                error = "cannot connect to " + AddressToString(ai->ai_addr, static_cast<socklen_t>(ai->ai_addrlen)) + ": " + ErrorText(e);
                continue;
            }
            if (!WaitForConnect(s.Get(), deadline, cancel, error)) {
                error = "cannot connect to " + AddressToString(ai->ai_addr, static_cast<socklen_t>(ai->ai_addrlen)) + ": " + error;
                continue;
            }
        }
        out = std::move(s);
        error.clear();
        return true;
    }
    if (error.empty())
        error = "no usable address for '" + host + "'";
    return false;
}

bool ConfigureStream(Socket& s, std::string& error)
{
    if (!SetNonBlocking(s.Get())) {
        error = "cannot make the socket non-blocking: " + LastErrorText();
        return false;
    }
    int one = 1;
    // interactive traffic: every key / frame must leave immediately (no Nagle buffering)
    setsockopt(Native(s.Get()), IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&one), sizeof(one));
    setsockopt(Native(s.Get()), SOL_SOCKET, SO_KEEPALIVE, reinterpret_cast<const char*>(&one), sizeof(one));
#ifdef SO_NOSIGPIPE
    setsockopt(Native(s.Get()), SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
    return true;
}

std::string PeerAddress(const Socket& s)
{
    sockaddr_storage addr{};
    socklen_t len = sizeof(addr);
    if (getpeername(Native(s.Get()), reinterpret_cast<sockaddr*>(&addr), &len) != 0)
        return "?";
    return AddressToString(reinterpret_cast<sockaddr*>(&addr), len);
}

uint16 LocalPort(const Socket& s)
{
    sockaddr_storage addr{};
    socklen_t len = sizeof(addr);
    if (getsockname(Native(s.Get()), reinterpret_cast<sockaddr*>(&addr), &len) != 0)
        return 0;
    if (addr.ss_family == AF_INET)
        return ntohs(reinterpret_cast<const sockaddr_in*>(&addr)->sin_port);
    if (addr.ss_family == AF_INET6)
        return ntohs(reinterpret_cast<const sockaddr_in6*>(&addr)->sin6_port);
    return 0;
}

bool Waker::Create(std::string& error)
{
    const char* loopbacks[] = { "127.0.0.1", "::1" };
    for (auto address : loopbacks) {
        addrinfo hints{};
        hints.ai_family   = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_flags    = AI_NUMERICHOST;
        AddrInfo info;
        if (getaddrinfo(address, "0", &hints, &info.list) != 0 || info.list == nullptr)
            continue;
        Socket s(CreateSocket(info.list->ai_family, SOCK_DGRAM, 0));
        if (!s.IsValid())
            continue;
        if (bind(Native(s.Get()), info.list->ai_addr, static_cast<int>(info.list->ai_addrlen)) != 0)
            continue;
        sockaddr_storage self{};
        socklen_t len = sizeof(self);
        if (getsockname(Native(s.Get()), reinterpret_cast<sockaddr*>(&self), &len) != 0)
            continue;
        if (connect(Native(s.Get()), reinterpret_cast<sockaddr*>(&self), len) != 0)
            continue;
        if (!SetNonBlocking(s.Get()))
            continue;
        socket = std::move(s);
        return true;
    }
    error = "cannot create the loopback wake-up socket: " + LastErrorText();
    return false;
}
void Waker::Signal()
{
    if (!socket.IsValid())
        return;
    const char b = 1;
    // a full socket buffer means a wake-up is already pending -> the error is irrelevant
    (void) send(Native(socket.Get()), &b, 1, 0);
}
void Waker::Drain()
{
    if (!socket.IsValid())
        return;
    char buffer[64];
    while (recv(Native(socket.Get()), buffer, sizeof(buffer), 0) > 0) {
    }
}

bool IsIpAddress(const std::string& host)
{
    in_addr v4;
    in6_addr v6;
    return inet_pton(AF_INET, host.c_str(), &v4) == 1 || inet_pton(AF_INET6, host.c_str(), &v6) == 1;
}

bool ParseHostPort(std::string_view text, std::string& host, uint16& port, uint16 defaultPort)
{
    std::string_view h = text;
    std::string_view p;
    if (text.empty() || text.size() > 255)
        return false;
    if (text.front() == '[') {
        const auto close = text.find(']');
        if (close == std::string_view::npos)
            return false;
        h = text.substr(1, close - 1);
        if (close + 1 < text.size()) {
            if (text[close + 1] != ':')
                return false;
            p = text.substr(close + 2);
        }
    } else {
        const auto first = text.find(':');
        if (first != std::string_view::npos && text.find(':', first + 1) == std::string_view::npos) {
            h = text.substr(0, first);
            p = text.substr(first + 1);
        }
        // more than one ':' -> a bare IPv6 address (no port)
    }
    if (h.empty())
        return false;
    for (auto ch : h) {
        const bool ok =
              (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '.' || ch == '-' || ch == '_' || ch == ':' || ch == '%';
        if (!ok)
            return false;
    }
    uint32 value = defaultPort;
    if (!p.empty()) {
        if (p.size() > 5)
            return false;
        value = 0;
        for (auto ch : p) {
            if (ch < '0' || ch > '9')
                return false;
            value = value * 10 + static_cast<uint32>(ch - '0');
        }
    }
    if (value == 0 || value > 65535)
        return false;
    host = std::string(h);
    port = static_cast<uint16>(value);
    return true;
}
} // namespace GView::Remote::Net
