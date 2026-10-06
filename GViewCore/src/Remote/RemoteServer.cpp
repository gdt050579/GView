#include "RemoteServer.hpp"

#include <algorithm>
#include <csignal>
#include <cstring>
#include <ctime>
#include <iostream>
#include <limits>
#include <optional>

namespace GView::Remote
{
using namespace Protocol;
using AppCUI::Application::FrontendEvent;
using AppCUI::Application::FrontendEventType;

namespace
{
    constexpr size_t MAX_QUEUED_EVENTS      = 1024;
    constexpr size_t MAX_PENDING_HANDSHAKES = 8; // unauthenticated connections (pre-auth resource cap)
    constexpr auto HELLO_TIMEOUT            = std::chrono::seconds(10);
    constexpr auto MIN_RECONNECT_DELAY      = std::chrono::milliseconds(1000);
    constexpr auto MAX_RECONNECT_DELAY      = std::chrono::milliseconds(30000);

    volatile std::sig_atomic_t interrupted = 0;
    void OnInterrupt(int)
    {
        interrupted = 1;
    }
    std::mutex logLock;
} // namespace

void ServerLog(std::string_view message)
{
    const auto now = std::time(nullptr);
    std::tm utc{};
#ifdef BUILD_FOR_WINDOWS
    gmtime_s(&utc, &now);
#else
    gmtime_r(&now, &utc);
#endif
    char stamp[32];
    std::strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%SZ", &utc);
    std::lock_guard<std::mutex> guard(logLock);
    std::cerr << "[" << stamp << "] " << message << std::endl;
}

// ------------------------------------------------------------------ one connected analyst
class ServerSession : public Channel::Handler
{
  public:
    ServerSession(Server& owner, uint64 sessionId, std::string peerAddress, std::unique_ptr<Tls::Stream> stream)
        : server(owner), id(sessionId), peer(std::move(peerAddress)), channel(std::move(stream), true)
    {
    }
    void Start()
    {
        thread = std::thread([this]() { Run(); });
    }
    // runs the whole session (TLS handshake, protocol handshake, streaming) on the calling thread
    void Run();
    void Stop(CloseReason reason)
    {
        channel.Stop(reason);
    }
    void Wake()
    {
        channel.Wake();
    }
    bool IsFinished() const
    {
        return finished.load();
    }
    std::thread& GetThread()
    {
        return thread;
    }
    bool WasAuthenticated() const
    {
        return authenticated;
    }

    bool OnMessage(MessageType type, std::span<const uint8> payload, CloseReason& reason, std::string& text) override;
    void ProduceOutgoing(std::vector<uint8>& out) override;

  private:
    Server& server;
    uint64 id;
    std::string peer;
    Channel channel;
    std::thread thread;
    std::atomic<bool> finished{ false };
    bool authenticated{ false }; // the TLS handshake succeeded (mutual authentication)
    bool holdsSlot{ false };     // counted in the maximum number of analysts

    // I/O thread state
    bool helloReceived{ false };
    bool welcomePending{ false };
    bool optimizedFrames{ false };
    std::shared_ptr<const Screen> lastSent;
    uint32 lastFrameId{ 0 };
    uint32 nextFrameId{ 1 };
    std::optional<CursorState> lastCursor;
};

void ServerSession::Run()
{
    std::string error;
    if (!channel.Init(error)) {
        ServerLog("[" + peer + "] internal error: " + error);
    } else if (!channel.Handshake(Tls::DEFAULT_HANDSHAKE_TIMEOUT, error)) {
        ServerLog("[" + peer + "] connection refused: " + error);
    } else {
        const auto& p = channel.GetPeer();
        authenticated = true;
        holdsSlot     = server.OnSessionAuthenticated(id);
        if (!holdsSlot) {
            ServerLog("[" + peer + "] refused (" + p.subject + "): too many connected analysts");
            channel.Stop(CloseReason::ServerFull);
        } else {
            ServerLog("[" + peer + "] analyst connected: " + p.subject + " (SHA-256 " + p.fingerprint + ", " + p.cipher + ")");
        }
        channel.SetDeadline(std::chrono::steady_clock::now() + HELLO_TIMEOUT);
        const auto result = channel.Run(*this);
        ServerLog("[" + peer + "] disconnected: " + result.text);
    }
    server.OnSessionEnded(id, holdsSlot);
    server.WakeAcceptLoop();
    finished.store(true); // must stay the last statement (the owner may join and delete the session right after)
}

bool ServerSession::OnMessage(MessageType type, std::span<const uint8> payload, CloseReason& reason, std::string& text)
{
    reason = CloseReason::ProtocolError;
    if (type == MessageType::Hello) {
        Hello hello;
        if (helloReceived || !DecodeHello(payload, hello)) {
            text = "invalid or duplicated Hello";
            return false;
        }
        if (hello.version != VERSION) {
            reason = CloseReason::UnsupportedVersion;
            text   = "this server only supports protocol version " + std::to_string(VERSION);
            return false;
        }
        helloReceived   = true;
        welcomePending  = true;
        optimizedFrames = (hello.capabilities & CAP_OPTIMIZED_FRAMES) != 0;
        channel.ClearDeadline();
        uint32 w = hello.width, h = hello.height;
        ClampScreenSize(w, h);
        server.SetRequestedSize(id, w, h);
        return true;
    }
    if (!helloReceived) {
        text = "the first message must be Hello";
        return false;
    }
    switch (type) {
    case MessageType::KeyEvent: {
        KeyEvent wire;
        FrontendEvent e;
        bool isShiftState = false;
        if (!ParseKeyEvent(payload, wire) || !DecodeKeyEvent(wire, e.Key, e.UnicodeChar, isShiftState)) {
            text = "malformed key event";
            return false;
        }
        if (isShiftState) {
            e.Type = FrontendEventType::ShiftStateChanged;
        } else {
            // AppCUI only processes key presses (releases are accepted and ignored)
            if (wire.pressed == 0 || (e.Key == AppCUI::Input::Key::None && e.UnicodeChar == 0))
                return true;
            e.Type = FrontendEventType::KeyPressed;
        }
        server.PushEvent(e);
        return true;
    }
    case MessageType::MouseEvent: {
        MouseEvent wire;
        FrontendEvent e;
        if (!ParseMouseEvent(payload, wire) || !ToFrontendEvent(wire, e)) {
            text = "malformed mouse event";
            return false;
        }
        // coordinates of a screen size that just changed are dropped (never forwarded out of bounds)
        if (server.IsInsideScreen(wire.x, wire.y))
            server.PushEvent(e);
        return true;
    }
    case MessageType::Resize: {
        uint16 w16, h16;
        if (!DecodeResize(payload, w16, h16)) {
            text = "malformed resize";
            return false;
        }
        uint32 w = w16, h = h16;
        ClampScreenSize(w, h);
        server.SetRequestedSize(id, w, h);
        return true;
    }
    default:
        text = "unexpected message";
        return false;
    }
}

void ServerSession::ProduceOutgoing(std::vector<uint8>& out)
{
    std::shared_ptr<const Screen> current;
    CursorState cursor;
    server.GetScreen(current, cursor);
    if (welcomePending) {
        Welcome w;
        w.capabilities = optimizedFrames ? CAP_OPTIMIZED_FRAMES : 0;
        w.width        = static_cast<uint16>(current ? current->width : DEFAULT_WIDTH);
        w.height       = static_cast<uint16>(current ? current->height : DEFAULT_HEIGHT);
        AppendWelcome(out, w);
        welcomePending = false;
    }
    if (!helloReceived)
        return;
    if (current && current != lastSent) {
        if (optimizedFrames) {
            if (nextFrameId == std::numeric_limits<uint32>::max()) {
                // ~4 billion frames: end the session (the client reconnects with fresh frame ids)
                channel.Stop(CloseReason::Normal);
                return;
            }
            const auto logical = EncodeFrame(lastSent.get(), lastFrameId, *current);
            if (!logical.empty()) {
                AppendOptimizedFrame(out, nextFrameId, logical);
                lastFrameId = nextFrameId++;
            }
        } else {
            AppendTuiFrame(out, *current);
        }
        lastSent = current;
    }
    if (!lastCursor.has_value() || *lastCursor != cursor) {
        AppendCursor(out, cursor);
        lastCursor = cursor;
    }
}

// ------------------------------------------------------------------ server
Server::Server(ServerOptions o) : options(std::move(o))
{
    options.maxClients = std::clamp<uint32>(options.maxClients, 1, MAX_CLIENTS_LIMIT);
    ClampScreenSize(options.width, options.height);
    targetWidth  = options.width;
    targetHeight = options.height;
}

Server::~Server()
{
    Stop();
}

bool Server::Start(std::string& error)
{
    if (started) {
        error = "the server was already started";
        return false;
    }
    if (!Net::Startup(error))
        return false;
    const bool reverse = !options.reverseHost.empty();
    if (!tls.Init(options.tls, reverse ? Tls::Role::Client : Tls::Role::Server, error))
        return false;
    if (!acceptWaker.Create(error))
        return false;
    if (reverse) {
        if (options.reverseServerName.empty())
            options.reverseServerName = options.reverseHost;
        ServerLog("reverse mode: connecting to the analyst at " + options.reverseHost + ":" + std::to_string(options.reversePort));
        acceptThread = std::thread([this]() { ReverseLoop(); });
    } else {
        if (!Net::Listen(options.bindAddress, options.port, listener, error))
            return false;
        ServerLog(
              "listening on " + (options.bindAddress.empty() ? std::string("*") : options.bindAddress) + ":" + std::to_string(options.port) +
              " (TLS 1.3, mutual authentication, at most " + std::to_string(options.maxClients) + " analysts)");
        if (options.bindAddress == "127.0.0.1" || options.bindAddress == "::1" || options.bindAddress == "localhost")
            ServerLog("only local connections are accepted (use --bind <address> to accept connections from other machines)");
        acceptThread = std::thread([this]() { AcceptLoop(); });
    }
    started = true;
    std::signal(SIGINT, OnInterrupt);
#ifdef SIGTERM
    std::signal(SIGTERM, OnInterrupt);
#endif
    return true;
}

void Server::Stop()
{
    if (!started || stopping.exchange(true))
        return;
    acceptWaker.Signal();
    {
        std::lock_guard<std::mutex> guard(sessionsLock);
        for (auto& s : sessions)
            s->Stop(CloseReason::Shutdown);
    }
    if (acceptThread.joinable())
        acceptThread.join();
    std::vector<std::unique_ptr<ServerSession>> all;
    {
        std::lock_guard<std::mutex> guard(sessionsLock);
        all.swap(sessions);
    }
    for (auto& s : all) {
        s->Stop(CloseReason::Shutdown);
        if (s->GetThread().joinable())
            s->GetThread().join();
    }
    listener.Close();
    eventsAvailable.notify_all();
    ServerLog("server stopped");
}

bool Server::WaitStoppable(std::chrono::milliseconds duration)
{
    const auto until = std::chrono::steady_clock::now() + duration;
    while (!stopping.load()) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= until)
            return true;
        Net::PollRequest req{};
        req.socket   = acceptWaker.Get();
        req.wantRead = true;
        Net::Poll(&req, 1, static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(until - now).count()));
        if (req.readable)
            acceptWaker.Drain();
    }
    return false;
}

void Server::ReapFinishedSessions()
{
    std::vector<std::unique_ptr<ServerSession>> done;
    {
        std::lock_guard<std::mutex> guard(sessionsLock);
        for (auto it = sessions.begin(); it != sessions.end();) {
            if ((*it)->IsFinished()) {
                done.push_back(std::move(*it));
                it = sessions.erase(it);
            } else {
                ++it;
            }
        }
    }
    for (auto& s : done)
        if (s->GetThread().joinable())
            s->GetThread().join();
}

void Server::AcceptLoop()
{
    while (!stopping.load()) {
        Net::PollRequest req[2] = {};
        req[0].socket           = listener.Get();
        req[0].wantRead         = true;
        req[1].socket           = acceptWaker.Get();
        req[1].wantRead         = true;
        if (!Net::Poll(req, 2, 1000)) {
            ServerLog("poll failed: " + Net::LastErrorText());
            WaitStoppable(std::chrono::milliseconds(100));
            continue;
        }
        if (req[1].readable)
            acceptWaker.Drain();
        ReapFinishedSessions();
        if (!req[0].readable || stopping.load())
            continue;

        while (!stopping.load()) {
            Net::Socket client;
            std::string peer, error;
            if (!Net::Accept(listener, client, peer, error)) {
                if (!error.empty())
                    ServerLog(error);
                break;
            }
            {
                std::lock_guard<std::mutex> guard(sessionsLock);
                if (sessions.size() >= static_cast<size_t>(options.maxClients) + MAX_PENDING_HANDSHAKES) {
                    ServerLog("[" + peer + "] refused: too many connections");
                    continue; // the socket is closed by its destructor
                }
            }
            if (!Net::ConfigureStream(client, error)) {
                ServerLog("[" + peer + "] " + error);
                continue;
            }
            std::string reloadError;
            auto context = tls.Get(reloadError);
            if (!reloadError.empty())
                ServerLog(reloadError);
            auto stream = Tls::Stream::Create(context, std::move(client), "", error);
            if (!stream) {
                ServerLog("[" + peer + "] " + error);
                continue;
            }
            std::lock_guard<std::mutex> guard(sessionsLock);
            sessions.push_back(std::make_unique<ServerSession>(*this, nextSessionId++, peer, std::move(stream)));
            sessions.back()->Start();
        }
    }
}

void Server::ReverseLoop()
{
    auto delay        = MIN_RECONNECT_DELAY;
    const auto target = options.reverseHost + ":" + std::to_string(options.reversePort);
    while (!stopping.load()) {
        Net::Socket socket;
        std::string error;
        if (!Net::Connect(options.reverseHost, options.reversePort, 10000, &stopping, socket, error) || !Net::ConfigureStream(socket, error)) {
            if (stopping.load())
                break;
            ServerLog("reverse: " + error + " (retrying in " + std::to_string(delay.count() / 1000) + "s)");
            WaitStoppable(delay);
            delay = std::min(delay * 2, MAX_RECONNECT_DELAY);
            continue;
        }
        std::string reloadError;
        auto context = tls.Get(reloadError);
        if (!reloadError.empty())
            ServerLog(reloadError);
        auto stream = Tls::Stream::Create(context, std::move(socket), options.reverseServerName, error);
        if (!stream) {
            ServerLog("reverse: " + error);
            WaitStoppable(delay);
            continue;
        }
        ServerSession* session = nullptr;
        {
            std::lock_guard<std::mutex> guard(sessionsLock);
            sessions.push_back(std::make_unique<ServerSession>(*this, nextSessionId++, target, std::move(stream)));
            session = sessions.back().get();
        }
        session->Run(); // inline: a single reverse session at a time
        const bool wasAuthenticated = session->WasAuthenticated();
        {
            std::lock_guard<std::mutex> guard(sessionsLock);
            for (auto it = sessions.begin(); it != sessions.end(); ++it) {
                if (it->get() == session) {
                    sessions.erase(it);
                    break;
                }
            }
        }
        // a refused handshake backs off; a session that ended normally reconnects quickly
        delay = wasAuthenticated ? MIN_RECONNECT_DELAY : std::min(delay * 2, MAX_RECONNECT_DELAY);
        WaitStoppable(delay);
    }
}

void Server::WakeAcceptLoop()
{
    acceptWaker.Signal();
}

bool Server::OnSessionAuthenticated(uint64)
{
    std::lock_guard<std::mutex> guard(sessionsLock);
    if (authenticatedSessions >= options.maxClients)
        return false;
    authenticatedSessions++;
    return true;
}

void Server::OnSessionEnded(uint64 sessionId, bool holdsSlot)
{
    std::lock_guard<std::mutex> guard(sessionsLock);
    if (holdsSlot && authenticatedSessions > 0)
        authenticatedSessions--;
    if (requestedSizes.erase(sessionId) > 0)
        UpdateTargetSizeLocked();
}

void Server::SetRequestedSize(uint64 sessionId, uint32 width, uint32 height)
{
    std::lock_guard<std::mutex> guard(sessionsLock);
    requestedSizes[sessionId] = { width, height };
    UpdateTargetSizeLocked();
}

void Server::UpdateTargetSizeLocked()
{
    // like tmux: the shared screen has the size of the smallest connected analyst (everyone sees the whole UI)
    if (requestedSizes.empty())
        return; // nobody connected: keep the current size
    uint32 w = MAX_SCREEN_WIDTH, h = MAX_SCREEN_HEIGHT;
    for (const auto& [_, size] : requestedSizes) {
        w = std::min(w, size.first);
        h = std::min(h, size.second);
    }
    ClampScreenSize(w, h);
    if (w == targetWidth && h == targetHeight)
        return;
    targetWidth  = w;
    targetHeight = h;
    FrontendEvent e;
    e.Type   = FrontendEventType::Resized;
    e.Width  = w;
    e.Height = h;
    PushEvent(e);
}

void Server::GetScreen(std::shared_ptr<const Screen>& s, CursorState& c)
{
    std::lock_guard<std::mutex> guard(screenLock);
    s = screen;
    c = cursor;
}

bool Server::IsInsideScreen(uint32 x, uint32 y)
{
    std::lock_guard<std::mutex> guard(screenLock);
    return screen && x < screen->width && y < screen->height;
}

void Server::NotifySessions()
{
    std::lock_guard<std::mutex> guard(sessionsLock);
    for (auto& s : sessions)
        s->Wake();
}

void Server::PushEvent(const FrontendEvent& e)
{
    {
        std::lock_guard<std::mutex> guard(eventsLock);
        if (e.Type == FrontendEventType::MouseMove && !events.empty() && events.back().Type == FrontendEventType::MouseMove &&
            events.back().Button == e.Button && events.back().Key == e.Key) {
            events.back() = e; // coalesce mouse moves (only the last position matters)
        } else if (events.size() >= MAX_QUEUED_EVENTS) {
            droppedEvents++;
            return;
        } else {
            events.push_back(e);
        }
    }
    eventsAvailable.notify_one();
}

// ---- CustomFrontendInterface
bool Server::OnInit(uint32& width, uint32& height)
{
    std::lock_guard<std::mutex> guard(sessionsLock);
    width  = targetWidth;
    height = targetHeight;
    return true;
}

void Server::OnUnInit()
{
    Stop();
}

void Server::OnFlushToScreen(const AppCUI::Graphics::Character* characters, uint32 width, uint32 height)
{
    if (characters == nullptr || width == 0 || height == 0 || width > MAX_SCREEN_WIDTH || height > MAX_SCREEN_HEIGHT)
        return;
    const size_t count = static_cast<size_t>(width) * height;
    {
        std::lock_guard<std::mutex> guard(screenLock);
        if (screen && screen->width == width && screen->height == height &&
            std::memcmp(screen->cells.data(), characters, count * sizeof(AppCUI::Graphics::Character)) == 0)
            return; // nothing changed -> nothing is sent
    }
    auto s    = std::make_shared<Screen>();
    s->width  = width;
    s->height = height;
    s->cells.assign(characters, characters + count);
    {
        std::lock_guard<std::mutex> guard(screenLock);
        screen = std::move(s);
    }
    NotifySessions();
}

void Server::OnUpdateCursor(uint32 x, uint32 y, bool visible)
{
    {
        std::lock_guard<std::mutex> guard(screenLock);
        cursor.x       = static_cast<uint16>(std::min<uint32>(x, 0xFFFF));
        cursor.y       = static_cast<uint16>(std::min<uint32>(y, 0xFFFF));
        cursor.visible = visible;
    }
    NotifySessions();
}

bool Server::WaitForEvent(FrontendEvent& e, uint32 timeoutMs)
{
    const auto until = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    std::unique_lock<std::mutex> guard(eventsLock);
    while (events.empty()) {
        if (interrupted) {
            interrupted = 0;
            ServerLog("interrupted: closing GView");
            e      = FrontendEvent{};
            e.Type = FrontendEventType::Closed;
            return true;
        }
        const auto now = std::chrono::steady_clock::now();
        if (now >= until)
            return false;
        // short slices so that Ctrl+C is noticed even without remote activity
        eventsAvailable.wait_until(guard, std::min(until, now + std::chrono::milliseconds(200)));
    }
    e = events.front();
    events.pop_front();
    return true;
}

bool Server::HasSupportFor(AppCUI::Application::SpecialCharacterSetType type)
{
    return type != AppCUI::Application::SpecialCharacterSetType::Auto;
}
} // namespace GView::Remote
