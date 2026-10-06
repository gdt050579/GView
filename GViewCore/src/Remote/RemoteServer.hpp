#pragma once

// GView in server mode: AppCUI renders into this custom frontend (no local terminal), the screen is streamed to every
// connected analyst and their keyboard / mouse input is executed in the order it was received (single FIFO queue).
//
//   listen mode  : the server accepts connections (TLS server)
//   reverse mode : the server connects to an analyst that waits for it (TLS client) and reconnects when the session
//                  ends - for hosts that can not accept inbound connections

#include "RemoteChannel.hpp"

#include <condition_variable>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

namespace GView::Remote
{
constexpr uint16 DEFAULT_PORT        = 18262;
constexpr uint32 DEFAULT_MAX_CLIENTS = 4;
constexpr uint32 MAX_CLIENTS_LIMIT   = 32;
constexpr uint32 DEFAULT_WIDTH       = 120;
constexpr uint32 DEFAULT_HEIGHT      = 40;

struct ServerOptions {
    std::string bindAddress{ "127.0.0.1" }; // local only unless explicitly changed
    uint16 port{ DEFAULT_PORT };
    std::string reverseHost; // not empty -> reverse mode
    uint16 reversePort{ DEFAULT_PORT };
    std::string reverseServerName; // name expected in the analyst certificate (default: reverseHost)
    uint32 maxClients{ DEFAULT_MAX_CLIENTS };
    uint32 width{ DEFAULT_WIDTH };
    uint32 height{ DEFAULT_HEIGHT };
    Tls::Settings tls;
};

class ServerSession;

class Server : public AppCUI::Application::CustomFrontendInterface
{
  public:
    explicit Server(ServerOptions options);
    ~Server() override;
    Server(const Server&)            = delete;
    Server& operator=(const Server&) = delete;

    bool Start(std::string& error);
    void Stop();

    // ---- CustomFrontendInterface (UI thread)
    bool OnInit(uint32& width, uint32& height) override;
    void OnUnInit() override;
    void OnFlushToScreen(const AppCUI::Graphics::Character* characters, uint32 width, uint32 height) override;
    void OnUpdateCursor(uint32 x, uint32 y, bool visible) override;
    bool WaitForEvent(AppCUI::Application::FrontendEvent& evnt, uint32 timeoutMs) override;
    bool HasSupportFor(AppCUI::Application::SpecialCharacterSetType type) override;

    // ---- sessions (I/O threads)
    void PushEvent(const AppCUI::Application::FrontendEvent& evnt);
    void SetRequestedSize(uint64 sessionId, uint32 width, uint32 height);
    void GetScreen(std::shared_ptr<const Protocol::Screen>& screen, Protocol::CursorState& cursor);
    bool IsInsideScreen(uint32 x, uint32 y);
    // takes one of the maxClients slots; false when the session must be refused (too many analysts)
    bool OnSessionAuthenticated(uint64 sessionId);
    void OnSessionEnded(uint64 sessionId, bool holdsSlot);
    void WakeAcceptLoop();

  private:
    void AcceptLoop();
    void ReverseLoop();
    void ReapFinishedSessions();
    void UpdateTargetSizeLocked();
    void NotifySessions();
    bool WaitStoppable(std::chrono::milliseconds duration);

    ServerOptions options;
    Tls::ContextProvider tls;
    Net::Socket listener;
    Net::Waker acceptWaker;
    std::thread acceptThread;
    std::atomic<bool> stopping{ false };
    bool started{ false };

    std::mutex sessionsLock; // order: sessionsLock -> eventsLock
    std::vector<std::unique_ptr<ServerSession>> sessions;
    std::map<uint64, std::pair<uint32, uint32>> requestedSizes;
    uint64 nextSessionId{ 1 };
    uint32 authenticatedSessions{ 0 };
    uint32 targetWidth{ DEFAULT_WIDTH };
    uint32 targetHeight{ DEFAULT_HEIGHT };

    std::mutex screenLock;
    std::shared_ptr<const Protocol::Screen> screen;
    Protocol::CursorState cursor;

    std::mutex eventsLock;
    std::condition_variable eventsAvailable;
    std::deque<AppCUI::Application::FrontendEvent> events;
    uint64 droppedEvents{ 0 };
};

// prints a timestamped line on stderr (the server has no local UI)
void ServerLog(std::string_view message);
} // namespace GView::Remote
