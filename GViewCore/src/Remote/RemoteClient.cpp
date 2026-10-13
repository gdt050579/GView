#include "RemoteClient.hpp"
#include "RemoteConfig.hpp"
#include "Internal.hpp"

namespace GView::Remote
{
using namespace Protocol;
using namespace AppCUI::Controls;
using namespace AppCUI::Graphics;
using namespace AppCUI::Input;

namespace
{
    constexpr size_t MAX_PENDING_INPUT = 256; // input messages waiting to be sent (a stalled link drops the excess)
    constexpr auto CONNECT_TIMEOUT_MS  = 10000;
    constexpr auto WELCOME_TIMEOUT     = std::chrono::seconds(10);

    bool IsMouseMoveMessage(const std::vector<uint8>& m)
    {
        return m.size() == HEADER_SIZE + MOUSE_EVENT_PAYLOAD_SIZE && m[0] == static_cast<uint8>(MessageType::MouseEvent) &&
               m[HEADER_SIZE] == static_cast<uint8>(MouseEventKind::Move);
    }
} // namespace

std::string ClientOptions::Describe() const
{
    const auto address = (host.find(':') != std::string::npos ? "[" + host + "]" : host) + ":" + std::to_string(port);
    return mode == Mode::Connect ? address : "reverse, waiting on " + address;
}

// ------------------------------------------------------------------ session
ClientSession::ClientSession(ClientOptions o) : options(std::move(o))
{
}

ClientSession::~ClientSession()
{
    Stop();
    if (thread.joinable())
        thread.join();
}

void ClientSession::Start(uint32 w, uint32 h)
{
    ClampScreenSize(w, h);
    {
        std::lock_guard<std::mutex> guard(lock);
        width  = w;
        height = h;
    }
    std::string error;
    if (!Net::Startup(error) || !connectWaker.Create(error)) {
        SetState(State::Closed, error);
        return;
    }
    thread = std::thread([this]() { Run(); });
}

void ClientSession::Stop()
{
    stopRequested.store(true);
    connectWaker.Signal();
    std::lock_guard<std::mutex> guard(lock);
    if (channel)
        channel->Stop(CloseReason::Normal);
}

void ClientSession::SetState(State s, std::string text)
{
    std::lock_guard<std::mutex> guard(lock);
    state  = s;
    status = std::move(text);
}

ClientSession::State ClientSession::GetState(std::string& text)
{
    std::lock_guard<std::mutex> guard(lock);
    text = status;
    return state;
}

bool ClientSession::Establish(std::unique_ptr<Tls::Stream>& stream, std::string& error)
{
    Net::Socket socket;
    if (options.mode == ClientOptions::Mode::Connect) {
        SetState(State::Connecting, "connecting to " + options.Describe() + " ...");
        if (!Net::Connect(options.host, options.port, CONNECT_TIMEOUT_MS, &stopRequested, socket, error))
            return false;
    } else {
        Net::Socket listener;
        if (!Net::Listen(options.host, options.port, listener, error))
            return false;
        SetState(State::Listening, "waiting for a GView server to connect on " + options.Describe() + " ...");
        while (true) {
            if (stopRequested.load()) {
                error = "cancelled";
                return false;
            }
            Net::PollRequest req[2] = {};
            req[0].socket           = listener.Get();
            req[0].wantRead         = true;
            req[1].socket           = connectWaker.Get();
            req[1].wantRead         = true;
            if (!Net::Poll(req, 2, 1000)) {
                error = "poll: " + Net::LastErrorText();
                return false;
            }
            if (req[1].readable)
                connectWaker.Drain();
            std::string peer;
            if (req[0].readable && Net::Accept(listener, socket, peer, error))
                break;
            if (!error.empty())
                return false;
        }
        // a single reverse connection: the port is closed as soon as the server is connected
    }
    if (!Net::ConfigureStream(socket, error))
        return false;
    const auto role = options.mode == ClientOptions::Mode::Connect ? Tls::Role::Client : Tls::Role::Server;
    auto context    = Tls::Context::Create(options.tls, role, error);
    if (!context)
        return false;
    const auto& name = options.serverName.empty() ? options.host : options.serverName;
    stream           = Tls::Stream::Create(context, std::move(socket), role == Tls::Role::Client ? name : std::string(), error);
    return stream != nullptr;
}

void ClientSession::Run()
{
    std::string error;
    std::unique_ptr<Tls::Stream> stream;
    if (!Establish(stream, error)) {
        SetState(State::Closed, stopRequested.load() ? "closed" : error);
        return;
    }
    Channel ch(std::move(stream), false);
    if (!ch.Init(error)) {
        SetState(State::Closed, error);
        return;
    }
    {
        std::lock_guard<std::mutex> guard(lock);
        channel = &ch;
        state   = State::Handshaking;
        status  = "TLS handshake with " + options.Describe() + " ...";
        if (stopRequested.load())
            ch.Stop(CloseReason::Normal);
    }
    Channel::Result result;
    if (!ch.Handshake(Tls::DEFAULT_HANDSHAKE_TIMEOUT, error)) {
        result.text = "connection refused: " + error;
    } else {
        SetState(State::Handshaking, "authenticated " + ch.GetPeer().subject + ", waiting for the remote screen ...");
        ch.SetDeadline(std::chrono::steady_clock::now() + WELCOME_TIMEOUT);
        result = ch.Run(*this);
        if (result.closedByPeer && result.reason != CloseReason::Normal)
            result.text = "closed by the server: " + result.text;
    }
    std::lock_guard<std::mutex> guard(lock);
    channel = nullptr; // the channel is destroyed when Run returns
    state   = State::Closed;
    status  = "disconnected: " + result.text;
}

bool ClientSession::OnMessage(MessageType type, std::span<const uint8> payload, CloseReason& reason, std::string& text)
{
    reason = CloseReason::ProtocolError;
    if (type == MessageType::Welcome) {
        Welcome w;
        if (welcomeReceived || !DecodeWelcome(payload, w)) {
            text = "invalid or duplicated Welcome";
            return false;
        }
        if (w.version != VERSION) {
            reason = CloseReason::UnsupportedVersion;
            text   = "this client only supports protocol version " + std::to_string(VERSION);
            return false;
        }
        welcomeReceived = true;
        std::lock_guard<std::mutex> guard(lock);
        if (channel) {
            channel->ClearDeadline();
            state  = State::Connected;
            status = "connected to " + options.Describe() + " (" + channel->GetPeer().subject + ")";
        }
        return true;
    }
    if (!welcomeReceived) {
        text = "the first message must be Welcome";
        return false;
    }
    switch (type) {
    case MessageType::TuiFrame: {
        Screen s;
        if (!DecodeTuiFrame(payload, s)) {
            text = "malformed frame";
            return false;
        }
        std::lock_guard<std::mutex> guard(lock);
        screen        = std::move(s);
        screenFrameId = 0; // full frames are not a base for deltas
        screenChanged = true;
        return true;
    }
    case MessageType::TuiOptimizedFrame: {
        const auto r = assembler.AddChunk(payload);
        if (r == FrameAssembler::Result::Error) {
            text = assembler.GetError();
            return false;
        }
        if (r == FrameAssembler::Result::NeedMore)
            return true;
        std::lock_guard<std::mutex> guard(lock);
        if (!ApplyFrame(screen, screenFrameId, assembler.GetFrameId(), assembler.GetFrame(), text))
            return false;
        screenChanged = true;
        return true;
    }
    case MessageType::Cursor: {
        CursorState c;
        if (!DecodeCursor(payload, c)) {
            text = "malformed cursor";
            return false;
        }
        std::lock_guard<std::mutex> guard(lock);
        cursor        = c;
        screenChanged = true;
        return true;
    }
    default:
        text = "unexpected message";
        return false;
    }
}

void ClientSession::ProduceOutgoing(std::vector<uint8>& out)
{
    std::lock_guard<std::mutex> guard(lock);
    if (!helloSent) {
        Hello h;
        h.capabilities = CAP_OPTIMIZED_FRAMES;
        h.width        = static_cast<uint16>(width);
        h.height       = static_cast<uint16>(height);
        AppendHello(out, h);
        helloSent     = true;
        resizePending = false;
    }
    if (resizePending) {
        AppendResize(out, static_cast<uint16>(width), static_cast<uint16>(height));
        resizePending = false;
    }
    for (const auto& m : outgoing)
        out.insert(out.end(), m.begin(), m.end());
    outgoing.clear();
}

void ClientSession::SendKey(Key key, char16 unicodeCharacter)
{
    const auto e = EncodeKeyEvent(key, unicodeCharacter);
    if (e.code == 0)
        return; // nothing to send (modifier only events are not reported by AppCUI controls)
    std::vector<uint8> m;
    AppendKeyEvent(m, e);
    std::lock_guard<std::mutex> guard(lock);
    if (state != State::Connected || !channel || outgoing.size() >= MAX_PENDING_INPUT)
        return;
    outgoing.push_back(std::move(m));
    channel->Wake();
}

void ClientSession::SendMouse(const MouseEvent& e)
{
    std::vector<uint8> m;
    AppendMouseEvent(m, e);
    std::lock_guard<std::mutex> guard(lock);
    if (state != State::Connected || !channel)
        return;
    if (IsMouseMoveMessage(m) && !outgoing.empty() && IsMouseMoveMessage(outgoing.back()))
        outgoing.back() = std::move(m); // only the last position of a movement matters
    else if (outgoing.size() < MAX_PENDING_INPUT)
        outgoing.push_back(std::move(m));
    else
        return;
    channel->Wake();
}

void ClientSession::Resize(uint32 w, uint32 h)
{
    ClampScreenSize(w, h);
    std::lock_guard<std::mutex> guard(lock);
    if (w == width && h == height)
        return;
    width         = w;
    height        = h;
    resizePending = helloSent;
    if (channel)
        channel->Wake();
}

bool ClientSession::TakeScreen(Screen& s, CursorState& c)
{
    std::lock_guard<std::mutex> guard(lock);
    if (!screenChanged)
        return false;
    s             = screen;
    c             = cursor;
    screenChanged = false;
    return true;
}

// ------------------------------------------------------------------ UI
namespace
{
    constexpr int CMD_LOCAL_KEY = 30020001;

    class RemoteScreen : public UserControl
    {
        std::unique_ptr<ClientSession> session;
        Canvas canvas;
        CursorState cursor;
        bool hasScreen{ false };
        bool localKeyArmed{ false };
        bool started{ false };
        ClientSession::State lastState{ ClientSession::State::Connecting };
        std::string lastStatus;

      public:
        RemoteScreen(std::unique_ptr<ClientSession> s) : UserControl("d:c"), session(std::move(s))
        {
        }

        void UpdateTitle()
        {
            auto win = GetParent();
            if (!win.IsValid())
                return;
            const char* stateText = "";
            switch (lastState) {
            case ClientSession::State::Connecting:
                stateText = " [connecting]";
                break;
            case ClientSession::State::Listening:
                stateText = " [waiting]";
                break;
            case ClientSession::State::Handshaking:
                stateText = " [authenticating]";
                break;
            case ClientSession::State::Connected:
                stateText = localKeyArmed ? " [next key: local]" : "";
                break;
            case ClientSession::State::Closed:
                stateText = " [disconnected]";
                break;
            }
            const auto title = "Remote: " + session->GetOptions().Describe() + stateText;
            win->SetText(std::string_view(title));
        }

        bool OnFrameUpdate() override
        {
            bool repaint = false;
            if (!started && GetWidth() > 0 && GetHeight() > 0) {
                started = true;
                session->Start(static_cast<uint32>(GetWidth()), static_cast<uint32>(GetHeight()));
            }
            std::string status;
            const auto state = session->GetState(status);
            if (state != lastState || status != lastStatus) {
                lastState  = state;
                lastStatus = status;
                UpdateTitle();
                repaint = true;
            }
            Screen s;
            if (session->TakeScreen(s, cursor)) {
                if (s.IsValid()) {
                    if (canvas.GetWidth() != s.width || canvas.GetHeight() != s.height)
                        canvas.Resize(s.width, s.height);
                    // sanitized once per received frame (never in Paint): the local terminal only ever receives
                    // printable characters and opaque colors from a remote screen
                    auto dst = canvas.GetCharactersBuffer();
                    for (size_t i = 0; i < s.cells.size(); i++)
                        dst[i] = SanitizeCell(s.cells[i]);
                    hasScreen = true;
                }
                repaint = true;
            }
            return repaint;
        }

        void Paint(Renderer& renderer) override
        {
            renderer.Clear(' ', ColorPair{ Color::Silver, Color::Black });
            if (hasScreen)
                renderer.DrawCanvas(0, 0, canvas);
            if (lastState != ClientSession::State::Connected) {
                const auto y = std::max(0, GetHeight() / 2 - 1);
                const auto w = static_cast<uint32>(std::max(1, GetWidth() - 4));
                renderer.FillRectSize(0, y, static_cast<uint32>(GetWidth()), 3, ' ', ColorPair{ Color::White, Color::DarkBlue });
                renderer.WriteSingleLineText(2, y, w, std::string_view(lastStatus), ColorPair{ Color::White, Color::DarkBlue }, TextAlignament::Center);
                if (lastState == ClientSession::State::Closed)
                    renderer.WriteSingleLineText(
                          2, y + 1, w, "Press Escape to close this window", ColorPair{ Color::Yellow, Color::DarkBlue }, TextAlignament::Center);
            } else if (cursor.visible && HasFocus() && cursor.x < GetWidth() && cursor.y < GetHeight()) {
                renderer.SetCursor(cursor.x, cursor.y);
            }
        }

        void OnAfterResize(int newWidth, int newHeight) override
        {
            if (started && newWidth > 0 && newHeight > 0)
                session->Resize(static_cast<uint32>(newWidth), static_cast<uint32>(newHeight));
        }

        bool OnKeyEvent(Key keyCode, char16 unicodeCharacter) override
        {
            if (keyCode == GView::App::InstanceCommands::REMOTE_LOCAL_KEY.Key && keyCode != Key::None) {
                localKeyArmed = !localKeyArmed;
                UpdateTitle();
                return true;
            }
            if (localKeyArmed) {
                // this key is for the local GView (window manager, menus, ...)
                localKeyArmed = false;
                UpdateTitle();
                return false;
            }
            if (lastState != ClientSession::State::Connected)
                return false; // e.g. Escape closes a disconnected window
            session->SendKey(keyCode, unicodeCharacter);
            return true;
        }

        void SendMouse(MouseEventKind kind, int x, int y, uint8 button, Key keyCode)
        {
            if (lastState != ClientSession::State::Connected || x < 0 || y < 0 || x > 0xFFFF || y > 0xFFFF)
                return;
            MouseEvent e;
            e.kind      = kind;
            e.x         = static_cast<uint16>(x);
            e.y         = static_cast<uint16>(y);
            e.button    = button;
            e.modifiers = EncodeModifiers8(keyCode);
            session->SendMouse(e);
        }
        void OnMousePressed(int x, int y, MouseButton button, Key keyCode) override
        {
            const auto b = EncodeMouseButtons(button);
            if (b & (MOUSE_BUTTON_LEFT | MOUSE_BUTTON_RIGHT | MOUSE_BUTTON_MIDDLE))
                SendMouse(MouseEventKind::Press, x, y, b, keyCode);
        }
        void OnMouseReleased(int x, int y, MouseButton button, Key keyCode) override
        {
            SendMouse(MouseEventKind::Release, x, y, EncodeMouseButtons(button), keyCode);
        }
        bool OnMouseDrag(int x, int y, MouseButton button, Key keyCode) override
        {
            SendMouse(MouseEventKind::Move, x, y, EncodeMouseButtons(button) & ~MOUSE_BUTTON_DOUBLE_CLICK, keyCode);
            return false;
        }
        bool OnMouseOver(int x, int y) override
        {
            SendMouse(MouseEventKind::Move, x, y, 0, Key::None);
            return false;
        }
        bool OnMouseWheel(int x, int y, MouseWheel direction, Key keyCode) override
        {
            const auto w = EncodeMouseWheel(direction);
            if (w != 0)
                SendMouse(MouseEventKind::Wheel, x, y, w, keyCode);
            return true;
        }
        bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override
        {
            commandBar.SetCommand(GView::App::InstanceCommands::REMOTE_LOCAL_KEY, CMD_LOCAL_KEY);
            return true;
        }
        bool OnEvent(Reference<Control> sender, Event eventType, int controlID) override
        {
            if (eventType == Event::Command && controlID == CMD_LOCAL_KEY) {
                localKeyArmed = !localKeyArmed;
                UpdateTitle();
                return true;
            }
            return UserControl::OnEvent(sender, eventType, controlID);
        }
        void StopSession()
        {
            session->Stop();
        }
    };

    class RemoteWindow : public Window
    {
        Reference<RemoteScreen> screen;

      public:
        RemoteWindow(std::unique_ptr<ClientSession> session) : Window("Remote", "d:c", WindowFlags::Sizeable)
        {
            screen = this->CreateChildControl<RemoteScreen>(std::move(session));
            screen->UpdateTitle();
            screen->SetFocus();
        }
        bool OnEvent(Reference<Control> sender, Event eventType, int controlID) override
        {
            if (eventType == Event::WindowClose && screen.IsValid())
                screen->StopSession(); // the session thread is joined when the control is destroyed
            return Window::OnEvent(sender, eventType, controlID);
        }
    };

    // small "address" dialog shared by the connect / listen commands
    class AddressDialog : public Window
    {
        constexpr static int BUTTON_ID_OK     = 1;
        constexpr static int BUTTON_ID_CANCEL = 2;
        Reference<TextField> input;
        std::string result;

      public:
        AddressDialog(std::string_view title, std::string_view label, std::string_view value) : Window(title, "d:c,w:64,h:9", WindowFlags::ProcessReturn)
        {
            Factory::Label::Create(this, label, "l:1,t:1,r:1,h:1");
            input = Factory::TextField::Create(this, value, "l:1,t:2,r:1,h:1", TextFieldFlags::None);
            Factory::Label::Create(this, "Certificates: [Remote] section of gview.ini", "l:1,t:4,r:1,h:1");
            Factory::Button::Create(this, "&OK", "l:16,b:0,w:13", BUTTON_ID_OK);
            Factory::Button::Create(this, "&Cancel", "l:32,b:0,w:13", BUTTON_ID_CANCEL);
            input->SetFocus();
        }
        bool OnEvent(Reference<Control> sender, Event eventType, int controlID) override
        {
            if ((eventType == Event::ButtonClicked && controlID == BUTTON_ID_OK) || eventType == Event::WindowAccept) {
                input->GetText().ToString(result);
                Exit(Dialogs::Result::Ok);
                return true;
            }
            if ((eventType == Event::ButtonClicked && controlID == BUTTON_ID_CANCEL) || eventType == Event::WindowClose) {
                Exit(Dialogs::Result::Cancel);
                return true;
            }
            return Window::OnEvent(sender, eventType, controlID);
        }
        const std::string& GetResult() const
        {
            return result;
        }
    };

    std::optional<ClientOptions> AskForAddress(ClientOptions::Mode mode)
    {
        const auto config = LoadRemoteConfig();
        std::string error;
        if (!config.tls.Validate(error)) {
            Dialogs::MessageBox::ShowError("Remote", error);
            return std::nullopt;
        }
        const bool connect = mode == ClientOptions::Mode::Connect;
        AddressDialog dlg(
              connect ? "Connect to a remote GView" : "Wait for a reverse connection",
              connect ? "Server (host[:port]):" : "Listen on (address[:port], 0.0.0.0 = every interface):",
              connect ? "" : "0.0.0.0:" + std::to_string(config.port));
        if (dlg.Show() != Dialogs::Result::Ok)
            return std::nullopt;
        ClientOptions options;
        options.mode = mode;
        options.tls  = config.tls;
        if (!Net::ParseHostPort(dlg.GetResult(), options.host, options.port, config.port)) {
            Dialogs::MessageBox::ShowError("Remote", "Invalid address (expected host, host:port or [IPv6]:port)");
            return std::nullopt;
        }
        return options;
    }
} // namespace

bool OpenRemoteWindow(const ClientOptions& options)
{
    auto session = std::make_unique<ClientSession>(options);
    auto win     = std::make_unique<RemoteWindow>(std::move(session));
    return AppCUI::Application::AddWindow(std::move(win)) != InvalidItemHandle;
}

void ShowConnectDialog()
{
    if (auto options = AskForAddress(ClientOptions::Mode::Connect))
        OpenRemoteWindow(*options);
}

void ShowListenDialog()
{
    if (auto options = AskForAddress(ClientOptions::Mode::Listen))
        OpenRemoteWindow(*options);
}
} // namespace GView::Remote
