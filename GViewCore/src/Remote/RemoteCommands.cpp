// Command line entry points of the remote TUI (GView serve / connect / listen / remote-certs) and its configuration.

#include "RemoteConfig.hpp"
#include "RemoteClient.hpp"
#include "Internal.hpp"

#include <iostream>

namespace GView::Remote
{
namespace
{
    constexpr uint32 DEFAULT_CERTIFICATE_DAYS = 14;
    constexpr uint32 DEFAULT_CA_DAYS          = 365;

    std::filesystem::path Utf8Path(std::string_view value)
    {
        return std::filesystem::path(std::u8string(reinterpret_cast<const char8_t*>(value.data()), value.size()));
    }
    std::filesystem::path ResolvePath(std::string_view value)
    {
        std::filesystem::path p = Utf8Path(value);
        if (p.empty() || p.is_absolute())
            return p;
        // relative to the folder of gview.ini (portable deployment)
        return AppCUI::Application::GetAppSettingsFile().parent_path() / p;
    }
    bool ParseNumber(std::string_view text, uint32 minValue, uint32 maxValue, uint32& value)
    {
        if (text.empty() || text.size() > 9)
            return false;
        uint32 v = 0;
        for (auto ch : text) {
            if (ch < '0' || ch > '9')
                return false;
            v = v * 10 + static_cast<uint32>(ch - '0');
        }
        if (v < minValue || v > maxValue)
            return false;
        value = v;
        return true;
    }
    bool ParseSize(std::string_view text, uint32& w, uint32& h)
    {
        const auto x = text.find_first_of("xX");
        return x != std::string_view::npos && ParseNumber(text.substr(0, x), Protocol::MIN_SCREEN_WIDTH, Protocol::MAX_SCREEN_WIDTH, w) &&
               ParseNumber(text.substr(x + 1), Protocol::MIN_SCREEN_HEIGHT, Protocol::MAX_SCREEN_HEIGHT, h);
    }

    // "--name value", "--name=value" or "--name:value"
    class Arguments
    {
        const std::vector<std::string>& args;
        size_t index{ 0 };

      public:
        explicit Arguments(const std::vector<std::string>& a) : args(a)
        {
        }
        bool Next(std::string& name, std::string& inlineValue, std::string& positional)
        {
            name.clear();
            inlineValue.clear();
            positional.clear();
            if (index >= args.size())
                return false;
            const auto& a = args[index++];
            if (a.size() > 2 && a[0] == '-' && a[1] == '-') {
                const auto sep = a.find_first_of("=:");
                name           = a.substr(2, sep == std::string::npos ? std::string::npos : sep - 2);
                if (sep != std::string::npos)
                    inlineValue = a.substr(sep + 1);
            } else {
                positional = a;
            }
            return true;
        }
        bool Value(const std::string& inlineValue, std::string& value)
        {
            if (!inlineValue.empty()) {
                value = inlineValue;
                return true;
            }
            if (index >= args.size())
                return false;
            value = args[index++];
            return true;
        }
    };

    int Fail(std::string_view message)
    {
        std::cerr << "GView: " << message << std::endl;
        return 1;
    }

    // TLS options shared by every command; returns 1 = handled, 0 = not a TLS option, -1 = error
    int ParseTlsOption(Arguments& args, const std::string& name, const std::string& inlineValue, Tls::Settings& tls)
    {
        std::string value;
        if (name == "cert" || name == "key" || name == "ca" || name == "alpn" || name == "max-cert-days") {
            if (!args.Value(inlineValue, value)) {
                Fail("missing value for --" + name);
                return -1;
            }
            if (name == "cert")
                tls.certificate = ResolvePath(value);
            else if (name == "key")
                tls.privateKey = ResolvePath(value);
            else if (name == "ca")
                tls.trustedCA = ResolvePath(value);
            else if (name == "alpn")
                tls.alpn = value;
            else if (!ParseNumber(value, 0, 3650, tls.maxPeerCertificateLifetimeDays)) {
                Fail("invalid --max-cert-days value");
                return -1;
            }
            return 1;
        }
        return 0;
    }

    int RunServe(const std::vector<std::string>& arguments)
    {
        const auto config = LoadRemoteConfig();
        ServerOptions options;
        options.tls         = config.tls;
        options.bindAddress = config.bindAddress;
        options.port        = config.port;
        options.maxClients  = config.maxClients;
        std::vector<std::string> files;

        Arguments args(arguments);
        std::string name, inlineValue, positional, value;
        while (args.Next(name, inlineValue, positional)) {
            if (!positional.empty()) {
                files.push_back(positional);
                continue;
            }
            const int tlsOption = ParseTlsOption(args, name, inlineValue, options.tls);
            if (tlsOption < 0)
                return 1;
            if (tlsOption > 0)
                continue;
            if (!args.Value(inlineValue, value))
                return Fail("missing value for --" + name);
            uint32 number = 0;
            if (name == "bind") {
                options.bindAddress = value;
            } else if (name == "port") {
                if (!ParseNumber(value, 1, 65535, number))
                    return Fail("invalid --port value");
                options.port = static_cast<uint16>(number);
            } else if (name == "max-clients") {
                if (!ParseNumber(value, 1, MAX_CLIENTS_LIMIT, options.maxClients))
                    return Fail("invalid --max-clients value (1.." + std::to_string(MAX_CLIENTS_LIMIT) + ")");
            } else if (name == "size") {
                if (!ParseSize(value, options.width, options.height))
                    return Fail("invalid --size value (expected <width>x<height>)");
            } else if (name == "reverse") {
                if (!Net::ParseHostPort(value, options.reverseHost, options.reversePort, config.port))
                    return Fail("invalid --reverse value (expected host[:port])");
            } else if (name == "server-name") {
                options.reverseServerName = value;
            } else {
                return Fail("unknown option --" + name + " (see 'GView help')");
            }
        }

        Server server(std::move(options));
        std::string error;
        if (!server.Start(error))
            return Fail(error);
        GView::App::SetHeadlessFrontend(&server);
        if (!GView::App::Init(false)) {
            server.Stop();
            return Fail("cannot initialize GView");
        }
        for (const auto& f : files)
            GView::App::OpenFile(Utf8Path(f), GView::App::OpenMethod::FirstMatch, "", nullptr, "remote server");
        GView::App::Run("");
        server.Stop();
        return 0;
    }

    int RunClient(ClientOptions::Mode mode, const std::vector<std::string>& arguments)
    {
        const auto config = LoadRemoteConfig();
        ClientOptions options;
        options.mode = mode;
        options.tls  = config.tls;
        if (mode == ClientOptions::Mode::Listen) {
            options.host = "0.0.0.0";
            options.port = config.port;
        }
        bool hasAddress = false;

        Arguments args(arguments);
        std::string name, inlineValue, positional, value;
        while (args.Next(name, inlineValue, positional)) {
            if (!positional.empty()) {
                if (hasAddress || !Net::ParseHostPort(positional, options.host, options.port, config.port))
                    return Fail("invalid address '" + positional + "' (expected host, host:port or [IPv6]:port)");
                hasAddress = true;
                continue;
            }
            const int tlsOption = ParseTlsOption(args, name, inlineValue, options.tls);
            if (tlsOption < 0)
                return 1;
            if (tlsOption > 0)
                continue;
            if (name == "server-name" && mode == ClientOptions::Mode::Connect && args.Value(inlineValue, value)) {
                options.serverName = value;
                continue;
            }
            return Fail("unknown option --" + name + " (see 'GView help')");
        }
        if (mode == ClientOptions::Mode::Connect && !hasAddress)
            return Fail("use: GView connect <host[:port]> [options]");
        std::string error;
        if (!options.tls.Validate(error))
            return Fail(error);

        if (!GView::App::Init(false))
            return Fail("cannot initialize GView");
        if (!OpenRemoteWindow(options))
            return Fail("cannot open the remote window");
        GView::App::Run("");
        return 0;
    }

    int RunCertificates(const std::vector<std::string>& arguments)
    {
        std::string directory, certName, name, inlineValue, positional, value;
        uint32 days = DEFAULT_CERTIFICATE_DAYS, caDays = DEFAULT_CA_DAYS;
        Arguments args(arguments);
        while (args.Next(name, inlineValue, positional)) {
            if (!positional.empty()) {
                if (!directory.empty())
                    return Fail("only one output folder can be specified");
                directory = positional;
                continue;
            }
            if (!args.Value(inlineValue, value))
                return Fail("missing value for --" + name);
            if (name == "name")
                certName = value;
            else if (name == "days") {
                if (!ParseNumber(value, 1, 825, days))
                    return Fail("invalid --days value (1..825)");
            } else if (name == "ca-days") {
                if (!ParseNumber(value, 1, 3650, caDays))
                    return Fail("invalid --ca-days value (1..3650)");
            } else
                return Fail("unknown option --" + name);
        }
        if (directory.empty() || certName.empty())
            return Fail("use: GView remote-certs <folder> --name <host|analyst> [--days N] [--ca-days N]");
        std::string report, error;
        if (!Tls::GenerateCertificates(Utf8Path(directory), certName, days, caDays, report, error))
            return Fail(error);
        std::cout << report;
        std::cout << "Keep the *.key files private. Give every GView instance its own certificate and the CA certificate\n"
                     "(never the CA private key) and point the [Remote] section of gview.ini (or --cert/--key/--ca) to them.\n";
        return 0;
    }
} // namespace

RemoteConfig LoadRemoteConfig()
{
    RemoteConfig config;
    auto ini = AppCUI::Application::GetAppSettings();
    if (!ini)
        return config;
    auto sect = ini->GetSection("Remote");
    if (!sect.Exists())
        return config;
    if (auto v = sect.GetValue("Certificate").AsStringView(); v.has_value())
        config.tls.certificate = ResolvePath(*v);
    if (auto v = sect.GetValue("PrivateKey").AsStringView(); v.has_value())
        config.tls.privateKey = ResolvePath(*v);
    if (auto v = sect.GetValue("TrustedCA").AsStringView(); v.has_value())
        config.tls.trustedCA = ResolvePath(*v);
    if (auto v = sect.GetValue("ALPN").AsStringView(); v.has_value() && !v->empty())
        config.tls.alpn = std::string(*v);
    if (auto v = sect.GetValue("BindAddress").AsStringView(); v.has_value() && !v->empty())
        config.bindAddress = std::string(*v);
    config.tls.maxPeerCertificateLifetimeDays =
          std::min<uint32>(sect.GetValue("MaxPeerCertificateLifetimeDays").ToUInt32(Tls::DEFAULT_MAX_PEER_CERTIFICATE_LIFETIME_DAYS), 3650);
    const auto port = sect.GetValue("Port").ToUInt32(DEFAULT_PORT);
    if (port >= 1 && port <= 65535)
        config.port = static_cast<uint16>(port);
    config.maxClients = std::clamp<uint32>(sect.GetValue("MaxClients").ToUInt32(DEFAULT_MAX_CLIENTS), 1, MAX_CLIENTS_LIMIT);
    return config;
}

void WriteDefaultRemoteConfig(AppCUI::Utils::IniObject& ini)
{
    auto sect                              = ini["Remote"];
    sect["Certificate"]                    = "";
    sect["PrivateKey"]                     = "";
    sect["TrustedCA"]                      = "";
    sect["ALPN"]                           = Tls::DEFAULT_ALPN;
    sect["BindAddress"]                    = "127.0.0.1";
    sect["Port"]                           = static_cast<uint32>(DEFAULT_PORT);
    sect["MaxClients"]                     = DEFAULT_MAX_CLIENTS;
    sect["MaxPeerCertificateLifetimeDays"] = Tls::DEFAULT_MAX_PEER_CERTIFICATE_LIFETIME_DAYS;
}
} // namespace GView::Remote

bool GView::App::IsRemoteSupported()
{
    return true;
}

int GView::App::RunRemoteCommand(std::string_view command, const std::vector<std::string>& arguments)
{
    using namespace GView::Remote;
    if (command == "serve")
        return RunServe(arguments);
    if (command == "connect")
        return RunClient(ClientOptions::Mode::Connect, arguments);
    if (command == "listen")
        return RunClient(ClientOptions::Mode::Listen, arguments);
    if (command == "remote-certs")
        return RunCertificates(arguments);
    return Fail("unknown remote command");
}
