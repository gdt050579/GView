#include "../GViewCore/include/GView.hpp"
#include <iostream>

enum class CommandID {
    Unknown,
    Help,
    Open,
    Reset,
    ListTypes,
    UpdateConfig,
    Test,
    Learn,
    Serve,
    Connect,
    Listen,
    RemoteCerts,
};

struct CommandInfo
{
    CommandID ID;
#ifdef BUILD_FOR_WINDOWS
    std::u16string_view name;
#else
    std::string_view name;
#endif
};

// clang-format off
#ifdef BUILD_FOR_WINDOWS
#    define _U(x) (u##x)
#    define _CHAR16_FROM_WCHAR(x) ((char16*)x)
#else
#    define _U(x) (x)
#    define _CHAR16_FROM_WCHAR(x) (x)
#endif
// clang-format on

CommandInfo commands[] = {
    { CommandID::Help, _U("help") },
    { CommandID::Open, _U("open") },
    { CommandID::Reset, _U("reset") },
    { CommandID::ListTypes, _U("list-types") },
    { CommandID::UpdateConfig, _U("updateconfig") },
    { CommandID::Test, _U("test") },
    { CommandID::Learn, _U("learn") },
    { CommandID::Serve, _U("serve") },
    { CommandID::Connect, _U("connect") },
    { CommandID::Listen, _U("listen") },
    { CommandID::RemoteCerts, _U("remote-certs") },
};

std::string_view help = R"HELP(
Use: GView <command> [File|Files|Folder] <options> 
Where <command> is on of:
   help                     Shows this help
                            Ex: 'GView help'

   open [fileName|path]     Opens one or multiple file names or folders
                            Ex: 'GView open a.exe b.pdf c.doc'

   reset                    Resets the entire configuration file (gview.ini)
                            and reload all existing plugins. Be carefull when
                            using this options as all your presets will be 
                            lost.
                            Ex: 'GView reset'        

   updateConfig             Updates current condiguration file (gview.ini) by
                            adding new plugins (if any). For old plugins new
                            configuration options will be added as well. 
                            Ex: 'GView updateConfig'
   
   test [fileName|path]     Opens a script for testing                     

   learn <connectionString> Opens the Learning and Evaluation Mode window and
                            connects with the connection string provided by
                            the teacher.
                            Ex: 'GView learn ZXhhbXBsZQ=='

   list-types               List all available types (as loaded from gview.ini).
                            Ex: 'GView list-types' 

Remote mode (requires a build with -DGVIEW_ENABLE_REMOTE=ON):
   serve [files] [options]  Runs GView as a server: the analysis runs here and
                            only the screen is sent to the connected analysts
                            (TLS 1.3, mutual authentication).
                            Ex: 'GView serve --bind 0.0.0.0 sample.exe'
                            --bind <address>        (default: 127.0.0.1)
                            --port <port>           (default: 18262)
                            --max-clients <n>       (default: 4)
                            --size <width>x<height> (screen before a client connects)
                            --reverse <host[:port]> connect to an analyst that waits
                                                    with 'GView listen'
                            --server-name <name>    name in the analyst certificate
                                                    (reverse mode)

   connect <host[:port]>    Opens the screen of a remote GView server.
                            Ex: 'GView connect 10.0.0.5:18262'
                            --server-name <name>    name in the server certificate

   listen [address[:port]]  Waits for a GView server started with --reverse.
                            Ex: 'GView listen 0.0.0.0:18262'

   remote-certs <folder> --name <name> [--days N] [--ca-days N]
                            Creates a private CA (once) and a short-lived
                            certificate for a server host or an analyst.
                            Ex: 'GView remote-certs ./pki --name server.lab'

   TLS options of serve/connect/listen (default: [Remote] section of gview.ini):
                            --cert <file> --key <file> --ca <file>
                            --alpn <protocol> --max-cert-days <n>
And <options> are:
   --type:<type>            Specify the type of the file (if knwon)
                            Ex: 'GView open a.temp --type:PE'    
   --selectType             Specify the type of the file should be manually selected
                            Ex: 'GView open a.temp --selectType'   
)HELP";

template <typename T>
std::string ArgumentToUtf8(const T* argument)
{
    // wide (Windows) or native narrow arguments -> UTF-8
    const auto u8 = std::filesystem::path(argument).u8string();
    return std::string(reinterpret_cast<const char*>(u8.data()), u8.size());
}

template <typename T>
int ProcessRemoteCommand(std::string_view command, int argc, T** argv)
{
    std::vector<std::string> arguments;
    for (int index = 2; index < argc; index++)
        arguments.push_back(ArgumentToUtf8(argv[index]));
    return GView::App::RunRemoteCommand(command, arguments);
}

void ShowHelp()
{
    std::cout << "GView [A file/Process] viewer" << std::endl;
    std::cout << "Build on: " << __DATE__ << " " << __TIME__ << std::endl;
    std::cout << "Version : " << GVIEW_VERSION << std::endl;
    std::cout << help << std::endl;
}

template <typename T>
CommandID GetCommandID(T name)
{
    auto cnt = ARRAY_LEN(commands);
    for (size_t idx = 0; idx < cnt; idx++)
    {
        if (commands[idx].name == _CHAR16_FROM_WCHAR(name))
            return commands[idx].ID;
    }

    // if nothing is recognize
    return CommandID::Unknown;
}

bool ListTypes()
{
    CHECK(GView::App::Init(false), false, "");
    auto cnt = GView::App::GetTypePluginsCount();
    std::cout << "Types : " << cnt << std::endl;
    for (auto index = 0U; index < cnt; index++)
    {
        auto name = GView::App::GetTypePluginName(index);
        auto desc = GView::App::GetTypePluginDescription(index);
        std::cout << " " << std::left << std::setw(15) << name << desc << std::endl;
    }
    return true;
}

std::string readFile(const std::filesystem::path& path)
{
    const auto dataBuffer = AppCUI::OS::File::ReadContent(path);
    if (!dataBuffer.GetLength())
        return {};

    auto content = std::string(reinterpret_cast<char*>(dataBuffer.GetData()), dataBuffer.GetLength());
    return content;
}

template <typename T>
int ProcessOpenCommand(int argc, T** argv, int startIndex, bool isTesting = false)
{
    CHECK(GView::App::Init(isTesting), 1, "");
    auto start = startIndex;
    LocalString<128> tempString;
    LocalString<16> type;
    auto method = GView::App::OpenMethod::FirstMatch;

    // check options
    for (; start < argc; start++)
    {
        if (argv[start][0] == '-')
        {
            // options are always in ASCII format
            tempString.Clear();
            const T* p = argv[start];
            while ((*p))
            {
                tempString.AddChar(static_cast<char>(*p));
                p++;
            }
            if (tempString.StartsWith("--type:", true))
            {
                method = GView::App::OpenMethod::ForceType;
                type.Set(tempString.ToStringView().substr(7));
                continue;
            }
            if (tempString.Equals("--selectType", true))
            {
                method = GView::App::OpenMethod::Select;
                continue;
            }
            std::cout << "Unknown option: " << tempString.ToStringView() << std::endl;
            std::cout << "Type 'GView help' for a detailed list of available options" << std::endl;
            return 1;
        }
    }
    std::string testingContent;
    start = startIndex;
    if (!isTesting) {
        while (start < argc) {
            // skip options
            if (argv[start][0] != '-')
                GView::App::OpenFile(argv[start], method, type.ToStringView(),nullptr, "initial access");
            start++;
        }
    }else {
        bool foundFile = false;
        while (start < argc) {
            if (!foundFile && argv[start][0] != '-') {
                foundFile = true;
                GView::App::OpenFile(argv[start], method, type.ToStringView(),nullptr, "initial access");
                start++;
                continue;
            }
            testingContent = readFile(argv[start]);
            break;
        }
        if (!foundFile) {
            std::cout << "Missing file to test\n";
            return 1;
        }
        if (testingContent.empty()) {
            std::cout << "Unable to read testing script file\n";
            return 1;
        }
    }

    AppCUI::Application::ArrangeWindows(AppCUI::Application::ArrangeWindowsMethod::Grid);
    GView::App::Run(testingContent);

    return isTesting ? 0 : GView::App::FinishPendingUpdate();
}

#ifdef BUILD_FOR_WINDOWS
int wmain(int argc, const wchar_t** argv)
#else
int main(int argc, const char** argv)
#endif
{
    GView::App::SetCommandLineArguments(argc, argv);
    if (argc < 2)
    {
        const char* openCurrentFolderCommand[] = { "."};
        return ProcessOpenCommand(1, openCurrentFolderCommand, 0);
    }

    auto cmdID = GetCommandID(argv[1]);
    switch (cmdID)
    {
    case CommandID::Help:
        ShowHelp();
        return 0;
    case CommandID::Reset:
        GView::App::ResetConfiguration();
        return 0;
    case CommandID::ListTypes:
        ListTypes();
        return 0;
    case CommandID::Open:
        return ProcessOpenCommand(argc, argv, 2);
    case CommandID::Learn: {
        if (argc != 3) {
            std::cout << "Use: GView learn <connectionString>" << std::endl;
            return 1;
        }
        // connection strings are base64 (ASCII): reject anything else before it reaches the application
        std::string cs;
        for (const auto* p = argv[2]; *p; p++) {
            if (*p < 0x21 || *p > 0x7E) {
                std::cout << "Invalid connection string" << std::endl;
                return 1;
            }
            cs.push_back(static_cast<char>(*p));
        }
        CHECK(GView::App::Init(false), 1, "");
        GView::App::OpenLearningModeOnStart(cs);
        GView::App::Run("");
        return GView::App::FinishPendingUpdate();
    }
    case CommandID::Test: {
        if (argc < 4) {
            std::cout << "The program should have 3 arguments: test <fileToAnalyze> <scriptToRun>\n";
            return 1;
        }
        return ProcessOpenCommand(argc, argv, 2, true);
    }
    case CommandID::Serve:
        return ProcessRemoteCommand("serve", argc, argv);
    case CommandID::Connect:
        return ProcessRemoteCommand("connect", argc, argv);
    case CommandID::Listen:
        return ProcessRemoteCommand("listen", argc, argv);
    case CommandID::RemoteCerts:
        return ProcessRemoteCommand("remote-certs", argc, argv);
    case CommandID::Unknown:
        return ProcessOpenCommand(argc, argv, 1);
    default:
#ifdef BUILD_FOR_WINDOWS
        std::wcout << L"Unable to process command: " << argv[1] << std::endl;
#else
        std::cout << "Unable to process command: " << argv[1] << std::endl;
#endif
        return 1;
    }

    return 0;
}
