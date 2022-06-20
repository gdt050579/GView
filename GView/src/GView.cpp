#include "../GViewCore/include/GView.hpp"
#include <iostream>

enum class CommandID
{
    Unknown,
    Help,
    Open,
    Reset,
    UpdateConfig
};

struct CommandInfo
{
    CommandID ID;
    std::string_view name;
};

struct CommandInfoU16
{
    CommandID ID;
    std::u16string_view name;
};

CommandInfo commands[] = {
    { CommandID::Help, "help" },
    { CommandID::Open, "open" },
    { CommandID::Reset, "reset" },
    { CommandID::UpdateConfig, "updateconfig" },
};

CommandInfoU16 commandsU16[] = {
    { CommandID::Help, u"help" },
    { CommandID::Open, u"open" },
    { CommandID::Reset, u"reset" },
    { CommandID::UpdateConfig, u"updateconfig" },
};

std::string_view help = R"HELP(
Use: GView <command> <options> [File|Files|Folder]
Where <command> is on of:
   help                   Shows this help
                          Ex: 'GView help'

   open [fileName|path]   Opens one or multiple file names or folders
                          Ex: 'GView open a.exe b.pdf c.doc'

   reset                  Resets the entire configuration file (gview.ini)
                          and reload all existing plugins. Be carefull when
                          using this options as all your presets will be 
                          lost.
                          Ex: 'GView reset'        

   updateConfig           Updates current condiguration file (gview.ini) by
                          adding new plugins (if any). For old plugins new
                          configuration options will be added as well. 
                          Ex: 'GView updateConfig'                  
)HELP";

void ShowHelp()
{
    std::cout << "GView [A file/Process] viewer" << std::endl;
    std::cout << "Build on: " << __DATE__ << " " << __TIME__ << std::endl;
    std::cout << "Version : " << GVIEW_VERSION << std::endl;
    std::cout << help << std::endl;
}

CommandID GetCommandID(const char* name)
{
    auto cnt = ARRAY_LEN(commands);
    for (size_t idx = 0; idx < cnt; idx++)
    {
        if (String::Equals(name, commands[idx].name.data()))
            return commands[idx].ID;
    }

    // if nothing is recognize
    return CommandID::Unknown;
}

CommandID GetCommandID(const wchar_t* name)
{
    auto cnt = ARRAY_LEN(commands);
    for (size_t idx = 0; idx < cnt; idx++)
    {
        if (commandsU16[idx].name == (char16*) name)
            return commands[idx].ID;
    }

    // if nothing is recognize
    return CommandID::Unknown;
}

template <typename T>
int ProcessOpenCommand(int argc, T argv, int start)
{
    CHECK(GView::App::Init(), 1, "");

    while (start < argc)
    {
        GView::App::OpenFile(argv[start]);
        start++;
    }

    AppCUI::Application::ArrangeWindows(AppCUI::Application::ArrangeWindowsMethod::Grid);
    GView::App::Run();

    return 0;
}

#ifdef BUILD_FOR_WINDOWS
int wmain(int argc, const wchar_t** argv)
#else
int main(int argc, const char** argv)
#endif
{
    if (argc < 2)
    {
        ShowHelp();
        return 0;
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
    case CommandID::Open:
        return ProcessOpenCommand(argc, argv, 2);
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
