#include "GViewApp.hpp"
#include <iostream>

std::string_view help = R"HELP(
Use: GView <command> <options>
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
)HELP";

void ShowHelp()
{
    std::cout << "GView [A file/Process] viewer" << std::endl;
    std::cout << "Build on: " << __DATE__ << " " << __TIME__ << std::endl;
    std::cout << help << std::endl;
}

int main(int argc,const char **argv)
{
    if (argc<2)
    {
        ShowHelp();
        return 0;
    }
    GView::App::Instance gviewApp;

    if (AppCUI::Utils::String::Equals(argv[1], "reset"))
    {
        gviewApp.ResetConfiguration();
        return 0;
    }


    
    if (!gviewApp.Init())
        return 1;    
    gviewApp.AddFileWindow(argv[1]);
    gviewApp.Run();
    
    return 0;
}
