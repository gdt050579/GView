#include "../GViewCore/include/GView.hpp"
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

   updateConfig           Updates current condiguration file (gview.ini) by
                          adding new plugins (if any). For old plugins new
                          configuration options will be added as well. 
                          Ex: 'GView updateConfig'                  
)HELP";

void ShowHelp()
{
    std::cout << "GView [A file/Process] viewer" << std::endl;
    std::cout << "Build on: " << __DATE__ << " " << __TIME__ << std::endl;
    std::cout << "Version : " << "x.x.x" << std::endl;
    std::cout << help << std::endl;
}

int main(int argc,const char **argv)
{
    if (argc<2)
    {
        ShowHelp();
        return 0;
    }
    GView::App::Init();

    if (AppCUI::Utils::String::Equals(argv[1], "reset"))
    {
        GView::App::ResetConfiguration();
        return 0;
    }


    
    if (!GView::App::Init())
        return 1;    
    GView::App::OpenFile(argv[1]);
    GView::App::Run();
    
    return 0;
}
