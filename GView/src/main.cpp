#include "GViewApp.hpp"


int main()
{
    AppCUI::Log::ToStdOut();
    GView::App::Instance gviewApp;
    if (!gviewApp.Init())
        return 1;
    gviewApp.AddFileWindow("<...path to an executable...>");
    gviewApp.Run();
    
    return 0;
}
