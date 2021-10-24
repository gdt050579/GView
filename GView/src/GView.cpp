#include "GViewApp.hpp"

int main(int argc,const char **argv)
{
    AppCUI::Log::ToOutputDebugString();

    CHECK(argc == 2, 1, "Expecting a file name as a parameter for the main executable");

    GView::App::Instance gviewApp;
    if (!gviewApp.Init())
        return 1;    
    gviewApp.AddFileWindow(argv[1]);
    gviewApp.Run();
    
    return 0;
}
