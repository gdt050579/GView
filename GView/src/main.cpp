#include "GViewApp.hpp"


int main()
{
    GView::App::Instance gviewApp;
    if (!gviewApp.Init())
        return 1;
    gviewApp.Run();
    
    return 0;
}
