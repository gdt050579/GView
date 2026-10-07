// Built when GView is configured without the remote TUI (GVIEW_ENABLE_REMOTE=OFF): no network code is compiled in.

#include "GView.hpp"

#include <iostream>

bool GView::App::IsRemoteSupported()
{
    return false;
}

int GView::App::RunRemoteCommand(std::string_view, const std::vector<std::string>&)
{
    std::cerr << "GView: this build does not include the remote mode (configure CMake with -DGVIEW_ENABLE_REMOTE=ON)" << std::endl;
    return 1;
}
