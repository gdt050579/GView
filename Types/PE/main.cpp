#include "GView.hpp"

using namespace AppCUI;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;

bool PLUGIN_EXPORT Validate(GView::Buffer buf, std::string extension)
{
    if (buf.length < 2)
        return false;
    return (buf[0] == 'M') && (buf[1] == 'Z');
}

int main()
{
    return 0;
}
