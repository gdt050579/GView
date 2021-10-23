#include "GView.hpp"

using namespace AppCUI;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;

extern "C"
{
    bool PLUGIN_EXPORT Validate(const GView::Utils::Buffer& buf, const std::string_view& extension)
    {
        if (buf.length < 2)
            return false;
        return (buf[0] == 'm') && (buf[1] == 'Z');
    }
    Instance PLUGIN_EXPORT CreateInstance()
    {
        return nullptr; // no instance needed
    }
    void PLUGIN_EXPORT DeleteInstance(Instance instance)
    {
        // do nothing - instance is nullptr
    }
    bool PLUGIN_EXPORT PopulateWindow(Reference<GView::View::WindowInterface> win)
    {
        return true;
    }
}

int main()
{
    return 0;
}
