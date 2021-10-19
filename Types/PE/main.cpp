#include "GView.hpp"

using namespace AppCUI;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;

extern "C"
{
    bool PLUGIN_EXPORT Validate(const GView::Utils::Buffer &buf, const std::string_view &extension)
    {
        if (buf.length < 2)
            return false;
        return (buf[0] == 'm') && (buf[1] == 'Z');
    }
    bool PLUGIN_EXPORT Create(GView::View::FactoryInterface& builder, const GView::Object& object)
    {        
        return true;
    }
}

int main()
{
    return 0;
}
