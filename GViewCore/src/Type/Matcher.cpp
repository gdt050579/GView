#include "Internal.hpp"

namespace GView::Type::Matcher
{

Interface* CreateFromString(std::string_view str)
{
    Interface* i = nullptr;
    string_view data;
    while (true)
    {
        if (str.starts_with("magic:"))
        {
            i = new MagicMatcher();
            data = str.substr(6);
            break;
        }
        if (str.starts_with("startswith:"))
        {
            i    = new StartsWithMatcher();
            data = str.substr(11);
            break;
        }
        // invalid type
        return nullptr;
    }
    if (i->Init(data)==false)
    {
        delete i;
        return nullptr;
    }
    return i;
}
} // namespace GView::Type::Matcher
