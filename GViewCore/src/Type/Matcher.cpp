#include "Internal.hpp"

namespace GView::Type::Matcher
{

Interface* CreateFromString(std::string_view str)
{
    Interface* i = nullptr;
    string_view data;
    if (str.empty())
        return nullptr;

    auto ch = str[0];
    switch (ch)
    {
    case 'm':
        if (str.starts_with("magic:"))
        {
            i    = new MagicMatcher();
            data = str.substr(6);
        }
        break;
    case 's':
        if (str.starts_with("startswith:"))
        {
            i    = new StartsWithMatcher();
            data = str.substr(11);
        }
        break;
    case 'l':
        if (str.starts_with("linestartswith:"))
        {
            i    = new LineStartsWithMatcher();
            data = str.substr(15);
        }
        break;
    }
    if (i == nullptr)
        return nullptr;
    if (i->Init(data) == false)
    {
        delete i;
        return nullptr;
    }
    return i;
}
} // namespace GView::Type::Matcher
