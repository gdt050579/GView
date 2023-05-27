#include "Internal.hpp"

namespace GView::Type::Matcher
{
bool LineStartsWithMatcher::CheckStartsWith(TextParser& text, uint32 offset)
{
    auto txt = text.GetText();
    if (static_cast<size_t>(offset) + static_cast<size_t>(this->value.Len()) > txt.size())
        return false;
    auto* p = txt.data() + offset;
    auto* e = p + this->value.Len();
    auto* c = this->value.GetText();
    while ((p < e) && ((*p) == (*c)))
    {
        p++;
        c++;
    }
    return (p == e);
}
bool LineStartsWithMatcher::Init(std::string_view text)
{
    CHECK(text.length() > 0, false, "");
    this->value = text;
    return true;
}
bool LineStartsWithMatcher::Match(AppCUI::Utils::BufferView buf, TextParser& text)
{
    auto lines = text.GetLines();
    for (auto ofs: lines)
    {
        if (CheckStartsWith(text, ofs))
            return true;
    }
    return false;
}
} // namespace GView::Type::Matcher