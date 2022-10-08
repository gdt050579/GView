#include "Internal.hpp"

namespace GView::Type::Matcher
{
bool StartsWithMatcher::Init(std::string_view text)
{
    CHECK(text.length() > 0, false, "");
    this->value = text;
    return true;
}
bool StartsWithMatcher::Match(AppCUI::Utils::BufferView buf, TextParser& text)
{
    auto txt = text.GetText();
    if (txt.size() < this->value.Len())
        return false;
    auto* p = txt.data();
    auto* e = p + this->value.Len();
    auto* c = this->value.GetText();
    while ((p < e) && ((*p) == (*c)))
    {
        p++;
        c++;
    }
    return (p == e);
}
} // namespace GView::Type::Matcher