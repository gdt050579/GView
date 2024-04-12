#include "../include/GView.hpp"

#include <string>
#include <re2/re2.h>

namespace GView::Regex
{
struct Context {
    bool isUnicode{ false };
    bool isCaseSensitive{ false };
    RE2 expression;
};

bool Matcher::Init(std::string_view expression, bool isUnicode, bool isCaseSensitive)
{
    CHECK(this->context == nullptr, false, "");

    RE2::Options options;
    options.set_case_sensitive(isCaseSensitive);
    options.set_longest_match(true);

    absl::string_view asv{ expression.data(), expression.size() };

    auto c = new Context{
        .isUnicode       = isUnicode,
        .isCaseSensitive = isCaseSensitive,
        .expression      = RE2(asv, options),
    };

    this->context = c;
}

Matcher::~Matcher()
{
    if (this->context != nullptr) {
        delete reinterpret_cast<Context*>(this->context);
    }
}

bool Matcher::Match(BufferView buffer, uint64& start, uint64& end)
{
    auto ctx = reinterpret_cast<Context*>(this->context);
    CHECK(ctx != nullptr, false, "");
    CHECK(ctx->expression.ok(), false, "");

    absl::string_view sv{ reinterpret_cast<const char*>(buffer.GetData()), buffer.GetLength() };
    re2::StringPiece result;
    if (RE2::PartialMatch(sv, ctx->expression, &result)) {
        start = result.data() - sv.data();
        end   = start + result.size();
        return true;
    }

    return false;
}
} // namespace GView::Regex
