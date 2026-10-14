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
    options.set_longest_match(false);

    absl::string_view asv{ expression.data(), expression.size() };

    auto c = new Context{
        .isUnicode       = isUnicode,
        .isCaseSensitive = isCaseSensitive,
        .expression      = RE2(asv, options),
    };

    this->context = c;

    return true;
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
    // submatch 0 is the whole match, so this works for patterns with or without capture groups
    // (RE2::PartialMatch with one output argument returns capture group 1 and fails when the pattern has no group)
    re2::StringPiece result;
    if (ctx->expression.Match(sv, 0, sv.size(), RE2::UNANCHORED, &result, 1)) {
        start = result.data() - sv.data();
        end   = start + result.size();
        return true;
    }

    return false;
}
} // namespace GView::Regex
