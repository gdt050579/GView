#include "js.hpp"
#include "ast.hpp"
#include "Transformers/FunctionHoister.hpp"

#include <unordered_map>
#include <vector>
#include <stack>

namespace GView::Type::JS::Plugins
{
using namespace GView::View::LexicalViewer;

std::string_view HoistFunctions::GetName()
{
    return "Hoist Functions";
}
std::string_view HoistFunctions::GetDescription()
{
    return "Hoist functions.";
}
bool HoistFunctions::CanBeAppliedOn(const GView::View::LexicalViewer::PluginData& data)
{
    return true;
}

GView::View::LexicalViewer::PluginAfterActionRequest HoistFunctions::Execute(GView::View::LexicalViewer::PluginData& data)
{
    AST::Instance i;
    i.Create(data.tokens);

    {
        AST::DumpVisitor dump("_ast.json");
        i.script->AcceptConst(dump);
    }

    Transformer::FunctionHoister hoister;

    AST::PluginVisitor visitor(&hoister, &data.editor);

    AST::Node* _rep;
    i.script->Accept(visitor, _rep);

    size_t start = 0;

    for (auto& [fun, info] : hoister.funs) {
        size_t dest = 0;

        if (info.anchor == nullptr) {
            // Global scope
            dest = start;
        } else {
            dest = info.anchor->sourceStart + 1; // {
        }
        
        // Already defined in global scope
        if (dest > fun->sourceStart) {
            continue;
        }

        // The destination can overlap with the source
        std::u16string content = { ((std::u16string_view) data.editor).data() + fun->sourceStart, fun->sourceSize };

        data.editor.Insert(dest, content);
        data.editor.Delete(fun->sourceStart + fun->sourceSize, fun->sourceSize);

        if (info.anchor == nullptr) {
            start += fun->sourceSize;
        }
    }

    {
        AST::DumpVisitor dump("_ast_after.json");
        i.script->AcceptConst(dump);
    }

    return PluginAfterActionRequest::Rescan;
}
} // namespace GView::Type::JS::Plugins