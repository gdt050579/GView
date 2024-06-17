#include "js.hpp"
#include "ast.hpp"
#include "Transformers/FunctionInliner.hpp"

#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <stack>

namespace GView::Type::JS::Plugins
{
using namespace GView::View::LexicalViewer;

std::string_view InlineFunctions::GetName()
{
    return "Inline Functions";
}
std::string_view InlineFunctions::GetDescription()
{
    return "Inline functions.";
}
bool InlineFunctions::CanBeAppliedOn(const GView::View::LexicalViewer::PluginData& data)
{
    return true;
}

GView::View::LexicalViewer::PluginAfterActionRequest InlineFunctions::Execute(GView::View::LexicalViewer::PluginData& data)
{
    AST::Instance i;
    i.Create(data.tokens);

    {
        AST::DumpVisitor dump("_ast.json");
        i.script->AcceptConst(dump);
    }

    Transformer::FunctionInliner inliner;

    // return PluginAfterActionRequest::None;

    AST::PluginVisitor visitor(&inliner, &data.editor);

    AST::Node* _rep;
    i.script->Accept(visitor, _rep);

    {
        AST::DumpVisitor dump("_ast_after.json");
        i.script->AcceptConst(dump);
    }

    return PluginAfterActionRequest::Rescan;
}
} // namespace GView::Type::JS::Plugins