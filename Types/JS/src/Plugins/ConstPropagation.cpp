#include "js.hpp"
#include "ast.hpp"
#include "Transformers/ConstPropagator.hpp"

#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <stack>

namespace GView::Type::JS::Plugins
{
using namespace GView::View::LexicalViewer;

std::string_view ConstPropagation::GetName()
{
    return "Constant Propagation";
}
std::string_view ConstPropagation::GetDescription()
{
    return "Propagate constants.";
}
bool ConstPropagation::CanBeAppliedOn(const GView::View::LexicalViewer::PluginData& data)
{
    return true;
}

GView::View::LexicalViewer::PluginAfterActionRequest ConstPropagation::Execute(GView::View::LexicalViewer::PluginData& data, Reference<Window> parent)
{
    AST::Instance i;
    i.Create(data.tokens);

    {
        AST::DumpVisitor dump("_ast.json");
        i.script->AcceptConst(dump);
    }

    Transformer::ConstPropagator propagator;

    // return PluginAfterActionRequest::None;

    AST::PluginVisitor visitor(&propagator, &data.editor);

    AST::Node* _rep;
    i.script->Accept(visitor, _rep);

    {
        AST::DumpVisitor dump("_ast_after.json");
        i.script->AcceptConst(dump);
    }

    return PluginAfterActionRequest::Rescan;
}
} // namespace GView::Type::JS::Plugins