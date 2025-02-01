#include "js.hpp"
#include "ast.hpp"
#include "Transformers/DeadCodeRemover.hpp"

#include <stack>

namespace GView::Type::JS::Plugins
{
using namespace GView::View::LexicalViewer;
using namespace GView::Type::JS;

std::string_view RemoveDeadCode::GetName()
{
    return "Remove Dead Code";
}
std::string_view RemoveDeadCode::GetDescription()
{
    return "Remove dead code.";
}
bool RemoveDeadCode::CanBeAppliedOn(const GView::View::LexicalViewer::PluginData& data)
{
    return true;
}

GView::View::LexicalViewer::PluginAfterActionRequest RemoveDeadCode::Execute(GView::View::LexicalViewer::PluginData& data)
{
    AST::Instance i;
    i.Create(data.tokens);

    {
        AST::DumpVisitor dump("_ast.json");
        i.script->AcceptConst(dump);
    }

    // return PluginAfterActionRequest::None;

    Transformer::DeadCodeRemover remover;
    AST::PluginVisitor visitor(&remover, &data.editor);

    // TODO: instance should also handle the action for the script block
    AST::Node* _rep;
    i.script->Accept(visitor, _rep);

    {
        AST::DumpVisitor dump("_ast_after.json");
        i.script->AcceptConst(dump);
    }

    return PluginAfterActionRequest::Rescan;
}
} // namespace GView::Type::JS::Plugins