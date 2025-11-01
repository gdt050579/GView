#include "js.hpp"
#include "ast.hpp"
#include "Transformers/DummyCodeRemover.hpp"

#include <stack>
#include <unordered_set>

namespace GView::Type::JS::Plugins
{
using namespace GView::View::LexicalViewer;
using namespace GView::Type::JS;

std::string_view RemoveDummyCode::GetName()
{
    return "Remove Dummy Code";
}
std::string_view RemoveDummyCode::GetDescription()
{
    return "Remove code that has no side effects.";
}
bool RemoveDummyCode::CanBeAppliedOn(const GView::View::LexicalViewer::PluginData& data)
{
    return true;
}

GView::View::LexicalViewer::PluginAfterActionRequest RemoveDummyCode::Execute(GView::View::LexicalViewer::PluginData& data, Reference<Window> parent)
{
    AST::Instance i;
    i.Create(data.tokens);

    {
        AST::DumpVisitor dump("_ast.json");
        i.script->AcceptConst(dump);
    }

    Transformer::DummyCodeRemover remover;

    AST::PluginVisitor visitor(&remover, &data.editor);

    AST::Node* _rep;
    i.script->Accept(visitor, _rep);

    // Prepare AST for a second visitor
    i.script->AdjustSourceOffset(0);

    Transformer::DummyCodePostRemover postRemover(remover.dummy);
    AST::PluginVisitor postVisitor(&postRemover, &data.editor);

    i.script->Accept(postVisitor, _rep);

    {
        AST::DumpVisitor dump("_ast_after.json");
        i.script->AcceptConst(dump);
    }

    return PluginAfterActionRequest::Rescan;
}
} // namespace GView::Type::JS::Plugins