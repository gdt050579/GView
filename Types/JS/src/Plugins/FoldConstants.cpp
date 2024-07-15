#include "js.hpp"
#include "ast.hpp"
#include "Transformers/ConstFolder.hpp"

namespace GView::Type::JS::Plugins
{
using namespace GView::View::LexicalViewer;
using namespace GView::Type::JS;

std::string_view FoldConstants::GetName()
{
    return "Fold Constants";
}
std::string_view FoldConstants::GetDescription()
{
    return "Apply const folding.";
}
bool FoldConstants::CanBeAppliedOn(const GView::View::LexicalViewer::PluginData& data)
{
    return true;
}

GView::View::LexicalViewer::PluginAfterActionRequest FoldConstants::Execute(GView::View::LexicalViewer::PluginData& data)
{
    AST::Instance i;
    i.Create(data.tokens);

    {
        AST::DumpVisitor dump("_ast.json");
        i.script->AcceptConst(dump);
    }

    // return PluginAfterActionRequest::None;

    Transformer::ConstFolder folder;
    AST::PluginVisitor visitor(&folder, &data.editor);

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