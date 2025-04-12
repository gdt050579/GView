#include "js.hpp"
#include "ast.hpp"
#include "Transformers/ContextAwareRenamer.hpp"

#include <stack>
#include <unordered_set>

namespace GView::Type::JS::Plugins
{
using namespace GView::View::LexicalViewer;
using namespace GView::Type::JS;

std::string_view ContextAwareRename::GetName()
{
    return "Context Aware Rename";
}
std::string_view ContextAwareRename::GetDescription()
{
    return "Rename variables.";
}
bool ContextAwareRename::CanBeAppliedOn(const GView::View::LexicalViewer::PluginData& data)
{
    return true;
}

GView::View::LexicalViewer::PluginAfterActionRequest ContextAwareRename::Execute(GView::View::LexicalViewer::PluginData& data, Reference<Window> parent)
{
    AST::Instance i;
    i.Create(data.tokens);

    {
        AST::DumpVisitor dump("_ast.json");
        i.script->AcceptConst(dump);
    }

    Transformer::ContextAwareRenamer renamer;

    // return PluginAfterActionRequest::None;

    AST::PluginVisitor visitor(&renamer, &data.editor);

    AST::Node* _rep;
    i.script->Accept(visitor, _rep);

    {
        AST::DumpVisitor dump("_ast_intermediary.json");
        i.script->AcceptConst(dump);
    }

    // Prepare AST for a second visitor
    i.script->AdjustSourceOffset(0);

    // Late rename
    Transformer::ContextAwareLateRenamer lateRenamer(renamer.lateRenameNodes);
    visitor = AST::PluginVisitor(&lateRenamer, &data.editor);

    // TODO: instance should also handle the action for the script block
    i.script->Accept(visitor, _rep);

    {
        AST::DumpVisitor dump("_ast_after.json");
        i.script->AcceptConst(dump);
    }

    return PluginAfterActionRequest::Rescan;
}
} // namespace GView::Type::JS::Plugins