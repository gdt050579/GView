#include "js.hpp"
#include "ast.hpp"
#include "Transformers/ConstFolder.hpp"
#include "Transformers/ConstPropagator.hpp"
#include "Transformers/ContextAwareRenamer.hpp"
#include "Transformers/DeadCodeRemover.hpp"
#include "Transformers/DummyCodeRemover.hpp"
#include "Transformers/FunctionHoister.hpp"
#include "Transformers/FunctionInliner.hpp"

namespace GView::Type::JS::Plugins
{
using namespace GView::View::LexicalViewer;
using namespace GView::Type::JS;

std::string_view Simplify::GetName()
{
    return "Simplify";
}
std::string_view Simplify::GetDescription()
{
    return "Simplify code as much as possible.";
}
bool Simplify::CanBeAppliedOn(const GView::View::LexicalViewer::PluginData& data)
{
    return true;
}

GView::View::LexicalViewer::PluginAfterActionRequest Simplify::Execute(GView::View::LexicalViewer::PluginData& data)
{
    AST::Instance i;
    i.Create(data.tokens);

    {
        AST::DumpVisitor dump("_ast.json");
        i.script->AcceptConst(dump);
    }

    bool dirty;

    do {
        dirty = false;

        {
            i.script->AdjustSourceOffset(0);

            Transformer::ConstFolder folder;
            AST::PluginVisitor visitor(&folder, &data.editor);

            AST::Node* _rep;
            i.script->Accept(visitor, _rep);

            dirty |= visitor.dirty;
        }

        {
            i.script->AdjustSourceOffset(0);

            Transformer::ConstPropagator propagator;
            AST::PluginVisitor visitor(&propagator, &data.editor);

            AST::Node* _rep;
            i.script->Accept(visitor, _rep);

            dirty |= visitor.dirty;
        }

        {
            i.script->AdjustSourceOffset(0);

            Transformer::DeadCodeRemover remover;
            AST::PluginVisitor visitor(&remover, &data.editor);

            AST::Node* _rep;
            i.script->Accept(visitor, _rep);

            dirty |= visitor.dirty;
        }

        {
            i.script->AdjustSourceOffset(0);

            Transformer::DummyCodeRemover remover;
            AST::PluginVisitor visitor(&remover, &data.editor);

            AST::Node* _rep;
            i.script->Accept(visitor, _rep);

            i.script->AdjustSourceOffset(0);

            Transformer::DummyCodePostRemover postRemover(remover.dummy);
            AST::PluginVisitor postVisitor(&postRemover, &data.editor);

            i.script->Accept(postVisitor, _rep);

            dirty |= visitor.dirty;
        }

        {
            i.script->AdjustSourceOffset(0);

            Transformer::FunctionInliner inliner;
            AST::PluginVisitor visitor(&inliner, &data.editor);

            AST::Node* _rep;
            i.script->Accept(visitor, _rep);

            dirty |= visitor.dirty;
        }
    } while (dirty);

    // At the end, hoist

    /*{
        i.script->AdjustSourceOffset(0);

        Transformer::ContextAwareRenamer renamer;
        AST::PluginVisitor visitor(&renamer, &data.editor);

        AST::Node* _rep;
        i.script->Accept(visitor, _rep);

        Transformer::ContextAwareLateRenamer lateRenamer(renamer.lateRenameNodes);
        visitor = AST::PluginVisitor(&lateRenamer, &data.editor);

        i.script->Accept(visitor, _rep);
    }*/

    {
        i.script->AdjustSourceOffset(0);

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
                //continue;
            }

            // The destination can overlap with the source
            std::u16string content = { ((std::u16string_view) data.editor).data() + fun->sourceStart, fun->sourceSize };

            data.editor.Insert(dest, content);
            data.editor.Delete(fun->sourceStart + fun->sourceSize, fun->sourceSize);

            if (info.anchor == nullptr) {
                start += fun->sourceSize;
            }
        }
    }

    {
        AST::DumpVisitor dump("_ast_after.json");
        i.script->AcceptConst(dump);
    }

    return PluginAfterActionRequest::Rescan;
}
} // namespace GView::Type::JS::Plugins