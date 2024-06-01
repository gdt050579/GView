#include "js.hpp"
#include "ast.hpp"

namespace GView::Type::JS::Plugins
{
using namespace GView::View::LexicalViewer;
using namespace GView::Type::JS;

std::string_view BuildAST::GetName()
{
    return "Build AST";
}
std::string_view BuildAST::GetDescription()
{
    return "Build AST from code.";
}
bool BuildAST::CanBeAppliedOn(const GView::View::LexicalViewer::PluginData& data)
{
    return true;
}

class ConstFolder : public AST::Plugin
{
  public:
    virtual AST::Action OnEnterBinop(AST::Binop* node, AST::Expr*& replacement) override
    {
        return FoldBinop(node, replacement);
    }

    virtual AST::Action OnExitBinop(AST::Binop* node, AST::Expr*& replacement) override
    {
        return FoldBinop(node, replacement);
    }

    private:
    AST::Action FoldBinop(AST::Binop* node, AST::Expr*& replacement)
    {
        if (node->left->GetExprType() == AST::ExprType::Constant) {
            if (((AST::Constant*) node->left)->GetConstType() == AST::ConstType::Number) {
                if (node->right->GetExprType() == AST::ExprType::Constant) {
                    if (((AST::Constant*) node->right)->GetConstType() == AST::ConstType::Number) {
                        auto sum = ((AST::Number*) node->left)->value + ((AST::Number*) node->right)->value;

                        replacement = new AST::Number(sum);

                        return AST::Action::Replace;
                    }
                }
            }
        }

        return AST::Action::None;
    }
};

GView::View::LexicalViewer::PluginAfterActionRequest BuildAST::Execute(GView::View::LexicalViewer::PluginData& data)
{
    AST::Instance i;
    i.Create(data.tokens);

    {
        AST::DumpVisitor dump("_ast.json");
        i.script->AcceptConst(dump);
    }

    //return PluginAfterActionRequest::None;

    ConstFolder folder;
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