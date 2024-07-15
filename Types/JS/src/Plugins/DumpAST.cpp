#include "js.hpp"
#include "ast.hpp"

namespace GView::Type::JS::Plugins
{
using namespace GView::View::LexicalViewer;
using namespace GView::Type::JS;

std::string_view DumpAST::GetName()
{
    return "Dump AST";
}
std::string_view DumpAST::GetDescription()
{
    return "Dump AST to _ast.json";
}
bool DumpAST::CanBeAppliedOn(const GView::View::LexicalViewer::PluginData& data)
{
    return true;
}

GView::View::LexicalViewer::PluginAfterActionRequest DumpAST::Execute(GView::View::LexicalViewer::PluginData& data)
{
    AST::Instance i;
    i.Create(data.tokens);

    AST::DumpVisitor dump("_ast.json");
    i.script->AcceptConst(dump);

    return PluginAfterActionRequest::None;
}
} // namespace GView::Type::JS::Plugins