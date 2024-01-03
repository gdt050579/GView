#pragma once

#include "jclass.hpp"
#include "global.hpp"
#include "ast.hpp"

using namespace AppCUI;
using namespace AppCUI::OS;
using namespace AppCUI::Controls;
using namespace AppCUI::Application;
using namespace GView::Type;
using namespace GView::View;

namespace GView::Type::JClass
{
bool ClassViewer::Parse()
{
    auto buffer = this->obj->GetData().GetEntireFile();

    ClassParser parser;
    BufferReader reader{ buffer.GetData(), buffer.GetLength() };
    FCHECK(parser.parse(reader, this->areas));

    AstCreator creator{ parser };

    auto clazz = creator.create();
    FCHECK(clazz);

    return true;
}

string_view ClassViewer::GetTypeName()
{
    return "class";
}

void ClassViewer::RunCommand(std::string_view)
{
}

} // namespace GView::Type::JClass
