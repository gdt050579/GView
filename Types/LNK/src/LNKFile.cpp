#include "LNK.hpp"

using namespace GView::Type::LNK;

LNKFile::LNKFile()
{
}

bool LNKFile::Update()
{
    CHECK(obj->GetData().Copy<Header>(0, header), false, "");
    return true;
}
