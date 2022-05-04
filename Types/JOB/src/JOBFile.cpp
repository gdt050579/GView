#include "JOB.hpp"

using namespace GView::Type::JOB;

JOBFile::JOBFile()
{
}

bool JOBFile::Update()
{
    auto offset = 0;
    CHECK(obj->GetData().Copy<FIXDLEN_DATA>(offset, fixedLengthData), false, "");
    offset += sizeof(FIXDLEN_DATA);

    return true;
}
