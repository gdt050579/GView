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

    CHECK(obj->GetData().Copy<uint16>(offset, variableSizeDataSection.runningInstanceCount), false, "");
    offset += sizeof(uint16);

    applicationNameSize = 0;
    CHECK(obj->GetData().Copy<uint16>(offset, applicationNameSize), false, "");
    offset += sizeof(uint16);
    if (applicationNameSize > 0)
    {
        variableSizeDataSection.applicationName = obj->GetData().CopyToBuffer(offset, applicationNameSize * sizeof(char16));
        CHECK(variableSizeDataSection.applicationName.IsValid(), false, "");
        offset += applicationNameSize * sizeof(char16);
    }

    parametersSize = 0;
    CHECK(obj->GetData().Copy<uint16>(offset, parametersSize), false, "");
    offset += sizeof(uint16);
    if (parametersSize > 0)
    {
        variableSizeDataSection.parameters = obj->GetData().CopyToBuffer(offset, parametersSize * sizeof(char16));
        CHECK(variableSizeDataSection.parameters.IsValid(), false, "");
        offset += parametersSize * sizeof(char16);
    }

    workingDirectorySize = 0;
    CHECK(obj->GetData().Copy<uint16>(offset, workingDirectorySize), false, "");
    offset += sizeof(uint16);
    if (workingDirectorySize > 0)
    {
        variableSizeDataSection.workingDirectory = obj->GetData().CopyToBuffer(offset, workingDirectorySize * sizeof(char16));
        CHECK(variableSizeDataSection.workingDirectory.IsValid(), false, "");
        offset += workingDirectorySize * sizeof(char16);
    }

    authorSize = 0;
    CHECK(obj->GetData().Copy<uint16>(offset, authorSize), false, "");
    offset += sizeof(uint16);
    if (authorSize > 0)
    {
        variableSizeDataSection.author = obj->GetData().CopyToBuffer(offset, authorSize * sizeof(char16));
        CHECK(variableSizeDataSection.author.IsValid(), false, "");
        offset += authorSize * sizeof(char16);
    }

    commentSize = 0;
    CHECK(obj->GetData().Copy<uint16>(offset, commentSize), false, "");
    offset += sizeof(uint16);
    if (commentSize > 0)
    {
        variableSizeDataSection.comment = obj->GetData().CopyToBuffer(offset, commentSize * sizeof(char16));
        CHECK(variableSizeDataSection.comment.IsValid(), false, "");
        offset += commentSize * sizeof(char16);
    }

    uint16 userDataSize = 0;
    CHECK(obj->GetData().Copy<uint16>(offset, userDataSize), false, "");
    offset += sizeof(uint16);
    if (userDataSize > 0)
    {
        variableSizeDataSection.userData = obj->GetData().CopyToBuffer(offset, userDataSize);
        CHECK(variableSizeDataSection.userData.IsValid(), false, "");
        offset += userDataSize;
    }

    CHECK(obj->GetData().Copy<uint16>(offset, variableSizeDataSection.reservedData.size), false, "");
    offset += sizeof(uint16);
    if (variableSizeDataSection.reservedData.size > 0)
    {
        CHECK(obj->GetData().Copy<uint32>(offset, variableSizeDataSection.reservedData.taskReserved1.startError), false, "");
        offset += sizeof(variableSizeDataSection.reservedData.taskReserved1.startError);
        CHECK(obj->GetData().Copy<uint32>(offset, variableSizeDataSection.reservedData.taskReserved1.taskFlags), false, "");
        offset += sizeof(variableSizeDataSection.reservedData.taskReserved1.taskFlags);
    }

    CHECK(obj->GetData().Copy<uint16>(offset, variableSizeDataSection.triggers.count), false, "");
    offset += sizeof(uint16);
    if (variableSizeDataSection.triggers.count > 0)
    {
        for (uint32 i = 0; i < variableSizeDataSection.triggers.count; i++)
        {
            auto& trigger = variableSizeDataSection.triggers.items.emplace_back();
            CHECK(obj->GetData().Copy<Trigger>(offset, trigger), false, "");
            offset += sizeof(Trigger);
        }
    }

    if (offset < obj->GetData().GetSize())
    {
        JobSignature jobSignature;
        CHECK(obj->GetData().Copy<JobSignature>(offset, jobSignature), false, "");
        offset += sizeof(JobSignature);
        variableSizeDataSection.jobSignature.emplace(jobSignature);
    }

    return true;
}
