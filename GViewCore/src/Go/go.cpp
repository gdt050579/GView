#include "../include/GView.hpp"

namespace GView::Golang
{
const char* GetNameForGoMagic(GoMagic magic)
{
    switch (magic)
    {
    case GoMagic::_12:
        return "Version 1.2";
    case GoMagic::_116:
        return "Version 1.16";
    case GoMagic::_118:
        return "Version 1.18";
    default:
        return "Version Unknown";
    }
}

struct GoPclntab112Context
{
    Buffer buffer{};
    GoFunctionHeader* header{ nullptr };
    Architecture arch{ Architecture::Unknown };

    // https://go.dev/src/debug/gosym/pclntab.go
    uint32 nfunctab{ 0 };
    uint8* funcdata{ nullptr };
    uint8* funcnametab{ nullptr };
    uint8* functab{ nullptr };
    uint8* pctab{ nullptr };
    int32 functabsize{ 0 };
    uint32 fileoff{ 0 };
    uint8* filetab{ nullptr };
    uint32 nfiletab{ 0 };

    std::map<uint64, std::string_view> files;
    std::vector<FstEntry32*> entries32;
    std::vector<FstEntry64*> entries64;
    std::vector<Function> functions;

    bool processed{ false };
};

GoPclntab112::GoPclntab112()
{
    context = new GoPclntab112Context;
}

GoPclntab112::~GoPclntab112()
{
    delete (GoPclntab112Context*) context;
}

void GoPclntab112::Reset()
{
    delete (GoPclntab112Context*) context;
    context = new GoPclntab112Context;
}

bool GoPclntab112::Process(const Buffer& buffer, Architecture arch)
{
    CHECK(context != nullptr, false, "");
    CHECK(buffer.IsValid(), false, "");
    CHECK(buffer.GetLength() > sizeof(Golang::GoFunctionHeader), false, "");
    CHECK(arch != Architecture::Unknown, false, "");

    auto goContext = (GoPclntab112Context*) this->context;
    CHECK(goContext->processed == false, false, "");
    goContext->buffer = buffer;
    goContext->arch   = arch;

    goContext->header      = (Golang::GoFunctionHeader*) goContext->buffer.GetData();
    goContext->nfunctab    = *(uint32*) (goContext->buffer.GetData() + sizeof(Golang::GoFunctionHeader));
    goContext->funcdata    = goContext->buffer.GetData();
    goContext->funcnametab = goContext->buffer.GetData();
    goContext->functab     = goContext->buffer.GetData() + 8 + goContext->header->sizeOfUintptr;
    goContext->pctab       = goContext->buffer.GetData();
    goContext->functabsize = (goContext->nfunctab * 2 + 1) * goContext->header->sizeOfUintptr; // TODO: version >= 1.18 size is fixed to 4
    goContext->fileoff     = *(uint32*) (goContext->functab + goContext->functabsize);
    goContext->filetab     = goContext->buffer.GetData() + goContext->fileoff;
    goContext->nfiletab    = *(uint32*) goContext->filetab;
    goContext->filetab     = goContext->filetab + goContext->nfiletab * 4;

    {
        uint32 offset = 0;
        for (uint32 i = 0; i < goContext->nfiletab - 1; i++)
        {
            auto fname                 = (char*) (goContext->filetab + offset);
            const auto& [pair, result] = goContext->files.emplace(std::pair<uint32, std::string_view>{ i, fname });
            offset += (uint32) pair->second.size() + 2;
        }
    }

    if (arch == Architecture::x86)
    {
        auto entries = (Golang::FstEntry32*) goContext->functab;
        for (auto i = 0U; i < goContext->nfunctab; i++)
        {
            const auto entry32 = entries + i;
            goContext->entries32.emplace_back(entry32);
        }

        for (const auto& entry : goContext->entries32)
        {
            const auto f32 = (Golang::Func32*) (goContext->buffer.GetData() + entry->functionOffset);

            auto& e      = goContext->functions.emplace_back();
            e.func.entry = f32->entry;
            memcpy(
                  (char*) &e.func.entry + sizeof(e.func.entry),
                  (char*) &f32->entry + sizeof(f32->entry),
                  sizeof(Golang::Func32) - sizeof(Golang::Func32::entry));
            e.name = (char*) goContext->funcnametab + e.func.name;
        }
    }
    else if (arch == Architecture::x64)
    {
        auto entries = (Golang::FstEntry64*) goContext->functab;
        for (auto i = 0U; i < goContext->nfunctab; i++)
        {
            const auto entry64 = entries + i;
            goContext->entries64.emplace_back(entry64);
        }

        for (const auto& entry : goContext->entries64)
        {
            auto& e = goContext->functions.emplace_back(Function{ nullptr, *(Golang::Func64*) (buffer.GetData() + entry->functionOffset) });
            e.name  = (char*) goContext->funcnametab + e.func.name;
        }
    }

    if (goContext->functions.empty() == false)
    {
        goContext->functions.pop_back();
        std::reverse(goContext->functions.begin(), goContext->functions.end());
    }

    goContext->processed = true;

    return true;
}

GoFunctionHeader* GoPclntab112::GetHeader() const
{
    CHECK(context != nullptr, nullptr, "");
    const auto goContext = (GoPclntab112Context*) this->context;
    CHECK(goContext->processed, nullptr, "");
    return goContext->header;
}

uint64 GoPclntab112::GetFilesCount() const
{
    CHECK(context != nullptr, 0, "");
    const auto goContext = (GoPclntab112Context*) this->context;
    CHECK(goContext->processed, 0, "");
    return goContext->files.size();
}

bool GoPclntab112::GetFile(uint64 index, std::string_view& file) const
{
    CHECK(context != nullptr, false, "");
    const auto goContext = (GoPclntab112Context*) this->context;
    CHECK(goContext->processed, false, "");
    CHECK(index < goContext->files.size(), false, "");
    file = goContext->files.at(index);
    return true;
}

uint64 GoPclntab112::GetFunctionsCount() const
{
    CHECK(context != nullptr, 0, "");
    const auto goContext = (GoPclntab112Context*) this->context;
    CHECK(goContext->processed, 0, "");

    return goContext->functions.size();
}

bool GoPclntab112::GetFunction(uint64 index, Function& func) const
{
    CHECK(context != nullptr, false, "");
    const auto goContext = (GoPclntab112Context*) this->context;
    CHECK(goContext->processed, false, "");

    CHECK(index < goContext->functions.size(), false, "");
    func = goContext->functions.at(index);

    return true;
}

uint64 GoPclntab112::GetEntriesCount() const
{
    CHECK(context != nullptr, 0, "");
    const auto goContext = (GoPclntab112Context*) this->context;
    CHECK(goContext->processed, 0, "");

    if (goContext->arch == Architecture::x86)
        return goContext->entries32.size();

    if (goContext->arch == Architecture::x64)
        return goContext->entries64.size();

    return 0;
}

} // namespace GView::Golang
