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

    std::vector<std::string_view> files;
    std::vector<FstEntry32*> entries32;
    std::vector<FstEntry64*> entries64;
    std::vector<Function> functions;

    bool processed{ false };

    std::string buildId{ "UNKNOWN" };             // this gets set from outside
    std::string runtimeBuildVersion{ "UNKNOWN" }; // this gets set from outside
    std::string runtimeBuildModInfo{ "UNKNOWN" }; // this gets set from outside
};

GoPclntab112::GoPclntab112()
{
    context = new GoPclntab112Context;
}

GoPclntab112::~GoPclntab112()
{
    delete reinterpret_cast<GoPclntab112Context*>(context);
}

void GoPclntab112::Reset()
{
    delete reinterpret_cast<GoPclntab112Context*>(context);
    context = new GoPclntab112Context;
}

bool GoPclntab112::Process(const Buffer& buffer, Architecture arch)
{
    CHECK(context != nullptr, false, "");
    CHECK(buffer.IsValid(), false, "");
    CHECK(buffer.GetLength() > sizeof(Golang::GoFunctionHeader), false, "");
    CHECK(arch != Architecture::Unknown, false, "");

    auto goCtx = reinterpret_cast<GoPclntab112Context*>(this->context);
    CHECK(goCtx->processed == false, false, "");
    goCtx->buffer = buffer;
    goCtx->arch   = arch;

    goCtx->header      = reinterpret_cast<Golang::GoFunctionHeader*>(goCtx->buffer.GetData());
    goCtx->nfunctab    = *reinterpret_cast<uint32*>(goCtx->buffer.GetData() + sizeof(Golang::GoFunctionHeader));
    goCtx->funcdata    = goCtx->buffer.GetData();
    goCtx->funcnametab = goCtx->buffer.GetData();
    goCtx->functab     = goCtx->buffer.GetData() + 8 + goCtx->header->sizeOfUintptr;
    goCtx->pctab       = goCtx->buffer.GetData();
    goCtx->functabsize = (goCtx->nfunctab * 2 + 1) * goCtx->header->sizeOfUintptr; // TODO: version >= 1.18 size is fixed to 4
    goCtx->fileoff     = *reinterpret_cast<uint32*>(goCtx->functab + goCtx->functabsize);
    goCtx->filetab     = goCtx->buffer.GetData() + goCtx->fileoff;
    goCtx->nfiletab    = *reinterpret_cast<uint32*>(goCtx->filetab);
    goCtx->filetab     = goCtx->filetab + goCtx->nfiletab * 4;

    {
        goCtx->files.reserve(goCtx->nfiletab);

        uint32 offset = 0;
        for (uint32 i = 0; i < goCtx->nfiletab - 1; i++)
        {
            auto fname      = (char*) (goCtx->filetab + offset);
            const auto& res = goCtx->files.emplace_back(fname);
            offset += static_cast<uint32>(res.size()) + 2;
        }
    }

    if (arch == Architecture::x86)
    {
        goCtx->entries32.reserve(goCtx->nfunctab);
        goCtx->functions.reserve(goCtx->nfunctab);

        auto entries = reinterpret_cast<Golang::FstEntry32*>(goCtx->functab);
        for (auto i = 0U; i < goCtx->nfunctab; i++)
        {
            const auto entry32 = entries + i;
            goCtx->entries32.emplace_back(entry32);
        }

        for (const auto& entry : goCtx->entries32)
        {
            const auto f32 = (Golang::Func32*) (goCtx->buffer.GetData() + entry->functionOffset);

            auto& e      = goCtx->functions.emplace_back();
            e.func.entry = f32->entry;
            memcpy(
                  reinterpret_cast<char*>(&e.func.entry) + sizeof(e.func.entry),
                  reinterpret_cast<char*>(&f32->entry) + sizeof(f32->entry),
                  sizeof(Golang::Func32) - sizeof(Golang::Func32::entry));
            e.name = (char*) goCtx->funcnametab + e.func.name;
        }
    }
    else if (arch == Architecture::x64)
    {
        goCtx->entries64.reserve(goCtx->nfunctab);
        goCtx->functions.reserve(goCtx->nfunctab);

        auto entries = reinterpret_cast<Golang::FstEntry64*>(goCtx->functab);
        for (auto i = 0U; i < goCtx->nfunctab; i++)
        {
            const auto entry64 = entries + i;
            goCtx->entries64.emplace_back(entry64);
        }

        for (const auto& entry : goCtx->entries64)
        {
            auto& e = goCtx->functions.emplace_back(
                  Function{ nullptr, *reinterpret_cast<Golang::Func64*>(buffer.GetData() + entry->functionOffset) });
            e.name = reinterpret_cast<char*>(goCtx->funcnametab) + e.func.name;
        }
    }

    if (goCtx->functions.empty() == false)
    {
        goCtx->functions.pop_back();
        std::reverse(goCtx->functions.begin(), goCtx->functions.end());
    }

    goCtx->processed = true;

    return true;
}

GoFunctionHeader* GoPclntab112::GetHeader() const
{
    CHECK(context != nullptr, nullptr, "");
    const auto goContext = reinterpret_cast<GoPclntab112Context*>(this->context);
    CHECK(goContext->processed, nullptr, "");
    return goContext->header;
}

uint64 GoPclntab112::GetFilesCount() const
{
    CHECK(context != nullptr, 0, "");
    const auto goContext = reinterpret_cast<GoPclntab112Context*>(this->context);
    CHECK(goContext->processed, 0, "");
    return goContext->files.size();
}

bool GoPclntab112::GetFile(uint64 index, std::string_view& file) const
{
    CHECK(context != nullptr, false, "");
    const auto goContext = reinterpret_cast<GoPclntab112Context*>(this->context);
    CHECK(goContext->processed, false, "");
    CHECK(index < goContext->files.size(), false, "");
    file = goContext->files.at(index);
    return true;
}

uint64 GoPclntab112::GetFunctionsCount() const
{
    CHECK(context != nullptr, 0, "");
    const auto goContext = reinterpret_cast<GoPclntab112Context*>(this->context);
    CHECK(goContext->processed, 0, "");
    return goContext->functions.size();
}

bool GoPclntab112::GetFunction(uint64 index, Function& func) const
{
    CHECK(context != nullptr, false, "");
    const auto goContext = reinterpret_cast<GoPclntab112Context*>(this->context);
    CHECK(goContext->processed, false, "");
    CHECK(index < goContext->functions.size(), false, "");
    func = goContext->functions.at(index);
    return true;
}

uint64 GoPclntab112::GetEntriesCount() const
{
    CHECK(context != nullptr, 0, "");
    const auto goContext = reinterpret_cast<GoPclntab112Context*>(this->context);
    CHECK(goContext->processed, 0, "");

    if (goContext->arch == Architecture::x86)
    {
        return goContext->entries32.size();
    }

    if (goContext->arch == Architecture::x64)
    {
        return goContext->entries64.size();
    }

    return 0;
}

void GoPclntab112::SetBuildId(std::string_view buildId)
{
    CHECKRET(context != nullptr, "");
    const auto goContext = reinterpret_cast<GoPclntab112Context*>(this->context);
    CHECKRET(goContext->processed, "");

    goContext->buildId = buildId;
}

const std::string& GoPclntab112::GetBuildId() const
{
    static const std::string empty;
    CHECK(context != nullptr, empty, "");
    const auto goContext = reinterpret_cast<GoPclntab112Context*>(this->context);
    CHECK(goContext->processed, empty, "");

    return goContext->buildId;
}

void GoPclntab112::SetRuntimeBuildVersion(std::string_view runtimeBuildVersion)
{
    CHECKRET(context != nullptr, "");
    const auto goContext = reinterpret_cast<GoPclntab112Context*>(this->context);
    CHECKRET(goContext->processed, "");

    goContext->runtimeBuildVersion = runtimeBuildVersion;
}

const std::string& GoPclntab112::RuntimeBuildVersion() const
{
    static const std::string empty;
    CHECK(context != nullptr, empty, "");
    const auto goContext = reinterpret_cast<GoPclntab112Context*>(this->context);
    CHECK(goContext->processed, empty, "");

    return goContext->runtimeBuildVersion;
}

void GoPclntab112::SetRuntimeBuildModInfo(std::string_view runtimeBuildModInfo)
{
    CHECKRET(context != nullptr, "");
    const auto goContext = reinterpret_cast<GoPclntab112Context*>(this->context);
    CHECKRET(goContext->processed, "");

    goContext->runtimeBuildModInfo = runtimeBuildModInfo;
}

const std::string& GoPclntab112::GetRuntimeBuildModInfo() const
{
    static const std::string empty;
    CHECK(context != nullptr, empty, "");
    const auto goContext = reinterpret_cast<GoPclntab112Context*>(this->context);
    CHECK(goContext->processed, empty, "");

    return goContext->runtimeBuildModInfo;
}
} // namespace GView::Golang
