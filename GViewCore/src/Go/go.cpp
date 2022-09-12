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
    uint8* cutab{ nullptr };
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

    goCtx->header = reinterpret_cast<Golang::GoFunctionHeader*>(goCtx->buffer.GetData());
    // data validation
    CHECK(goCtx->header->magic == GoMagic::_116 || goCtx->header->magic == GoMagic::_118 || goCtx->header->magic == GoMagic::_12,
          false,
          "");
    CHECK(goCtx->header->instructionSizeQuantum <= 4, false, "");
    CHECK(goCtx->header->sizeOfUintptr <= 8, false, "");

    switch (goCtx->header->magic) // functabsize = sizeOfUintptr when version <= 118 else 4
    {
    case GoMagic::_116:
        goCtx->nfunctab = *reinterpret_cast<uint32*>(goCtx->buffer.GetData() + sizeof(Golang::GoFunctionHeader));
        goCtx->nfiletab =
              *reinterpret_cast<uint32*>(goCtx->buffer.GetData() + sizeof(Golang::GoFunctionHeader) + 1 * goCtx->header->sizeOfUintptr);
        goCtx->funcnametab =
              goCtx->buffer.GetData() +
              *reinterpret_cast<uint32*>(goCtx->buffer.GetData() + sizeof(Golang::GoFunctionHeader) + 2 * goCtx->header->sizeOfUintptr);
        goCtx->cutab =
              goCtx->buffer.GetData() +
              *reinterpret_cast<uint32*>(goCtx->buffer.GetData() + sizeof(Golang::GoFunctionHeader) + 3 * goCtx->header->sizeOfUintptr);
        goCtx->filetab =
              goCtx->buffer.GetData() +
              *reinterpret_cast<uint32*>(goCtx->buffer.GetData() + sizeof(Golang::GoFunctionHeader) + 4 * goCtx->header->sizeOfUintptr);
        goCtx->pctab =
              goCtx->buffer.GetData() +
              *reinterpret_cast<uint32*>(goCtx->buffer.GetData() + sizeof(Golang::GoFunctionHeader) + 5 * goCtx->header->sizeOfUintptr);
        goCtx->funcdata =
              goCtx->buffer.GetData() +
              *reinterpret_cast<uint32*>(goCtx->buffer.GetData() + sizeof(Golang::GoFunctionHeader) + 6 * goCtx->header->sizeOfUintptr);
        goCtx->functab =
              goCtx->buffer.GetData() +
              *reinterpret_cast<uint32*>(goCtx->buffer.GetData() + sizeof(Golang::GoFunctionHeader) + 6 * goCtx->header->sizeOfUintptr);
        goCtx->functabsize = (goCtx->nfunctab * 2 + 1) * goCtx->header->sizeOfUintptr;
        break;
    case GoMagic::_118:
        goCtx->nfunctab = *reinterpret_cast<uint32*>(goCtx->buffer.GetData() + sizeof(Golang::GoFunctionHeader));
        goCtx->nfiletab =
              *reinterpret_cast<uint32*>(goCtx->buffer.GetData() + sizeof(Golang::GoFunctionHeader) + 1 * goCtx->header->sizeOfUintptr);
        goCtx->funcnametab =
              goCtx->buffer.GetData() +
              *reinterpret_cast<uint32*>(goCtx->buffer.GetData() + sizeof(Golang::GoFunctionHeader) + 3 * goCtx->header->sizeOfUintptr);
        goCtx->cutab =
              goCtx->buffer.GetData() +
              *reinterpret_cast<uint32*>(goCtx->buffer.GetData() + sizeof(Golang::GoFunctionHeader) + 4 * goCtx->header->sizeOfUintptr);
        goCtx->filetab =
              goCtx->buffer.GetData() +
              *reinterpret_cast<uint32*>(goCtx->buffer.GetData() + sizeof(Golang::GoFunctionHeader) + 5 * goCtx->header->sizeOfUintptr);
        goCtx->pctab =
              goCtx->buffer.GetData() +
              *reinterpret_cast<uint32*>(goCtx->buffer.GetData() + sizeof(Golang::GoFunctionHeader) + 6 * goCtx->header->sizeOfUintptr);
        goCtx->funcdata =
              goCtx->buffer.GetData() +
              *reinterpret_cast<uint32*>(goCtx->buffer.GetData() + sizeof(Golang::GoFunctionHeader) + 7 * goCtx->header->sizeOfUintptr);
        goCtx->functab =
              goCtx->buffer.GetData() +
              *reinterpret_cast<uint32*>(goCtx->buffer.GetData() + sizeof(Golang::GoFunctionHeader) + 7 * goCtx->header->sizeOfUintptr);
        goCtx->functabsize = (goCtx->nfunctab * 2 + 1) * goCtx->header->sizeOfUintptr;
        break;
    case GoMagic::_12:
        goCtx->header      = reinterpret_cast<Golang::GoFunctionHeader*>(goCtx->buffer.GetData());
        goCtx->nfunctab    = *reinterpret_cast<uint32*>(goCtx->buffer.GetData() + sizeof(Golang::GoFunctionHeader));
        goCtx->funcdata    = goCtx->buffer.GetData();
        goCtx->funcnametab = goCtx->buffer.GetData();
        goCtx->functab     = goCtx->buffer.GetData() + 8 + goCtx->header->sizeOfUintptr;
        goCtx->pctab       = goCtx->buffer.GetData();
        goCtx->functabsize = (goCtx->nfunctab * 2 + 1) * goCtx->header->sizeOfUintptr;
        goCtx->fileoff     = *reinterpret_cast<uint32*>(goCtx->functab + goCtx->functabsize);
        goCtx->filetab     = goCtx->buffer.GetData() + goCtx->fileoff;
        goCtx->nfiletab    = *reinterpret_cast<uint32*>(goCtx->filetab);
        goCtx->filetab     = goCtx->filetab + goCtx->nfiletab * 4;
        break;
    default:
        throw std::runtime_error("Not implemented!");
    }

    {
        goCtx->files.reserve(goCtx->nfiletab);

        uint32 offset = 0;
        for (uint32 i = 0; i < goCtx->nfiletab - 1; i++)
        {
            auto fname      = (char*) (goCtx->filetab + offset);
            const auto& res = goCtx->files.emplace_back(fname);

            switch (goCtx->header->magic)
            {
            case GoMagic::_116:
            case GoMagic::_118:
                offset += static_cast<uint32>(res.size()) + 1;
                break;
            case GoMagic::_12:
                offset += static_cast<uint32>(res.size()) + 2;
                break;
            default:
                break;
            }
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
            switch (goCtx->header->magic)
            {
            case GoMagic::_116:
            case GoMagic::_118:
            {
                auto& e          = goCtx->functions.emplace_back(Function{ nullptr, {} });
                const auto index = goCtx->functions.size() - 1;
                if (index == 0)
                {
                    e.name = reinterpret_cast<char*>(goCtx->funcnametab) + e.func.name;
                }
                else
                {
                    const auto& ePrevious = goCtx->functions.at(goCtx->functions.size() - 2);
                    e.name                = ePrevious.name + strlen(ePrevious.name) + 1;
                }
            }
            break;
            case GoMagic::_12:
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
            break;
            default:
                throw std::runtime_error("Check this magic");
            }
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
            switch (goCtx->header->magic)
            {
            case GoMagic::_116:
            case GoMagic::_118:
            {
                auto& e          = goCtx->functions.emplace_back(Function{ .name = nullptr, .func = {}, .fstEntry{ ._64 = entry } });
                const auto index = goCtx->functions.size() - 1;
                if (index == 0)
                {
                    e.name = reinterpret_cast<char*>(goCtx->funcnametab) + e.func.name;
                }
                else
                {
                    const auto& ePrevious = goCtx->functions.at(goCtx->functions.size() - 2);
                    e.name                = ePrevious.name + strlen(ePrevious.name) + 1;
                }
            }
            break;
            case GoMagic::_12:
            {
                auto& e = goCtx->functions.emplace_back(
                      Function{ nullptr, *reinterpret_cast<Golang::Func64*>(buffer.GetData() + entry->functionOffset) });
                e.name = reinterpret_cast<char*>(goCtx->funcnametab) + e.func.name;
            }
            break;
            default:
                throw std::runtime_error("Check this magic");
            }
        }
    }

    switch (goCtx->header->magic)
    {
    case GoMagic::_116:
    case GoMagic::_118:
    {
        auto ePrevious = &goCtx->functions.at(goCtx->functions.size() - 1);
        auto ptr       = ePrevious->name + strlen(ePrevious->name) + 1;
        while (*(char*) (ePrevious->name + strlen(ePrevious->name) + 1) != 0 && ptr < (char*) goCtx->cutab) // it is risky
        {
            auto& e   = goCtx->functions.emplace_back(Function{ .name = nullptr, .func = {}, .fstEntry{ ._64 = nullptr } });
            e.name    = ptr;
            ePrevious = &goCtx->functions.at(goCtx->functions.size() - 1);
            ptr       = ePrevious->name + strlen(ePrevious->name) + 1;
        }
    }
    case GoMagic::_12:
    default:
        break;
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
    goContext->buildId   = buildId;
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
    const auto goContext           = reinterpret_cast<GoPclntab112Context*>(this->context);
    goContext->runtimeBuildVersion = runtimeBuildVersion;
}

const std::string& GoPclntab112::GetRuntimeBuildVersion() const
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
    const auto goContext           = reinterpret_cast<GoPclntab112Context*>(this->context);
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
