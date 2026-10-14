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

struct PcLnTabContext
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

PcLnTab::PcLnTab()
{
    context = new PcLnTabContext;
}

PcLnTab::~PcLnTab()
{
    delete reinterpret_cast<PcLnTabContext*>(context);
}

void PcLnTab::Reset()
{
    delete reinterpret_cast<PcLnTabContext*>(context);
    context = new PcLnTabContext;
}

bool PcLnTab::Process(const Buffer& buffer, Architecture arch)
{
    CHECK(context != nullptr, false, "");
    CHECK(buffer.IsValid(), false, "");
    CHECK(buffer.GetLength() > sizeof(Golang::GoFunctionHeader), false, "");
    CHECK(arch != Architecture::Unknown, false, "");

    auto goCtx = reinterpret_cast<PcLnTabContext*>(this->context);
    CHECK(goCtx->processed == false, false, "");
    goCtx->buffer = buffer;
    goCtx->arch   = arch;

    // Process may be called again (with another candidate) after a failed attempt
    goCtx->files.clear();
    goCtx->entries32.clear();
    goCtx->entries64.clear();
    goCtx->functions.clear();

    goCtx->header = reinterpret_cast<Golang::GoFunctionHeader*>(goCtx->buffer.GetData());
    // data validation
    CHECK(goCtx->header->magic == GoMagic::_116 || goCtx->header->magic == GoMagic::_118 || goCtx->header->magic == GoMagic::_12,
          false,
          "");
    CHECK(goCtx->header->instructionSizeQuantum <= 4, false, "");
    CHECK(goCtx->header->sizeOfUintptr <= 8, false, "");

    const auto data       = goCtx->buffer.GetData();
    const uint64 dataSize = goCtx->buffer.GetLength();
    constexpr auto hSize  = sizeof(Golang::GoFunctionHeader);
    const uint64 ptrSize  = goCtx->header->sizeOfUintptr;

    // every offset / count below comes from the file => validate it against the buffer
    auto ReadU32 = [data, dataSize](uint64 offset, uint32& value) -> bool
    {
        if (offset > dataSize || dataSize - offset < sizeof(uint32))
            return false;
        memcpy(&value, data + offset, sizeof(uint32));
        return true;
    };
    auto ReadTable = [data, dataSize, &ReadU32](uint64 offset, uint8*& table) -> bool
    {
        uint32 tableOffset = 0;
        if (!ReadU32(offset, tableOffset) || tableOffset > dataSize)
            return false;
        table = data + tableOffset;
        return true;
    };
    // true if a NUL terminated string starts at offset and ends inside the buffer
    auto IsStringAt = [data, dataSize](uint64 offset) -> bool
    {
        return offset < dataSize &&
               strnlen(reinterpret_cast<const char*>(data + offset), static_cast<size_t>(dataSize - offset)) < dataSize - offset;
    };

    switch (goCtx->header->magic) // functabsize = sizeOfUintptr when version <= 118 else 4
    {
    case GoMagic::_116:
        CHECK(ReadU32(hSize, goCtx->nfunctab), false, "");
        CHECK(ReadU32(hSize + 1ull * ptrSize, goCtx->nfiletab), false, "");
        CHECK(ReadTable(hSize + 2ull * ptrSize, goCtx->funcnametab), false, "");
        CHECK(ReadTable(hSize + 3ull * ptrSize, goCtx->cutab), false, "");
        CHECK(ReadTable(hSize + 4ull * ptrSize, goCtx->filetab), false, "");
        CHECK(ReadTable(hSize + 5ull * ptrSize, goCtx->pctab), false, "");
        CHECK(ReadTable(hSize + 6ull * ptrSize, goCtx->funcdata), false, "");
        CHECK(ReadTable(hSize + 6ull * ptrSize, goCtx->functab), false, "");
        goCtx->functabsize = static_cast<int32>((goCtx->nfunctab * 2ull + 1ull) * goCtx->header->sizeOfUintptr);
        break;
    case GoMagic::_118:
        CHECK(ReadU32(hSize, goCtx->nfunctab), false, "");
        CHECK(ReadU32(hSize + 1ull * ptrSize, goCtx->nfiletab), false, "");
        CHECK(ReadTable(hSize + 3ull * ptrSize, goCtx->funcnametab), false, "");
        CHECK(ReadTable(hSize + 4ull * ptrSize, goCtx->cutab), false, "");
        CHECK(ReadTable(hSize + 5ull * ptrSize, goCtx->filetab), false, "");
        CHECK(ReadTable(hSize + 6ull * ptrSize, goCtx->pctab), false, "");
        CHECK(ReadTable(hSize + 7ull * ptrSize, goCtx->funcdata), false, "");
        CHECK(ReadTable(hSize + 7ull * ptrSize, goCtx->functab), false, "");
        goCtx->functabsize = static_cast<int32>((goCtx->nfunctab * 2ull + 1ull) * goCtx->header->sizeOfUintptr);
        break;
    case GoMagic::_12:
    {
        goCtx->header = reinterpret_cast<Golang::GoFunctionHeader*>(data);
        CHECK(ReadU32(hSize, goCtx->nfunctab), false, "");
        CHECK(goCtx->nfunctab < 0xA00000, false, ""); // sanity checks for invalid sigs
        goCtx->funcdata    = data;
        goCtx->funcnametab = data;
        CHECK(8 + ptrSize <= dataSize, false, "");
        goCtx->functab     = data + 8 + goCtx->header->sizeOfUintptr;
        goCtx->pctab       = data;
        goCtx->functabsize = (goCtx->nfunctab * 2 + 1) * goCtx->header->sizeOfUintptr;
        CHECK(ReadU32(8 + ptrSize + static_cast<uint64>(goCtx->functabsize), goCtx->fileoff), false, "");
        CHECK(ReadU32(goCtx->fileoff, goCtx->nfiletab), false, "");
        CHECK(goCtx->nfiletab < 0xA00000, false, ""); // sanity checks for invalid sigs
        const uint64 filetabOffset = goCtx->fileoff + goCtx->nfiletab * 4ull;
        CHECK(filetabOffset <= dataSize, false, "");
        goCtx->filetab = data + filetabOffset;
    }
    break;
    default:
        throw std::runtime_error("Not implemented!");
    }

    CHECK(goCtx->nfiletab < 0xA00000, false, ""); // sanity checks for invalid sigs
    CHECK(goCtx->nfunctab < 0xA00000, false, ""); // sanity checks for invalid sigs

    {
        goCtx->files.reserve(goCtx->nfiletab);

        const uint64 filetabOffset = static_cast<uint64>(goCtx->filetab - data);
        uint64 offset              = 0;
        for (uint32 i = 0; i + 1 < goCtx->nfiletab; i++)
        {
            const uint64 fnameOffset = filetabOffset + offset;
            if (fnameOffset >= dataSize)
            {
                break;
            }
            auto fname      = reinterpret_cast<char*>(data + fnameOffset);
            const auto& res = goCtx->files.emplace_back(fname, strnlen(fname, static_cast<size_t>(dataSize - fnameOffset)));

            switch (goCtx->header->magic)
            {
            case GoMagic::_116:
            case GoMagic::_118:
                offset += res.size() + 1;
                break;
            case GoMagic::_12:
                offset += res.size() + 2;
                break;
            default:
                break;
            }
        }
    }

    // a function name: a NUL terminated string inside the buffer (nullptr if invalid)
    auto NameAt = [data, &IsStringAt](int64 offset) -> char*
    {
        return offset >= 0 && IsStringAt(static_cast<uint64>(offset)) ? reinterpret_cast<char*>(data + offset) : nullptr;
    };
    // the name stored right after an already validated name (nullptr if invalid)
    auto NextName = [data, &NameAt](const char* name) -> char*
    {
        return NameAt(static_cast<int64>(reinterpret_cast<const uint8*>(name) - data + strlen(name) + 1));
    };
    const int64 funcnametabOffset = goCtx->funcnametab - data;
    const uint64 functabOffset    = static_cast<uint64>(goCtx->functab - data);

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
                    e.name = NameAt(funcnametabOffset + e.func.name);
                }
                else
                {
                    const auto& ePrevious = goCtx->functions.at(goCtx->functions.size() - 2);
                    e.name                = NextName(ePrevious.name);
                }
                CHECK(e.name != nullptr, false, "");
            }
            break;
            case GoMagic::_12:
            {
                const uint64 entryOffset = functabOffset + static_cast<uint64>(entry - entries) * sizeof(Golang::FstEntry32);
                CHECK(entryOffset <= dataSize && dataSize - entryOffset >= sizeof(Golang::FstEntry32), false, "");
                CHECK(entry->functionOffset <= dataSize && dataSize - entry->functionOffset >= sizeof(Golang::Func32), false, "");
                const auto f32 = reinterpret_cast<Golang::Func32*>(goCtx->buffer.GetData() + entry->functionOffset);

                auto& e      = goCtx->functions.emplace_back();
                e.func.entry = f32->entry;
                memcpy(
                      reinterpret_cast<char*>(&e.func.entry) + sizeof(e.func.entry),
                      reinterpret_cast<char*>(&f32->entry) + sizeof(f32->entry),
                      sizeof(Golang::Func32) - sizeof(Golang::Func32::entry));
                e.name = NameAt(funcnametabOffset + e.func.name);
                CHECK(e.name != nullptr, false, "");
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
                    e.name = NameAt(funcnametabOffset + e.func.name);
                }
                else
                {
                    const auto& ePrevious = goCtx->functions.at(goCtx->functions.size() - 2);
                    e.name                = NextName(ePrevious.name);
                }
                CHECK(e.name != nullptr, false, "");
            }
            break;
            case GoMagic::_12:
            {
                const uint64 entryOffset = functabOffset + static_cast<uint64>(entry - entries) * sizeof(Golang::FstEntry64);
                CHECK(entryOffset <= dataSize && dataSize - entryOffset >= sizeof(Golang::FstEntry64), false, "");
                CHECK(entry->functionOffset <= dataSize && dataSize - entry->functionOffset >= sizeof(Golang::Func64), false, "");
                auto& e = goCtx->functions.emplace_back(Function{ nullptr, {} });
                memcpy(&e.func, data + entry->functionOffset, sizeof(Golang::Func64));
                e.name = NameAt(funcnametabOffset + e.func.name);
                CHECK(e.name != nullptr, false, "");
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
        if (goCtx->functions.empty())
        {
            break;
        }
        // NextName validates that each name is NUL terminated inside the buffer (cutab is also inside the buffer)
        auto ptr = NextName(goCtx->functions.back().name);
        while (ptr != nullptr && *ptr != 0 && ptr < reinterpret_cast<char*>(goCtx->cutab)) // it is risky
        {
            auto& e = goCtx->functions.emplace_back(Function{ .name = nullptr, .func = {}, .fstEntry{ ._64 = nullptr } });
            e.name  = ptr;
            ptr     = NextName(e.name);
        }
    }
    case GoMagic::_12:
    default:
        break;
    }

    goCtx->processed = true;

    return true;
}

GoFunctionHeader* PcLnTab::GetHeader() const
{
    CHECK(context != nullptr, nullptr, "");
    const auto goContext = reinterpret_cast<PcLnTabContext*>(this->context);
    CHECK(goContext->processed, nullptr, "");
    return goContext->header;
}

uint64 PcLnTab::GetFilesCount() const
{
    CHECK(context != nullptr, 0, "");
    const auto goContext = reinterpret_cast<PcLnTabContext*>(this->context);
    CHECK(goContext->processed, 0, "");
    return goContext->files.size();
}

bool PcLnTab::GetFile(uint64 index, std::string_view& file) const
{
    CHECK(context != nullptr, false, "");
    const auto goContext = reinterpret_cast<PcLnTabContext*>(this->context);
    CHECK(goContext->processed, false, "");
    CHECK(index < goContext->files.size(), false, "");
    file = goContext->files.at(index);
    return true;
}

uint64 PcLnTab::GetFunctionsCount() const
{
    CHECK(context != nullptr, 0, "");
    const auto goContext = reinterpret_cast<PcLnTabContext*>(this->context);
    CHECK(goContext->processed, 0, "");
    return goContext->functions.size();
}

bool PcLnTab::GetFunction(uint64 index, Function& func) const
{
    CHECK(context != nullptr, false, "");
    const auto goContext = reinterpret_cast<PcLnTabContext*>(this->context);
    CHECK(goContext->processed, false, "");
    CHECK(index < goContext->functions.size(), false, "");
    func = goContext->functions.at(index);
    return true;
}

uint64 PcLnTab::GetEntriesCount() const
{
    CHECK(context != nullptr, 0, "");
    const auto goContext = reinterpret_cast<PcLnTabContext*>(this->context);
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

void PcLnTab::SetBuildId(std::string_view buildId)
{
    CHECKRET(context != nullptr, "");
    const auto goContext = reinterpret_cast<PcLnTabContext*>(this->context);
    goContext->buildId   = buildId;
}

const std::string& PcLnTab::GetBuildId() const
{
    static const std::string empty;
    CHECK(context != nullptr, empty, "");
    const auto goContext = reinterpret_cast<PcLnTabContext*>(this->context);
    CHECK(goContext->processed, empty, "");

    return goContext->buildId;
}

void PcLnTab::SetRuntimeBuildVersion(std::string_view runtimeBuildVersion)
{
    CHECKRET(context != nullptr, "");
    const auto goContext           = reinterpret_cast<PcLnTabContext*>(this->context);
    goContext->runtimeBuildVersion = runtimeBuildVersion;
}

const std::string& PcLnTab::GetRuntimeBuildVersion() const
{
    static const std::string empty;
    CHECK(context != nullptr, empty, "");
    const auto goContext = reinterpret_cast<PcLnTabContext*>(this->context);
    CHECK(goContext->processed, empty, "");

    return goContext->runtimeBuildVersion;
}

void PcLnTab::SetRuntimeBuildModInfo(std::string_view runtimeBuildModInfo)
{
    CHECKRET(context != nullptr, "");
    const auto goContext           = reinterpret_cast<PcLnTabContext*>(this->context);
    goContext->runtimeBuildModInfo = runtimeBuildModInfo;
}

const std::string& PcLnTab::GetRuntimeBuildModInfo() const
{
    static const std::string empty;
    CHECK(context != nullptr, empty, "");
    const auto goContext = reinterpret_cast<PcLnTabContext*>(this->context);
    CHECK(goContext->processed, empty, "");

    return goContext->runtimeBuildModInfo;
}
} // namespace GView::Golang
