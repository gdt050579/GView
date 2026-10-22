#include "pe.hpp"

#include <algorithm>
#include <set>
#include <tuple>
#include <unordered_map>
#include <unordered_set>

using namespace AppCUI;
using namespace AppCUI::Input;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView::Type;
using namespace GView;
using namespace GView::View;

constexpr auto OVERLAY_BOOKMARK_VALUE = 0;

GVIEW_PLUGIN_ENTRY_POINTS {
PLUGIN_EXPORT bool Validate(const AppCUI::Utils::BufferView& buf, const std::string_view& extension)
{
    auto dos = buf.GetObject<PE::ImageDOSHeader>();
    if (!dos)
        return false;
    if (dos->e_magic != PE::Constants::IMAGE_DOS_SIGNATURE)
        return false;
    auto nth32 = buf.GetObject<PE::ImageNTHeaders32>(dos->e_lfanew);
    if (!nth32)
        return false;
    return nth32->Signature == PE::Constants::IMAGE_NT_SIGNATURE;
}

PLUGIN_EXPORT TypeInterface* CreateInstance()
{
    return new PE::PEFile();
}

void CreateBufferView(Reference<GView::View::WindowInterface> win, Reference<PE::PEFile> pe)
{
    LocalString<128> tempStr;
    BufferViewer::Settings settings;

    settings.AddZone(0, sizeof(pe->dos), pe->peCols.colMZ, "DOS Header");
    settings.AddZone(pe->dos.e_lfanew, sizeof(pe->nth32), pe->peCols.colPE, "NT Header");
    if (pe->nrSections > 0)
        settings.AddZone(pe->sectStart, pe->nrSections * sizeof(PE::ImageSectionHeader), pe->peCols.colSectDef, "SectDef");

    if (pe->hasOverlay) {
        settings.AddBookmark(OVERLAY_BOOKMARK_VALUE, pe->computedSize);
    }

    // sections
    for (uint32 tr = 0; tr < pe->nrSections; tr++) {
        if ((pe->sect[tr].PointerToRawData != 0) && (pe->sect[tr].SizeOfRawData > 0)) {
            pe->CopySectionName(tr, tempStr);
            settings.AddZone(pe->sect[tr].PointerToRawData, pe->sect[tr].SizeOfRawData, pe->peCols.colSect, tempStr);
            if (tr < 9)
                settings.AddBookmark(tr + 1, pe->sect[tr].PointerToRawData);
        }
    }

    // directories
    auto* dr = pe->dirs;
    for (auto tr = 0; tr < 15; tr++, dr++) {
        if ((dr->VirtualAddress > 0) && (dr->Size > 0)) {
            if (tr == (uint8) PE::DirectoryType::Security) {
                settings.AddZone(dr->VirtualAddress, dr->Size, pe->peCols.colDir[tr], PE::PEFile::DirectoryIDToName(tr));
            } else {
                const auto FA = pe->RVAToFA(dr->VirtualAddress);
                if (FA != PE_INVALID_ADDRESS) {
                    settings.AddZone(FA, dr->Size, pe->peCols.colDir[tr], PE::PEFile::DirectoryIDToName(tr));
                }
            }
        }
    }

    // translation
    settings.SetOffsetTranslationList({ "RVA", "VA" }, pe.ToBase<GView::View::BufferViewer::OffsetTranslateInterface>());

    // set specific color for opcodes
    switch (static_cast<PE::MachineType>(pe->nth32.FileHeader.Machine)) {
    case PE::MachineType::I386:
    case PE::MachineType::IA64:
    case PE::MachineType::AMD64: {
        settings.SetPositionToColorCallback(pe.ToBase<GView::View::BufferViewer::PositionToColorInterface>());
    } break;
    };

    // set entry point
    const uint32 addressOfEntryPoint = pe->hdr64 ? pe->nth64.OptionalHeader.AddressOfEntryPoint : pe->nth32.OptionalHeader.AddressOfEntryPoint;
    settings.SetEntryPointOffset(pe->RVAToFA(addressOfEntryPoint));

    const uint32 pointerToSymbolTable = pe->hdr64 ? pe->nth64.FileHeader.PointerToSymbolTable : pe->nth32.FileHeader.PointerToSymbolTable;
    if (pointerToSymbolTable > 0) {
        const uint64 numberOfSymbols = (uint64) (pe->hdr64 ? pe->nth64.FileHeader.NumberOfSymbols : pe->nth32.FileHeader.NumberOfSymbols);
        settings.AddZone(pointerToSymbolTable, numberOfSymbols * PE::IMAGE_SIZEOF_SYMBOL, pe->peCols.colSectDef, "SymbolTable");

        const auto stringsTableOffset = pointerToSymbolTable + numberOfSymbols * PE::IMAGE_SIZEOF_SYMBOL;
        uint32 stringsTableSize       = 0;
        pe->obj->GetData().Copy(stringsTableOffset, stringsTableSize);

        settings.AddZone(stringsTableOffset, stringsTableSize, pe->peCols.colPE, "StringsTable");
    }

    switch (static_cast<PE::MachineType>(pe->nth32.FileHeader.Machine)) {
    case PE::MachineType::I386:
        settings.SetArchitecture(GView::Dissasembly::Architecture::x86);
        settings.SetDesign(GView::Dissasembly::Design::Intel);
        settings.SetEndianess(GView::Dissasembly::Endianess::Little);
        break;
    case PE::MachineType::IA64:
    case PE::MachineType::AMD64:
        settings.SetArchitecture(GView::Dissasembly::Architecture::x64);
        settings.SetDesign(GView::Dissasembly::Design::Intel);
        settings.SetEndianess(GView::Dissasembly::Endianess::Little);
        break;
    case PE::MachineType::ARM:
    case PE::MachineType::ARMNT:
        settings.SetArchitecture(GView::Dissasembly::Architecture::x86);
        settings.SetDesign(GView::Dissasembly::Design::ARM);
        settings.SetEndianess(GView::Dissasembly::Endianess::Little);
        break;
    case PE::MachineType::ARM64:
        settings.SetArchitecture(GView::Dissasembly::Architecture::x64);
        settings.SetDesign(GView::Dissasembly::Design::ARM);
        settings.SetEndianess(GView::Dissasembly::Endianess::Little);
    default:
        break;
    }

    pe->selectionZoneInterface = win->GetSelectionZoneInterfaceFromViewerCreation(settings);
}

// The known starts of functions: the deep scan of the disassembly labels them even when nothing calls them directly
extern "C++" { // the file is in the extern "C" block of the entry points: the helpers return C++ types
namespace
{
// the compressed integers of the FuncInfo of __CxxFrameHandler4: the low bits of the first byte give the length (0: 1 byte, 01: 2 bytes,
// 011: 3 bytes, 0111: 4 bytes, the value shifted by the length; 1111: the 4 bytes after it), the RVAs are 4 bytes
struct CompressedReader {
    GView::Utils::DataCache& data;
    uint64 offset;
    bool failed = false;

    uint8 Byte()
    {
        uint8 value = 0;
        if (failed) // an offset past a failed read is not followed
            return 0;
        failed |= !data.Copy<uint8>(offset, value);
        offset++;
        return value;
    }
    int32 Int()
    {
        int32 value = 0;
        if (failed)
            return 0;
        failed |= !data.Copy<int32>(offset, value);
        offset += 4;
        return value;
    }
    uint32 Unsigned()
    {
        uint8 first = 0;
        if (failed || !data.Copy<uint8>(offset, first)) {
            failed = true;
            return 0;
        }
        if ((first & 0xF) == 0xF) {
            offset++;
            return static_cast<uint32>(Int());
        }
        const uint32 length = (first & 1) == 0 ? 1 : (first & 3) == 1 ? 2 : (first & 7) == 3 ? 3 : 4;
        uint32 value        = 0;
        for (uint32 index = 0; index < length; index++)
            value |= static_cast<uint32>(Byte()) << (8 * index);
        return value >> length;
    }
};

// the name of a type of the RTTI (the TypeDescriptor of a catch): ".?AVbad_alloc@std@@" -> "std::bad_alloc", ".PEAVCItem@@" ->
// "CItem *"; the other forms (templates, the basic types) as they are
std::string DemangleCatchType(std::string_view name)
{
    std::string_view rest = name.starts_with('.') ? name.substr(1) : name;
    std::string suffix;
    if (rest.starts_with("PEA") || rest.starts_with("PEB")) {
        suffix = rest[2] == 'B' ? " const *" : " *";
        rest.remove_prefix(3);
    } else if (rest.starts_with('?'))
        rest.remove_prefix(1);
    if (!(rest.starts_with("AV") || rest.starts_with("AU")) || !rest.ends_with("@@"))
        return std::string(name);
    rest = rest.substr(2, rest.size() - 4);
    std::vector<std::string_view> parts;
    while (!rest.empty()) {
        const auto at = rest.find('@');
        parts.push_back(rest.substr(0, at));
        rest = at == std::string_view::npos ? std::string_view() : rest.substr(at + 1);
    }
    std::string result;
    for (auto part = parts.rbegin(); part != parts.rend(); ++part) {
        if (part->empty() || part->front() == '?')
            return std::string(name); // a template (?$vector@...), a nested anonymous name
        if (!result.empty())
            result += "::";
        result += *part;
    }
    return result + suffix;
}

// the type a catch takes (HandlerType: adjectives, the RVA of a TypeDescriptor whose name is after the vtable pointer and the spare)
std::string FormatCatchType(Reference<PE::PEFile> pe, GView::Utils::DataCache& data, uint32 adjectives, int32 typeDescriptor)
{
    constexpr uint32 HT_IS_CONST = 1, HT_IS_REFERENCE = 8, HT_IS_STD_DOT_DOT = 0x40;
    if (typeDescriptor == 0 || (adjectives & HT_IS_STD_DOT_DOT))
        return "...";
    const auto fa = pe->RVAToFA(static_cast<uint32>(typeDescriptor) + 16);
    if (fa == PE_INVALID_ADDRESS)
        return "?";
    std::string name;
    for (uint32 index = 0; index < 256; index++) {
        uint8 c = 0;
        if (!data.Copy<uint8>(fa + index, c) || c == 0)
            break;
        if (c < 0x20 || c > 0x7E)
            return "?";
        name += static_cast<char>(c);
    }
    std::string text = (adjectives & HT_IS_CONST) ? "const " : "";
    text += DemangleCatchType(name);
    if (adjectives & HT_IS_REFERENCE)
        text += " &";
    return text;
}

// the C++ exception data of an x64 function (the language specific data of __CxxFrameHandler3 / 4, or of the GS checks that call them:
// the RVA of a FuncInfo, `funcInfo`), [begin, end): RVAs. The funclets are the catch handlers and the unwind actions that are functions of
// .pdata (an unwind action can be another function: a thunk); the try ranges from the IP-to-state map. The data of another handler fails
// the checks: the magic of FuncInfo (FH3), the IP-to-state map inside the function with the states of the unwind map, the counts
bool ReadCppExceptionFunclets(
      Reference<PE::PEFile> pe,
      GView::Utils::DataCache& data,
      uint32 begin,
      uint32 end,
      uint32 funcInfo,
      const std::unordered_set<uint32>& functionStarts,
      std::vector<DissasmViewer::ExceptionFunclet>& funclets,
      std::vector<DissasmViewer::ExceptionObject>& objects)
{
    constexpr uint32 MAX_STATES = 0x4000, MAX_TRY_BLOCKS = 0x400, MAX_CATCHES = 64, MAX_IP_ENTRIES = 0x10000;
    const auto fa = pe->RVAToFA(funcInfo);
    if (funcInfo == 0 || fa == PE_INVALID_ADDRESS)
        return false;
    struct TryBlock {
        int32 low, high;
        std::vector<std::pair<int32, std::string>> catches; // the RVA of the funclet, the type
    };
    std::vector<TryBlock> tryBlocks;
    std::vector<int32> unwindFunclets;
    std::vector<std::tuple<int32, int32, bool>> unwindObjects; // FH4: the destructor (RVA), the object (from the establisher frame), a pointer
    std::vector<std::pair<uint32, int32>> ipStates; // the RVA from which a state holds
    int32 stateCount = 0;
    const auto rvaFa = [&pe](int32 rva) { return rva > 0 ? pe->RVAToFA(static_cast<uint32>(rva)) : PE_INVALID_ADDRESS; };
    // the item `index` of a table of `size` bytes items at an RVA
    const auto itemFa = [&rvaFa](int32 table, uint64 index, uint64 size) {
        const auto start = rvaFa(table);
        return start == PE_INVALID_ADDRESS ? PE_INVALID_ADDRESS : start + index * size;
    };

    uint32 magic = 0;
    if (!data.Copy<uint32>(fa, magic))
        return false;
    if ((magic & 0x1FFFFFFF) >= 0x19930520 && (magic & 0x1FFFFFFF) <= 0x19930522) {
        // __CxxFrameHandler3: FuncInfo { magic, maxState, dispUnwindMap, nTryBlocks, dispTryBlockMap, nIPMapEntries, dispIPToStateMap }
        struct FuncInfo3 {
            uint32 magic;
            int32 maxState, unwindMap;
            uint32 tryBlockCount;
            int32 tryBlockMap;
            uint32 ipCount;
            int32 ipMap;
        } info;
        if (!data.Copy<FuncInfo3>(fa, info) || info.maxState < 0 || static_cast<uint32>(info.maxState) > MAX_STATES || info.tryBlockCount > MAX_TRY_BLOCKS ||
            info.ipCount > MAX_IP_ENTRIES)
            return false;
        stateCount = info.maxState;
        for (int32 state = 0; state < info.maxState; state++) {
            int32 entry[2]; // toState, action
            if (!data.Copy(itemFa(info.unwindMap, state, 8), entry))
                return false;
            if (entry[1] != 0)
                unwindFunclets.push_back(entry[1]);
        }
        for (uint32 index = 0; index < info.ipCount; index++) {
            int32 entry[2]; // ip, state
            if (!data.Copy(itemFa(info.ipMap, index, 8), entry))
                return false;
            if (static_cast<uint32>(entry[0]) >= begin && static_cast<uint32>(entry[0]) < end) // the map has the IPs of the funclets too
                ipStates.emplace_back(static_cast<uint32>(entry[0]), entry[1]);
        }
        if (info.ipCount > 0 && ipStates.empty())
            return false; // the FuncInfo of another function (a catch funclet of ARM64 has the one of its function)
        for (uint32 index = 0; index < info.tryBlockCount; index++) {
            int32 entry[5]; // tryLow, tryHigh, catchHigh, nCatches, dispHandlerArray
            if (!data.Copy(itemFa(info.tryBlockMap, index, 20), entry) || entry[3] < 0 || static_cast<uint32>(entry[3]) > MAX_CATCHES)
                return false;
            TryBlock block{ entry[0], entry[1], {} };
            for (int32 handler = 0; handler < entry[3]; handler++) {
                int32 type[5]; // adjectives, dispType, dispCatchObj, dispOfHandler, dispFrame
                if (!data.Copy(itemFa(entry[4], handler, 20), type))
                    return false;
                block.catches.emplace_back(type[3], FormatCatchType(pe, data, static_cast<uint32>(type[0]), type[1]));
            }
            tryBlocks.push_back(std::move(block));
        }
    } else {
        // __CxxFrameHandler4: a header byte, then the maps (RVAs) and compressed integers
        CompressedReader reader{ data, fa };
        const uint8 header = reader.Byte();
        if (header & 0x80) // reserved
            return false;
        if (header & 4) // BBT flags
            reader.Unsigned();
        const int32 unwindMap   = (header & 8) ? reader.Int() : 0;
        const int32 tryBlockMap = (header & 16) ? reader.Int() : 0;
        int32 ipMap             = reader.Int();
        if (reader.failed)
            return false;
        if (header & 2) { // separated code: the IP-to-state map of each part, the one of this function
            CompressedReader parts{ data, rvaFa(ipMap) };
            const uint32 count = parts.Unsigned();
            ipMap              = 0;
            for (uint32 index = 0; index < count && index < 64 && !parts.failed; index++) {
                const int32 start = parts.Int(), map = parts.Int();
                if (static_cast<uint32>(start) == begin)
                    ipMap = map;
            }
            if (parts.failed)
                return false;
        }
        if (unwindMap != 0) {
            CompressedReader unwind{ data, rvaFa(unwindMap) };
            const uint32 count = unwind.Unsigned();
            if (count > MAX_STATES)
                return false;
            stateCount = static_cast<int32>(count);
            for (uint32 index = 0; index < count && !unwind.failed; index++) {
                const uint32 type = unwind.Unsigned() & 3; // the next offset (>> 2), the type: none, a destructor with an object, an RVA
                if (type == 1 || type == 2) {
                    const int32 destructor = unwind.Int();
                    const auto object      = static_cast<int32>(unwind.Unsigned());
                    unwindObjects.emplace_back(destructor, object, type == 2);
                } else if (type == 3)
                    unwindFunclets.push_back(unwind.Int());
            }
            if (unwind.failed)
                return false;
        }
        if (tryBlockMap != 0) {
            CompressedReader tries{ data, rvaFa(tryBlockMap) };
            const uint32 count = tries.Unsigned();
            if (count > MAX_TRY_BLOCKS)
                return false;
            for (uint32 index = 0; index < count && !tries.failed; index++) {
                TryBlock block{};
                block.low = static_cast<int32>(tries.Unsigned());
                block.high = static_cast<int32>(tries.Unsigned());
                tries.Unsigned(); // catchHigh
                CompressedReader handlers{ data, rvaFa(tries.Int()) };
                const uint32 handlerCount = handlers.Unsigned();
                if (handlerCount > MAX_CATCHES)
                    return false;
                for (uint32 handler = 0; handler < handlerCount && !handlers.failed; handler++) {
                    const uint8 flags        = handlers.Byte(); // adjectives, dispType, dispCatchObj, contIsRVA, the count of continuations
                    const uint32 adjectives  = (flags & 1) ? handlers.Unsigned() : 0;
                    const int32 type         = (flags & 2) ? handlers.Int() : 0;
                    if (flags & 4)
                        handlers.Unsigned();
                    const int32 funclet = handlers.Int();
                    for (uint32 continuation = 0; continuation < ((flags >> 4) & 3u); continuation++) { // RVAs or offsets in the function
                        if (flags & 8)
                            handlers.Int();
                        else
                            handlers.Unsigned();
                    }
                    block.catches.emplace_back(funclet, FormatCatchType(pe, data, adjectives, type));
                }
                if (handlers.failed)
                    return false;
                tryBlocks.push_back(std::move(block));
            }
            if (tries.failed)
                return false;
        }
        if (ipMap != 0) {
            CompressedReader states{ data, rvaFa(ipMap) };
            const uint32 count = states.Unsigned();
            if (count > MAX_IP_ENTRIES)
                return false;
            uint32 ip = begin;
            for (uint32 index = 0; index < count && !states.failed; index++) {
                ip += states.Unsigned();
                ipStates.emplace_back(ip, static_cast<int32>(states.Unsigned()) - 1);
            }
            if (states.failed)
                return false;
        }
    }

    // the checks: the IP-to-state map in the function, in order, with the states of the unwind map; the try blocks on these states
    for (size_t index = 0; index < ipStates.size(); index++)
        if (ipStates[index].first < begin || ipStates[index].first > end || ipStates[index].second < -1 || ipStates[index].second >= std::max(stateCount, 1) ||
            (index > 0 && ipStates[index].first < ipStates[index - 1].first))
            return false;
    for (const auto& block : tryBlocks)
        if (block.low < 0 || block.high < block.low || block.high >= stateCount)
            return false;

    // the funclets: the unwind actions and the catch handlers that are functions of .pdata (once each)
    std::unordered_set<int32> added;
    for (const int32 funclet : unwindFunclets) {
        const auto funcletFa = rvaFa(funclet);
        if (functionStarts.contains(static_cast<uint32>(funclet)) && funcletFa != PE_INVALID_ADDRESS && added.insert(funclet).second)
            funclets.push_back({ funcletFa, false, {}, {} });
    }
    for (const auto& block : tryBlocks) {
        // the code of the try: the runs of the IP-to-state map whose state is one of the try block
        std::vector<std::pair<uint64, uint64>> ranges;
        for (size_t index = 0; index < ipStates.size(); index++) {
            if (ipStates[index].second < block.low || ipStates[index].second > block.high)
                continue;
            const uint32 runEnd   = index + 1 < ipStates.size() ? ipStates[index + 1].first : end;
            const auto rangeBegin = pe->RVAToFA(ipStates[index].first);
            const auto rangeLast  = runEnd > ipStates[index].first ? pe->RVAToFA(runEnd - 1) : PE_INVALID_ADDRESS;
            if (rangeBegin == PE_INVALID_ADDRESS || rangeLast == PE_INVALID_ADDRESS)
                continue;
            if (!ranges.empty() && ranges.back().second == rangeBegin)
                ranges.back().second = rangeLast + 1;
            else
                ranges.emplace_back(rangeBegin, rangeLast + 1);
        }
        for (const auto& [funclet, type] : block.catches) {
            const auto funcletFa = rvaFa(funclet);
            if (functionStarts.contains(static_cast<uint32>(funclet)) && funcletFa != PE_INVALID_ADDRESS && added.insert(funclet).second)
                funclets.push_back({ funcletFa, true, type, ranges });
        }
    }
    // the objects the unwinding destroys (once each slot)
    std::unordered_set<int32> slots;
    for (const auto& [destructor, object, isPointer] : unwindObjects)
        if (slots.insert(object).second) {
            const auto destructorFa = rvaFa(destructor);
            objects.push_back({ object, destructorFa == PE_INVALID_ADDRESS ? 0 : destructorFa, isPointer });
        }
    return !funclets.empty() || !objects.empty();
}

// the language specific data of a function with an exception handler (x64 / ARM64) at `handlerData` (the file offset after the RVA of the
// handler), [begin, end): RVAs. The scope table of __C_specific_handler (a count, then the scopes { begin, end, handler, target }: every
// scope inside the function, its handler EXCEPTION_EXECUTE_HANDLER (1) or a function of .pdata, its target 0 (__finally) or in the
// function; `leafHandlers`: ARM64, a filter can be a leaf function without .pdata, a handler in the code), else the FuncInfo of the C++
// exception handling (the same word is its RVA). The data of another handler (the GS cookie) fails the checks
void AddFunctionExceptionData(
      DissasmViewer::Settings& settings,
      Reference<PE::PEFile> pe,
      GView::Utils::DataCache& data,
      uint32 begin,
      uint32 end,
      uint64 handlerData,
      const std::unordered_set<uint32>& functionStarts,
      uint8 prologSize,
      uint8 frameRegister,
      uint8 frameOffset,
      bool leafHandlers)
{
    struct ScopeRecord {
        uint32 BeginAddress;
        uint32 EndAddress;
        uint32 HandlerAddress;
        uint32 JumpTarget;
    };
    constexpr uint32 MAX_SCOPES = 64;
    const auto fa         = pe->RVAToFA(begin);
    uint32 scopeCount     = 0;
    if (fa == PE_INVALID_ADDRESS || !data.Copy<uint32>(handlerData, scopeCount))
        return;
    const auto isCode = [&pe](uint32 rva) {
        for (uint32 index = 0; index < pe->nrSections; index++) {
            const auto& section = pe->sect[index];
            if (rva >= section.VirtualAddress && rva - section.VirtualAddress < std::max(section.Misc.VirtualSize, section.SizeOfRawData))
                return (section.Characteristics & (__IMAGE_SCN_MEM_EXECUTE | __IMAGE_SCN_CNT_CODE)) != 0;
        }
        return false;
    };
    std::vector<DissasmViewer::ExceptionScope> scopes;
    bool valid = scopeCount > 0 && scopeCount <= MAX_SCOPES;
    for (uint32 index = 0; index < scopeCount && valid; index++) {
        ScopeRecord scope;
        if (!data.Copy<ScopeRecord>(handlerData + 4 + static_cast<uint64>(index) * sizeof(ScopeRecord), scope)) {
            valid = false;
            break;
        }
        valid = scope.BeginAddress >= begin && scope.BeginAddress < scope.EndAddress && scope.EndAddress <= end + 1 &&
                (scope.HandlerAddress == 1 || functionStarts.contains(scope.HandlerAddress) || (leafHandlers && isCode(scope.HandlerAddress))) &&
                (scope.JumpTarget == 0 ? scope.HandlerAddress != 1 : scope.JumpTarget >= begin && scope.JumpTarget < end);
        if (!valid)
            break;
        const auto scopeBegin = pe->RVAToFA(scope.BeginAddress);
        const auto scopeLast  = pe->RVAToFA(scope.EndAddress - 1);
        const auto handler    = scope.HandlerAddress == 1 ? 0 : pe->RVAToFA(scope.HandlerAddress);
        const auto target     = scope.JumpTarget == 0 ? 0 : pe->RVAToFA(scope.JumpTarget);
        valid = scopeBegin != PE_INVALID_ADDRESS && scopeLast != PE_INVALID_ADDRESS && handler != PE_INVALID_ADDRESS && target != PE_INVALID_ADDRESS;
        if (valid)
            scopes.push_back({ scopeBegin, scopeLast + 1, handler, target });
    }
    if (valid) {
        settings.AddExceptionScopes(fa, prologSize, frameRegister, frameOffset, scopes);
        return;
    }
    std::vector<DissasmViewer::ExceptionFunclet> funclets;
    std::vector<DissasmViewer::ExceptionObject> objects;
    if (!ReadCppExceptionFunclets(pe, data, begin, end, scopeCount, functionStarts, funclets, objects))
        return;
    if (!funclets.empty())
        settings.AddExceptionFunclets(fa, prologSize, frameRegister, frameOffset, funclets);
    if (!objects.empty())
        settings.AddExceptionObjects(fa, prologSize, frameRegister, frameOffset, objects);
}
} // namespace
} // extern "C++"

void AddDissasmFunctionEntries(DissasmViewer::Settings& settings, Reference<PE::PEFile> pe, GView::Utils::DataCache& data)
{
    if (pe->dirs == nullptr)
        return;

    // exports (a forwarded export points to a "dll.function" text inside the export directory, not to code)
    const auto& exportDir = pe->GetDirectory(PE::DirectoryType::Export);
    for (const auto& item : pe->exp) {
        if (item.RVA >= exportDir.VirtualAddress && item.RVA < static_cast<uint64>(exportDir.VirtualAddress) + exportDir.Size)
            continue;
        const auto fa = pe->RVAToFA(item.RVA);
        if (fa != PE_INVALID_ADDRESS)
            settings.AddFunctionEntry(fa, item.Name, DissasmViewer::FunctionEntryType::Export);
    }

    // ARM64 / ARM (Thumb-2) exception data (.pdata): 8 bytes entries, the start of a function and its unwind data: packed (the function
    // length in its bits 2..12) or the RVA of its .xdata record (the function length in the bits 0..17 of its first word); the length is in
    // 4 bytes units for ARM64, in 2 bytes units for ARM, whose function starts have the Thumb bit
    const auto machine = static_cast<PE::MachineType>(pe->nth32.FileHeader.Machine);
    if (machine == PE::MachineType::ARM64 || machine == PE::MachineType::ARMNT) {
        const uint64 lengthUnit = machine == PE::MachineType::ARM64 ? 4 : 2;
        struct Arm64RuntimeFunction {
            uint32 BeginAddress;
            uint32 UnwindData;
        };
        constexpr uint32 MAX_RUNTIME_FUNCTIONS = 0x100000;
        const auto& exceptionDir               = pe->GetDirectory(PE::DirectoryType::Exception);
        const auto start                       = exceptionDir.VirtualAddress != 0 ? pe->RVAToFA(exceptionDir.VirtualAddress) : PE_INVALID_ADDRESS;
        const uint32 count = start != PE_INVALID_ADDRESS ? std::min<uint32>(exceptionDir.Size / sizeof(Arm64RuntimeFunction), MAX_RUNTIME_FUNCTIONS) : 0;
        // ARM64: the functions with an exception handler (the X bit of their .xdata) and the file offset of its data (after the RVA of the
        // handler, past the epilog scopes and the unwind codes)
        struct HandledFunction {
            uint32 begin, end;
            uint64 handlerData;
        };
        std::vector<HandledFunction> handled;
        std::unordered_set<uint32> functionStarts;
        for (uint32 index = 0; index < count; index++) {
            Arm64RuntimeFunction function;
            if (!data.Copy<Arm64RuntimeFunction>(start + static_cast<uint64>(index) * sizeof(Arm64RuntimeFunction), function))
                break;
            if ((function.BeginAddress & ~1u) == 0)
                continue;
            uint64 length    = 0;
            const uint32 flag = function.UnwindData & 3;
            if (flag == 1 || flag == 2) // packed unwind data
                length = static_cast<uint64>((function.UnwindData >> 2) & 0x7FF) * lengthUnit;
            else if (flag == 0) {
                uint32 header       = 0;
                const auto xdataFa = pe->RVAToFA(function.UnwindData);
                if (xdataFa != PE_INVALID_ADDRESS && data.Copy<uint32>(xdataFa, header))
                    length = static_cast<uint64>(header & 0x3FFFF) * lengthUnit;
                // the header: the function length (18 bits), the version (2), X (a handler), E (one epilog in the header), the epilog
                // count (5), the code words (5); both 0: an extension word (the epilog count 16 bits, the code words 8)
                uint32 epilogs = (header >> 22) & 0x1F, codeWords = header >> 27, extension = 0;
                uint64 position = xdataFa + 4;
                if (epilogs == 0 && codeWords == 0 && data.Copy<uint32>(position, extension)) {
                    epilogs   = extension & 0xFFFF;
                    codeWords = (extension >> 16) & 0xFF;
                    position += 4;
                }
                if (machine == PE::MachineType::ARM64 && xdataFa != PE_INVALID_ADDRESS && ((header >> 20) & 1) && length > 0) {
                    const uint64 codes = position + (((header >> 21) & 1) ? 0 : 4ull * epilogs);
                    handled.push_back({ function.BeginAddress, function.BeginAddress + static_cast<uint32>(length), codes + 4ull * codeWords + 4 });
                }
            } else
                continue; // 3: a reserved form
            const auto fa = pe->RVAToFA(function.BeginAddress & ~1u);
            if (fa != PE_INVALID_ADDRESS)
                settings.AddFunctionEntry(fa, {}, DissasmViewer::FunctionEntryType::ExceptionData, length);
            functionStarts.insert(function.BeginAddress & ~1u);
        }
        // the scope tables of __C_specific_handler, the FuncInfo of the C++ exception handling (as x64; no frame register in the data)
        for (const auto& function : handled)
            AddFunctionExceptionData(settings, pe, data, function.begin, function.end, function.handlerData, functionStarts, 0, 0, 0, true);
    }
    // x64 exception data (.pdata): a RUNTIME_FUNCTION for nearly every function that is not a leaf, with its size
    else if (pe->hdr64) {
        struct RuntimeFunction {
            uint32 BeginAddress;
            uint32 EndAddress;
            uint32 UnwindInfoAddress;
        };
        constexpr uint32 MAX_RUNTIME_FUNCTIONS = 0x100000;
        constexpr uint8 UNW_FLAG_CHAININFO     = 0x4;
        constexpr uint8 UNW_FLAG_HANDLERS      = 0x3; // UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER: a language specific handler and its data
        std::vector<RuntimeFunction> handled;         // the functions with a handler (their scope tables are read after the loop)
        std::unordered_set<uint32> functionStarts;    // the funclets of the scopes are functions of .pdata
        std::vector<std::pair<RuntimeFunction, uint32>> chained; // a chained entry, the start of the entry it chains to
        struct PrimaryFunction {
            uint32 end;
            uint8 prologSize;
        };
        std::unordered_map<uint32, PrimaryFunction> primaries; // the function entries, by start
        const auto& exceptionDir               = pe->GetDirectory(PE::DirectoryType::Exception);
        const auto start                       = exceptionDir.VirtualAddress != 0 ? pe->RVAToFA(exceptionDir.VirtualAddress) : PE_INVALID_ADDRESS;
        const uint32 count = start != PE_INVALID_ADDRESS ? std::min<uint32>(exceptionDir.Size / sizeof(RuntimeFunction), MAX_RUNTIME_FUNCTIONS) : 0;
        for (uint32 index = 0; index < count; index++) {
            RuntimeFunction function;
            if (!data.Copy<RuntimeFunction>(start + static_cast<uint64>(index) * sizeof(RuntimeFunction), function))
                break;
            if (function.BeginAddress == 0 || function.EndAddress <= function.BeginAddress)
                continue;
            // a chained entry (or an indirect one, odd unwind address) is a part of the function of another entry, not a function start:
            // the entry of that function is the one after its unwind codes (indirect: at the unwind address)
            RuntimeFunction primary;
            if (function.UnwindInfoAddress & 1) {
                const auto at = pe->RVAToFA(function.UnwindInfoAddress & ~1u);
                if (at != PE_INVALID_ADDRESS && data.Copy<RuntimeFunction>(at, primary))
                    chained.emplace_back(function, primary.BeginAddress);
                continue;
            }
            uint8 versionAndFlags = 0, prologSize = 0, codeCount = 0;
            const auto unwindInfo = pe->RVAToFA(function.UnwindInfoAddress);
            if (unwindInfo != PE_INVALID_ADDRESS && data.Copy<uint8>(unwindInfo, versionAndFlags) && ((versionAndFlags >> 3) & UNW_FLAG_CHAININFO)) {
                if (data.Copy<uint8>(unwindInfo + 2, codeCount) && data.Copy<RuntimeFunction>(unwindInfo + 4 + 2ull * ((codeCount + 1u) & ~1u), primary))
                    chained.emplace_back(function, primary.BeginAddress);
                continue;
            }
            if (unwindInfo != PE_INVALID_ADDRESS)
                data.Copy<uint8>(unwindInfo + 1, prologSize);
            primaries[function.BeginAddress] = { function.EndAddress, prologSize };
            const auto fa = pe->RVAToFA(function.BeginAddress);
            if (fa != PE_INVALID_ADDRESS)
                settings.AddFunctionEntry(fa, {}, DissasmViewer::FunctionEntryType::ExceptionData, function.EndAddress - function.BeginAddress);
            functionStarts.insert(function.BeginAddress);
            if (unwindInfo != PE_INVALID_ADDRESS && ((versionAndFlags >> 3) & UNW_FLAG_HANDLERS))
                handled.push_back(function);
        }
        // the chained entries: a part of the function of their primary entry (followed through the chained ones). Right after it (the
        // padding between them) it is the rest of the function (its size), elsewhere a chunk of it (its cold code: AddFunctionChunk), the
        // parts that follow each other one chunk
        std::sort(chained.begin(), chained.end(), [](const auto& left, const auto& right) { return left.first.BeginAddress < right.first.BeginAddress; });
        std::unordered_map<uint32, uint32> chainedTo;
        for (const auto& [part, parent] : chained)
            chainedTo.emplace(part.BeginAddress, parent);
        std::unordered_map<uint32, uint32> functionEnds; // the extended ones
        struct Chunk {
            uint32 begin, end, function;
        };
        std::vector<Chunk> chunks;
        constexpr uint32 MAX_PADDING = 16;
        for (const auto& [part, parent] : chained) {
            uint32 root = parent;
            for (uint32 steps = 0; steps < 32 && !primaries.contains(root); steps++) {
                const auto next = chainedTo.find(root);
                if (next == chainedTo.end())
                    break;
                root = next->second;
            }
            const auto primary = primaries.find(root);
            if (primary == primaries.end() || root == part.BeginAddress)
                continue;
            auto& end = functionEnds.try_emplace(root, primary->second.end).first->second;
            if (part.BeginAddress >= end && part.BeginAddress - end < MAX_PADDING) {
                end = part.EndAddress;
                continue;
            }
            if (!chunks.empty() && chunks.back().function == root && part.BeginAddress >= chunks.back().end && part.BeginAddress - chunks.back().end < MAX_PADDING)
                chunks.back().end = part.EndAddress;
            else
                chunks.push_back({ part.BeginAddress, part.EndAddress, root });
        }
        for (const auto& [root, end] : functionEnds) {
            const auto fa = pe->RVAToFA(root);
            if (fa != PE_INVALID_ADDRESS && end > primaries[root].end)
                settings.AddFunctionEntry(fa, {}, DissasmViewer::FunctionEntryType::ExceptionData, end - root);
        }
        for (const auto& chunk : chunks) {
            const auto fa         = pe->RVAToFA(chunk.begin);
            const auto functionFa = pe->RVAToFA(chunk.function);
            if (fa != PE_INVALID_ADDRESS && functionFa != PE_INVALID_ADDRESS)
                settings.AddFunctionChunk(fa, chunk.end - chunk.begin, functionFa, primaries[chunk.function].prologSize);
        }

        // the language specific data of the functions with a handler: the scope tables of __C_specific_handler, the FuncInfo of C++
        for (const auto& function : handled) {
            const auto unwindInfo = pe->RVAToFA(function.UnwindInfoAddress);
            struct UnwindHeader {
                uint8 versionAndFlags, prologSize, codeCount, frame; // frame: the register (low 4 bits), its offset / 16 (high 4 bits)
            } header;
            if (!data.Copy<UnwindHeader>(unwindInfo, header))
                continue;
            const uint64 handlerData = unwindInfo + 4 + 2ull * ((header.codeCount + 1u) & ~1u) + 4; // the codes (an even count), the handler RVA
            AddFunctionExceptionData(
                  settings, pe, data, function.BeginAddress, function.EndAddress, handlerData, functionStarts, header.prologSize, header.frame & 0xF, header.frame >> 4, false);
        }
    }

    // TLS callbacks: run before the entry point (IDA names them TlsCallback_N); the directory fields are 64 bit for PE32+
    const auto& tlsDir = pe->GetDirectory(PE::DirectoryType::TLS);
    const auto tlsFa   = (tlsDir.VirtualAddress != 0 && tlsDir.Size != 0) ? pe->RVAToFA(tlsDir.VirtualAddress) : PE_INVALID_ADDRESS;
    if (tlsFa == PE_INVALID_ADDRESS)
        return;
    const uint32 pointerSize = pe->hdr64 ? 8 : 4;
    auto readPointer         = [&data, pointerSize](uint64 offset, uint64& value) {
        if (pointerSize == 8)
            return data.Copy<uint64>(offset, value);
        uint32 value32 = 0;
        const bool ok  = data.Copy<uint32>(offset, value32);
        value          = value32;
        return ok;
    };
    uint64 callbacksVA = 0;
    if (!readPointer(tlsFa + 3ull * pointerSize, callbacksVA) || callbacksVA == 0) // StartAddressOfRawData, EndAddressOfRawData, AddressOfIndex
        return;
    const auto callbacks = pe->VAtoFA(callbacksVA);
    if (callbacks == PE_INVALID_ADDRESS)
        return;
    constexpr uint32 MAX_TLS_CALLBACKS = 64;
    LocalString<32> name;
    for (uint32 index = 0; index < MAX_TLS_CALLBACKS; index++) {
        uint64 callbackVA = 0;
        if (!readPointer(callbacks + static_cast<uint64>(index) * pointerSize, callbackVA) || callbackVA == 0)
            break;
        const auto fa = pe->VAtoFA(callbackVA);
        if (fa != PE_INVALID_ADDRESS && name.SetFormat("TlsCallback_%u", index))
            settings.AddFunctionEntry(fa, name.ToStringView(), DissasmViewer::FunctionEntryType::TlsCallback);
    }
}

// a pointer of the image (4 or 8 bytes) at a file offset
static bool ReadImagePointer(GView::Utils::DataCache& data, uint64 offset, bool is64, uint64& value)
{
    if (is64)
        return data.Copy<uint64>(offset, value);
    uint32 value32 = 0;
    const bool ok  = data.Copy<uint32>(offset, value32);
    value          = value32;
    return ok;
}

// The delay loaded imports (IMAGE_DELAYLOAD_DESCRIPTOR): the code calls them through their own IAT (call [__imp_Name]), whose slots hold
// the address of a load thunk until the first call (__imp_load_Name: lea rax, [__imp_Name]; jmp __tailMerge_dll). The slots are named
// like the imports, the load thunks and the __tailMerge_ helpers of every DLL are functions (IDA names).
void AddDissasmDelayImports(DissasmViewer::Settings& settings, Reference<PE::PEFile> pe, GView::Utils::DataCache& data)
{
    struct DelayLoadDescriptor {
        uint32 Attributes; // bit 0: the fields are RVAs (VC 6 used VAs)
        uint32 DllNameRVA;
        uint32 ModuleHandleRVA;
        uint32 ImportAddressTableRVA;
        uint32 ImportNameTableRVA;
        uint32 BoundImportAddressTableRVA;
        uint32 UnloadInformationTableRVA;
        uint32 TimeDateStamp;
    };
    constexpr uint32 MAX_DELAY_DLLS      = 1024;
    constexpr uint32 MAX_DELAY_FUNCTIONS = 0x10000;
    constexpr uint32 MAX_NAME_SIZE       = 512;
    const auto& directory                = pe->GetDirectory(PE::DirectoryType::DelayImport);
    if (directory.VirtualAddress == 0 || directory.Size < sizeof(DelayLoadDescriptor))
        return;
    const auto start = pe->RVAToFA(directory.VirtualAddress);
    if (start == PE_INVALID_ADDRESS)
        return;
    const bool is64           = pe->hdr64;
    const uint32 pointerSize  = is64 ? 8 : 4;
    const uint64 ordinalFlag  = is64 ? 0x8000000000000000ull : 0x80000000ull;
    const auto machine        = static_cast<PE::MachineType>(pe->nth32.FileHeader.Machine);
    const bool isX86          = machine != PE::MachineType::ARM64 && machine != PE::MachineType::ARMNT;
    std::set<uint64> namedFunctions; // the file offsets of the thunks / helpers already named
    LocalString<128> text;

    for (uint32 dll = 0; dll < MAX_DELAY_DLLS; dll++) {
        DelayLoadDescriptor descriptor{};
        if (!data.Copy<DelayLoadDescriptor>(start + static_cast<uint64>(dll) * sizeof(DelayLoadDescriptor), descriptor) || descriptor.DllNameRVA == 0)
            break;
        // VC 6: the fields are VAs (32 bit images)
        const uint64 fieldBase = (descriptor.Attributes & 1) ? 0 : pe->imageBase;
        const auto toRVA       = [fieldBase](uint32 value) -> uint64 { return value >= fieldBase ? value - fieldBase : 0; };
        const uint64 iat       = toRVA(descriptor.ImportAddressTableRVA);
        const uint64 names     = toRVA(descriptor.ImportNameTableRVA);
        const auto namesFa     = names != 0 ? pe->RVAToFA(names) : PE_INVALID_ADDRESS;
        if (iat == 0 || namesFa == PE_INVALID_ADDRESS)
            continue;
        // __tailMerge_ + the name of the DLL ('.' and '-' become '_'): certenroll.dll -> __tailMerge_certenroll_dll
        const auto dllName        = pe->ReadString(static_cast<uint32>(toRVA(descriptor.DllNameRVA)), MAX_NAME_SIZE);
        std::string tailMergeName = "__tailMerge_";
        for (const char c : dllName)
            tailMergeName.push_back(c == '.' || c == '-' ? '_' : c);
        // the thunks of the imports by ordinal: __imp_load_certenroll_Ordinal_42 (the ordinals of two DLLs are not the same functions)
        std::string ordinalPrefix = "__imp_load_";
        for (const char c : dllName.substr(0, std::min(dllName.size(), dllName.rfind('.'))))
            ordinalPrefix.push_back(c == '-' ? '_' : c);
        ordinalPrefix += "_Ordinal_";

        for (uint32 index = 0; index < MAX_DELAY_FUNCTIONS; index++) {
            uint64 nameEntry = 0;
            if (!ReadImagePointer(data, namesFa + static_cast<uint64>(index) * pointerSize, is64, nameEntry) || nameEntry == 0)
                break;
            const uint64 slot = iat + static_cast<uint64>(index) * pointerSize;
            std::string rawName;
            if (nameEntry & ordinalFlag) {
                text.SetFormat("Ordinal:%u", static_cast<uint32>(nameEntry & 0xFFFF));
                rawName = text.GetText();
            } else
                rawName = std::string(pe->ReadString(static_cast<uint32>(toRVA(static_cast<uint32>(nameEntry)) + 2), MAX_NAME_SIZE)); // after the hint
            if (rawName.empty())
                continue;
            // the slot, named like a regular import (demangled C++ names); Demangle adds to its output: a new string for every name
            String demangled;
            if (GView::Utils::Demangle(rawName.c_str(), demangled))
                settings.AddMemoryMapping(slot, demangled.GetText(), DissasmViewer::MemoryMappingType::FunctionMapping);
            else
                settings.AddMemoryMapping(slot, rawName, DissasmViewer::MemoryMappingType::FunctionMapping);

            // the load thunk: the first value of the slot
            const auto slotFa = pe->RVAToFA(slot);
            uint64 thunkVA    = 0;
            if (slotFa == PE_INVALID_ADDRESS || !ReadImagePointer(data, slotFa, is64, thunkVA) || thunkVA < pe->imageBase)
                continue;
            const auto thunkFa = pe->RVAToFA(thunkVA - pe->imageBase);
            if (thunkFa == PE_INVALID_ADDRESS || !namedFunctions.insert(thunkFa).second)
                continue;
            const std::string thunkName = (nameEntry & ordinalFlag) ? ordinalPrefix + std::to_string(nameEntry & 0xFFFF) : "__imp_load_" + rawName;
            settings.AddFunctionEntry(thunkFa, thunkName, DissasmViewer::FunctionEntryType::Symbol);

            // the helper the thunk jumps to: x64 lea rax, [rip + slot]; jmp rel32 - x86 mov eax, slot; jmp rel32
            if (!isX86)
                continue;
            uint8 code[12]{};
            const uint32 codeSize = is64 ? 12 : 10;
            bool readCode         = true;
            for (uint32 byte = 0; byte < codeSize && readCode; byte++)
                readCode = data.Copy<uint8>(thunkFa + byte, code[byte]);
            if (!readCode)
                continue;
            const auto dword = [&code](uint32 at) {
                return static_cast<uint32>(code[at]) | (static_cast<uint32>(code[at + 1]) << 8) | (static_cast<uint32>(code[at + 2]) << 16) |
                       (static_cast<uint32>(code[at + 3]) << 24);
            };
            uint64 tailMergeVA = 0;
            if (is64 && code[0] == 0x48 && code[1] == 0x8D && code[2] == 0x05 && code[7] == 0xE9 &&
                thunkVA + 7 + static_cast<int64>(static_cast<int32>(dword(3))) == pe->imageBase + slot)
                tailMergeVA = thunkVA + 12 + static_cast<int64>(static_cast<int32>(dword(8)));
            else if (!is64 && code[0] == 0xB8 && code[5] == 0xE9 && dword(1) == pe->imageBase + slot)
                tailMergeVA = (thunkVA + 10 + static_cast<int64>(static_cast<int32>(dword(6)))) & 0xFFFFFFFFull;
            if (tailMergeVA < pe->imageBase)
                continue;
            const auto tailMergeFa = pe->RVAToFA(tailMergeVA - pe->imageBase);
            if (tailMergeFa != PE_INVALID_ADDRESS && namedFunctions.insert(tailMergeFa).second)
                settings.AddFunctionEntry(tailMergeFa, tailMergeName, DissasmViewer::FunctionEntryType::Symbol);
        }
    }
}

// The load config directory (_load_config_used), named like IDA:
// - the variables it points to: the security cookie of /GS (mov rax, cs:__security_cookie in every protected function), the pointers of
//   the Control Flow Guard that the indirect calls go through (call cs:__guard_dispatch_icall_fptr), the tables (__guard_fids_table, ...)
// - the functions: every valid target of an indirect call (the CFG function table: RVAs, with flag bytes after them), the exception
//   handlers of a 32 bit image (the SafeSEH table)
void AddDissasmLoadConfig(DissasmViewer::Settings& settings, Reference<PE::PEFile> pe, GView::Utils::DataCache& data)
{
    const auto& directory = pe->GetDirectory(PE::DirectoryType::Config);
    const auto start      = directory.VirtualAddress != 0 ? pe->RVAToFA(directory.VirtualAddress) : PE_INVALID_ADDRESS;
    uint32 size           = 0; // the first field: the size of the structure (it grows with the Windows versions)
    if (start == PE_INVALID_ADDRESS || !data.Copy<uint32>(start, size))
        return;
    const bool is64 = pe->hdr64;
    settings.AddMemoryMapping(directory.VirtualAddress, "_load_config_used", DissasmViewer::MemoryMappingType::TextMapping);
    struct ConfigField {
        uint32 offset32, offset64;
        std::string_view name;
    };
    // the pointers (to variables, to the function pointers of the guards, to tables)
    constexpr ConfigField fields[] = {
        { 32, 40, "__lock_prefix_table" },
        { 60, 88, "__security_cookie" },
        { 64, 96, "__safe_se_handler_table" },
        { 72, 112, "__guard_check_icall_fptr" },
        { 76, 120, "__guard_dispatch_icall_fptr" },
        { 80, 128, "__guard_fids_table" },
        { 104, 160, "__guard_iat_table" },
        { 112, 176, "__guard_longjmp_table" },
        { 120, 192, "__dynamic_value_reloc_table" },
        { 124, 200, "__chpe_metadata" },
        { 132, 216, "__guard_ss_verify_failure_fptr" },
        { 144, 232, "__guard_ss_verify_sp_default" },
        { 156, 248, "__enclave_config" },
        { 160, 256, "__volatile_metadata" },
        { 164, 264, "__guard_eh_cont_table" },
        { 172, 280, "__guard_xfg_check_icall_fptr" },
        { 176, 288, "__guard_xfg_dispatch_icall_fptr" },
        { 180, 296, "__guard_xfg_table_dispatch_icall_fptr" },
        { 184, 304, "__castguard_check_failure_os_handled_fptr" },
        { 188, 312, "__guard_memcpy_fptr" },
    };
    const uint32 pointerSize = is64 ? 8u : 4u;
    // the fields of the directory: a line each in the data zone, named (P: the size of a pointer)
    {
        using Type            = DissasmViewer::DataFieldType;
        constexpr uint8 P     = 0;
        struct Field {
            uint8 size;
            Type type;
            std::string_view name;
        };
        constexpr Field common[] = {
            { 4, Type::Value, "Size" },           { 4, Type::Value, "TimeDateStamp" },    { 2, Type::Value, "MajorVersion" },
            { 2, Type::Value, "MinorVersion" },   { 4, Type::Value, "GlobalFlagsClear" }, { 4, Type::Value, "GlobalFlagsSet" },
            { 4, Type::Value, "CriticalSectionDefaultTimeout" },                          { P, Type::Value, "DeCommitFreeBlockThreshold" },
            { P, Type::Value, "DeCommitTotalFreeThreshold" },                             { P, Type::Pointer, "LockPrefixTable" },
            { P, Type::Value, "MaximumAllocationSize" },                                  { P, Type::Value, "VirtualMemoryThreshold" },
        };
        // the order of these two differs between the layouts
        constexpr Field affinity64[] = { { 8, Type::Value, "ProcessAffinityMask" }, { 4, Type::Value, "ProcessHeapFlags" } };
        constexpr Field affinity32[] = { { 4, Type::Value, "ProcessHeapFlags" }, { 4, Type::Value, "ProcessAffinityMask" } };
        constexpr Field rest[] = {
            { 2, Type::Value, "CSDVersion" },
            { 2, Type::Value, "DependentLoadFlags" },
            { P, Type::Pointer, "EditList" },
            { P, Type::Pointer, "SecurityCookie" },
            { P, Type::Pointer, "SEHandlerTable" },
            { P, Type::Value, "SEHandlerCount" },
            { P, Type::Pointer, "GuardCFCheckFunctionPointer" },
            { P, Type::Pointer, "GuardCFDispatchFunctionPointer" },
            { P, Type::Pointer, "GuardCFFunctionTable" },
            { P, Type::Value, "GuardCFFunctionCount" },
            { 4, Type::Value, "GuardFlags" },
            { 12, Type::Value, "CodeIntegrity" },
            { P, Type::Pointer, "GuardAddressTakenIatEntryTable" },
            { P, Type::Value, "GuardAddressTakenIatEntryCount" },
            { P, Type::Pointer, "GuardLongJumpTargetTable" },
            { P, Type::Value, "GuardLongJumpTargetCount" },
            { P, Type::Pointer, "DynamicValueRelocTable" },
            { P, Type::Pointer, "CHPEMetadataPointer" },
            { P, Type::Pointer, "GuardRFFailureRoutine" },
            { P, Type::Pointer, "GuardRFFailureRoutineFunctionPointer" },
            { 4, Type::Value, "DynamicValueRelocTableOffset" },
            { 2, Type::Value, "DynamicValueRelocTableSection" },
            { 2, Type::Value, "Reserved2" },
            { P, Type::Pointer, "GuardRFVerifyStackPointerFunctionPointer" },
            { 4, Type::Value, "HotPatchTableOffset" },
            { 4, Type::Value, "Reserved3" },
            { P, Type::Pointer, "EnclaveConfigurationPointer" },
            { P, Type::Pointer, "VolatileMetadataPointer" },
            { P, Type::Pointer, "GuardEHContinuationTable" },
            { P, Type::Value, "GuardEHContinuationCount" },
            { P, Type::Pointer, "GuardXFGCheckFunctionPointer" },
            { P, Type::Pointer, "GuardXFGDispatchFunctionPointer" },
            { P, Type::Pointer, "GuardXFGTableDispatchFunctionPointer" },
            { P, Type::Pointer, "CastGuardOsDeterminedFailureMode" },
            { P, Type::Pointer, "GuardMemcpyFunctionPointer" },
        };
        const uint64 directoryVA = pe->imageBase + directory.VirtualAddress;
        uint32 offset            = 0;
        const auto addFields     = [&](const auto& fields) {
            for (const auto& field : fields) {
                const uint32 fieldSize = field.size == P ? pointerSize : field.size;
                if (offset + fieldSize > size)
                    return;
                settings.AddDataField(directoryVA + offset, fieldSize, field.type, field.name);
                offset += fieldSize;
            }
        };
        addFields(common);
        if (is64)
            addFields(affinity64);
        else
            addFields(affinity32);
        addFields(rest);
    }
    const auto readField     = [&](uint32 offset32, uint32 offset64) -> uint64 {
        const uint32 offset = is64 ? offset64 : offset32;
        uint64 value        = 0;
        return offset + pointerSize <= size && ReadImagePointer(data, start + offset, is64, value) ? value : 0;
    };
    for (const auto& field : fields) {
        const uint64 va = readField(field.offset32, field.offset64);
        if (va > pe->imageBase)
            settings.AddMemoryMapping(va - pe->imageBase, field.name, DissasmViewer::MemoryMappingType::TextMapping);
    }
    // the CFG function table: an RVA for every valid target of an indirect call, followed by the flag bytes of GuardFlags (bits 28..31)
    constexpr uint32 MAX_TABLE_ENTRIES = 0x100000;
    uint32 guardFlags                  = 0;
    const uint32 flagsOffset           = is64 ? 144 : 88;
    const uint64 functionTable         = readField(80, 128);
    const uint64 functionCount         = readField(84, 136);
    // the entries of the guard tables: an RVA (the function, the IAT slot, the target) and the flag bytes of GuardFlags
    if (flagsOffset + 4 <= size && data.Copy<uint32>(start + flagsOffset, guardFlags)) {
        const uint32 entrySize = 4 + ((guardFlags >> 28) & 0xF);
        struct GuardTable {
            uint32 table32, table64, count32, count64;
            std::string_view entry;
        };
        constexpr GuardTable tables[] = {
            { 80, 128, 84, 136, "function" },
            { 104, 160, 108, 168, "iat entry" },
            { 112, 176, 116, 184, "longjmp target" },
            { 164, 264, 168, 272, "eh continuation" },
        };
        for (const auto& table : tables) {
            const uint64 tableVA = readField(table.table32, table.table64);
            const uint64 count   = readField(table.count32, table.count64);
            if (tableVA <= pe->imageBase || count > MAX_TABLE_ENTRIES)
                continue;
            for (uint64 index = 0; index < count; index++) {
                settings.AddDataField(tableVA + index * entrySize, 4, DissasmViewer::DataFieldType::RVA, table.entry);
                if (entrySize > 4)
                    settings.AddDataField(tableVA + index * entrySize + 4, entrySize - 4, DissasmViewer::DataFieldType::Value, "flags");
            }
        }
    }
    if (flagsOffset + 4 <= size && data.Copy<uint32>(start + flagsOffset, guardFlags) && functionTable > pe->imageBase && functionCount <= MAX_TABLE_ENTRIES) {
        const uint32 entrySize = 4 + ((guardFlags >> 28) & 0xF);
        const auto tableFa     = pe->RVAToFA(functionTable - pe->imageBase);
        for (uint64 index = 0; tableFa != PE_INVALID_ADDRESS && index < functionCount; index++) {
            uint32 rva = 0;
            if (!data.Copy<uint32>(tableFa + index * entrySize, rva))
                break;
            if (const auto fa = pe->RVAToFA(rva); fa != PE_INVALID_ADDRESS)
                settings.AddFunctionEntry(fa, {}, DissasmViewer::FunctionEntryType::Symbol);
        }
    }
    // the SafeSEH handlers (32 bit): RVAs of functions
    const uint64 handlerTable = is64 ? 0 : readField(64, 96);
    const uint64 handlerCount = is64 ? 0 : readField(68, 104);
    if (handlerTable > pe->imageBase && handlerCount <= MAX_TABLE_ENTRIES) {
        const auto tableFa = pe->RVAToFA(handlerTable - pe->imageBase);
        for (uint64 index = 0; tableFa != PE_INVALID_ADDRESS && index < handlerCount; index++) {
            uint32 rva = 0;
            if (!data.Copy<uint32>(tableFa + index * 4, rva))
                break;
            if (const auto fa = pe->RVAToFA(rva); fa != PE_INVALID_ADDRESS)
                settings.AddFunctionEntry(fa, {}, DissasmViewer::FunctionEntryType::Symbol);
            settings.AddDataField(handlerTable + index * 4, 4, DissasmViewer::DataFieldType::RVA, "handler");
        }
    }
}

// The directories of the image as typed structures of the data zones (IDA): the import descriptors (__IMPORT_DESCRIPTOR_KERNEL32, their
// lookup tables and hint / name entries), the export directory and its tables, the TLS directory (_tls_used) and its callbacks, the debug
// directory and its CodeView record (the PDB)
void AddDissasmDirectoryFields(DissasmViewer::Settings& settings, Reference<PE::PEFile> pe, GView::Utils::DataCache& data)
{
    using Type                    = DissasmViewer::DataFieldType;
    const bool is64               = pe->hdr64;
    const uint32 pointerSize      = is64 ? 8u : 4u;
    const uint64 base             = pe->imageBase;
    constexpr uint32 MAX_ENTRIES  = 0x10000;
    const auto readString         = [&](uint64 rva) {
        std::string text;
        const auto fa = pe->RVAToFA(rva);
        for (uint32 index = 0; fa != PE_INVALID_ADDRESS && index < 512; index++) {
            uint8 c = 0;
            if (!data.Copy<uint8>(fa + index, c) || c == 0)
                break;
            text.push_back(static_cast<char>(c));
        }
        return text;
    };
    const auto addFields = [&](uint64 rva, std::initializer_list<std::tuple<uint32, Type, std::string_view>> fields) {
        uint64 offset = 0;
        for (const auto& [size, type, name] : fields) {
            settings.AddDataField(base + rva + offset, size, type, name);
            offset += size;
        }
    };

    // the imports: IMAGE_IMPORT_DESCRIPTOR {OriginalFirstThunk, TimeDateStamp, ForwarderChain, Name, FirstThunk} until an empty one
    if (const auto& directory = pe->GetDirectory(PE::DirectoryType::Import); directory.VirtualAddress != 0) {
        for (uint32 index = 0; index < 4096; index++) {
            const uint64 rva = directory.VirtualAddress + index * 20ull;
            const auto fa    = pe->RVAToFA(rva);
            uint32 fields[5] = {};
            if (fa == PE_INVALID_ADDRESS || !data.Copy<uint32>(fa, fields[0]) || !data.Copy<uint32>(fa + 4, fields[1]) || !data.Copy<uint32>(fa + 8, fields[2]) ||
                !data.Copy<uint32>(fa + 12, fields[3]) || !data.Copy<uint32>(fa + 16, fields[4]))
                break;
            if ((fields[0] | fields[3] | fields[4]) == 0)
                break;
            std::string dll = readString(fields[3]);
            if (const auto dot = dll.rfind('.'); dot != std::string::npos)
                dll = dll.substr(0, dot);
            std::string label = "__IMPORT_DESCRIPTOR_";
            for (const char c : dll)
                label.push_back(std::isalnum(static_cast<unsigned char>(c)) ? static_cast<char>(std::toupper(static_cast<unsigned char>(c))) : '_');
            settings.AddMemoryMapping(rva, label, DissasmViewer::MemoryMappingType::TextMapping);
            addFields(rva, { { 4, Type::RVA, "OriginalFirstThunk" }, { 4, Type::Value, "TimeDateStamp" }, { 4, Type::Value, "ForwarderChain" },
                             { 4, Type::RVA, "Name" }, { 4, Type::RVA, "FirstThunk" } });
            // the import lookup table: an RVA of a hint / name entry, or an ordinal (the high bit)
            for (uint32 entry = 0; fields[0] != 0 && entry < MAX_ENTRIES; entry++) {
                const uint64 slotRVA = fields[0] + static_cast<uint64>(entry) * pointerSize;
                const auto slotFa    = pe->RVAToFA(slotRVA);
                uint64 value         = 0;
                if (slotFa == PE_INVALID_ADDRESS || !ReadImagePointer(data, slotFa, is64, value) || value == 0)
                    break;
                const bool byOrdinal = (value >> (is64 ? 63 : 31)) != 0;
                if (byOrdinal) {
                    settings.AddDataField(base + slotRVA, pointerSize, Type::Value, "ordinal " + std::to_string(value & 0xFFFF));
                    continue;
                }
                const uint64 hintRVA   = value & 0x7FFFFFFF;
                const std::string name = readString(hintRVA + 2);
                settings.AddDataField(base + slotRVA, pointerSize, Type::RVA, name);
                settings.AddDataField(base + hintRVA, 2, Type::Value, "hint");
                if (!name.empty())
                    settings.AddDataField(base + hintRVA + 2, static_cast<uint32>(name.size() + 1), Type::String, "name");
            }
        }
    }

    // the exports: IMAGE_EXPORT_DIRECTORY, the addresses of the functions (by ordinal), the names and their ordinals
    if (const auto& directory = pe->GetDirectory(PE::DirectoryType::Export); directory.VirtualAddress != 0) {
        const auto fa       = pe->RVAToFA(directory.VirtualAddress);
        uint32 fields[10]   = {}; // from Name (offset 12)
        bool ok             = fa != PE_INVALID_ADDRESS;
        for (uint32 index = 0; ok && index < 7; index++)
            ok = data.Copy<uint32>(fa + 12 + index * 4ull, fields[index]);
        if (ok) {
            addFields(directory.VirtualAddress,
                      { { 4, Type::Value, "Characteristics" }, { 4, Type::Value, "TimeDateStamp" }, { 2, Type::Value, "MajorVersion" },
                        { 2, Type::Value, "MinorVersion" }, { 4, Type::RVA, "Name" }, { 4, Type::Value, "Base" }, { 4, Type::Value, "NumberOfFunctions" },
                        { 4, Type::Value, "NumberOfNames" }, { 4, Type::RVA, "AddressOfFunctions" }, { 4, Type::RVA, "AddressOfNames" },
                        { 4, Type::RVA, "AddressOfNameOrdinals" } });
            const uint32 ordinalBase = fields[1], functions = fields[2], names = fields[3];
            const uint32 functionsRVA = fields[4], namesRVA = fields[5], ordinalsRVA = fields[6];
            std::vector<std::string> functionNames(std::min(functions, MAX_ENTRIES));
            for (uint32 index = 0; index < names && index < MAX_ENTRIES; index++) {
                uint32 nameRVA = 0;
                uint16 ordinal = 0;
                const auto nameFa    = pe->RVAToFA(namesRVA + index * 4ull);
                const auto ordinalFa = pe->RVAToFA(ordinalsRVA + index * 2ull);
                if (nameFa == PE_INVALID_ADDRESS || ordinalFa == PE_INVALID_ADDRESS || !data.Copy<uint32>(nameFa, nameRVA) || !data.Copy<uint16>(ordinalFa, ordinal))
                    break;
                const std::string name = readString(nameRVA);
                if (ordinal < functionNames.size())
                    functionNames[ordinal] = name;
                settings.AddDataField(base + namesRVA + index * 4ull, 4, Type::RVA, "name");
                settings.AddDataField(base + ordinalsRVA + index * 2ull, 2, Type::Value, "ordinal");
                if (!name.empty())
                    settings.AddDataField(base + nameRVA, static_cast<uint32>(name.size() + 1), Type::String, "export name");
            }
            for (uint32 index = 0; index < functionNames.size(); index++)
                settings.AddDataField(base + functionsRVA + index * 4ull, 4, Type::RVA,
                                      functionNames[index].empty() ? "ordinal " + std::to_string(ordinalBase + index) : functionNames[index]);
        }
    }

    // TLS: IMAGE_TLS_DIRECTORY (_tls_used) and its callbacks (pointers until 0)
    if (const auto& directory = pe->GetDirectory(PE::DirectoryType::TLS); directory.VirtualAddress != 0) {
        settings.AddMemoryMapping(directory.VirtualAddress, "_tls_used", DissasmViewer::MemoryMappingType::TextMapping);
        addFields(directory.VirtualAddress,
                  { { pointerSize, Type::Pointer, "StartAddressOfRawData" }, { pointerSize, Type::Pointer, "EndAddressOfRawData" },
                    { pointerSize, Type::Pointer, "AddressOfIndex" }, { pointerSize, Type::Pointer, "AddressOfCallBacks" },
                    { 4, Type::Value, "SizeOfZeroFill" }, { 4, Type::Value, "Characteristics" } });
        uint64 callbacks  = 0;
        const auto tlsFa  = pe->RVAToFA(directory.VirtualAddress);
        if (tlsFa != PE_INVALID_ADDRESS && ReadImagePointer(data, tlsFa + 3ull * pointerSize, is64, callbacks) && callbacks > base) {
            for (uint32 index = 0; index < 256; index++) {
                uint64 callback  = 0;
                const auto entry = pe->RVAToFA(callbacks - base + index * static_cast<uint64>(pointerSize));
                if (entry == PE_INVALID_ADDRESS || !ReadImagePointer(data, entry, is64, callback) || callback == 0)
                    break;
                settings.AddDataField(callbacks + index * static_cast<uint64>(pointerSize), pointerSize, Type::Pointer, "callback");
            }
        }
    }

    // the debug directory: IMAGE_DEBUG_DIRECTORY entries; a CodeView record (RSDS): its GUID, age and the path of the PDB
    if (const auto& directory = pe->GetDirectory(PE::DirectoryType::Debug); directory.VirtualAddress != 0) {
        for (uint32 index = 0; index < directory.Size / 28 && index < 64; index++) {
            const uint64 rva = directory.VirtualAddress + index * 28ull;
            addFields(rva, { { 4, Type::Value, "Characteristics" }, { 4, Type::Value, "TimeDateStamp" }, { 2, Type::Value, "MajorVersion" },
                             { 2, Type::Value, "MinorVersion" }, { 4, Type::Value, "Type" }, { 4, Type::Value, "SizeOfData" },
                             { 4, Type::RVA, "AddressOfRawData" }, { 4, Type::Value, "PointerToRawData" } });
            const auto fa = pe->RVAToFA(rva);
            uint32 type = 0, dataSize = 0, dataRVA = 0, signature = 0;
            if (fa == PE_INVALID_ADDRESS || !data.Copy<uint32>(fa + 12, type) || !data.Copy<uint32>(fa + 16, dataSize) || !data.Copy<uint32>(fa + 20, dataRVA))
                continue;
            const auto recordFa = dataRVA != 0 ? pe->RVAToFA(dataRVA) : PE_INVALID_ADDRESS;
            if (type == 2 && dataSize >= 24 && recordFa != PE_INVALID_ADDRESS && data.Copy<uint32>(recordFa, signature) && signature == 0x53445352) { // RSDS
                const std::string pdb = readString(dataRVA + 24);
                addFields(dataRVA, { { 4, Type::Value, "Signature" }, { 16, Type::Value, "Guid" }, { 4, Type::Value, "Age" } });
                settings.AddDataField(base + dataRVA + 24, static_cast<uint32>(pdb.size() + 1), Type::String, "PdbFileName");
            }
        }
    }
}

// x86 MSVC merges .rdata into .text (/MERGE:.rdata=.text): the read-only data starts the section, its last group the debug data
// (.rdata$zzzdbg: the CodeView / POGO records the debug directory points to), then the code (after the zeros of its alignment); the delay
// import descriptors and the names they point to close the section. The RVAs where the code starts and where the read-only data at its
// end starts (0: none); codeStart 0 when the section is not one (its own .rdata section, no debug directory in it, the entry point
// before the code)
struct MergedReadOnlyData {
    uint32 codeStart = 0;
    uint32 tailStart = 0;
};
static MergedReadOnlyData FindMergedReadOnlyData(Reference<PE::PEFile> pe, GView::Utils::DataCache& data, uint32 sectionStart, uint32 sectionEnd, uint32 entryPoint)
{
    struct DebugDirectory {
        uint32 Characteristics, TimeDateStamp;
        uint16 MajorVersion, MinorVersion;
        uint32 Type, SizeOfData, AddressOfRawData, PointerToRawData;
    };
    constexpr uint32 MAX_DEBUG_ENTRIES = 32;
    constexpr uint32 MAX_ALIGNMENT     = 0x100;
    MergedReadOnlyData result;
    const auto& debug = pe->GetDirectory(PE::DirectoryType::Debug);
    if (debug.VirtualAddress < sectionStart || debug.VirtualAddress >= sectionEnd || debug.Size < sizeof(DebugDirectory))
        return result;
    const auto debugFa = pe->RVAToFA(debug.VirtualAddress);
    if (debugFa == PE_INVALID_ADDRESS)
        return result;
    uint32 dataEnd = debug.VirtualAddress + debug.Size;
    for (uint32 index = 0; index < std::min<uint32>(debug.Size / sizeof(DebugDirectory), MAX_DEBUG_ENTRIES); index++) {
        DebugDirectory entry;
        if (!data.Copy<DebugDirectory>(debugFa + static_cast<uint64>(index) * sizeof(DebugDirectory), entry))
            break;
        if (entry.AddressOfRawData >= sectionStart && entry.AddressOfRawData < sectionEnd && entry.SizeOfData < sectionEnd - entry.AddressOfRawData)
            dataEnd = std::max(dataEnd, entry.AddressOfRawData + entry.SizeOfData);
    }
    if (dataEnd >= sectionEnd)
        return result;
    // the zeros of the alignment of the first function
    uint32 codeStart = dataEnd;
    const auto codeFa = pe->RVAToFA(codeStart);
    for (uint8 value = 0; codeFa != PE_INVALID_ADDRESS && codeStart < sectionEnd && codeStart - dataEnd < MAX_ALIGNMENT; codeStart++)
        if (!data.Copy<uint8>(codeFa + (codeStart - dataEnd), value) || value != 0)
            break;
    const bool entryInSection = entryPoint >= sectionStart && entryPoint < sectionEnd;
    if (codeStart >= sectionEnd || (entryInSection && entryPoint < codeStart))
        return result;
    result.codeStart  = codeStart;
    const auto& delay = pe->GetDirectory(PE::DirectoryType::DelayImport);
    if (delay.VirtualAddress > codeStart && delay.VirtualAddress < sectionEnd && (!entryInSection || entryPoint < delay.VirtualAddress))
        result.tailStart = delay.VirtualAddress;
    return result;
}

void CreateDissasmView(Reference<GView::View::WindowInterface> win, Reference<PE::PEFile> pe)
{
    DissasmViewer::Settings settings;

    // one code zone for every executable section (and a data zone for every section of initialized data) (.text, PAGE / INIT of the drivers, CODE of Delphi, UPX1 of the packed files) and for the
    // section of the entry point: the sections are not contiguous in the file and in memory in the same way, a zone keeps the addresses of
    // one section. Only the zone of the entry point has an entry point.
    if (pe->HasPanel(PE::Panels::IDs::Sections)) {
        uint64 entryPoint = pe->hdr64 ? pe->nth64.OptionalHeader.AddressOfEntryPoint : pe->nth32.OptionalHeader.AddressOfEntryPoint;
        entryPoint        = pe->RVAToFA(entryPoint);
        DissasmViewer::DisassemblyLanguage language = pe->hdr64 ? DissasmViewer::DisassemblyLanguage::x64 : DissasmViewer::DisassemblyLanguage::x86;
        if (static_cast<PE::MachineType>(pe->nth32.FileHeader.Machine) == PE::MachineType::ARM64)
            language = DissasmViewer::DisassemblyLanguage::ARM64;
        else if (static_cast<PE::MachineType>(pe->nth32.FileHeader.Machine) == PE::MachineType::ARMNT) {
            language   = DissasmViewer::DisassemblyLanguage::Thumb; // Windows on ARM 32: Thumb-2 only
            entryPoint = pe->RVAToFA(pe->nth32.OptionalHeader.AddressOfEntryPoint & ~1u);
        }

        LocalString<128> sectionName;
        const uint64 fileSize = win->GetObject()->GetData().GetSize();
        std::vector<std::pair<uint64, uint64>> zones; // the raw data of the zones added: a malformed file can have sections that overlap
        for (auto tr = 0U; tr < pe->nrSections; tr++) {
            const auto& section = pe->sect[tr];
            const uint64 start  = section.PointerToRawData;
            const uint64 size   = section.SizeOfRawData;
            // the uninitialized data of a data section: the part past its raw data (VirtualSize > SizeOfRawData), a .bss without raw data
            const bool isExecutableSection = (section.Characteristics & (__IMAGE_SCN_MEM_EXECUTE | __IMAGE_SCN_CNT_CODE)) != 0;
            if (!isExecutableSection && section.Misc.VirtualSize > size) {
                pe->CopySectionName(tr, sectionName);
                auto uninitializedName = sectionName.ToStringView();
                uninitializedName      = uninitializedName.substr(0, uninitializedName.find('\0'));
                if (uninitializedName != ".rsrc" && uninitializedName != ".reloc" && uninitializedName != ".pdata")
                    settings.AddUninitializedDataZone(
                          pe->imageBase + section.VirtualAddress + size, section.Misc.VirtualSize - size, language, std::string(uninitializedName) + " (uninitialized)");
            }
            if (size == 0 || start >= fileSize) // UPX0: no bytes in the file
                continue;
            const bool hasEntryPoint = entryPoint != PE_INVALID_ADDRESS && entryPoint >= start && entryPoint - start < size;
            const bool isCode        = (section.Characteristics & (__IMAGE_SCN_MEM_EXECUTE | __IMAGE_SCN_CNT_CODE)) != 0;
            pe->CopySectionName(tr, sectionName);
            auto name = sectionName.ToStringView();
            name      = name.substr(0, name.find('\0')); // the 8 bytes of the name are padded with zeros
            // the initialized data (.rdata, .data, .idata, ...) is a data zone: the strings, the pointers and the labels the code refers to;
            // the resources, the relocations and the exception data are shown by their panels
            const bool isData = !isCode && !hasEntryPoint && (section.Characteristics & __IMAGE_SCN_CNT_INITIALIZED_DATA) != 0 && name != ".rsrc" &&
                                name != ".reloc" && name != ".pdata";
            if (!isCode && !hasEntryPoint && !isData)
                continue;
            const bool overlaps =
                  std::any_of(zones.begin(), zones.end(), [start, size](const auto& zone) { return start < zone.second && zone.first < start + size; });
            if (overlaps)
                continue;
            zones.emplace_back(start, start + size);
            const uint64 dataSize = section.Misc.VirtualSize != 0 ? std::min<uint64>(size, section.Misc.VirtualSize) : size;
            const auto merged     = isData ? MergedReadOnlyData{}
                                           : FindMergedReadOnlyData(
                                                   pe,
                                                   win->GetObject()->GetData(),
                                                   section.VirtualAddress,
                                                   section.VirtualAddress + static_cast<uint32>(dataSize),
                                                   pe->hdr64 ? pe->nth64.OptionalHeader.AddressOfEntryPoint : pe->nth32.OptionalHeader.AddressOfEntryPoint);
            if (isData) // the data, not the file alignment padding after it (VirtualSize < SizeOfRawData); its zeros are variables
                settings.AddDataZone(start, dataSize, language, name);
            else if (merged.codeStart != 0) {
                // .rdata merged into the code section: a data zone for it (its strings, pointers, the load config), a code zone for the code
                const uint64 codeOffset = start + (merged.codeStart - section.VirtualAddress);
                const uint64 tailOffset = merged.tailStart != 0 ? start + (merged.tailStart - section.VirtualAddress) : start + size;
                const std::string dataName = std::string(name) + " (.rdata)";
                settings.AddDataZone(start, codeOffset - start, language, dataName);
                settings.AddDisassemblyZone(codeOffset, tailOffset - codeOffset, hasEntryPoint ? entryPoint : DissasmViewer::NO_ENTRY_POINT, language, name);
                if (tailOffset < start + dataSize)
                    settings.AddDataZone(tailOffset, start + dataSize - tailOffset, language, dataName);
            } else
                settings.AddDisassemblyZone(start, size, hasEntryPoint ? entryPoint : DissasmViewer::NO_ENTRY_POINT, language, name);
        }
    }

    // translation
    settings.SetOffsetTranslationList({ "RVA", "VA" }, pe.ToBase<GView::View::BufferViewer::OffsetTranslateInterface>());

    uint32 typeImageDOSHeader = settings.AddType(
          "ImageDOSHeader",
          R"(UInt16 e_magic;
UInt16 e_cblp;
UInt16 e_cp;
UInt16 e_crlc;
UInt16 e_res[4];)");

    //                uint32 typeImageDOSHeader = settings.AddType(
    //              "ImageDOSHeader",
    //              R"(UInt16 e_magic;
    // UInt16 e_cblp;
    // UInt16 e_cp;
    // UInt16 e_crlc;
    // UInt16 e_cparhdr;
    // UInt16 e_minalloc;
    // UInt16 e_maxalloc;
    // UInt16 e_ss;
    // UInt16 e_sp;
    // UInt16 e_csum;
    // UInt16 e_ip;
    // UInt16 e_cs;
    // UInt16 e_lfarlc;
    // UInt16 e_ovno;
    // UInt16 e_res[4];
    // UInt16 e_oemid;
    // UInt16 e_oeminfo;
    // UInt16 e_res2[10];
    // UInt32 e_lfanew;)");

    settings.AddVariable(0, "ImageDOSHeader", typeImageDOSHeader);

    // LocalString<128> processedName;

    for (const auto& [RVA, dllIndex, Name] : pe->impFunc) {
        // processedName.SetFormat("%s:%s", pe->impDLL[dllIndex].Name.GetText(), Name.GetText());
        settings.AddMemoryMapping(RVA, Name, DissasmViewer::MemoryMappingType::FunctionMapping);
    }
    AddDissasmFunctionEntries(settings, pe, win->GetObject()->GetData());
    AddDissasmDelayImports(settings, pe, win->GetObject()->GetData());
    AddDissasmLoadConfig(settings, pe, win->GetObject()->GetData());
    AddDissasmDirectoryFields(settings, pe, win->GetObject()->GetData());

    win->CreateViewer(settings);
}

PLUGIN_EXPORT bool PopulateWindow(Reference<GView::View::WindowInterface> win)
{
    auto pe = win->GetObject()->GetContentType<PE::PEFile>();
    pe->Update();

#ifdef DISSASM_DEV
    CreateDissasmView(win, pe);
    CreateBufferView(win, pe);
#else
    CreateBufferView(win, pe);
    CreateDissasmView(win, pe);
#endif

    if (pe->HasPanel(PE::Panels::IDs::Information))
        win->AddPanel(Pointer<TabPage>(new PE::Panels::Information(win->GetObject(), pe)), true);
    if (pe->HasPanel(PE::Panels::IDs::Headers))
        win->AddPanel(Pointer<TabPage>(new PE::Panels::Headers(pe, win)), true);
    if (pe->HasPanel(PE::Panels::IDs::Sections))
        win->AddPanel(Pointer<TabPage>(new PE::Panels::Sections(pe, win)), false);
    if (pe->HasPanel(PE::Panels::IDs::Directories))
        win->AddPanel(Pointer<TabPage>(new PE::Panels::Directories(pe, win)), true);
    if (pe->HasPanel(PE::Panels::IDs::Imports))
        win->AddPanel(Pointer<TabPage>(new PE::Panels::Imports(pe, win)), true);
    if (pe->HasPanel(PE::Panels::IDs::Exports))
        win->AddPanel(Pointer<TabPage>(new PE::Panels::Exports(pe, win)), true);
    if (pe->HasPanel(PE::Panels::IDs::Resources))
        win->AddPanel(Pointer<TabPage>(new PE::Panels::Resources(pe, win)), false);
    if (pe->HasPanel(PE::Panels::IDs::Icons))
        win->AddPanel(Pointer<TabPage>(new PE::Panels::Icons(pe, win)), true);
    if (pe->HasPanel(PE::Panels::IDs::Symbols))
        win->AddPanel(Pointer<TabPage>(new PE::Panels::Symbols(pe, win)), false);
    if (pe->HasPanel(PE::Panels::IDs::GoInformation)) {
        win->AddPanel(Pointer<TabPage>(new PE::Panels::GoInformation(win->GetObject(), pe)), true);
        win->AddPanel(Pointer<TabPage>(new PE::Panels::GoFiles(win->GetObject(), pe)), true);
        win->AddPanel(Pointer<TabPage>(new PE::Panels::GoFunctions(pe, win)), false);
    }
    if (pe->HasPanel(PE::Panels::IDs::OpCodes)) {
        win->AddPanel(Pointer<TabPage>(new PE::Panels::OpCodes(win->GetObject(), pe)), true);
    }

    return true;
}

PLUGIN_EXPORT void UpdateSettings(IniSection sect)
{
    sect["Pattern"]                  = "magic:4D 5A";
    sect["Priority"]                 = 1;
    sect["Description"]              = "Portable executable format for Windows OS binaries";
    sect["OpCodes.Mask"]             = (uint32) GView::Dissasembly::Opcodes::All;

    LocalString<128> buffer;
    for (const auto& command : PE::PE_COMMANDS) {

        buffer.SetFormat("Command.%s", command.Caption);
        sect[buffer.GetText()] = command.DefaultKey;
    }
}
}
