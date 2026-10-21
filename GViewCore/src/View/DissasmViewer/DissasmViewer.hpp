#pragma once

#include "Internal.hpp"

#include <unordered_map>
#include <utility>
#include <deque>
#include <optional>
#include <chrono>
#include <list>
#include <cassert>
#include <capstone/capstone.h>

#include "AdvancedSelection.hpp"
#include "DissasmAssistantRequest.hpp"
#include "DissasmDataTypes.hpp"
#include "Config.hpp"
#include "DissasmCache.hpp"

class DissasmTestInstance;

namespace GView
{
namespace View
{
    namespace DissasmViewer
    {
        using namespace AppCUI;

        inline char* portable_strdup(const char* s)
        {
#if defined(_WIN32)
            return _strdup(s);
#else
            return strdup(s);
#endif
        }

        static constexpr size_t CACHE_OFFSETS_DIFFERENCE      = 500;
        static constexpr size_t DISSASM_MAX_CACHED_LINES      = 50;
        static constexpr size_t DISSASM_INITIAL_EXTENDED_SIZE = 1;
        static constexpr size_t DISSAM_MINIMUM_COMMENTS_X     = 50;
        static constexpr size_t DISSAM_MAXIMUM_STRING_PREVIEW = 180;
        static constexpr size_t DISSASM_MINIMUM_STRING_PREVIEW = 3; // shorter texts are rarely strings (random bytes, small numbers)

        // x86/x64: a cached offset (zone line <-> file offset) is kept every DISSASM_INSTRUCTION_OFFSET_MARGIN bytes of code, so decoding
        // any line never needs more than the bytes between two cached offsets
        static constexpr uint64 DISSASM_INSTRUCTION_OFFSET_MARGIN = 500;
        static constexpr uint64 DISSASM_MAX_INSTRUCTION_SIZE      = 15;
        // a line: an instruction, or the padding up to the next 16 bytes aligned address (align 0x10, DecodeX86Line)
        static constexpr uint64 DISSASM_MAX_LINE_SIZE             = 16;
        static constexpr uint64 DISSASM_NO_PADDING_ALIGNMENT      = UINT64_MAX; // DecodeX86Line: every padding instruction is a line
        // the zones of the uninitialized data (AddUninitializedDataZone) have no bytes in the file: they get file offsets from here on (after
        // the end of any file, one space of DISSASM_UNINITIALIZED_ZONE_SPACE each, in their order), their bytes read as zeros (GetZoneBytes)
        static constexpr uint64 DISSASM_UNINITIALIZED_ZONES_BASE = 1ull << 62;
        static constexpr uint64 DISSASM_UNINITIALIZED_ZONE_SPACE = 1ull << 40;
        static constexpr uint64 DISSASM_MAX_UNINITIALIZED_ZONE   = 64ull * 1024 * 1024;

        // DecodeX86Line: the instruction set of a zone; 32 bit ARM: the mode at every address (ARM, Thumb, data), from its changes
        struct DissasmInstructionSet {
            enum class Kind : uint8 { X86, Arm64, Arm32 };
            Kind kind               = Kind::X86;
            bool uninitialized      = false; // the data lines of an uninitialized zone have no values: dd ? / db 0x10 dup(?)
            ArmCodeMode defaultMode = ArmCodeMode::Arm;
            std::vector<std::pair<uint64, ArmCodeMode>> modeChanges; // relative address -> the mode from there on, sorted
            ArmCodeMode ModeAt(uint64 address) const
            {
                const auto next = std::upper_bound(
                      modeChanges.begin(), modeChanges.end(), address, [](uint64 value, const std::pair<uint64, ArmCodeMode>& change) { return value < change.first; });
                return next == modeChanges.begin() ? defaultMode : (next - 1)->second;
            }
            // the data inside the code found by the analysis (the jump tables of the switches) or defined by the user (IDA D / A): data lines
            // of `unit` bytes (1, 2, 4, 8), or a string (ASCII_STRING, UTF16_STRING)
            static constexpr uint8 ASCII_STRING = 0;
            static constexpr uint8 UTF16_STRING = 0x10;
            static constexpr uint8 BYTES_ROW    = 0x20; // the bytes of a data zone that are not a string / a pointer: rows of up to 16 bytes
            // the address of a reference: the value (a VA), the image base plus the value (an RVA), the address of the value plus the value (a
            // signed offset from the field)
            static constexpr uint8 REFERENCE_VA       = 0;
            static constexpr uint8 REFERENCE_RVA      = 1;
            static constexpr uint8 REFERENCE_RELATIVE = 2;
            static bool IsValidDataUnit(uint64 unit)
            {
                return unit == ASCII_STRING || unit == UTF16_STRING || unit == 1 || unit == 2 || unit == 4 || unit == 8;
            }
            struct DataRange {
                uint64 start; // relative addresses [start, end)
                uint64 end;
                uint8 unit;
                bool isOffset = false; // the values (4 / 8 bytes) are addresses: shown with the name of what they point to
                uint8 reference = REFERENCE_VA; // isOffset: how a value gives its address
                bool operator==(const DataRange&) const = default;
            };
            std::vector<DataRange> dataRanges; // sorted, not overlapping
            // the padding instructions (nop / int3) that the code reaches (a fall through, a branch target): instructions, never an align
            // line (IDA: align only for the bytes no code reaches). Relative addresses, sorted
            std::vector<uint64> reachablePadding;
            const DataRange* DataRangeAt(uint64 address) const
            {
                const auto next = std::upper_bound(
                      dataRanges.begin(), dataRanges.end(), address, [](uint64 value, const DataRange& range) { return value < range.start; });
                return next != dataRanges.begin() && address < (next - 1)->end ? &*(next - 1) : nullptr;
            }
            // the start of the first range after `address` (an instruction never runs into it)
            std::optional<uint64> NextDataRangeStart(uint64 address) const
            {
                const auto next = std::upper_bound(
                      dataRanges.begin(), dataRanges.end(), address, [](uint64 value, const DataRange& range) { return value < range.start; });
                return next != dataRanges.end() ? std::optional<uint64>(next->start) : std::nullopt;
            }
            // adds the range (inside [0, codeSize)) when it overlaps no other one; false when it was not added
            bool AddDataRange(const DataRange& range)
            {
                if (range.end <= range.start)
                    return false;
                const auto next = std::upper_bound(
                      dataRanges.begin(), dataRanges.end(), range.start, [](uint64 value, const DataRange& item) { return value < item.start; });
                if ((next != dataRanges.end() && next->start < range.end) || (next != dataRanges.begin() && (next - 1)->end > range.start))
                    return false;
                dataRanges.insert(next, range);
                return true;
            }
        };
        static constexpr uint64 DISSASM_MAX_CODE_WINDOW_SIZE      = 4096;

        static constexpr uint32 DISSASM_ASSISTANT_FUNCTION_NAMES_TO_REQUEST = 5;

        enum class QueryTypeSmartAssistant : uint8 { FunctionName, ExplainCode, ConvertToHighLevel, FunctionNameAndExplanation, MitreTechiques };

        struct QuerySmartAssistantParams {
            bool stopAtTheEndOfTheFunction;
            bool displayPromptUsesMnemonicParam;
            bool includeComments;
            std::string_view mnemonicStarsWith, mnemonicStartsWithError;
            std::string_view displayPrompt;
            std::string_view prompt;
            // selection based queries: the code starts at the selected line (not below a function label) and at most `maxLines`
            // zone lines are analysed (0 = the default limit)
            bool startsAtSelectedLine;
            uint32 maxLines;
        };

        struct DisassemblyZone {
            uint64 startingZonePoint;
            uint64 size;
            uint64 entryPoint; // NO_ENTRY_POINT: the zone has none
            DisassemblyLanguage language;
            std::string name; // shown in the title of the zone (a section name), not saved in the cache
            bool isData = false; // a data zone (AddDataZone): no instructions, its bytes are data lines
            // an uninitialized data zone (AddUninitializedDataZone): its VA, its file offset is from DISSASM_UNINITIALIZED_ZONES_BASE
            bool isUninitialized  = false;
            uint64 virtualAddress = 0;

            bool HasEntryPoint() const
            {
                return entryPoint >= startingZonePoint && entryPoint - startingZonePoint < size;
            }

            // the validation record of the zone: the hash of its bytes (`hashWholeZone` false: only the first data cache window, as the
            // caches saved before did) and its fields
            bool ToBuffer(std::vector<std::byte>& buffer, Reference<GView::Object> obj, bool hashWholeZone = true) const;
        };

        enum class InternalDissasmType : uint8 {
            UInt8,
            UInt16,
            UInt32,
            UInt64,
            Int8,
            Int16,
            Int32,
            Int64,
            AsciiZ,
            Utf16Z,
            Utf32Z,
            UnidimnsionalArray,
            BidimensionalArray,
            UserDefined,
            CustomTypesStartingId
        };

        struct DissasmStructureType {
            InternalDissasmType primaryType{ InternalDissasmType::CustomTypesStartingId };
            std::string_view name{};

            uint32 secondaryType{ 0 };
            uint32 width{ 0 };
            uint32 height{ 0 };

            std::vector<DissasmStructureType> internalTypes{};
            uint32 GetExpandedSize() const;
            // bytes of the file covered by the type, the fields one after another as they are drawn (no padding); 0 for the types whose
            // size depends on the data (strings)
            uint64 GetByteSize() const;

            DissasmStructureType() = default;
            DissasmStructureType(InternalDissasmType primary, std::string_view name, uint32 secondary = 0, uint32 width = 0, uint32 height = 0)
                : primaryType(primary), name(name), secondaryType(secondary), width(width), height(height)
            {
            }
        };

        enum class DissasmParseZoneType : uint8 { StructureParseZone, DissasmCodeParseZone, CollapsibleAndTextZone };

        struct ParseZone {
            // zones are owned through std::unique_ptr<ParseZone>, the derived members must be destroyed as well
            virtual ~ParseZone() = default;

            uint32 startLineIndex;
            uint32 endingLineIndex;
            uint32 extendedSize;
            // uint32 textLinesOffset;
            uint16 zoneID; // TODO: maybe can be replaced by the index in an array
            bool isCollapsed;

            DissasmParseZoneType zoneType;
        };

        struct DissasmParseStructureZone : public ParseZone {
            int16 structureIndex;
            DissasmStructureType dissasmType;
            std::list<std::reference_wrapper<const DissasmStructureType>> types;
            std::list<int32> levels;
            uint64 textFileOffset;
            uint64 initialTextFileOffset;
        };

        struct CollapsibleAndTextData {
            uint64 startingOffset;
            uint64 size;

            bool canBeCollapsed;
        };

        struct CollapsibleAndTextZone : public ParseZone {
            CollapsibleAndTextData data;
        };

        struct AsmOffsetLine {
            uint64 offset;
            uint32 line;
        };

        struct DissasmCodeZone;
        struct X86OperandsInfo;
        struct MemoryMappingEntry;
        struct DissasmDataField;
        struct DissasmInsnExtractLineParams {
            Reference<GView::Object> obj;
            uint32 asmLine;
            uint32 actualLine;
            struct DissasmCodeZone* zone;
            struct DrawLineInfo* dli;
            struct SettingsData* settings;
            struct AsmData* asmData;
        };

        struct DissasmAsmPreCacheLine {
            enum InstructionFlag : uint8 { NoneFlag = 0x00, CallFlag = 0x1, PushFlag = 0x2, JmpFlag = 0x4 };

            enum class LocalVariableKind : uint8 { None, Definition, Reference };

            // the jump arrows are drawn left of the instructions: ARROW_LANES vertical lanes followed by a column for the arrow heads
            static constexpr uint32 ARROW_LANES   = 3;
            static constexpr uint32 ARROW_COLUMNS = ARROW_LANES + 1;
            // the sides of an arrow cell that are connected to its neighbours
            enum ArrowCellFlag : uint8 {
                ArrowNone  = 0x00,
                ArrowUp    = 0x01,
                ArrowDown  = 0x02,
                ArrowLeft  = 0x04,
                ArrowRight = 0x08,
                ArrowHead  = 0x10, // the arrow reaches its target on this line
            };

            uint64 address     = 0;
            uint8 bytes[24]    = {};
            uint16 size        = 0;
            uint32 currentLine = 0;
            char mnemonic[CS_MNEMONIC_SIZE] = {};
            char* op_str       = nullptr;
            uint32 op_str_size = 0;
            std::optional<uint64> branchTarget; // target of a direct jump / call, same base as `address`
            uint8 flags                           = 0;
            uint8 instructionKind                 = 0; // X86InstructionKind (x86_x64/X86InstructionInfo.hpp): the color of the mnemonic
            uint8 arrowCells[ARROW_COLUMNS]       = {}; // ArrowCellFlag for every arrow column
            const void* mapping                   = nullptr;
            bool isCollapsedLine                  = false; // the line of a collapsed zone (it hides the other lines of the zone)
            bool hasNoBytes                       = false; // a line of an uninitialized zone: no op codes, no text

            // the argument of the x64 calling convention written by the instruction (GetX64ArgumentSlot)
            static constexpr uint8 NO_ARGUMENT = 0xFF;
            uint8 argumentSlot                 = NO_ARGUMENT;
            // 32 bit: a call to a function of the zone that pops its arguments (ret 8): the pushes it takes (DissasmCodeZone::calleeStackPurges)
            static constexpr uint8 NO_PUSHES = 0xFF;
            uint8 calleePushes               = NO_PUSHES;

            // the comment is the name of a status / HRESULT of the operand (FormatDistinctiveConstant): an argument takes it as its value
            bool constantComment = false;

            bool shouldAddButton = false;
            bool isZoneCollapsed = false;

            // local variable defined by this line (variable line) or used by the operands of this instruction
            LocalVariableKind localVariableKind = LocalVariableKind::None;
            int32 localVariableOffset           = 0;
            uint64 localVariableFunction        = 0;
            uint32 localVariableNameStart       = 0; // position of the variable name inside op_str
            uint32 localVariableNameSize        = 0;

            // generated text shown after the user comment (referenced string, import, API argument name): recomputed every time the line
            // is built, never saved and never mixed with the comments of the user
            std::string autoComment;
            // a label line: its name (the mnemonic keeps only its first CS_MNEMONIC_SIZE - 1 characters)
            std::string label;

            // the text of the mnemonic column: the whole name of a label
            std::string_view GetMnemonicText() const
            {
                return label.empty() ? std::string_view(mnemonic) : std::string_view(label);
            }

            uint32 GetLineSize() const
            {
                return size * 2 + op_str_size;
            }

            DissasmAsmPreCacheLine() = default;

            DissasmAsmPreCacheLine(DissasmAsmPreCacheLine&& other) noexcept(true)
            {
                CopyFieldsFrom(other);
                op_str       = other.op_str;
                other.op_str = nullptr;
            }
            DissasmAsmPreCacheLine(const DissasmAsmPreCacheLine& other)
            {
                CopyFieldsFrom(other);
                op_str = other.op_str ? portable_strdup(other.op_str) : nullptr;
            }
            // op_str is an owned raw buffer: assigning would either leak or double free it
            DissasmAsmPreCacheLine& operator=(const DissasmAsmPreCacheLine&) = delete;
            DissasmAsmPreCacheLine& operator=(DissasmAsmPreCacheLine&&)      = delete;
            bool TryGetDataFromInsn(DissasmInsnExtractLineParams& params);
            void SetMnemonic(std::string_view text); // always NUL terminated, truncated to CS_MNEMONIC_SIZE - 1
            void SetOperands(const char* operands, const struct DissasmCodeZone* zone);
            // x86 / x64: the operands with the names of the places at their fixed addresses (cs:dword_14000C0D0, lea rcx, aText, push offset
            // aText), else as they are
            void SetSymbolicOperands(const cs_insn& insn, const struct X86OperandsInfo& operands, DissasmInsnExtractLineParams& params);
            void DropCommentShownInOperands(); // the automatic comment is in the operands already (an import, a label)

            ~DissasmAsmPreCacheLine()
            {
                if (op_str)
                    free(op_str);
            }

          private:
            void CopyFieldsFrom(const DissasmAsmPreCacheLine& other)
            {
                address     = other.address;
                size        = other.size;
                currentLine = other.currentLine;
                op_str_size = other.op_str_size;
                memcpy(bytes, other.bytes, sizeof(bytes));
                memcpy(mnemonic, other.mnemonic, CS_MNEMONIC_SIZE);
                branchTarget           = other.branchTarget;
                flags                  = other.flags;
                instructionKind        = other.instructionKind;
                memcpy(arrowCells, other.arrowCells, sizeof(arrowCells));
                mapping                = other.mapping;
                isCollapsedLine        = other.isCollapsedLine;
                hasNoBytes             = other.hasNoBytes;
                shouldAddButton        = other.shouldAddButton;
                isZoneCollapsed        = other.isZoneCollapsed;
                argumentSlot           = other.argumentSlot;
                calleePushes           = other.calleePushes;
                constantComment        = other.constantComment;
                localVariableKind      = other.localVariableKind;
                localVariableOffset    = other.localVariableOffset;
                localVariableFunction  = other.localVariableFunction;
                localVariableNameStart = other.localVariableNameStart;
                localVariableNameSize  = other.localVariableNameSize;
                autoComment            = other.autoComment;
                label                  = other.label;
            }
        };

        struct AsmFunctionDetails {
            struct NameType {
                const char* name;
                const char* type;
            };

            std::string_view functionName;
            std::vector<NameType> params;
            std::string_view prototype;  // "HANDLE CreateFileW(LPCWSTR lpFileName, ...)"
            std::string_view returnType; // "HANDLE"; empty for void
            std::string_view returnName; // the name of a variable that holds its return value when not the one of its name (GetReturnValueName):
                                         // an inferred wrapper, the one of the API it returns (File for the wrapper of CreateFileW)
        };
        // the prototypes of the common APIs (Windows, the C run-time / POSIX; DissasmApiPrototypes.cpp): by the name of an import / a function
        // (the import prefixes, the version / stdcall suffixes, the underscore of Mach-O, Zw for Nt); null when it is not known
        const AsmFunctionDetails* FindApiPrototype(std::string_view name);
        size_t GetApiPrototypesCount();
        void ForEachApiPrototype(const std::function<void(const AsmFunctionDetails&)>& callback);
        // the type a pointer parameter points to (the variable whose address is passed): PHKEY / LPDWORD / HMODULE* / REFIID -> HKEY / DWORD /
        // HMODULE / IID, LPCWSTR -> WCHAR; empty for void and for a type that is not a pointer
        std::string GetPointedType(std::string_view type);
        // the name of a variable that holds the value an API returns (the decompiler's): the verb dropped from Get / Create / Open / Load /
        // Find / Allocate (GetProcAddress -> ProcAddress, CreateFileW -> File: the A / W ending too, ExAllocatePoolWithTag -> PoolWithTag),
        // else the function and _result (malloc_result; a BOOL / NTSTATUS / HRESULT status: CreateProcess_result)
        std::string GetReturnValueName(const AsmFunctionDetails& function);
        // the symbolic name of a constant passed to a parameter of an API (DissasmApiConstants.cpp, IDA's standard enumerations):
        // GENERIC_READ | GENERIC_WRITE for the dwDesiredAccess of CreateFileW, OPEN_EXISTING, HKEY_LOCAL_MACHINE, MEM_COMMIT | MEM_RESERVE,
        // a pool tag ('NtFs'), CTL_CODE(...) for an I/O control code; empty when the parameter / the value has no name
        std::string FormatApiConstant(std::string_view function, std::string_view parameter, uint64 value);
        // the symbolic name of a value an API returns, the one it is compared with (cmp eax, 0x102 after WaitForSingleObject: WAIT_TIMEOUT;
        // GetLastError: ERROR_ALREADY_EXISTS; an HRESULT, an NTSTATUS, an LSTATUS, INVALID_HANDLE_VALUE); empty when it has none
        std::string FormatApiReturnConstant(const AsmFunctionDetails& function, uint64 value);
        // the name of a value that is a status wherever it is (an error NTSTATUS: STATUS_OBJECT_NAME_NOT_FOUND, an HRESULT error: E_INVALIDARG,
        // HRESULT_FROM_WIN32(ERROR_NOT_FOUND)); empty for the other values
        std::string FormatDistinctiveConstant(uint64 value);
        // COM (DissasmComInterfaces.cpp): the name of a known GUID (16 bytes: IID_IWbemLocator, CLSID_ShellLink, FOLDERID_Startup); the
        // interface of an IID; the methods of the interfaces by their index in the vtable (the ones of the bases first: IUnknown::Release is
        // 2), with the parameter that receives the interface a method gives; the APIs that give one (CoCreateInstance: by its IID)
        struct DissasmComMethod {
            std::string_view name;
            int8 outParameter;           // the parameter (after this, from 0) of the interface it gives; -1: none
            std::string_view outInterface; // its interface, else the IID of riidParameter says which
            int8 riidParameter;          // -1: none
        };
        struct DissasmComProducer {
            int8 riidParameter;      // the parameter of the IID of the interface (-1: always outInterface)
            int8 outParameter;       // the parameter that receives it; -1: the return value
            std::string_view outInterface;
        };
        std::string_view FindGuidName(const uint8* bytes);
        std::string_view FindInterfaceOfIid(const uint8* bytes);
        bool IsComInterface(std::string_view name);
        std::optional<std::pair<std::string_view, DissasmComMethod>> FindComMethod(std::string_view interfaceName, uint32 index);
        const DissasmComProducer* FindComProducer(std::string_view function);
        // an immediate operand (3, 0x80000000, -1, #0x10 of ARM); the one of the last operand of an instruction (edx, 0x80000000)
        std::optional<int64> ParseOperandImmediate(std::string_view text);
        std::optional<uint64> GetLastOperandImmediate(std::string_view operands);
        // the sets of constants the user can give to an operand (IDA M): their names (ACCESS_RIGHTS, WIN32_ERRORS, HRESULTS, POOL_TAG ...) and
        // titles; the name of a value in one (empty: none); the operands with the immediate of the last one replaced by its name in the set
        // (edx, 0x80000000 -> edx, GENERIC_READ), none when it is not an immediate / the set does not name it
        void ForEachConstantSet(const std::function<void(std::string_view id, std::string_view title)>& callback);
        bool IsConstantSetName(std::string_view id);
        std::string FormatConstantOfSet(std::string_view id, uint64 value);
        std::optional<std::string> ApplyOperandConstant(std::string_view operands, std::string_view id);
        // a prototype the user writes for a function (IDA Y): "int decrypt(char* buf, int len)" parsed as the ones of the APIs; its texts are
        // kept with it. Null when it is not one: no parentheses, a name / a parameter name that is not an identifier, a parameter without a
        // name, a pointer to a function as a parameter, more than DISSASM_MAX_USER_PROTOTYPE_SIZE characters
        constexpr size_t DISSASM_MAX_USER_PROTOTYPE_SIZE = 512;
        struct DissasmUserPrototype {
            std::deque<std::string> strings;
            AsmFunctionDetails details;
        };
        std::shared_ptr<const DissasmUserPrototype> ParseUserPrototype(std::string_view text);
        // a type of parameter that takes 8 bytes of the stack in 32 bit code (__int64, double, LARGE_INTEGER, ...): two pushes
        bool IsWideX86Type(std::string_view type);
        // 32 bit: the pushes a known API takes from the stack when it returns (stdcall: its parameters, 8 byte ones twice); none for the C
        // run-time (cdecl: its caller removes them, the lowercase names but the Winsock ones) and the variadic ones
        std::optional<uint32> GetX86StdcallPushes(const AsmFunctionDetails& prototype);
        // the structures the APIs take by address (STARTUPINFOW, WIN32_FIND_DATAW, PROCESS_INFORMATION, ...; DissasmApiStructures.cpp), laid
        // out for 32 or 64 bit code; null when it is not known
        const DissasmApiStructure* FindApiStructure(std::string_view name, bool is64);
        size_t GetApiStructuresCount(bool is64);
        void ForEachApiStructure(bool is64, const std::function<void(const DissasmApiStructure&)>& callback);
        // IDA T: the displacement of the memory operand of an instruction as the field of a structure: x86 [rbx + 0x3c] -> [rbx +
        // STARTUPINFOW.dwFlags], [rbx] -> [rbx + STARTUPINFOW.cb]; ARM [x19, #0x3c] -> [x19, #STARTUPINFOW.dwFlags]. None when the operands
        // have no memory operand with a base register and a positive displacement (rip / pc relative, an index register on ARM, [rbx - 8])
        std::optional<std::string> ApplyOperandStructure(std::string_view operands, const DissasmApiStructure& structure, bool isArm);
        // the field at an offset of the structure, as IDA writes it after the variable: .dwFlags, .ftLastWriteTime.dwHighDateTime,
        // .cFileName+2, +0x46 (the padding); the offset 0 is the variable itself (lea), or its first field for an access of the memory (.cb)
        std::string FormatApiStructureMember(const DissasmApiStructure& structure, uint32 offset, bool memoryAccess = false);
        // the color of a cell of the navigation band (DissasmBandCell), the one of the rows of the Functions window for a category: the
        // injection red, the anti-debug pink, the processes magenta, the network aqua, the crypto yellow, ... the other functions dark blue
        AppCUI::Graphics::Color GetDissasmBandColor(uint8 cell);

        struct DissasmAsmPreCacheData {
            std::vector<DissasmAsmPreCacheLine> cachedAsmLines;
            std::unordered_map<uint32, uint8> instructionFlags;
            uint16 index;
            uint32 maxLineSize;
            bool CheckInstructionHasFlag(uint32 line, DissasmAsmPreCacheLine::InstructionFlag flag) const
            {
                const auto it = instructionFlags.find(line);
                if (it == instructionFlags.end())
                    return false;
                return (it->second & flag) > 0;
            }
            void AddInstructionFlag(uint32 line, DissasmAsmPreCacheLine::InstructionFlag flag)
            {
                auto& val = instructionFlags[line];
                val |= flag;
            }
            bool HasAnyFlag(uint32 line) const
            {
                const auto it = instructionFlags.find(line);
                if (it == instructionFlags.end())
                    return false;
                return it->second > 0;
            }
            DissasmAsmPreCacheLine* GetLine()
            {
                if (index >= cachedAsmLines.size())
                    return nullptr;
                return &cachedAsmLines[index++];
            }
            void ComputeMaxLine()
            {
                maxLineSize = 0;
                for (const auto& cachedLine : cachedAsmLines) {
                    const auto lineSize = cachedLine.GetLineSize();
                    if (lineSize > maxLineSize)
                        maxLineSize = lineSize;
                }
            }
            void PrepareLabelArrows();

            void Clear()
            {
                for (auto& cachedLine : cachedAsmLines) {
                    free(cachedLine.op_str);
                    cachedLine.op_str = nullptr;
                }
                cachedAsmLines.clear();
                index       = 0;
                maxLineSize = 0;
            }
            void Reset()
            {
                index = 0;
            }

            DissasmAsmPreCacheData(size_t initial_size = 128) : index(0), maxLineSize(0)
            {
                cachedAsmLines.reserve(initial_size);
            }
            ~DissasmAsmPreCacheData()
            {
                Clear();
            }

            // the arguments of a known API: the names of its parameters are added to the automatic comments of the pushes placed before the call
            // the arguments of a call to a known function, on the lines prepared before it: the pushes (x86) or the instructions that write
            // the argument registers / stack slots (x64)
            void AnnounceCallInstruction(const AsmFunctionDetails* functionDetails, bool registerArguments);
        };

        // The lines of a x86/x64 code zone in the expanded layout (every line shown, no zone collapsed): the labels and the local variable
        // lines (annotations, keyed by their expanded line) placed between the instructions. The shown lines are derived from it
        // (DissasmCodeZone::DisplayToExpanded): a collapsed zone is a single line that hides the other lines of its range.
        struct DissasmCodeInternalType {
            AnnotationContainer annotations;
            // only while a cache record of versions 1 / 2 is loaded: its comments by line (DissasmCodeZone::MoveLineCommentsToAnchors)
            DissasmComments commentsData;
        };

        // A collapsible zone of a code zone: the range of lines [start, end) in the expanded layout. The zones are nested, never partially
        // overlapping; a collapsed zone shows only one line ("collapsed" and its name).
        struct DissasmCollapsibleZone {
            uint32 start = 0;
            uint32 end   = 0; // exclusive
            std::string name;
            bool isCollapsed = false;

            bool Contains(uint32 line) const
            {
                return start <= line && line < end;
            }
            bool Contains(const DissasmCollapsibleZone& other) const
            {
                return start <= other.start && other.end <= end;
            }
        };

        struct DissasmFunctionEntry {
            std::string name;      // empty: an automatic name (sub_...)
            uint64 size   = 0;     // 0: unknown
            bool isExport = false; // the name is the name of an export
        };

        struct DissasmCodeZoneInitData {
            Reference<DrawLineInfo> dli;
            int32 adjustedZoneSize;
            bool hasAdjustedSize;
            bool enableDeepScanDissasmOnStart;
            bool enableLocalVariablesDetection; // requires enableDeepScanDissasmOnStart
            bool alignPadding = true;           // the padding between the functions (int3, nop) is one line: align 0x10
            Reference<GView::Object> obj;
            uint32 visibleRows;
            // the VA of the start of the zone (DissasmCodeZone::labelAddressBase); none: the labels are named after the file offsets
            std::optional<uint64> labelAddressBase;
            // an address (address space of the labels) that is a location of the file: the immediates and the absolute memory operands of
            // 32 bit code are cross references only then (a constant is not); empty: they are not cross references
            std::function<bool(uint64)> isFileAddress;
            // the known starts of functions given by the plugin, by file offset (exports, exception data, TLS callbacks); can be null
            const std::map<uint64, DissasmFunctionEntry>* functionEntries = nullptr;
            // the file offsets where an instruction starts (the section starts of the plugin); the function entries are ones as well
            const std::vector<uint64>* instructionBoundaries = nullptr;
            std::optional<uint64> globalOffsetTable; // 32 bit x86 PIC: ebx in the PLT stubs (SettingsData::globalOffsetTable)
            // 32 bit ARM: the mode from a file offset on (ARM, Thumb, data); can be null
            const std::map<uint64, ArmCodeMode>* armCodeModes = nullptr;
            // the pointers the loader writes, by file offset (SettingsData::relocatedPointers); can be null
            const std::map<uint64, uint64>* relocatedPointers = nullptr;
            // the fields of the structures of the data, by VA; can be null
            const std::map<uint64, DissasmDataField>* dataFields = nullptr;
            // the named places of the plugin (imports, Objective-C references), keyed by RVA (by VA without an offset translation); can be null
            const std::unordered_map<uint64, MemoryMappingEntry>* memoryMappings = nullptr;
            // the import used by the operands of an instruction (import thunks: jmp [slot]); empty: there are no imports
            std::function<const MemoryMappingEntry*(const X86OperandsInfo&)> findImport;
            // the file offset of an address (address space of the labels): the jump tables of the switches are read there
            std::function<std::optional<uint64>(uint64)> addressToFileOffset;
            // the VA of the RVA 0 (PE): the jump tables of MSVC x64 hold RVAs
            std::optional<uint64> imageBase;
            // the time the deep scan may take in InitZone; it continues later (DissasmCodeZone::ContinueDeepScan) when it does not end. None: the
            // deep scan ends in InitZone
            std::optional<std::chrono::milliseconds> deepScanBudget;
            // the time the line count (a linear sweep of the whole code) may take in InitZone; the zone shows the lines counted so far and
            // the count continues later (ContinueDeepScan, before the deep scan). None: the lines are counted in InitZone
            std::optional<std::chrono::milliseconds> lineCountBudget;
        };

        struct MemoryMappingEntry {
            std::string name;
            MemoryMappingType type;
        };
        struct DissasmDataField {
            uint32 size;
            DataFieldType type;
            std::string name;
        };

        // TODO: improve to be more generic!
        enum class DissasmPEConversionType : uint8 { FileOffset = 0, RVA = 1, VA = 2 };
        // what the search (Ctrl+F) looks for: the text of the listing, a byte pattern, an immediate / displacement value
        enum class DissasmSearchKind : uint8 { Text, Bytes, Immediate };
        struct DissasmSearch {
            DissasmSearchKind kind = DissasmSearchKind::Text;
            std::string text;
            bool matchCase = false;
        };

        struct SettingsData {
            String name;

            DisassemblyLanguage defaultLanguage;
            std::map<uint64, DisassemblyZone> disassemblyZones;
            std::deque<char*> buffersToDelete;
            uint32 availableID;

            std::unordered_map<uint64, MemoryMappingEntry> memoryMappings; // memory locations to functions
            std::map<uint64, DissasmFunctionEntry> functionEntries;         // the known function starts, by file offset
            std::vector<uint64> instructionBoundaries;                      // the file offsets where an instruction starts (sections)
            std::optional<uint64> globalOffsetTable;                         // 32 bit x86 PIC: the value of ebx in the PLT stubs
            std::map<uint64, ArmCodeMode> armCodeModes;                     // 32 bit ARM: the mode from a file offset on
            std::map<uint64, uint64> relocatedPointers;                     // the pointers the loader writes (file offset -> VA)
            // Mach-O LC_DYLD_CHAINED_FIXUPS (Settings::AddChainedFixups): decoded into relocatedPointers / memoryMappings when the viewer
            // (or the headless analysis) takes the settings
            std::vector<uint8> chainedFixups;
            uint64 chainedFixupsImageBase = 0;
            // Mach-O LC_DYLD_INFO (Settings::AddDyldBindInfo): the bind / weak bind opcodes, decoded with the chained fixups
            struct DyldBindInfo {
                std::vector<uint8> opcodes;
                std::vector<uint64> segmentAddresses;
                uint8 pointerSize;
                uint64 imageBase;
            };
            std::vector<DyldBindInfo> dyldBindInfos;
            // Mach-O: the symbol of every pointer that dyld binds, by RVA. The line of the pointer shows it even when a structure that starts
            // there names the place (the isa of a metaclass bound to _OBJC_METACLASS_$_NSObject, the vptr of a typeinfo)
            std::unordered_map<uint64, std::string> boundSymbols;
            // the fields of the structures of the data (AddDataField and the parsers of the metadata), by VA
            std::map<uint64, DissasmDataField> dataFields;
            // the file offset (from DISSASM_UNINITIALIZED_ZONES_BASE) of a VA of an uninitialized data zone
            std::optional<uint64> GetUninitializedFileOffset(uint64 address) const
            {
                for (auto it = disassemblyZones.lower_bound(DISSASM_UNINITIALIZED_ZONES_BASE); it != disassemblyZones.end(); ++it) {
                    const auto& zone = it->second;
                    if (zone.isUninitialized && address >= zone.virtualAddress && address - zone.virtualAddress < zone.size)
                        return zone.startingZonePoint + (address - zone.virtualAddress);
                }
                return {};
            }
            std::vector<uint64> offsetsToSearch;
            std::vector<std::unique_ptr<ParseZone>> parseZones;
            std::map<uint64, DissasmStructureType> dissasmTypeMapped; // mapped types against the offset of the file
            std::map<uint64, CollapsibleAndTextData> collapsibleAndTextZones;
            std::unordered_map<TypeID, DissasmStructureType> userDesignedTypes; // user defined types
            Reference<BufferViewer::OffsetTranslateInterface> offsetTranslateCallback;

            bool SaveToCache(DissasmCache& cache, Reference<GView::Object> obj);
            bool ValidateCacheData(DissasmCache& cache, Reference<GView::Object> obj);
            SettingsData();
        };

        // Zones layout (Instance::RecomputeDissasmZones): the zones are placed in the order of their file offsets, one after another.
        // The bytes of the file that are not shown by a structure / code / collapsible zone are shown as raw text by the text zones: a gap
        // zone covers the bytes between the end of the previous zone and the start of the next one, the trailing zone the bytes after
        // the last zone (until the end of the file).
        struct DissasmZonesLayoutParams {
            uint32 textSize;   // bytes shown on a text line
            uint64 fileSize;
            bool showFileContent; // the gap / trailing text zones are shown
            bool structuresInitialCollapsedState;
        };
        void BuildDissasmParseZones(SettingsData& settings, const DissasmZonesLayoutParams& params);
        // lines of the text of a text zone: a collapsible zone has its title line besides them
        uint32 GetTextZoneExtendedSize(const CollapsibleAndTextData& data, uint32 textSize);
        // the text line size changed: the text zones get their new number of lines and every zone is moved after the previous one (the
        // structure and code zones keep their lines); true when any line changed
        bool RelayoutDissasmParseZones(std::vector<std::unique_ptr<ParseZone>>& zones, uint32 textSize);

        // The code zone records were keyed by the first line of their zone ("DissasmParseZoneType.<line>"): it depended on the view width
        // and on the zones placed before, so it rarely matches the current layout. When the cache is loaded they are moved (once) to the
        // file offset key of their zone ("DissasmCodeZone.<offset>"): the next save writes them under that key.
        void MigrateLegacyCodeZoneRecords(DissasmCache& cache, const std::vector<std::unique_ptr<ParseZone>>& zones);
        // every code zone knows the other code zones of the file (DissasmCodeZone::siblingZones)
        void LinkCodeZones(const std::vector<std::unique_ptr<ParseZone>>& zones);
        // the data defined by the user in a code zone, saved in the cache (read before the zone is analyzed)
        std::vector<DissasmInstructionSet::DataRange> ReadUserDataRanges(const DissasmCache& cache, const DissasmCodeZone& zone);
        // the functions edited by the user in a code zone (DissasmCodeZone::userFunctions), saved in the cache (read before the zone is
        // analyzed)
        std::map<uint64, uint8> ReadUserFunctions(const DissasmCache& cache, const DissasmCodeZone& zone);
        // the structures the user gave to the variables of a code zone (DissasmCodeZone::userVariableStructures), saved in the cache (read
        // before the zone is analyzed); the entries of a damaged record are dropped
        std::map<std::pair<uint64, int32>, std::string> ReadUserVariableStructures(const DissasmCache& cache, const DissasmCodeZone& zone);
        // the bytes of the record (the cache, the tests)
        void UserVariableStructuresToBuffer(const std::map<std::pair<uint64, int32>, std::string>& structures, std::vector<std::byte>& buffer);
        // the structure offsets of the operands of a code zone (DissasmCodeZone::operandStructures, IDA T), saved in the cache; the entries of a
        // damaged record are dropped
        std::map<uint64, std::string> ReadOperandStructures(const DissasmCache& cache, const DissasmCodeZone& zone);
        void OperandStructuresToBuffer(const std::map<uint64, std::string>& structures, std::vector<std::byte>& buffer);
        // the symbolic constants of the operands of a code zone (DissasmCodeZone::operandConstants, IDA M), saved in the cache; an entry with
        // a set that does not exist dropped
        std::map<uint64, std::string> ReadOperandConstants(const DissasmCache& cache, const DissasmCodeZone& zone);
        void OperandConstantsToBuffer(const std::map<uint64, std::string>& constants, std::vector<std::byte>& buffer);
        // the bookmarks of a code zone (DissasmCodeZone::bookmarks), saved in the cache; an empty / too long description or an address outside
        // of the zone dropped
        std::map<uint64, std::string> ReadBookmarks(const DissasmCache& cache, const DissasmCodeZone& zone);
        void BookmarksToBuffer(const std::map<uint64, std::string>& bookmarks, std::vector<std::byte>& buffer);
        // the repeatable comments of a code zone (DissasmCodeZone::repeatableComments), saved in the cache; an empty / too long text
        // (DISSASM_MAX_REPEATABLE_COMMENT_SIZE) or an address outside of the zone dropped
        std::map<uint64, std::string> ReadRepeatableComments(const DissasmCache& cache, const DissasmCodeZone& zone);
        void RepeatableCommentsToBuffer(const std::map<uint64, std::string>& comments, std::vector<std::byte>& buffer);
        // the prototypes the user gave to the functions of a code zone (DissasmCodeZone::userPrototypes, Y), saved in the cache; a text that is
        // not a prototype or a function outside of the zone dropped
        std::map<uint64, std::string> ReadUserPrototypes(const DissasmCache& cache, const DissasmCodeZone& zone);
        void UserPrototypesToBuffer(const std::map<uint64, std::string>& prototypes, std::vector<std::byte>& buffer);
        constexpr size_t DISSASM_MAX_REPEATABLE_COMMENT_SIZE = 64 * 1024;
        // a name the record and the annotations accept: empty (no structure) or the name of a structure (letters, digits, _)
        bool IsValidUserStructureName(std::string_view name);

        struct LayoutDissasm {
            uint32 visibleRows;
            uint32 totalCharactersPerLine;
            uint32 textSize; // charactersPerLine minus the left parts
            uint32 startingTextLineOffset;
            bool structuresInitialCollapsedState;

            uint32 totalLinesSize;
        };

        struct AsmData {
            std::unordered_map<uint32, const AsmFunctionDetails*> functions;
            std::deque<DissasmCodeZone*> zonesToClear;
        };
        // the APIs with known arguments (AnnounceCallInstruction, FindApiPrototype): their names in asmData.functions (empty: the arguments
        // are not named)
        void AddKnownFunctions(AsmData& asmData);

        struct DrawLineInfo {
            const uint8* start;
            const uint8* end;
            Character* chLineStart;
            Character* chNameAndSize;
            Character* chText;
            bool recomputeOffsets;

            uint32 currentLineFromOffset;
            uint32 screenLineToDraw;
            uint32 textLineToDraw;

            Renderer& renderer;

            uint32 lineOffset;
            ColorPair errorColor;
            DrawLineInfo(Renderer& renderer, uint32 lineOffset, ColorPair errorColor)
                : start(nullptr), end(nullptr), chLineStart(nullptr), chNameAndSize(nullptr), chText(nullptr), recomputeOffsets(true), currentLineFromOffset(0),
                  screenLineToDraw(0), textLineToDraw(0), renderer(renderer), lineOffset(lineOffset), errorColor(errorColor)
            {
            }

            void WriteErrorToScreen(std::string_view error) const;
        };

        // A cursor location stored by the jumps history. The line is kept relative to the zone that contains it, so the
        // location survives other zones being collapsed / expanded (that shifts the absolute line numbers).
        struct CursorState {
            static constexpr uint32 NO_ZONE = 0xFFFFFFFFu;

            uint32 zoneIndex{ NO_ZONE }; // NO_ZONE -> lineInZone is an absolute line
            uint32 lineInZone{ 0 };
            uint32 lineInView{ 0 }; // the row of the cursor on the screen
            uint32 offset{ 0 };     // the column of the cursor

            bool operator==(const CursorState& other) const
            {
                return zoneIndex == other.zoneIndex && lineInZone == other.lineInZone && lineInView == other.lineInView && offset == other.offset;
            }
        };

        // Back / forward history of the jumps (follow call / jump, go to entry point, go to line), like in a browser:
        // the list holds the visited locations (oldest first) and `current` is the one the cursor arrived at last.
        class JumpsHolder
        {
            const size_t maxCapacity;
            size_t current;
            std::deque<CursorState> history;

          public:
            JumpsHolder(size_t maxCapacity) : maxCapacity(maxCapacity), current(0)
            {
                assert(maxCapacity >= 2);
            }

            // records a jump: `from` replaces the current entry (the cursor may have moved since it arrived there) and the
            // locations that could be reached with "forward" are dropped
            void Record(const CursorState& from, const CursorState& to)
            {
                if (history.empty())
                    history.push_back(from);
                else {
                    history.erase(history.begin() + static_cast<std::ptrdiff_t>(current) + 1, history.end());
                    history[current] = from;
                }
                if (!(to == from))
                    history.push_back(to);
                while (history.size() > maxCapacity)
                    history.pop_front();
                current = history.size() - 1;
            }

            std::optional<CursorState> JumpBack()
            {
                if (history.empty() || current == 0)
                    return std::nullopt;
                return history[--current];
            }

            std::optional<CursorState> JumpForward()
            {
                if (current + 1 >= history.size())
                    return std::nullopt;
                return history[++current];
            }

            size_t Size() const
            {
                return history.size();
            }
        };

        enum class CollapsibleZoneOperation : uint8 { Add, Expand, Collapse, Remove };

        class Instance : public View::ViewControl
        {
            enum class MouseLocation : uint8 { OnView, OnHeader, Outside };
            struct MousePositionInfo {
                MouseLocation location;
                uint32 lines;
                uint32 offset;
            };

            struct CursorDissasm {
                uint32 startViewLine, lineInView, offset;
                [[nodiscard]] LinePosition ToLinePosition() const;
                uint64 GetOffset(uint32 textSize) const;
                bool hasMovedView;
            } Cursor;

            LayoutDissasm Layout;
            ColorManager ColorMan;

            struct {
                // uint8 buffer[256];
                uint32 size;
                uint64 start, end;
                // bool highlight;
            } CurrentSelection;

            struct ButtonsData {
                int x;
                int y;
                SpecialChars c;
                ColorPair color;
                uint64 offsetStructure;
                ParseZone* zone;
            };

            struct {
                std::vector<ButtonsData> buttons;
                // used for collpasible zones until buttons are fixed, TODO: remove
                std::vector<ButtonsData> bullets;
            } MyLine;

            struct ZoneLocation {
                uint32 zoneIndex;
                uint32 startingLine;
                uint32 endingLine;
            };

            Reference<GView::Object> obj;
            Pointer<SettingsData> settings;
            static Config config;
            CharacterBuffer chars;
            AdvancedSelection selection;
            CodePage codePage;
            Menu rightClickMenu;
            // uint64 rightClickOffset;

            AsmData asmData;
            JumpsHolder jumps_holder;

            // the operand numbers of the instruction on the cursor line, used by the hexadecimal <-> decimal switch (H key) and
            // by the cursor information; computed when needed and kept until the cursor line or the drawn lines change
            struct CursorLineNumber {
                uint32 column; // same base as Cursor.offset
                uint32 length;
                uint32 index; // FindOperandNumbers index (bit of DissasmCodeZone::decimalOperands)
                uint64 value;
                bool isHex;
            };
            struct {
                bool computed         = false;
                uint32 line           = 0;
                uint64 generation     = 0;
                bool valid            = false; // the cursor line is an instruction
                DissasmCodeZone* zone = nullptr;
                uint64 address        = 0;
                std::vector<CursorLineNumber> numbers;
                std::string location;              // the function of the line and the offset in it, the file offset (status bar)
                std::string instruction;           // the mnemonic and what it does (DescribeInstruction, status bar)
                std::string operands;              // the operands of the instruction and their columns (the token under the cursor)
                std::vector<uint32> operandColumns;
            } cursorLineNumbers;
            // the name / register / number under the cursor: all its occurrences are highlighted in the drawn lines (empty: none)
            std::string GetCursorToken();
            int PrintCursorLocationInfo(int x, int y, AppCUI::Graphics::Renderer& r);
            int PrintCursorInstructionInfo(int x, int y, AppCUI::Graphics::Renderer& r); // Op: cmovne: move if not equal ...
            uint64 drawnLinesGeneration = 0; // changes every time the lines of a dissasm zone are recomputed
            DissasmCache cacheData;
            CommonInterfaces::QueryInterface* queryInterface;

            inline void UpdateCurrentZoneIndex(const DissasmStructureType& cType, DissasmParseStructureZone* zone, bool increaseOffset);

            void RecomputeDissasmLayout();
            bool WriteTextLineToChars(DrawLineInfo& dli);
            bool WriteStructureToScreen(DrawLineInfo& dli, const DissasmStructureType& currentType, uint32 spaces, DissasmParseStructureZone* structureZone);
            bool DrawCollapsibleAndTextZone(DrawLineInfo& dli, CollapsibleAndTextZone* zone);
            bool DrawStructureZone(DrawLineInfo& dli, DissasmParseStructureZone* structureZone);
            bool DrawDissasmZone(DrawLineInfo& dli, DissasmCodeZone* zone);
            bool DrawDissasmX86AndX64CodeZone(DrawLineInfo& dli, DissasmCodeZone* zone);
            bool DrawDissasmJavaByteCodeZone(DrawLineInfo& dli, DissasmCodeZone* zone);
            bool PrepareDrawLineInfo(DrawLineInfo& dli);

            void RegisterStructureCollapseButton(uint32 screenLine, SpecialChars c, ParseZone* zone, bool isBullet = false);
            void ChangeZoneCollapseState(ParseZone* zoneToChange, uint32 line);

            void AddStringToChars(DrawLineInfo& dli, ColorPair pair, const char* fmt, ...);
            void AddStringToChars(DrawLineInfo& dli, ColorPair pair, string_view stringToAdd);

            void HighlightSelectionAndDrawCursorText(DrawLineInfo& dli, uint32 maxLineLength, uint32 availableCharacters);
            void RecomputeDissasmZones();
            uint64 GetZonesMaxSize() const;
            void UpdateLayoutTotalLines();

            // Utils
            bool ProcessSelectedDataToPrintable(UnicodeStringBuilder& usb);
            // the text of selection `index` when it is inside one x86/x64 code zone, built from the zone as the lines are drawn (the
            // selection storage only has the lines that were drawn on the screen)
            bool TryGetCodeZoneSelectionText(uint32 index, std::string& text);
            inline LinePosition OffsetToLinePosition(uint64 offset) const;
            // inline uint64 LinePositionToOffset(LinePosition linePosition) const;
            [[nodiscard]] vector<ZoneLocation> GetZonesIndexesFromPosition(uint64 startingOffset, uint64 endingOffset = 0) const;
            [[nodiscard]] vector<ZoneLocation> GetZonesIndexesFromLinePosition(uint32 lineStart, uint32 lineEnd = 0) const;

            void AdjustZoneExtendedSize(ParseZone* zone, uint32 newExtendedSize);

            void AnalyzeMousePosition(int x, int y, MousePositionInfo& mpInfo);

            void MoveTo(int32 offset = 0, int32 lines = 0, AppCUI::Input::Key key = AppCUI::Input::Key::None, bool select = false);
            void MoveScrollTo(int32 offset, int32 lines);

            int PrintCursorPosInfo(int x, int y, uint32 width, bool addSeparator, Renderer& r);
            int PrintCursorLineInfo(int x, int y, uint32 width, bool addSeparator, Renderer& r);

            void OpenCurrentSelection();

            // Operations
            // void AddNewCollapsibleTextZone();
            void AddComment();
            void RemoveComment();
            void RenameLabel();
            void RemoveLocalVariable();
            // dli: the line of the paint that prepares the zone (its errors are written there), none for a zone prepared in the background
            bool InitDissasmCodeZone(DrawLineInfo* dli, DissasmCodeZone* zone);
            // the code zones never shown are prepared too: their references to the other zones (the calls from PAGE to .text) are known
            // once they are analyzed. One zone (PrepareNextCodeZone, the frame updates) or all of them (PrepareCodeZones); false when
            // every zone is prepared
            bool PrepareNextCodeZone();
            // every data zone is prepared: analyzed once more with the pointers of the data zones prepared after them (a table of __const to
            // the strings of __cstring, .data to .rdata); false when there is nothing to do
            bool LinkDataZones();
            bool dataZonesLinked = false;
            void PrepareCodeZones();
            void PrepareCodeOnlyZones(); // the zones of instructions (not the data zones), their analysis ended
            void CommandExportAsmFile();
            // the annotations of the user as a plain text (JSON) file keyed by the addresses: written / added to the analysed zones
            void ExportAnnotations();
            void ImportAnnotations();
            void CreateSignatures();
            void ApplySignatures();
            void ProcessSpaceKey(bool goToEntryPoint = false);

            // jumps history (back / forward)
            CursorState SaveCursorState() const;
            void RestoreCursorState(const CursorState& state);
            void RecordJump(const CursorState& from);
            bool JumpInHistory(bool back);

            // hexadecimal <-> decimal operand numbers
            void RefreshCursorLineNumbers();
            // the display options changed (columns shown): the prepared lines of every drawn zone are built again
            void RefreshDrawnLines();
            // the address of the first decoded instruction of the zone as it is shown (config.AddressMode: VA, RVA or file offset)
            uint64 GetDisplayAddressBase(DissasmCodeZone* zone);
            // VA -> RVA -> file offset -> VA (only file offsets without the offset translation of a plugin)
            void ChangeAddressMode();
            // the cross references to the label / target of the cursor line, Enter jumps to one
            void ShowXrefs();
            // the instructions that use `target` (address space of the labels); the selected one gets the cursor
            void ShowXrefsTo(DissasmCodeZone* zone, uint64 target, const std::string& targetName);
            // the references to several places (an import: its slots and its thunks), but the ones made from `ignored` ([start, end): its thunks)
            void ShowXrefsTo(DissasmCodeZone* zone,
                             const std::vector<uint64>& targets,
                             const std::vector<std::pair<uint64, uint64>>& ignored,
                             const std::string& targetName);
            // the imports of the file (IDA's Imports, beyond: the category of each, its prototype, the places that use it); Enter: the uses
            void ShowImports();
            void ShowStrings();
            DissasmCodeZone* GetCursorOrFirstCodeZone();
            void UndoOrRedo(bool redo); // Ctrl+Z / Ctrl+Y: the edits of the zone of the cursor
            void ShowCommandPalette();
            void ShowCallTree(); // Ctrl+R: the callers and the callees of the function of the cursor
            void ShowFunctionGraph(); // Ctrl+B: the basic blocks of the function of the cursor
            void ToggleKeyProfile();  // Ctrl+Shift+P: the GView keys <-> the IDA keys
            // the suggestions of the assistant: shown (Ctrl+Shift+A), accepted (A) / dismissed (Shift+A) on the line of the cursor
            bool showAISuggestions = true;
            void AcceptOrDismissAISuggestion(bool accept);
            // names suggested for the current function and the functions it calls (Ctrl+Shift+K): one request at a time on a worker
            // thread, followed by the frame updates (the UI stays responsive while the assistant answers), Esc stops them
            struct {
                DissasmCodeZone* zone = nullptr;
                std::deque<uint64> functions; // relative addresses, not asked yet
                uint32 total    = 0;
                uint32 answered = 0;
                DissasmAssistantRequest request; // the request of requestFunction
                uint64 requestFunction = 0;
            } aiNaming;
            void StartAINaming();
            bool RunAINamingStep(bool wait); // false when the naming ended
            void StopAINaming();
            // asks the assistant on a worker thread while a window shows the time it takes; none when the user cancels it (Esc)
            std::optional<DissasmAssistantAnswer> AskAssistantWaiting(DissasmAssistantRequest::Assistant* assistant, std::string prompt, std::string displayPrompt);
            // the requests that were cancelled go on in the background: the view waits for them when it is destroyed (the assistant
            // belongs to the window)
            DissasmAssistantRequest::AbandonedRequests abandonedAssistantRequests;
            void FindNext(); // the next match of the last search (F6)
            std::optional<DissasmSearch> lastSearch;
            bool RunSearch(const DissasmSearch& search, bool showErrors);
            // moves the cursor to the instruction at the file offset (and to the labels above it); recorded in the jumps history
            bool MoveCursorToZoneFileOffset(DissasmCodeZone* zone, uint64 fileOffset, bool landOnLabels);
            // the deep scans that did not end in InitZone continue in the frame updates; their end adds the labels (the lines change)
            bool HasPendingDeepScans() const;
            void EndDeepScan(DissasmCodeZone* zone, bool cancel);
            void FinishDeepScans(); // the actions that need the labels (rename, comments, cache, export) end the pending scans first
            void CancelDeepScans();
            // GoTo: the file offset of an address / a label name, or the line (line:N); the reason when it can not be reached
            std::optional<uint64> ResolveGoToText(std::string_view text, std::string& error, std::optional<uint32>& line);
            // the cursor on the instruction of a file offset of a code zone (a zone that is not prepared yet: once it is drawn)
            bool GoToFileOffset(uint64 fileOffset);
            void ShowFunctions();
            std::optional<uint64> pendingGoTo; // the file offset to reach once its zone is prepared (it is drawn)
            bool movedCursorWhileDrawing = false; // pendingGoTo was reached during a paint: Paint draws the view again
            bool repaintRequested = false;      // asked during a paint: the next frame update repaints
            bool frameUpdatesSeen    = false; // the frontend delivers frame updates (FPS mode): the deep scans continue there
            uint32 deepScanFrames    = 0;
            // the number under the cursor, or the only number of the cursor line
            const CursorLineNumber* GetCursorLineNumber();
            void ToggleNumberBase();
            // IDA D / A / U on the cursor line: the data of the user changes, the zone is analyzed again (its annotations are kept)
            enum class UserDataEdit : uint8 { Data, String, Undefine };
            void DefineUserData(UserDataEdit edit);
            // IDA P (a function starts at the cursor line), Delete function, the noreturn attribute of the function of the cursor line: the
            // functions of the user change, the zone is analyzed again
            enum class UserFunctionEdit : uint8 { Create, Delete, ToggleNoReturn };
            void EditUserFunction(UserFunctionEdit edit);
            // IDA Alt+Q: the structure of the variable of the cursor line (its line or an instruction that uses it), chosen in a list
            void SetVariableStructure();
            // IDA T: the displacement of the memory operand of the cursor instruction as the field of a structure, chosen in the same list
            void SetOperandStructure();
            // IDA M: the immediate of the cursor instruction as a symbolic constant (GENERIC_READ), chosen among the sets that name its value
            void SetOperandConstant();
            // IDA Alt+M / Ctrl+M: a bookmark on the cursor line (its description; again: edited), the list of the bookmarks of the file
            void MarkPosition();
            void ShowBookmarks();
            // IDA ;: the repeatable comment of the label / the instruction of the cursor line (shown on the lines that refer to it too)
            void AddRepeatableComment();
            // IDA Y: the prototype of the function of the cursor line (empty: none), then a new analysis of the zone
            void SetFunctionPrototype();
            // the zone analyzed again; the cursor goes back to `keepAddress` (relative) when given. background: a big zone shows its lines at
            // once and its deep scan continues in the frame updates (the annotations come back when it ends, EndDeepScan); otherwise the whole
            // analysis runs now (ReanalyzeCodeZone)
            bool ReanalyzeZone(DissasmCodeZone* zone, std::optional<uint64> keepAddress, bool background);
            void FillCodeZoneInitData(DissasmCodeZoneInitData& initData, DrawLineInfo* dli, DissasmCodeZone* zone);
            void RefreshDataZones(); // the data zones analyzed again: a code zone changed its references (its labels there)
            // the labels of a zone changed (analyzed, renamed): the lines of the other zones are prepared again (their operands and comments
            // name its places: cs:dword_14000C0D0, dq sub_140001000)
            void ForgetLinesReferringTo(DissasmCodeZone* zone);
            int PrintCursorValueInfo(int x, int y, Renderer& r);
            void CommandExecuteCollapsibleZoneOperation(CollapsibleZoneOperation operation);
            void DissasmZoneProcessSpaceKey(DissasmCodeZone* zone, uint32 line, uint64* offsetToReach = nullptr);

            void EditDissasmCodeZoneCommand();
            void QuerySmartAssistant(QueryTypeSmartAssistant queryType);
            void QuerySmartAssistantX86X64(
                  DissasmCodeZone* codeZone, uint32 line, const QuerySmartAssistantParams& queryParams, QueryTypeSmartAssistant queryType);

            void LoadCacheData();
            void SaveCacheData();

          public:
            Instance(Reference<GView::Object> obj, Settings* settings);
            virtual ~Instance() override;

            virtual void Paint(AppCUI::Graphics::Renderer& renderer) override;
            // IDA's navigation band in the last column of the view (the functions colored by what their APIs do, the shown lines marked); a
            // click / a drag on it shows the lines of the row (a click is a jump: Ctrl+Q comes back)
            void PaintNavigationBand(AppCUI::Graphics::Renderer& renderer);
            bool ShowNavigationBandRow(int x, int y, bool recordJump);
            std::vector<uint8> navigationBand; // BuildDissasmNavigationBand, built again when navigationBandKey changes
            uint64 navigationBandKey = 0;
            virtual void OnAfterResize(int newWidth, int newHeight) override;
            virtual void OnStart() override;

            virtual bool GoTo(uint64 offset) override;
            virtual bool Select(uint64 offset, uint64 size) override;
            virtual bool ShowGoToDialog() override;
            virtual bool ShowFindDialog() override;
            virtual bool ShowCopyDialog() override;

            virtual void PaintCursorInformation(AppCUI::Graphics::Renderer& renderer, uint32 width, uint32 height) override;
            virtual bool UpdateKeys(KeyboardControlsInterface* interface) override;
            bool ExecuteNavigationCommand(uint32 commandId, bool select);

            // Mouse events
            virtual void OnMousePressed(int x, int y, Input::MouseButton button, Input::Key) override;
            virtual bool OnMouseDrag(int x, int y, Input::MouseButton button, Input::Key) override;
            virtual bool OnMouseWheel(int x, int y, Input::MouseWheel direction, Input::Key) override;

            // Events
            virtual bool OnKeyEvent(AppCUI::Input::Key keyCode, char16 characterCode) override;
            bool OnFrameUpdate() override;
            virtual bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
            virtual bool OnEvent(Reference<Control>, Event eventType, int ID) override;

            // Property interface
            virtual bool GetPropertyValue(uint32 propertyID, PropertyValue& value) override;
            virtual bool SetPropertyValue(uint32 propertyID, const PropertyValue& value, String& error) override;
            virtual void SetCustomPropertyValue(uint32 propertyID) override;
            virtual bool IsPropertyValueReadOnly(uint32 propertyID) override;
            virtual const vector<Property> GetPropertiesList() override;
            virtual std::string_view GetCategoryNameForSerialization() const override
            {
                return "View.Dissasm";
            }
            virtual bool AddCategoryBeforePropertyNameWhenSerializing() const override
            {
                return true;
            }

            static DissasmColors& GetConfigColors()
            {
                return config.ConfigColors;
            }
            static bool ConfigColorsHaveChanges()
            {
                return config.ConfigColors.hasChanges;
            }
            void OnFocus() override;
            void OnLoseFocus() override;

            friend DissasmTestInstance;
        }; // Instance

        class SingleLineEditWindow : public Window
        {
            std::string data;
            Reference<TextField> textField;

            bool allowEmpty = false; // an empty text is a valid answer (it removes what the text was)
            void Validate();

          public:
            SingleLineEditWindow(std::string initialText, const char* title, bool allowEmptyText = false);
            virtual bool OnEvent(Reference<Control>, Event eventType, int ID) override;
            inline std::string GetResult() const
            {
                return data;
            }
        };

        // GoTo an address or a label name (ParseDissasmGoToText); the resolver tells if the text can be reached (or why not)
        class GoToDialog : public Window
        {
          public:
            using Resolver = std::function<bool(std::string_view text, std::string& error)>;

          private:
            Reference<TextField> textField;
            Resolver resolver;
            std::string resultText;

            void Validate();

          public:
            GoToDialog(std::string_view shownAddressType, Resolver resolver);

            virtual bool OnEvent(Reference<Control>, Event eventType, int ID) override;
            inline const std::string& GetResultText() const
            {
                return resultText;
            }
        };

    } // namespace DissasmViewer
} // namespace View
}; // namespace GView
