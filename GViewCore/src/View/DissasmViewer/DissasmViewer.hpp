#pragma once

#include "Internal.hpp"

#include <unordered_map>
#include <utility>
#include <deque>
#include <optional>
#include <list>
#include <cassert>
#include <capstone/capstone.h>

#include "AdvancedSelection.hpp"
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
            uint64 entryPoint;
            DisassemblyLanguage language;

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
            uint8 arrowCells[ARROW_COLUMNS]       = {}; // ArrowCellFlag for every arrow column
            const void* mapping                   = nullptr;
            bool isCollapsedLine                  = false; // the line of a collapsed zone (it hides the other lines of the zone)

            // the argument of the x64 calling convention written by the instruction (GetX64ArgumentSlot)
            static constexpr uint8 NO_ARGUMENT = 0xFF;
            uint8 argumentSlot                 = NO_ARGUMENT;

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
                memcpy(arrowCells, other.arrowCells, sizeof(arrowCells));
                mapping                = other.mapping;
                isCollapsedLine        = other.isCollapsedLine;
                shouldAddButton        = other.shouldAddButton;
                isZoneCollapsed        = other.isZoneCollapsed;
                argumentSlot           = other.argumentSlot;
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
        };

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
            Reference<GView::Object> obj;
            uint32 visibleRows;
            // the VA of the start of the zone (DissasmCodeZone::labelAddressBase); none: the labels are named after the file offsets
            std::optional<uint64> labelAddressBase;
            // an address (address space of the labels) that is a location of the file: the immediates and the absolute memory operands of
            // 32 bit code are cross references only then (a constant is not); empty: they are not cross references
            std::function<bool(uint64)> isFileAddress;
            // the known starts of functions given by the plugin, by file offset (exports, exception data, TLS callbacks); can be null
            const std::map<uint64, DissasmFunctionEntry>* functionEntries = nullptr;
            // the import used by the operands of an instruction (import thunks: jmp [slot]); empty: there are no imports
            std::function<const MemoryMappingEntry*(const X86OperandsInfo&)> findImport;
        };

        struct MemoryMappingEntry {
            std::string name;
            MemoryMappingType type;
        };

        // TODO: improve to be more generic!
        enum class DissasmPEConversionType : uint8 { FileOffset = 0, RVA = 1, VA = 2 };

        struct SettingsData {
            String name;

            DisassemblyLanguage defaultLanguage;
            std::map<uint64, DisassemblyZone> disassemblyZones;
            std::deque<char*> buffersToDelete;
            uint32 availableID;

            std::unordered_map<uint64, MemoryMappingEntry> memoryMappings; // memory locations to functions
            std::map<uint64, DissasmFunctionEntry> functionEntries;         // the known function starts, by file offset
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

        struct LayoutDissasm {
            uint32 visibleRows;
            uint32 totalCharactersPerLine;
            uint32 textSize; // charactersPerLine minus the left parts
            uint32 startingTextLineOffset;
            bool structuresInitialCollapsedState;

            uint32 totalLinesSize;
        };

        struct AsmData {
            std::map<uint32, std::reference_wrapper<ColorPair>> instructionToColor;
            std::unordered_map<uint32, const AsmFunctionDetails*> functions;
            std::deque<DissasmCodeZone*> zonesToClear;
        };
        // the Windows APIs with known arguments (AnnounceCallInstruction)
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
            } cursorLineNumbers;
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
            bool InitDissasmCodeZone(DrawLineInfo& dli, DissasmCodeZone* zone);
            void CommandExportAsmFile();
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
            // moves the cursor to the instruction at the file offset (and to the labels above it); recorded in the jumps history
            bool MoveCursorToZoneFileOffset(DissasmCodeZone* zone, uint64 fileOffset, bool landOnLabels);
            // the number under the cursor, or the only number of the cursor line
            const CursorLineNumber* GetCursorLineNumber();
            void ToggleNumberBase();
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

            void Validate();

          public:
            SingleLineEditWindow(std::string initialText, const char* title);
            virtual bool OnEvent(Reference<Control>, Event eventType, int ID) override;
            inline std::string GetResult() const
            {
                return data;
            }
        };

        class GoToDialog : public Window
        {
          private:
            uint32 resultLine, totalAvailableLines;
            Reference<TextField> lineTextField;

            void Validate();

          public:
            GoToDialog(uint32 currentLine, uint32 totalAvailableLines);

            virtual bool OnEvent(Reference<Control>, Event eventType, int ID) override;
            inline uint32 GetResultedLine() const
            {
                return resultLine;
            }
        };

    } // namespace DissasmViewer
} // namespace View
}; // namespace GView
