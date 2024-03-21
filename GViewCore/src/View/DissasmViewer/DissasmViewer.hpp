#pragma once

#include "Internal.hpp"

#include <unordered_map>
#include <utility>
#include <deque>
#include <list>
#include <cassert>
#include <capstone/capstone.h>

#include "AdvancedSelection.hpp"
#include "DissasmDataTypes.hpp"
#include "Config.hpp"

class DissasmTestInstance;

namespace GView
{
namespace View
{
    namespace DissasmViewer
    {
        using namespace AppCUI;

        static constexpr size_t CACHE_OFFSETS_DIFFERENCE      = 500;
        static constexpr size_t DISSASM_MAX_CACHED_LINES      = 50;
        static constexpr size_t DISSASM_INITIAL_EXTENDED_SIZE = 1;
        static constexpr size_t DISSAM_MINIMUM_COMMENTS_X     = 50;
        static constexpr size_t DISSAM_MAXIMUM_STRING_PREVIEW = 90;

        using AnnotationDetails   = std::pair<std::string, uint64>;
        using AnnotationContainer = std::map<uint32, AnnotationDetails>;

        struct DisassemblyZone {
            uint64 startingZonePoint;
            uint64 size;
            uint64 entryPoint;
            DisassemblyLanguage language;
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
            InternalDissasmType primaryType;
            std::string_view name;

            uint32 secondaryType;
            uint32 width;
            uint32 height;

            std::vector<DissasmStructureType> internalTypes;
            uint32 GetExpandedSize() const;
        };

        enum class DissasmParseZoneType : uint8 { StructureParseZone, DissasmCodeParseZone, CollapsibleAndTextZone, JavaBytecodeZone };

        struct ParseZone {
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

        // JClass code
        struct JavaBytecodeZone : public ParseZone {
            DisassemblyZone zoneDetails;
            bool isInit;
            std::vector<std::string> bytecodeLines;
        };

        struct AsmOffsetLine {
            uint64 offset;
            uint32 line;
        };

        struct DissasmInsnExtractLineParams {
            Reference<GView::Object> obj;
            uint32 asmLine;
            uint32 actualLine;
            struct DissasmCodeZone* zone;
            struct DrawLineInfo* dli;
            struct SettingsData* settings;
            struct AsmData* asmData;
            bool isCollapsed;
            const std::string* zoneName;
        };

        struct DissasmCodeInternalType;
        struct DissasmAsmPreCacheLine {
            enum InstructionFlag : uint8 { NoneFlag = 0x00, CallFlag = 0x1, PushFlag = 0x2, JmpFlag = 0x4 };

            enum LineArrowToDrawFlag : uint8 {
                NoLines   = 0x00,
                DrawLine1 = 0x1,
                DrawLine2 = 0x2,
                DrawLine3 = 0x4,
                DrawLine4 = 0x8,
                DrawLine5 = 0x10,

                DrawStartingLine = 0x20,
                DrawEndingLine   = 0x40
            };

            uint64 address;
            uint8 bytes[24];
            uint16 size;
            uint32 currentLine;
            char mnemonic[CS_MNEMONIC_SIZE];
            char* op_str;
            uint32 op_str_size;
            std::optional<uint64> hexValue;
            uint8 flags;
            uint8 lineArrowToDraw;
            const void* mapping;

            bool shouldAddButton;
            bool isZoneCollapsed;

            uint32 GetLineSize() const
            {
                return size * 2 + op_str_size;
            }

            DissasmAsmPreCacheLine() = default;

            DissasmAsmPreCacheLine(DissasmAsmPreCacheLine&& other) noexcept(true)
            {
                address         = other.address;
                size            = other.size;
                currentLine     = other.currentLine;
                op_str_size     = other.op_str_size;
                op_str          = other.op_str;
                other.op_str    = nullptr;
                flags           = other.flags;
                lineArrowToDraw = other.lineArrowToDraw;
                mapping         = other.mapping;
                memcpy(bytes, other.bytes, sizeof(bytes));
                memcpy(mnemonic, other.mnemonic, CS_MNEMONIC_SIZE);
                shouldAddButton = other.shouldAddButton;
                isZoneCollapsed = false;
            }
            DissasmAsmPreCacheLine(const DissasmAsmPreCacheLine& other)
            {
                address         = other.address;
                size            = other.size;
                currentLine     = other.currentLine;
                op_str_size     = other.op_str_size;
                op_str          = strdup(other.op_str);
                flags           = other.flags;
                lineArrowToDraw = other.lineArrowToDraw;
                mapping         = other.mapping;
                memcpy(bytes, other.bytes, sizeof(bytes));
                memcpy(mnemonic, other.mnemonic, CS_MNEMONIC_SIZE);
                shouldAddButton = other.shouldAddButton;
                isZoneCollapsed = false;
            }
            bool TryGetDataFromAnnotations(const DissasmCodeInternalType& currentType, uint32 lineToSearch, struct DrawLineInfo* dli = nullptr);
            bool TryGetDataFromInsn(DissasmInsnExtractLineParams& params);

            ~DissasmAsmPreCacheLine()
            {
                if (op_str)
                    free(op_str);
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

        struct DissasmComments {
            std::map<uint32, std::string> comments;

            void AddOrUpdateComment(uint32 line, std::string comment);

            bool GetComment(uint32 line, std::string& comment) const;
            bool HasComment(uint32 line) const;
            void RemoveComment(uint32 line);
            void AdjustCommentsOffsets(uint32 changedLine, bool isAddedLine);
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

            DissasmAsmPreCacheData() : index(0), maxLineSize(0)
            {
            }
            ~DissasmAsmPreCacheData()
            {
                Clear();
            }

            void AnnounceCallInstruction(struct DissasmCodeZone* zone, const AsmFunctionDetails* functionDetails, DissasmComments& comments);
        };

        struct DissasmCodeRemovableZoneDetails {
            DissasmCodeInternalType* zone;
            DissasmCodeInternalType* parent;
            uint32 zoneIndex;
        };
        struct DissasmCodeInternalType {
            std::string name;
            uint32 indexZoneStart;
            uint32 indexZoneEnd;
            uint32 workingIndexZoneStart;
            uint32 workingIndexZoneEnd;

            uint32 beforeTextLines;
            uint32 beforeAsmLines;

            uint32 textLinesPassed;
            uint32 asmLinesPassed;
            AnnotationContainer annotations;
            DissasmComments commentsData;
            bool isCollapsed;
            std::vector<DissasmCodeInternalType> internalTypes;

            uint32 GetCurrentAsmLine() const
            {
                return beforeAsmLines + asmLinesPassed;
            }

            uint32 GetCurrentTextLine() const
            {
                return beforeTextLines + textLinesPassed;
            }

            uint32 GetCurrentActualLine() const
            {
                return beforeAsmLines + asmLinesPassed + beforeTextLines + textLinesPassed;
            }

            uint32 GetSize() const
            {
                if (isCollapsed)
                    return workingIndexZoneEnd - workingIndexZoneStart;
                return indexZoneEnd - indexZoneStart;
            }

            uint32 GetNewAsmBeforeLines() const
            {
                return GetSize() - (uint32) annotations.size();
            }

            void UpdateDataLineFromPrevious(const DissasmCodeInternalType& prev)
            {
                beforeTextLines = prev.beforeTextLines + (uint32) prev.annotations.size();
                beforeAsmLines  = prev.beforeAsmLines + prev.GetNewAsmBeforeLines();
            }
            bool IsValidDataLine() const
            {
                return beforeTextLines + beforeAsmLines == workingIndexZoneStart;
            }
            bool CanAddNewZone(uint32 zoneLineStart, uint32 zoneLineEnd) const;
            bool AddNewZone(uint32 zoneLineStart, uint32 zoneLineEnd);
            DissasmCodeRemovableZoneDetails GetRemoveZoneCollapsibleDetails(uint32 zoneLine, uint32 depthLevel = 0);
            bool RemoveCollapsibleZone(uint32 zoneLine, const DissasmCodeRemovableZoneDetails& removableDetails);
        };

        struct DissasmCodeZoneInitData {
            Reference<DrawLineInfo> dli;
            int32 adjustedZoneSize;
            bool hasAdjustedSize;
            bool enableDeepScanDissasmOnStart;
            Reference<GView::Object> obj;
            uint64 maxLocationMemoryMappingSize;
            uint32 visibleRows;
        };

        struct InternalTypeNewLevelChangeData {
            bool hasName;
            bool isCollapsed;
        };

        struct DissasmCodeZone : public ParseZone {
            enum class CollapseExpandType : uint8 { Collapse, Expand, NegateCurrentState };
            uint32 lastDrawnLine; // optimization not to recompute buffer every time
            uint32 lastClosestLine;
            uint32 offsetCacheMaxLine;
            BufferView lastData;
            uint32 lastReachedLine = -1u;

            const uint8* asmData;
            uint64 asmSize, asmAddress;

            uint32 structureIndex;
            std::list<std::reference_wrapper<DissasmCodeInternalType>> types;
            std::list<uint32> levels;
            DissasmCodeInternalType dissasmType;

            DissasmAsmPreCacheData asmPreCacheData;

            std::vector<AsmOffsetLine> cachedCodeOffsets;
            DisassemblyZone zoneDetails;
            int internalArchitecture; // used for dissasm libraries
            bool isInit;
            bool changedLevel;
            InternalTypeNewLevelChangeData newLevelChangeData;

            void ResetZoneCaching();
            bool AddCollapsibleZone(uint32 zoneLineStart, uint32 zoneLineEnd);
            bool CanAddNewZone(uint32 zoneLineStart, uint32 zoneLineEnd) const
            {
                if (zoneLineStart > zoneLineEnd || zoneLineEnd > dissasmType.indexZoneEnd)
                    return false;
                return dissasmType.CanAddNewZone(zoneLineStart, zoneLineEnd);
            }
            bool CollapseOrExtendZone(uint32 zoneLine, CollapseExpandType collapse, int32& difference);
            bool RemoveCollapsibleZone(uint32 zoneLine);

            bool InitZone(DissasmCodeZoneInitData& initData);
            void ReachZoneLine(uint32 line);

            bool ResetTypesReferenceList();
            bool TryRenameLine(uint32 line);

            bool GetComment(uint32 line, std::string& comment);
            bool AddOrUpdateComment(uint32 line, const std::string& comment,bool showErr = true);
            bool RemoveComment(uint32 line, bool showErr = true);
            DissasmAsmPreCacheLine GetCurrentAsmLine(uint32 currentLine, Reference<GView::Object> obj, DissasmInsnExtractLineParams* params);
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

            uint64 maxLocationMemoryMappingSize;
            std::unordered_map<uint64, MemoryMappingEntry> memoryMappings; // memory locations to functions
            std::vector<uint64> offsetsToSearch;
            std::vector<std::unique_ptr<ParseZone>> parseZones;
            std::map<uint64, DissasmStructureType> dissasmTypeMapped; // mapped types against the offset of the file
            std::map<uint64, CollapsibleAndTextData> collapsibleAndTextZones;
            std::unordered_map<TypeID, DissasmStructureType> userDesignedTypes; // user defined types
            Reference<BufferViewer::OffsetTranslateInterface> offsetTranslateCallback;
            SettingsData();
        };

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

        struct CursorState {
            uint32 startViewLine, lineInView;

            bool operator==(const CursorState& other) const
            {
                return startViewLine == other.startViewLine && lineInView == other.lineInView;
            }
        };

        class JumpsHolder
        {
            const size_t maxCapacity;
            int32 current_index;
            std::deque<CursorState> jumps;

          public:
            JumpsHolder(size_t maxCapacity) : maxCapacity(maxCapacity), current_index(-1)
            {
                assert(maxCapacity > 0);
            }

            void insert(CursorState&& newState)
            {
                for (uint32 i = 0u; i < jumps.size(); i++)
                    if (jumps[i] == newState) {
                        current_index = i;
                        return;
                    }
                if (jumps.size() == maxCapacity)
                    jumps.pop_back();
                jumps.push_back(newState);
                current_index = static_cast<int32>(jumps.size()) - 1;
            }

            std::pair<bool, CursorState> JumpBack()
            {
                if (current_index >= 0)
                    return { true, jumps[current_index--] };
                return { false, {} };
            }

            std::pair<bool, CursorState> JumpFront()
            {
                if (current_index + 1 < static_cast<int32>(jumps.size()))
                    return { true, jumps[++current_index] };
                return { false, {} };
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
                void restorePosition(const CursorState& oldState)
                {
                    lineInView    = oldState.lineInView;
                    startViewLine = oldState.startViewLine;
                }
                CursorState saveState() const
                {
                    return CursorState{ startViewLine, lineInView };
                }
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

            inline void UpdateCurrentZoneIndex(const DissasmStructureType& cType, DissasmParseStructureZone* zone, bool increaseOffset);

            void RecomputeDissasmLayout();
            bool WriteTextLineToChars(DrawLineInfo& dli);
            bool WriteStructureToScreen(DrawLineInfo& dli, const DissasmStructureType& currentType, uint32 spaces, DissasmParseStructureZone* structureZone);
            bool DrawCollapsibleAndTextZone(DrawLineInfo& dli, CollapsibleAndTextZone* zone);
            bool DrawStructureZone(DrawLineInfo& dli, DissasmParseStructureZone* structureZone);
            bool DrawJavaBytecodeZone(DrawLineInfo& dli, JavaBytecodeZone* zone);
            bool DrawDissasmZone(DrawLineInfo& dli, DissasmCodeZone* zone);
            bool DrawDissasmX86AndX64CodeZone(DrawLineInfo& dli, DissasmCodeZone* zone);
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
            void CommandExportAsmFile();
            void ProcessSpaceKey(bool goToEntryPoint = false);
            void CommandExecuteCollapsibleZoneOperation(CollapsibleZoneOperation operation);
            void DissasmZoneProcessSpaceKey(DissasmCodeZone* zone, uint32 line, uint64* offsetToReach = nullptr);

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
