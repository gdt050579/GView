#pragma once

#include "Internal.hpp"

#include <unordered_map>
#include <utility>
#include <deque>
#include <list>
#include <cassert>
#include <capstone/capstone.h>

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

        struct Config
        {
            struct
            {
                ColorPair Normal;
                ColorPair Highlight;
                ColorPair Inactive;
                ColorPair Cursor;
                ColorPair Line;
                ColorPair Selection;
                ColorPair OutsideZone;
                ColorPair StructureColor;
                ColorPair DataTypeColor;
                ColorPair AsmOffsetColor;                // 0xsomthing
                ColorPair AsmIrrelevantInstructionColor; // int3
                ColorPair AsmWorkRegisterColor;          // eax, ebx,ecx, edx
                ColorPair AsmStackRegisterColor;         // ebp, edi, esi
                ColorPair AsmCompareInstructionColor;    // test, cmp
                ColorPair AsmFunctionColor;              // ret call
                ColorPair AsmLocationInstruction;        // dword ptr[ ]
                ColorPair AsmJumpInstruction;            // jmp
                ColorPair AsmComment;                    // comments added by user
                ColorPair AsmDefaultColor;               // rest of things
            } Colors;
            struct
            {
                AppCUI::Input::Key AddNewType;
                AppCUI::Input::Key ShowFileContentKey;
                AppCUI::Input::Key ExportAsmToFile;
                AppCUI::Input::Key JumpBack;
                AppCUI::Input::Key JumpForward;
            } Keys;
            bool Loaded;

            bool ShowFileContent;
            static void Update(IniSection sect);
            void Initialize();
        };

        struct DisassemblyZone
        {
            uint64 startingZonePoint;
            uint64 size;
            uint64 entryPoint;
            DisassemblyLanguage language;
            DissasmArchitecture architecture;
        };

        enum class InternalDissasmType : uint8
        {
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

        struct DissasmType
        {
            InternalDissasmType primaryType;
            std::string_view name;

            uint32 secondaryType;
            uint32 width;
            uint32 height;

            std::vector<DissasmType> internalTypes;
            uint32 GetExpandedSize() const;
        };

        enum class DissasmParseZoneType : uint8
        {
            StructureParseZone,
            DissasmCodeParseZone,
            CollapsibleAndTextZone
        };

        struct ParseZone
        {
            uint32 startLineIndex;
            uint32 endingLineIndex;
            uint32 extendedSize;
            // uint32 textLinesOffset;
            uint16 zoneID; // TODO: maybe can be replaced by the index in an array
            bool isCollapsed;

            DissasmParseZoneType zoneType;
        };

        struct DissasmParseStructureZone : public ParseZone
        {
            int16 structureIndex;
            DissasmType dissasmType;
            std::list<std::reference_wrapper<const DissasmType>> types;
            std::list<int32> levels;
            uint64 textFileOffset;
            uint64 initialTextFileOffset;
        };

        struct CollapsibleAndTextData
        {
            uint64 startingOffset;
            uint64 size;

            bool canBeCollapsed;
        };

        struct CollapsibleAndTextZone : public ParseZone
        {
            CollapsibleAndTextData data;
        };

        struct AsmOffsetLine
        {
            uint64 offset;
            uint32 line;
        };

        struct DissasmCodeZone : public ParseZone
        {
            // uint32 startingCacheLineIndex;
            // uint64 lastInstrOffsetInCachedLines;
            // std::vector<CharacterBuffer> cachedLines;
            uint32 lastDrawnLine; // optimization not to recompute buffer every time
            uint32 lastClosestLine;
            uint32 offsetCacheMaxLine;
            BufferView lastData;

            const uint8* asmData;
            uint64 asmSize, asmAddress;

            std::vector<AsmOffsetLine> cachedCodeOffsets;
            DisassemblyZone zoneDetails;
            std::unordered_map<uint32, std::string> comments;
            int internalArchitecture; // used for dissasm libraries
            bool isInit;

            void AddOrUpdateComment(uint32 line, std::string comment);
            bool HasComment(uint32 line, std::string& comment) const;
            void RemoveComment(uint32 line);
        };

        struct SettingsData
        {
            String name;

            DisassemblyLanguage defaultLanguage;
            std::map<uint64, DisassemblyZone> disassemblyZones;
            std::deque<char*> buffersToDelete;
            uint32 availableID;

            std::unordered_map<uint64, string_view> memoryMappings; // memory locations to functions
            std::vector<uint64> offsetsToSearch;
            std::vector<std::unique_ptr<ParseZone>> parseZones;
            std::map<uint64, DissasmType> dissasmTypeMapped; // mapped types against the offset of the file
            std::map<uint64, CollapsibleAndTextData> collapsibleAndTextZones;
            std::unordered_map<TypeID, DissasmType> userDesignedTypes; // user defined types
            SettingsData();
        };

        struct LayoutDissasm
        {
            uint32 visibleRows;
            uint32 totalCharactersPerLine;
            uint32 textSize; // charactersPerLine minus the left parts
            uint32 startingTextLineOffset;
            bool structuresInitialCollapsedState;

            uint32 totalLinesSize;
        };

        struct AsmData
        {
            std::map<uint32, ColorPair> instructionToColor;
        };

        struct LinePosition
        {
            uint32 line;
            uint32 offset;
        };

        struct DrawLineInfo
        {
            const uint8* start;
            const uint8* end;
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
                : start(nullptr), end(nullptr), chNameAndSize(nullptr), chText(nullptr), recomputeOffsets(true), currentLineFromOffset(0), screenLineToDraw(0),
                  textLineToDraw(0), renderer(renderer), lineOffset(lineOffset), errorColor(errorColor)
            {
            }

            void WriteErrorToScreen(std::string_view error) const;
        };

        struct CursorState
        {
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
                for (int32 i = 0; i < jumps.size(); i++)
                    if (jumps[i] == newState)
                    {
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

        class Instance : public View::ViewControl
        {
            enum class MouseLocation : uint8
            {
                OnView,
                OnHeader,
                Outside
            };
            struct MousePositionInfo
            {
                MouseLocation location;
                uint32 lines;
                uint32 offset;
            };

            struct CursorDissasm
            {
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
            } Cursor;

            struct
            {
                ColorPair Normal, Line, Highlighted;
            } CursorColors;

            LayoutDissasm Layout;

            struct
            {
                // uint8 buffer[256];
                uint32 size;
                uint64 start, end;
                // bool highlight;
            } CurrentSelection;

            struct ButtonsData
            {
                int x;
                int y;
                SpecialChars c;
                ColorPair color;
                uint64 offsetStructure;
                ParseZone* zone;
            };

            struct
            {
                std::vector<ButtonsData> buttons;
            } MyLine;

            struct ZoneLocation
            {
                uint32 zoneIndex;
                uint32 startingLine;
                uint32 endingLine;
            };

            Reference<GView::Object> obj;
            Pointer<SettingsData> settings;
            static Config config;
            CharacterBuffer chars;
            Utils::Selection selection;
            CodePage codePage;
            Menu rightClickMenu;
            // uint64 rightClickOffset;

            AsmData asmData;
            JumpsHolder jumps_holder;

            inline void UpdateCurrentZoneIndex(const DissasmType& cType, DissasmParseStructureZone* zone, bool increaseOffset);

            void RecomputeDissasmLayout();
            bool WriteTextLineToChars(DrawLineInfo& dli);
            bool WriteStructureToScreen(DrawLineInfo& dli, const DissasmType& currentType, uint32 spaces, DissasmParseStructureZone* structureZone);
            bool DrawCollapsibleAndTextZone(DrawLineInfo& dli, CollapsibleAndTextZone* zone);
            bool DrawStructureZone(DrawLineInfo& dli, DissasmParseStructureZone* structureZone);
            bool InitDissasmZone(DrawLineInfo& dli, DissasmCodeZone* zone);
            bool DrawDissasmZone(DrawLineInfo& dli, DissasmCodeZone* zone);
            bool PrepareDrawLineInfo(DrawLineInfo& dli);

            void RegisterStructureCollapseButton(DrawLineInfo& dli, SpecialChars c, ParseZone* zone);
            void ChangeZoneCollapseState(ParseZone* zoneToChange);

            void AddStringToChars(DrawLineInfo& dli, ColorPair pair, const char* fmt, ...);
            void AddStringToChars(DrawLineInfo& dli, ColorPair pair, string_view stringToAdd);

            void HighlightSelectionAndDrawCursorText(DrawLineInfo& dli, uint32 maxLineLength, uint32 availableCharacters);
            void RecomputeDissasmZones();
            uint64 GetZonesMaxSize() const;
            void UpdateLayoutTotalLines();

            // Utils
            inline LinePosition OffsetToLinePosition(uint64 offset) const;
            // inline uint64 LinePositionToOffset(LinePosition linePosition) const;
            [[nodiscard]] vector<ZoneLocation> GetZonesIndexesFromPosition(uint64 startingOffset, uint64 endingOffset = 0) const;

            void AdjustZoneExtendedSize(ParseZone* zone, uint32 newExtendedSize);

            void AnalyzeMousePosition(int x, int y, MousePositionInfo& mpInfo);

            void MoveTo(int32 offset = 0, int32 lines = 0, bool select = false);
            void MoveScrollTo(int32 offset, int32 lines);

            int PrintCursorPosInfo(int x, int y, uint32 width, bool addSeparator, Renderer& r);
            int PrintCursorLineInfo(int x, int y, uint32 width, bool addSeparator, Renderer& r);

            // Operations
            void AddNewCollapsibleZone();
            void AddComment();
            void RemoveComment();
            void CommandExportAsmFile();
            void ProcessSpaceKey();
            void CommandDissasmAddZone();
            void CommandDissasmRemoveZone();
            void DissasmZoneProcessSpaceKey(DissasmCodeZone* zone, uint32 line);

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
            virtual void OnMousePressed(int x, int y, AppCUI::Input::MouseButton button) override;
            virtual bool OnMouseDrag(int x, int y, Input::MouseButton button) override;
            virtual bool OnMouseWheel(int x, int y, AppCUI::Input::MouseWheel direction) override;

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
        }; // Instance

        class CommentDataWindow : public Window
        {
            std::string data;
            Reference<TextField> commentTextField;

            void Validate();

          public:
            CommentDataWindow(std::string initialComment);
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
