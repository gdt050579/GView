#pragma once

#include "Internal.hpp"

#include <unordered_map>
#include <utility>
#include <deque>
#include <list>

namespace GView
{
namespace View
{
    namespace DissasmViewer
    {
        using namespace AppCUI;

        static constexpr size_t CACHE_OFFSETS_DIFFERENCE = 500;
        static constexpr size_t DISSASM_MAX_CACHED_LINES = 200;

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
            } Colors;
            struct
            {
                AppCUI::Input::Key AddNewType;
                AppCUI::Input::Key ShowFileContentKey;
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
            //uint32 textLinesOffset;
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

        struct DissasmCodeZone : public ParseZone
        {
            uint32 startingCacheLineIndex;
            uint64 lastInstrOffsetInCachedLines;
            std::vector<CharacterBuffer> cachedLines;
            std::vector<uint64> cachedCodeOffsets;
            DisassemblyZone zoneDetails;
            bool isInit;
        };

        struct SettingsData
        {
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

        class Instance : public View::ViewControl
        {
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
                DrawLineInfo(Renderer& renderer) : recomputeOffsets(true), currentLineFromOffset(0), screenLineToDraw(0), renderer(renderer)
                {
                }
            };

            enum class MouseLocation : uint8
            {
                OnView,
                OnHeader,
                Outside
            };
            struct MousePositionInfo
            {
                MouseLocation location;
                uint64 bufferOffset;
            };

            struct CursorDissasm
            {
                uint64 startView, currentPos;
                uint32 base;
            } Cursor;

            struct
            {
                ColorPair Normal, Line, Highlighted;
            } CursorColors;

            struct LayoutDissasm
            {
                uint32 visibleRows;
                uint32 totalCharactersPerLine;
                uint32 textSize; // charactersPerLine minus the left parts
                uint32 startingTextLineOffset;
                bool structuresInitialCollapsedState;
            } Layout;

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
                uint32 zoneLine;
            };

            struct LinePosition
            {
                uint32 line;
                uint32 offset;
            };

            FixSizeString<16> name;

            Reference<GView::Object> obj;
            Pointer<SettingsData> settings;
            static Config config;
            CharacterBuffer chars;
            Utils::Selection selection;
            CodePage codePage;
            Menu rightClickMenu;
            uint64 rightClickOffset;

            inline void UpdateCurrentZoneIndex(const DissasmType& cType, DissasmParseStructureZone* zone, bool increaseOffset);

            void RecomputeDissasmLayout();
            bool WriteTextLineToChars(DrawLineInfo& dli);
            bool WriteStructureToScreen(
                  DrawLineInfo& dli, const DissasmType& currentType, uint32 spaces, DissasmParseStructureZone* structureZone);
            bool DrawCollapsibleAndTextZone(DrawLineInfo& dli, CollapsibleAndTextZone* zone);
            bool DrawStructureZone(DrawLineInfo& dli, DissasmParseStructureZone* structureZone);
            bool DrawDissasmZone(DrawLineInfo& dli, DissasmCodeZone* zone);
            bool PrepareDrawLineInfo(DrawLineInfo& dli);

            void RegisterStructureCollapseButton(DrawLineInfo& dli, SpecialChars c, ParseZone* zone);
            void ChangeZoneCollapseState(ParseZone* zoneToChange);

            void AddStringToChars(DrawLineInfo& dli, ColorPair pair, const char* fmt, ...);
            void AddStringToChars(DrawLineInfo& dli, ColorPair pair, string_view stringToAdd);

            void HighlightSelectionText(DrawLineInfo& dli, uint64 maxLineLength);
            void RecomputeDissasmZones();
            uint64 GetZonesMaxSize() const;

            //Utils
            inline LinePosition OffsetToLinePosition(uint64 offset) const;
            inline uint64 LinePositionToOffset(LinePosition linePosition) const;
            vector<ZoneLocation> GetZonesIndexesFromPosition(uint64 startingOffset, uint64 endingOffset = 0) const;
            void WriteErrorToScreen(DrawLineInfo& dli, std::string_view error) const;

            void AdjustZoneExtendedSize(ParseZone* zone, uint32 newExtendedSize);

            void AnalyzeMousePosition(int x, int y, MousePositionInfo& mpInfo);

            void MoveTo(uint64 offset, bool select);
            void MoveScrollTo(uint64 offset);

            int PrintCursorPosInfo(int x, int y, uint32 width, bool addSeparator, Renderer& r);
            int PrintCursorLineInfo(int x, int y, uint32 width, bool addSeparator, Renderer& r);

            //Operations
            void AddNewCollapsibleZone();

          public:
            Instance(const std::string_view& name, Reference<GView::Object> obj, Settings* settings);
            virtual ~Instance() override;

            virtual void Paint(AppCUI::Graphics::Renderer& renderer) override;
            virtual void OnAfterResize(int newWidth, int newHeight) override;
            virtual void OnStart() override;

            virtual bool GoTo(uint64 offset) override;
            virtual bool Select(uint64 offset, uint64 size) override;
            virtual std::string_view GetName() override;
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
        };
    } // namespace DissasmViewer
} // namespace View

}; // namespace GView
