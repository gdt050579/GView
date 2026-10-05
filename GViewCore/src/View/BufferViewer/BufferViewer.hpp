#pragma once

#include "Internal.hpp"

namespace GView::View::BufferViewer
{
using namespace AppCUI;

enum class CharacterFormatMode : uint8 {
    Hex,
    Octal,
    SignedDecimal,
    UnsignedDecimal,

    Count // Must be the last
};
enum class StringType : uint8 { None, Ascii, Unicode };
struct OffsetTranslationMethod {
    FixSizeString<17> name;
};
struct SettingsData {
    GView::Utils::ZonesList zList;
    GView::Utils::ZonesList zListObjects;
    uint64 bookmarks[10];
    uint64 entryPointOffset;
    OffsetTranslationMethod translationMethods[16];
    uint32 translationMethodsCount;
    Reference<OffsetTranslateInterface> offsetTranslateCallback{ nullptr };
    Reference<PositionToColorInterface> positionToColorCallback{ nullptr };
    Reference<BufferColorInterface> bufferColorCallback{ nullptr };
    Reference<OnStartViewMoveInterface> onStartViewMoveCallback{ nullptr };
    Reference<BufferColorInterface> codeExecutionColorCallback{ nullptr };
    String name;
    SettingsData();

    // dissasm related settings
    GView::Dissasembly::Architecture architecture{ GView::Dissasembly::Architecture::Invalid };
    GView::Dissasembly::Design design{ GView::Dissasembly::Design::Invalid };
    GView::Dissasembly::Endianess endianess{ GView::Dissasembly::Endianess::Invalid };
};
enum class MouseLocation : uint8 { OnView, OnHeader, Outside };
struct MousePositionInfo {
    MouseLocation location;
    uint64 bufferOffset;
};
struct Config {
    struct {
        ColorPair Ascii;
        ColorPair Unicode;
    } Colors;
    bool Loaded;

    static void Update(IniSection sect);
    void Initialize();
};

class FindDialog : public Window, public Handlers::OnCheckInterface
{
  private:
    Reference<GView::Object> object;
    uint64 currentPos;

    Reference<CanvasViewer> description;
    Reference<TextField> input;

    Reference<RadioBox> textOption;
    Reference<RadioBox> binaryOption;
    Reference<RadioBox> textAscii;
    Reference<RadioBox> textUnicode;
    Reference<CheckBox> textRegex;
    Reference<RadioBox> textHex;
    Reference<RadioBox> textDec;

    Reference<RadioBox> searchFile;
    Reference<RadioBox> searchSelection;

    Reference<RadioBox> bufferSelect;
    Reference<RadioBox> bufferMoveCursorTo;

    Reference<CheckBox> ignoreCase;
    Reference<CheckBox> alingTextToUpperLeftCorner;

    uint64 position{ 0 };
    uint64 length{ 0 };

    UnicodeStringBuilder usb;
    std::pair<uint64, uint64> match;
    bool newRequest{ true };
    bool ProcessInput(uint64 end = GView::Utils::INVALID_OFFSET, bool last = false);

  public:
    FindDialog();

    virtual bool OnEvent(Reference<Control>, Event eventType, int ID) override;
    virtual bool OnKeyEvent(Input::Key keyCode, char16 UnicodeChar) override;
    virtual void OnCheck(Reference<Controls::Control> control, bool value) override;
    virtual void OnFocus() override; // but it's triggered only on first show call :(

    bool SetDescription();
    bool Update();
    void UpdateData(uint64 currentPos, Reference<GView::Object> object);
    std::pair<uint64, uint64> GetNextMatch(uint64 currentPos);
    std::pair<uint64, uint64> GetPreviousMatch(uint64 currentPos);

    bool SelectMatch()
    {
        CHECK(bufferSelect.IsValid(), false, "");
        return bufferSelect->IsChecked();
    }
    bool AlignToUpperRightCorner()
    {
        CHECK(alingTextToUpperLeftCorner.IsValid(), false, "");
        return alingTextToUpperLeftCorner->IsChecked();
    }
    bool HasResults() const
    {
        const auto& [start, length] = match;
        CHECK(start != GView::Utils::INVALID_OFFSET && length > 0, false, "");
        return true;
    }
};

namespace Commands
{
    constexpr int BUFFERVIEW_CMD_CHANGECOL         = 0xBF00;
    constexpr int BUFFERVIEW_CMD_CHANGEBASE        = 0xBF01;
    constexpr int BUFFERVIEW_CMD_CHANGEADDRESSMODE = 0xBF02;
    constexpr int BUFFERVIEW_CMD_GOTOEP            = 0xBF03;
    constexpr int BUFFERVIEW_CMD_CHANGECODEPAGE    = 0xBF04;
    constexpr int BUFFERVIEW_CMD_CHANGESELECTION   = 0xBF05;
    constexpr int BUFFERVIEW_CMD_HIDESTRINGS       = 0xBF06;
    constexpr int BUFFERVIEW_CMD_FINDNEXT          = 0xBF07;
    constexpr int BUFFERVIEW_CMD_FINDPREVIOUS      = 0xBF08;
    constexpr int BUFFERVIEW_CMD_DISSASM_DIALOG    = 0xBF09;
    /*
    constexpr int32 VIEW_COMMAND_ACTIVATE_COMPARE{ 0xBF10 };
    constexpr int32 VIEW_COMMAND_DEACTIVATE_COMPARE{ 0xBF11 };
    constexpr int32 VIEW_COMMAND_ACTIVATE_SYNC{ 0xBF12 };
    constexpr int32 VIEW_COMMAND_DEACTIVATE_SYNC{ 0xBF13 };
    constexpr int32 VIEW_COMMAND_ACTIVATE_CODE_EXECUTION{ 0xBF14 };
    constexpr int32 VIEW_COMMAND_DEACTIVATE_CODE_EXECUTION{ 0xBF15 };
    constexpr int32 VIEW_COMMAND_ACTIVATE_OBJECT_HIGHLIGHTING{ 0xBF16 };
    constexpr int32 VIEW_COMMAND_DEACTIVATE_OBJECT_HIGHLIGHTING{ 0xBF17 };
    */
    constexpr int BUFFERVIEW_CMD_SHOW_COLOR        = 0xBF18;

    // navigation commands (resolved through Commands::Map in OnKeyEvent)
    constexpr uint32 BUFFERVIEW_NAV_DOWN             = 0xC000;
    constexpr uint32 BUFFERVIEW_NAV_UP               = 0xC001;
    constexpr uint32 BUFFERVIEW_NAV_LEFT             = 0xC002;
    constexpr uint32 BUFFERVIEW_NAV_RIGHT            = 0xC003;
    constexpr uint32 BUFFERVIEW_NAV_PAGE_DOWN        = 0xC004;
    constexpr uint32 BUFFERVIEW_NAV_PAGE_UP          = 0xC005;
    constexpr uint32 BUFFERVIEW_NAV_LINE_START       = 0xC006;
    constexpr uint32 BUFFERVIEW_NAV_LINE_END         = 0xC007;
    constexpr uint32 BUFFERVIEW_NAV_SCROLL_UP        = 0xC008;
    constexpr uint32 BUFFERVIEW_NAV_SCROLL_DOWN      = 0xC009;
    constexpr uint32 BUFFERVIEW_NAV_SCROLL_LEFT      = 0xC00A;
    constexpr uint32 BUFFERVIEW_NAV_SCROLL_RIGHT     = 0xC00B;
    constexpr uint32 BUFFERVIEW_NAV_FILE_START       = 0xC00C;
    constexpr uint32 BUFFERVIEW_NAV_FILE_END         = 0xC00D;
    constexpr uint32 BUFFERVIEW_NAV_PREVIOUS_ZONE    = 0xC00E;
    constexpr uint32 BUFFERVIEW_NAV_NEXT_ZONE        = 0xC00F;
    constexpr uint32 BUFFERVIEW_NAV_PREVIOUS_BLOCK   = 0xC010;
    constexpr uint32 BUFFERVIEW_NAV_NEXT_BLOCK       = 0xC011;
    constexpr uint32 BUFFERVIEW_NAV_SELECTION_1      = 0xC012;
    constexpr uint32 BUFFERVIEW_NAV_SELECTION_2      = 0xC013;
    constexpr uint32 BUFFERVIEW_NAV_SELECTION_3      = 0xC014;
    constexpr uint32 BUFFERVIEW_NAV_SELECTION_4      = 0xC015;
    constexpr uint32 BUFFERVIEW_NAV_TILL_END_OF_BLOCK = 0xC016;
    constexpr uint32 BUFFERVIEW_NAV_SKIP_CHARACTER   = 0xC017;
    constexpr uint32 BUFFERVIEW_NAV_OPEN_SELECTION   = 0xC018;

    using Input::Key;
    using KF = KeyboardControlFlags;

    // command bar commands
    inline KeyboardControl ChangeColumnsCount    = { Key::F6, "ChangeColumnsCount", "Change the number of columns", BUFFERVIEW_CMD_CHANGECOL };
    inline KeyboardControl ChangeValueFormatOrCP = {
        Key::F2, "ChangeValueFormatOrCP", "Change the value format (hex/oct/dec) or the code page (full screen mode)", BUFFERVIEW_CMD_CHANGEBASE
    };
    inline KeyboardControl ChangeAddressMode   = { Key::F3, "ChangeAddressMode", "Change the address mode (file offset, RVA, ...)", BUFFERVIEW_CMD_CHANGEADDRESSMODE };
    inline KeyboardControl GoToEntryPoint      = { Key::F7, "GoToEntryPoint", "Go to the zone entrypoint", BUFFERVIEW_CMD_GOTOEP };
    inline KeyboardControl ChangeSelectionType = { Key::F9, "ChangeSelectionType", "Switch between single and multiple selection", BUFFERVIEW_CMD_CHANGESELECTION };
    inline KeyboardControl ShowHideStrings     = { Key::Alt | Key::F3, "ShowHideStrings", "Enable or disable string highlighting", BUFFERVIEW_CMD_HIDESTRINGS };
    inline KeyboardControl FindNext            = { Key::Ctrl | Key::F7, "FindNext", "Find the next occurrence (after a search)", BUFFERVIEW_CMD_FINDNEXT };
    inline KeyboardControl FindPrevious = { Key::Ctrl | Key::Shift | Key::F7, "FindPrevious", "Find the previous occurrence (after a search)", BUFFERVIEW_CMD_FINDPREVIOUS };
    inline KeyboardControl DissasmDialogCmd = { Key::Ctrl | Key::D, "DissasmDialog", "Open the disassembly dialog", BUFFERVIEW_CMD_DISSASM_DIALOG };
    inline KeyboardControl ShowColorNotFocused = {
        Key::Ctrl | Key::Alt | Key::C, "ShowColorNotFocused", "Keep the colors when the window is not focused", BUFFERVIEW_CMD_SHOW_COLOR
    };

    // navigation & editing (Shift extends the selection for the movement keys)
    inline KeyboardControl MoveDown      = { Key::Down, "MoveDown", "Move the cursor one line down", BUFFERVIEW_NAV_DOWN, KF::ShiftExtendsSelection };
    inline KeyboardControl MoveUp        = { Key::Up, "MoveUp", "Move the cursor one line up", BUFFERVIEW_NAV_UP, KF::ShiftExtendsSelection };
    inline KeyboardControl MoveLeft      = { Key::Left, "MoveLeft", "Move the cursor one byte to the left", BUFFERVIEW_NAV_LEFT, KF::ShiftExtendsSelection };
    inline KeyboardControl MoveRight     = { Key::Right, "MoveRight", "Move the cursor one byte to the right", BUFFERVIEW_NAV_RIGHT, KF::ShiftExtendsSelection };
    inline KeyboardControl MovePageDown  = { Key::PageDown, "MovePageDown", "Move the cursor one page down", BUFFERVIEW_NAV_PAGE_DOWN, KF::ShiftExtendsSelection };
    inline KeyboardControl MovePageUp    = { Key::PageUp, "MovePageUp", "Move the cursor one page up", BUFFERVIEW_NAV_PAGE_UP, KF::ShiftExtendsSelection };
    inline KeyboardControl MoveLineStart = { Key::Home, "MoveToLineStart", "Move the cursor to the start of the line", BUFFERVIEW_NAV_LINE_START, KF::ShiftExtendsSelection };
    inline KeyboardControl MoveLineEnd   = { Key::End, "MoveToLineEnd", "Move the cursor to the end of the line", BUFFERVIEW_NAV_LINE_END, KF::ShiftExtendsSelection };
    inline KeyboardControl MoveFileStart = { Key::Ctrl | Key::Home, "MoveToFileStart", "Move the cursor to the start of the file", BUFFERVIEW_NAV_FILE_START, KF::ShiftExtendsSelection };
    inline KeyboardControl MoveFileEnd   = { Key::Ctrl | Key::End, "MoveToFileEnd", "Move the cursor to the end of the file", BUFFERVIEW_NAV_FILE_END, KF::ShiftExtendsSelection };
    inline KeyboardControl PreviousZone  = { Key::Ctrl | Key::PageUp, "PreviousZone", "Move to the previous zone", BUFFERVIEW_NAV_PREVIOUS_ZONE, KF::ShiftExtendsSelection };
    inline KeyboardControl NextZone      = { Key::Ctrl | Key::PageDown, "NextZone", "Move to the next zone", BUFFERVIEW_NAV_NEXT_ZONE, KF::ShiftExtendsSelection };
    inline KeyboardControl PreviousBlock = {
        Key::Ctrl | Key::Alt | Key::PageUp, "PreviousBlock", "Move to the start of the previous block of identical bytes", BUFFERVIEW_NAV_PREVIOUS_BLOCK, KF::ShiftExtendsSelection
    };
    inline KeyboardControl NextBlock = {
        Key::Ctrl | Key::Alt | Key::PageDown, "NextBlock", "Move to the start of the next block of identical bytes", BUFFERVIEW_NAV_NEXT_BLOCK, KF::ShiftExtendsSelection
    };
    inline KeyboardControl TillEndOfBlock = { Key::E, "MoveTillEndOfBlock", "Move to the end of the current block", BUFFERVIEW_NAV_TILL_END_OF_BLOCK, KF::ShiftExtendsSelection };
    inline KeyboardControl SkipCharacter  = { Key::S, "SkipCharacter", "Skip all consecutive bytes equal to the current one", BUFFERVIEW_NAV_SKIP_CHARACTER, KF::ShiftExtendsSelection };
    inline KeyboardControl ScrollUp       = { Key::Ctrl | Key::Up, "ScrollUp", "Scroll the view one line up", BUFFERVIEW_NAV_SCROLL_UP };
    inline KeyboardControl ScrollDown     = { Key::Ctrl | Key::Down, "ScrollDown", "Scroll the view one line down", BUFFERVIEW_NAV_SCROLL_DOWN };
    inline KeyboardControl ScrollLeft     = { Key::Ctrl | Key::Left, "ScrollLeft", "Scroll the view one byte to the left", BUFFERVIEW_NAV_SCROLL_LEFT };
    inline KeyboardControl ScrollRight    = { Key::Ctrl | Key::Right, "ScrollRight", "Scroll the view one byte to the right", BUFFERVIEW_NAV_SCROLL_RIGHT };
    inline KeyboardControl GoToSelection1 = { Key::Alt | Key::N1, "GoToSelection1", "Move to selection 1", BUFFERVIEW_NAV_SELECTION_1 };
    inline KeyboardControl GoToSelection2 = { Key::Alt | Key::N2, "GoToSelection2", "Move to selection 2", BUFFERVIEW_NAV_SELECTION_2 };
    inline KeyboardControl GoToSelection3 = { Key::Alt | Key::N3, "GoToSelection3", "Move to selection 3", BUFFERVIEW_NAV_SELECTION_3 };
    inline KeyboardControl GoToSelection4 = { Key::Alt | Key::N4, "GoToSelection4", "Move to selection 4", BUFFERVIEW_NAV_SELECTION_4 };
    inline KeyboardControl OpenSelection  = { Key::Enter, "OpenSelection", "Open the current selection as a new object", BUFFERVIEW_NAV_OPEN_SELECTION };

    inline const std::array<KeyboardControl*, 10> CommandKeys = {
        &ChangeColumnsCount, &ChangeValueFormatOrCP, &ChangeAddressMode, &GoToEntryPoint,   &ChangeSelectionType,
        &ShowHideStrings,    &FindNext,              &FindPrevious,      &DissasmDialogCmd, &ShowColorNotFocused,
    };
    inline const std::array<KeyboardControl*, 25> NavigationKeys = {
        &MoveDown,       &MoveUp,         &MoveLeft,       &MoveRight,      &MovePageDown, &MovePageUp,     &MoveLineStart,
        &MoveLineEnd,    &MoveFileStart,  &MoveFileEnd,    &PreviousZone,   &NextZone,     &PreviousBlock,  &NextBlock,
        &TillEndOfBlock, &SkipCharacter,  &ScrollUp,       &ScrollDown,     &ScrollLeft,   &ScrollRight,    &GoToSelection1,
        &GoToSelection2, &GoToSelection3, &GoToSelection4, &OpenSelection,
    };
    inline Input::KeyMap Map;

    void RegisterKeys(KeyboardControlsInterface* interface);
    void OnKeysChanged();
}

class Instance : public View::ViewControl, public GView::Utils::SelectionZoneInterface, public GView::Utils::ObjectHighlightingZonesInterface
{
    struct DrawLineInfo {
        uint64 offset{ 0 };
        uint32 offsetAndNameSize{ 0 };
        uint32 numbersSize{ 0 };
        uint32 textSize{ 0 };
        const uint8* start{ nullptr };
        const uint8* end{ nullptr };
        Character* chNameAndSize{ nullptr };
        Character* chNumbers{ nullptr };
        Character* chText{ nullptr };
        bool recomputeOffsets{ true };
        DrawLineInfo() = default;
    };

    struct {
        CharacterFormatMode charFormatMode{ CharacterFormatMode::Hex };
        uint32 nrCols{ 0 };
        uint32 lineAddressSize{ 8 };
        uint32 lineNameSize{ 8 };
        uint32 charactersPerLine{ 1 };
        uint32 visibleRows{ 1 };
        uint32 xName{ 0 };
        uint32 xAddress{ 0 };
        uint32 xNumbers{ 0 };
        uint32 xText{ 0 };
    } Layout;

    struct {
      private:
        uint64 startView{ 0 };
        uint64 currentPos{ 0 };
        uint32 base{ 16 };
        int64 deltaStartView{ 0 }; // previous - current

      public:
        inline decltype(startView) GetStartView() const
        {
            return startView;
        }
        inline decltype(currentPos) GetCurrentPosition() const
        {
            return currentPos;
        }
        inline decltype(base) GetBase() const
        {
            return base;
        }
        inline decltype(deltaStartView) GetDeltaStartView() const
        {
            return deltaStartView;
        }

        inline void SetStartView(decltype(startView) startView)
        {
            deltaStartView  = startView - this->startView;
            this->startView = startView;
        }
        inline void SetCurrentPosition(decltype(currentPos) currentPos)
        {
            this->currentPos = currentPos;
        }
        inline void SetBase(decltype(base) base)
        {
            this->base = base;
        }
    } cursor;

    struct {
        uint64 start, end, middle;
        uint32 minCount{ 4 };
        bool AsciiMask[256];
        StringType type;
        String asciiMaskRepr;
        bool showAscii{ true };
        bool showUnicode{ true };
    } StringInfo;

    struct {
        ColorPair Normal, Line, Highlighted;
    } CursorColors;

    struct {
        uint8 buffer[256]{ 0 };
        uint32 size{ 0 };
        uint64 start{ GView::Utils::INVALID_OFFSET };
        uint64 end{ GView::Utils::INVALID_OFFSET };
        bool highlight{ true };
        void Clear()
        {
            start     = GView::Utils::INVALID_OFFSET;
            end       = GView::Utils::INVALID_OFFSET;
            size      = 0;
            buffer[0] = 0;
        }
    } CurrentSelection;

    bool showSyncCompare{ false };
    bool moveInSync{ false };
    bool showTypeObjects{ true };
    bool showCodeExecution{ false };
    bool showObjectsHighlighting{ false };
    CodePage codePage{ CodePageID::DOS_437 };
    Pointer<SettingsData> settings;
    Reference<GView::Object> obj;
    Utils::Selection selection;
    CharacterBuffer chars;
    uint32 currentAdrressMode{ 0 };
    String addressModesList;
    BufferColor bufColor;
    bool showColorNotFocused{ true };

    static Config config;

    FindDialog findDialog;

    int PrintSelectionInfo(uint32 selectionID, int x, int y, uint32 width, Renderer& r);
    int PrintCursorPosInfo(int x, int y, uint32 width, bool addSeparator, Renderer& r);
    int PrintCursorZone(int x, int y, uint32 width, Renderer& r);
    int Print8bitValue(int x, int height, AppCUI::Utils::BufferView buffer, Renderer& r);
    int Print16bitValue(int x, int height, AppCUI::Utils::BufferView buffer, Renderer& r);
    int Print32bitValue(int x, int height, AppCUI::Utils::BufferView buffer, Renderer& r);
    int Print32bitBEValue(int x, int height, AppCUI::Utils::BufferView buffer, Renderer& r);

    void UpdateCurrentSelection();

    void PrepareDrawLineInfo(DrawLineInfo& dli);
    void WriteHeaders(Renderer& renderer);
    void WriteLineAddress(DrawLineInfo& dli);
    void WriteLineNumbersToChars(DrawLineInfo& dli);
    void WriteLineTextToChars(DrawLineInfo& dli);
    void UpdateViewSizes();
    void MoveTo(uint64 offset, bool select);
    void MoveScrollTo(uint64 offset);
    void MoveToSelection(uint32 selIndex);
    void MoveToZone(bool startOfZone, bool select);
    void SkipCurentCaracter(bool selected);
    void MoveTillEndBlock(bool selected);
    void MoveTillNextBlock(bool select, int dir);

    void UpdateStringInfo(uint64 offset);
    void ResetStringInfo();
    std::string_view GetAsciiMaskStringRepresentation();
    bool SetStringAsciiMask(string_view stringRepresentation);

    ColorPair OffsetToColorZone(uint64 offset);
    ColorPair OffsetToColor(uint64 offset);

    void AnalyzeMousePosition(int x, int y, MousePositionInfo& mpInfo);

    void OpenCurrentSelection();

    virtual bool SetOnStartViewMoveCallback(Reference<OnStartViewMoveInterface>) override;
    virtual bool SetBufferColorProcessorCallback(Reference<BufferColorInterface>) override;
    virtual bool GetViewData(ViewData&, uint64) override;
    virtual bool AdvanceStartView(int64) override;
    virtual bool SetObjectsHighlightingZonesList(GView::Utils::ZonesList& zones) override;
    virtual GView::Utils::ZonesList& GetObjectsHighlightingZonesList() override;

  public:
    Instance(Reference<GView::Object> obj, Settings* settings);

    virtual void Paint(Renderer& renderer) override;
    virtual void OnAfterResize(int newWidth, int newHeight) override;
    virtual bool OnKeyEvent(AppCUI::Input::Key keyCode, char16 characterCode) override;
    virtual bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
    virtual bool OnEvent(Reference<Control>, Event eventType, int ID) override;
    virtual void OnFocus() override;
    virtual void OnLoseFocus() override;
    virtual bool UpdateKeys(KeyboardControlsInterface* interface) override;
    bool ExecuteNavigationCommand(uint32 commandId, bool select);

    virtual bool GoTo(uint64 offset) override;
    virtual bool Select(uint64 offset, uint64 size) override;
    virtual bool ShowGoToDialog() override;
    virtual bool ShowFindDialog() override;
    virtual bool ShowCopyDialog() override;
    bool ShowDissasmDialog();

    virtual void PaintCursorInformation(AppCUI::Graphics::Renderer& renderer, uint32 width, uint32 height) override;

    // mouse events
    virtual void OnMousePressed(int x, int y, AppCUI::Input::MouseButton button, Input::Key) override;
    virtual void OnMouseReleased(int x, int y, AppCUI::Input::MouseButton button, Input::Key) override;
    virtual bool OnMouseDrag(int x, int y, AppCUI::Input::MouseButton button, Input::Key) override;
    virtual bool OnMouseEnter() override;
    virtual bool OnMouseOver(int x, int y) override;
    virtual bool OnMouseLeave() override;
    virtual bool OnMouseWheel(int x, int y, AppCUI::Input::MouseWheel direction, Input::Key) override;

    // scrollbar data
    virtual void OnUpdateScrollBars() override;

    // property interface
    bool GetPropertyValue(uint32 id, PropertyValue& value) override;
    bool SetPropertyValue(uint32 id, const PropertyValue& value, String& error) override;
    void SetCustomPropertyValue(uint32 propertyID) override;
    bool IsPropertyValueReadOnly(uint32 propertyID) override;
    const vector<Property> GetPropertiesList() override;
    std::string_view GetCategoryNameForSerialization() const override
    {
        return "View.Buffer";
    }
    bool AddCategoryBeforePropertyNameWhenSerializing() const override
    {
        return true;
    }

    uint32 GetSelectionZonesCount() const override
    {
        uint32 count = 0;
        for (; count < selection.GetCount(); count++) {
            CHECKBK(selection.HasSelection(count), "");
        }

        return count;
    }

    GView::TypeInterface::SelectionZone GetSelectionZone(uint32 index) const override
    {
        static auto z = GView::TypeInterface::SelectionZone{ 0, 0 };
        CHECK(index < selection.GetCount(), z, "");

        return GView::TypeInterface::SelectionZone{ .start = selection.GetSelectionStart(index), .end = selection.GetSelectionEnd(index) };
    }

    virtual uint32 GetObjectsZonesCount() const override
    {
        return static_cast<uint32>(this->settings->zListObjects.GetCount());
    }

    virtual std::optional<GView::Utils::Zone> GetObjectsZone(uint32 index) const override
    {
        return this->settings->zListObjects.GetZone(index);
    }

    bool SetZones(const GView::Utils::ZonesList& zones) override
    {
        this->settings->zListObjects.Clear();

        for (uint32 i = 0; i < zones.GetCount(); i++) {
            const auto zone = zones.GetZone(i);
            CHECK(zone.has_value(), false, "");
            CHECK(this->settings->zListObjects.Add(*zone), false, "");
        }

        return true;
    }

    Reference<GView::Object> GetObject() const
    {
        return obj;
    };

    decltype(Instance::StringInfo) GetStringInfo() const
    {
        return StringInfo;
    };

    auto GetSettings() const
    {
        return settings.ToReference();
    }

    uint32 GetCurrentAddressMode() const
    {
        return currentAdrressMode;
    };

    uint64 GetCursorCurrentPosition() const
    {
        return cursor.GetCurrentPosition();
    };
};

class SelectionEditor : public Window
{
  private:
    Reference<Utils::Selection> selection;
    Reference<SettingsData> settings;
    Reference<TextField> txOffset;
    Reference<TextField> txSize;
    Reference<ComboBox> cbOfsType;
    Reference<ComboBox> cbBase;
    uint32 zoneIndex;
    uint64 maxSize;

    void RefreshSizeAndOffset();
    void Validate();
    bool GetValues(uint64& start, uint64& size);

  public:
    SelectionEditor(Reference<Utils::Selection> selection, uint32 index, Reference<SettingsData> settings, uint64 size);

    virtual bool OnEvent(Reference<Control>, Event eventType, int ID) override;
};

class GoToDialog : public Window
{
  private:
    Reference<SettingsData> settings;
    Reference<TextField> txOffset;
    Reference<ComboBox> cbOfsType;
    uint64 maxSize;
    uint64 resultedPos;

    void Validate();

  public:
    GoToDialog(Reference<SettingsData> settings, uint64 currentPos, uint64 size);

    virtual bool OnEvent(Reference<Control>, Event eventType, int ID) override;
    inline uint64 GetResultedPos() const
    {
        return resultedPos;
    }
};

class CopyDialog : public Window
{
  private:
    Reference<GView::View::BufferViewer::Instance> instance;

    Reference<RadioBox> copyAscii;
    Reference<RadioBox> copyUnicode;
    Reference<CheckBox> copyUnicodeAsSeen;
    Reference<RadioBox> copyDump;
    Reference<RadioBox> copyHex;
    Reference<RadioBox> copyArray;

    Reference<RadioBox> copyFile;
    Reference<RadioBox> copySelection;

    bool Process();
    void ShowCopiedDataInformation();

  public:
    CopyDialog(Reference<GView::View::BufferViewer::Instance> instance);

    virtual bool OnEvent(Reference<Control>, Event eventType, int ID) override;
};

class DissasmDialog : public Window, public Handlers::OnCheckInterface
{
    Reference<ListView> list;

    Reference<Instance> instance{};
    GView::Dissasembly::DissasemblerIntel dissasembler{};

    Reference<Label> architecture;
    Reference<RadioBox> x86;
    Reference<RadioBox> x64;

    Reference<Label> design;
    Reference<RadioBox> intel;
    Reference<RadioBox> arm;

    Reference<Label> endianess;
    Reference<RadioBox> little;
    Reference<RadioBox> big;

    void Validate();
    bool Update();

  public:
    DissasmDialog(Reference<Instance> instance);

    virtual bool OnEvent(Reference<Control>, Event eventType, int ID) override;
    virtual void OnCheck(Reference<Controls::Control> control, bool value) override;
};

} // namespace GView::View::BufferViewer
