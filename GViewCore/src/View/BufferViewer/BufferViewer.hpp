#pragma once

#include "Internal.hpp"

namespace GView::View::BufferViewer
{
using namespace AppCUI;

enum class CharacterFormatMode : uint8
{
    Hex,
    Octal,
    SignedDecimal,
    UnsignedDecimal,

    Count // Must be the last
};
enum class StringType : uint8
{
    None,
    Ascii,
    Unicode
};
struct OffsetTranslationMethod
{
    FixSizeString<17> name;
};
struct SettingsData
{
    GView::Utils::ZonesList zList;
    uint64 bookmarks[10];
    uint64 entryPointOffset;
    OffsetTranslationMethod translationMethods[16];
    uint32 translationMethodsCount;
    Reference<OffsetTranslateInterface> offsetTranslateCallback{ nullptr };
    Reference<PositionToColorInterface> positionToColorCallback{ nullptr };
    Reference<BufferColorInterface> bufferColorCallback{ nullptr };
    Reference<OnStartViewMoveInterface> onStartViewMoveCallback{ nullptr };
    String name;
    SettingsData();

    // dissasm related settings
    GView::Dissasembly::Architecture architecture{ GView::Dissasembly::Architecture::Invalid };
    GView::Dissasembly::Design design{ GView::Dissasembly::Design::Invalid };
    GView::Dissasembly::Endianess endianess{ GView::Dissasembly::Endianess::Invalid };
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
struct Config
{
    struct
    {
        ColorPair Ascii;
        ColorPair Unicode;
    } Colors;
    struct
    {
        AppCUI::Input::Key ChangeColumnsNumber;
        AppCUI::Input::Key ChangeValueFormatOrCP;
        AppCUI::Input::Key ChangeAddressMode;
        AppCUI::Input::Key GoToEntryPoint;
        AppCUI::Input::Key ChangeSelectionType;
        AppCUI::Input::Key ShowHideStrings;
        AppCUI::Input::Key FindNext;
        AppCUI::Input::Key FindPrevious;
        AppCUI::Input::Key Copy;
        AppCUI::Input::Key DissasmDialog;
    } Keys;
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

class Instance : public View::ViewControl, public GView::Utils::SelectionZoneInterface
{
    struct DrawLineInfo
    {
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

    struct
    {
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

    struct
    {
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

    struct
    {
        uint64 start, end, middle;
        uint32 minCount{ 4 };
        bool AsciiMask[256];
        StringType type;
        String asciiMaskRepr;
        bool showAscii{ true };
        bool showUnicode{ true };
    } StringInfo;

    struct
    {
        ColorPair Normal, Line, Highlighted;
    } CursorColors;

    struct
    {
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
    CodePage codePage{ CodePageID::DOS_437 };
    Pointer<SettingsData> settings;
    Reference<GView::Object> obj;
    Utils::Selection selection;
    CharacterBuffer chars;
    uint32 currentAdrressMode{ 0 };
    String addressModesList;
    BufferColor bufColor;

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

  public:
    Instance(Reference<GView::Object> obj, Settings* settings);

    virtual void Paint(Renderer& renderer) override;
    virtual void OnAfterResize(int newWidth, int newHeight) override;
    virtual bool OnKeyEvent(AppCUI::Input::Key keyCode, char16 characterCode) override;
    virtual bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
    virtual bool OnEvent(Reference<Control>, Event eventType, int ID) override;
    virtual void OnFocus() override;
    virtual void OnLoseFocus() override;

    virtual bool GoTo(uint64 offset) override;
    virtual bool Select(uint64 offset, uint64 size) override;
    virtual bool ShowGoToDialog() override;
    virtual bool ShowFindDialog() override;
    virtual bool ShowCopyDialog() override;
    bool ShowDissasmDialog();

    virtual void PaintCursorInformation(AppCUI::Graphics::Renderer& renderer, uint32 width, uint32 height) override;

    // mouse events
    virtual void OnMousePressed(int x, int y, AppCUI::Input::MouseButton button) override;
    virtual void OnMouseReleased(int x, int y, AppCUI::Input::MouseButton button) override;
    virtual bool OnMouseDrag(int x, int y, AppCUI::Input::MouseButton button) override;
    virtual bool OnMouseEnter() override;
    virtual bool OnMouseOver(int x, int y) override;
    virtual bool OnMouseLeave() override;
    virtual bool OnMouseWheel(int x, int y, AppCUI::Input::MouseWheel direction) override;

    // scrollbar data
    virtual void OnUpdateScrollBars() override;

    // property interface
    bool GetPropertyValue(uint32 id, PropertyValue& value) override;
    bool SetPropertyValue(uint32 id, const PropertyValue& value, String& error) override;
    void SetCustomPropertyValue(uint32 propertyID) override;
    bool IsPropertyValueReadOnly(uint32 propertyID) override;
    const vector<Property> GetPropertiesList() override;

    uint32 GetSelectionZonesCount() const override
    {
        uint32 count = 0;
        for (; count < selection.GetCount(); count++)
        {
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
