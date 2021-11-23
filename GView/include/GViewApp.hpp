#include <AppCUI/include/AppCUI.hpp>
#include <../GViewCore/include/GView.hpp>

#include <set>

using namespace AppCUI::Controls;
using namespace AppCUI::Graphics;
using namespace AppCUI::Utils;

namespace GView
{
namespace Utils
{
    class Selection
    {
        static const unsigned int MAX_SELECTION_ZONES = 4;
        struct
        {
            unsigned long long start, end, originalPoint;
        } zones[MAX_SELECTION_ZONES];
        bool singleSelectionZone;

      public:
        Selection();
        void Clear();
        bool Clear(int index);
        inline unsigned int GetCount() const
        {
            return Selection::MAX_SELECTION_ZONES;
        }
        bool GetSelection(int index, unsigned long long& Start, unsigned long long& End);
        void EnableMultiSelection(bool enable);
        inline void InvertMultiSelectionMode()
        {
            EnableMultiSelection(!singleSelectionZone);
        }
        inline bool IsMultiSelectionEnabled()
        {
            return !singleSelectionZone;
        }
        int OffsetToSelection(unsigned long long offset, unsigned long long& Start, unsigned long long& End);
        bool Contains(unsigned long long offset) const;
        bool UpdateSelection(int index, unsigned long long offset);
        int BeginSelection(unsigned long long offset);
        bool SetSelection(int index, unsigned long long start, unsigned long long end);
    };

    struct Zone
    {
        unsigned long long start, end;
        AppCUI::Graphics::ColorPair color;
        AppCUI::Utils::FixSizeString<25> name;

        Zone();
        void Set(unsigned long long s, unsigned long long e, AppCUI::Graphics::ColorPair c, std::string_view txt);
    };
    class ZonesList
    {
        Zone* list;
        Zone* lastZone;
        unsigned int count, allocated;
        unsigned long long cacheStart, cacheEnd;

      public:
        ZonesList();
        ~ZonesList();
        bool Add(unsigned long long start, unsigned long long end, AppCUI::Graphics::ColorPair c, std::string_view txt);
        bool Reserve(unsigned int count);
        const Zone* OffsetToZone(unsigned long long offset);
    };
} // namespace Utils
namespace Type
{
    namespace DefaultTypePlugin
    {
        bool Validate(const AppCUI::Utils::BufferView& buf, const std::string_view& extension);
        TypeInterface* CreateInstance(Reference<GView::Utils::FileCache> fileCache);
        bool PopulateWindow(Reference<GView::View::WindowInterface> win);
    }                                               // namespace DefaultTypePlugin
    constexpr unsigned int MAX_PATTERN_VALUES = 21; // muwt be less than 255
    class SimplePattern
    {
        unsigned char CharactersToMatch[MAX_PATTERN_VALUES];
        unsigned char Count;
        unsigned short Offset;

      public:
        SimplePattern();
        bool Init(std::string_view text, unsigned int ofs);
        bool Match(AppCUI::Utils::BufferView buf) const;
        inline bool Empty() const
        {
            return Count == 0;
        }
    };
    constexpr unsigned int PLUGIN_NAME_MAX_SIZE = 31; // must be less than 255 !!!
    class Plugin
    {
        SimplePattern Pattern;
        std::vector<SimplePattern> Patterns;
        unsigned long long Extension;
        std::set<unsigned long long> Extensions;
        unsigned char Name[PLUGIN_NAME_MAX_SIZE];
        unsigned char NameLength;
        unsigned short Priority;
        bool Loaded, Invalid;

        bool (*fnValidate)(const AppCUI::Utils::BufferView& buf, const std::string_view& extension);
        TypeInterface* (*fnCreateInstance)(Reference<GView::Utils::FileCache> fileCache);
        bool (*fnPopulateWindow)(Reference<GView::View::WindowInterface> win);

        bool LoadPlugin();

      public:
        Plugin();
        bool Init(AppCUI::Utils::IniSection section);
        void Init();
        bool Validate(AppCUI::Utils::BufferView buf, std::string_view extension);
        bool PopulateWindow(Reference<GView::View::WindowInterface> win) const;
        TypeInterface* CreateInstance(Reference<GView::Utils::FileCache> fileCache) const;
        inline bool operator<(const Plugin& plugin) const
        {
            return Priority > plugin.Priority;
        }
    };
} // namespace Type
namespace View
{
    class BufferViewer : public View::ViewControl, public View::BufferViewerInterface
    {
        enum class CharacterFormatMode : unsigned char
        {
            Hex,
            Octal,
            SignedDecimal,
            UnsignedDecimal,

            Count // Must be the last
        };
        enum class StringType : unsigned char
        {
            None,
            Ascii,
            Unicode
        };
        struct OffsetTranslationMethod
        {
            FixSizeString<17> name;
            MethodID methodID;
        };
        struct DrawLineInfo
        {
            unsigned long long offset;
            unsigned int offsetAndNameSize;
            unsigned int numbersSize;
            unsigned int textSize;
            const unsigned char* start;
            const unsigned char* end;
            Character* chNameAndSize;
            Character* chNumbers;
            Character* chText;
            bool recomputeOffsets;
            DrawLineInfo() : recomputeOffsets(true)
            {
            }
        };
        struct
        {
            CharacterFormatMode charFormatMode;
            unsigned int nrCols;
            unsigned int lineAddressSize;
            unsigned int lineNameSize;
            unsigned int charactersPerLine;
            unsigned int visibleRows;
            unsigned int xName;
            unsigned int xAddress;
            unsigned int xNumbers;
            unsigned int xText;
        } Layout;
        struct
        {
            unsigned long long startView, currentPos;
            unsigned int base;
        } Cursor;
        struct
        {
            unsigned long long start, end, middle;
            unsigned int minCount;
            bool AsciiMask[256];
            StringType type;
        } StringInfo;
        struct
        {
            ColorPair Normal, Line, Highlighted;
        } CursorColors;
        struct Config
        {
            struct
            {
                ColorPair Inactive;
                ColorPair OutsideZone;
                ColorPair Normal;
                ColorPair Header;
                ColorPair Line;
                ColorPair Cursor;
                ColorPair Selection;
                ColorPair Ascii;
                ColorPair Unicode;
            } Colors;
            struct
            {
                AppCUI::Input::Key ChangeColumnsNumber;
                AppCUI::Input::Key ChangeBase;
            } Keys;
            bool Loaded;
        };

        Reference<GView::Object> obj;
        Utils::Selection selection;
        CharacterBuffer chars;
        const char16_t* CodePage;
        GView::Utils::ZonesList zList;
        unsigned long long bookmarks[10];
        OffsetTranslationMethod translationMethods[16];
        unsigned int translationMethodsCount;
        FixSizeString<29> name;

        static Config config;

        int PrintSelectionInfo(unsigned int selectionID, int x, int y, unsigned int width, Renderer& r);
        int PrintCursorPosInfo(int x, int y, unsigned int width, bool addSeparator, Renderer& r);
        int PrintCursorZone(int x, int y, unsigned int width, Renderer& r);
        int Print8bitValue(int x, int height, AppCUI::Utils::BufferView buffer, Renderer& r);
        int Print16bitValue(int x, int height, AppCUI::Utils::BufferView buffer, Renderer& r);
        int Print32bitValue(int x, int height, AppCUI::Utils::BufferView buffer, Renderer& r);

        void PrepareDrawLineInfo(DrawLineInfo& dli);
        void WriteHeaders(Renderer& renderer);
        void WriteLineAddress(DrawLineInfo& dli);
        void WriteLineNumbersToChars(DrawLineInfo& dli);
        void WriteLineTextToChars(DrawLineInfo& dli);
        void UpdateViewSizes();
        void MoveTo(unsigned long long offset, bool select);
        void MoveScrollTo(unsigned long long offset);
        void MoveToSelection(unsigned int selIndex);
        void SkipCurentCaracter(bool selected);
        void MoveTillEndBlock(bool selected);
        void MoveTillNextBlock(bool select, int dir);

        void UpdateStringInfo(unsigned long long offset);

        ColorPair OffsetToColorZone(unsigned long long offset);
        ColorPair OffsetToColor(unsigned long long offset);

        static bool LoadConfig();

      public:
        BufferViewer(const std::string_view& name, Reference<GView::Object> obj);

        virtual void Paint(Renderer& renderer) override;
        virtual void OnAfterResize(int newWidth, int newHeight) override;
        virtual bool OnKeyEvent(AppCUI::Input::Key keyCode, char16_t characterCode) override;
        virtual bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
        virtual bool OnEvent(Reference<Control>, Event eventType, int ID) override;

        virtual bool GoTo(unsigned long long offset) override;
        virtual bool Select(unsigned long long offset, unsigned long long size) override;
        virtual std::string_view GetName() override;

        virtual void AddZone(unsigned long long start, unsigned long long size, ColorPair col, std::string_view name) override;
        virtual void AddBookmark(unsigned char bookmarkID, unsigned long long fileOffset) override;
        virtual void AddOffsetTranslationMethod(std::string_view name, MethodID methodID) override;
        virtual void PaintCursorInformation(AppCUI::Graphics::Renderer& renderer, unsigned int width, unsigned int height) override;

        static void UpdateConfig(IniSection sect);
    };

    class GridViewer : public View::ViewControl, public View::GridViewerInterface
    {
    private:
        Reference<GView::Object> obj;
        FixSizeString<29> name;

    public:
        GridViewer(std::string_view name, Reference<GView::Object> obj);

        bool GoTo(unsigned long long offset) override;
        bool Select(unsigned long long offset, unsigned long long size) override;
        std::string_view GetName() override;
        void PaintCursorInformation(AppCUI::Graphics::Renderer& renderer, unsigned int width, unsigned int height) override;
    };
} // namespace View
namespace App
{
    namespace MenuCommands
    {
        constexpr int ARRANGE_VERTICALLY       = 100000;
        constexpr int ARRANGE_HORIZONTALLY     = 100001;
        constexpr int ARRANGE_CASCADE          = 100002;
        constexpr int ARRANGE_GRID             = 100003;
        constexpr int CLOSE                    = 100004;
        constexpr int CLOSE_ALL                = 100005;
        constexpr int CLOSE_ALL_EXCEPT_CURRENT = 100006;
        constexpr int SHOW_WINDOW_MANAGER      = 100007;

        constexpr int CHECK_FOR_UPDATES = 110000;
        constexpr int ABOUT             = 110001;

    }; // namespace MenuCommands
    class Instance
    {
        AppCUI::Controls::Menu* mnuWindow;
        AppCUI::Controls::Menu* mnuHelp;
        std::vector<GView::Type::Plugin> typePlugins;
        GView::Type::Plugin defaultPlugin;
        unsigned int defaultCacheSize;

        bool BuildMainMenus();
        bool LoadSettings();
        bool Add(std::unique_ptr<AppCUI::OS::IFile> file, const AppCUI::Utils::ConstString& name, std::string_view ext);
        bool UpdateSettingsForTypePlugin(AppCUI::Utils::IniObject& ini, const std::filesystem::path& pluginPath);

      public:
        Instance();
        bool Init();
        bool AddFileWindow(const std::filesystem::path& path);
        void Run();
        bool ResetConfiguration();
    };
    class FileWindow : public Window, public GView::View::WindowInterface, public AppCUI::Controls::Handlers::OnFocusInterface
    {
        Reference<Splitter> vertical, horizontal;
        Reference<Tab> view, verticalPanels, horizontalPanels;
        ItemHandle cursorInfoHandle;
        GView::Object obj;
        unsigned int defaultCursorViewSize;
        unsigned int defaultVerticalPanelsSize;
        unsigned int defaultHorizontalPanelsSize;

        void UpdateDefaultPanelsSizes(Reference<Splitter> splitter);

      public:
        FileWindow(const AppCUI::Utils::ConstString& name);

        void Start();

        Reference<Object> GetObject() override;
        bool AddPanel(Pointer<TabPage> page, bool vertical) override;
        Reference<View::BufferViewerInterface> AddBufferViewer(const std::string_view& name) override;
        Reference<View::GridViewerInterface> AddGridViewer(const std::string_view& name) override;
        Reference<View::ViewControl> GetCurrentView() override;

        bool OnKeyEvent(AppCUI::Input::Key keyCode, char16_t unicode) override;
        bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
        bool OnEvent(Reference<Control>, Event eventType, int) override;
        void OnFocus(Reference<Control> control) override;
    };
} // namespace App

} // namespace GView
