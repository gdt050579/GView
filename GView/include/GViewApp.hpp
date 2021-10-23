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
        
    }
    namespace Type
    {
        namespace DefaultTypePlugin
        {
            bool Validate(const GView::Utils::Buffer& buf, const std::string_view& extension);
            Utils::Instance CreateInstance();
            void DeleteInstance(Utils::Instance instance);
            bool PopulateWindow(Reference<GView::View::Window> win);
        }
        constexpr unsigned int MAX_PATTERN_VALUES = 21; // muwt be less than 255
        class SimplePattern
        {
            unsigned char CharactersToMatch[MAX_PATTERN_VALUES];
            unsigned char Count;
            unsigned short Offset;
        public:
            SimplePattern();
            bool Init(std::string_view text, unsigned int ofs);
            bool Match(GView::Utils::Buffer buf) const;
            inline bool Empty() const { return Count == 0; }
        };
        constexpr unsigned int PLUGIN_NAME_MAX_SIZE = 31;  // must be less than 255 !!!
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

            bool (*fnValidate)(const GView::Utils::Buffer &buf, const std::string_view &extension);
            Utils::Instance (*fnCreateInstance)();
            void (*fnDeleteInstance)(Utils::Instance instance);
            bool (*fnPopulateWindow)(Reference<GView::View::Window> win);
            
            bool LoadPlugin();
        public:
            Plugin();
            bool Init(AppCUI::Utils::IniSection section);
            void Init();
            bool Validate(GView::Utils::Buffer buf, std::string_view extension);
            bool PopulateWindow(Reference<GView::View::Window> win) const;
            Utils::Instance CreateInstance() const;
            void DeleteInstance(Utils::Instance instance) const;
            inline bool operator< (const Plugin& plugin) const { return Priority > plugin.Priority; }
        };
    }
    namespace View
    {
        namespace Buffer
        {
            struct OffsetTranslationMethod
            {
                char name[14];
                unsigned char nameLength;
                MethodID  methodID;                
            };
            class Factory : public FactoryInterface
            {
            public:
                GView::Utils::ZonesList zList;
                unsigned long long bookmarks[10];
                OffsetTranslationMethod translationMethods[16];
                unsigned int translationMethodsCount;
                QueryInterface* queryInterface;
            public:
                Factory(const std::string_view& name);

                // interface
                void AddZone(unsigned long long start, unsigned long long size, AppCUI::Graphics::ColorPair col, std::string_view name) override;
                void AddBookmark(unsigned char index, unsigned long long fileOffset);
                void AddOffsetTranslationMethod(std::string_view name, MethodID ID);
                void SetQueryInterface(QueryInterface* queryInterface);
                Pointer<AppCUI::Controls::Control> Build(GView::Object& obj) override;
            };
            class ViewerControl : public UserControl
            {
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
                    DrawLineInfo(): recomputeOffsets(true) { }
                };
                struct 
                {
                    CharacterFormatMode charFormatMode;
                    unsigned int nrCols;
                    unsigned int lineOffsetSize;
                    unsigned int lineNameSize;
                    unsigned int charactersPerLine;
                    unsigned int visibleRows;                
                } Layout;
                struct 
                {
                    unsigned long long startView, currentPos;
                } Cursor;

                GView::Object& fileObj;
                CharacterBuffer chars;
                const char16_t* CodePage;

                void PrepareDrawLineInfo(DrawLineInfo& dli);
                void WriteLineNumbersToChars(DrawLineInfo& dli);
                void WriteLineTextToChars(DrawLineInfo& dli);
                void UpdateViewSizes();
                void MoveTo(unsigned long long offset, bool select);
                void MoveScrollTo(unsigned long long offset);
                void MoveToSelection(unsigned int selIndex);
                void SkipCurentCaracter(bool selected);
                void MoveTillEndBlock(bool selected);
                void MoveTillNextBlock(bool select, int dir);
            public:
                ViewerControl(GView::Object& obj, Factory* settings);

                virtual void Paint(Renderer& renderer) override;
                virtual void OnAfterResize(int newWidth, int newHeight) override;
                virtual bool OnKeyEvent(AppCUI::Input::Key keyCode, char16_t characterCode) override;
            };
        }


        class Factory : public FactoryInterface
        {            
        public:
            std::vector<std::unique_ptr<AppCUI::Controls::TabPage>> verticalPanels;
            std::vector<std::unique_ptr<AppCUI::Controls::TabPage>> horizontalPanels;
            std::vector<std::unique_ptr<GView::View::BuildInterface>> views;
            std::unique_ptr<GView::Object> fileObject;
        
            Factory(std::unique_ptr<GView::Object> obj);
            bool AddPanel(std::unique_ptr<AppCUI::Controls::TabPage> ctrl, bool vertical) override;
            Reference<Buffer::FactoryInterface> CreateBufferView(const std::string_view& name) override;
        };
    }
    namespace App
    {
        namespace MenuCommands
        {
            constexpr int ARRANGE_VERTICALLY = 100000;
            constexpr int ARRANGE_HORIZONTALLY = 100001;
            constexpr int ARRANGE_CASCADE = 100002;
            constexpr int ARRANGE_GRID = 100003;
            constexpr int CLOSE = 100004;
            constexpr int CLOSE_ALL = 100005;
            constexpr int CLOSE_ALL_EXCEPT_CURRENT = 100006;
            constexpr int SHOW_WINDOW_MANAGER = 100007;

            constexpr int CHECK_FOR_UPDATES = 110000;
            constexpr int ABOUT = 110001;

        };
        class Instance
        {
            AppCUI::Controls::Menu* mnuWindow;
            AppCUI::Controls::Menu* mnuHelp;
            std::vector<GView::Type::Plugin> typePlugins;
            GView::Type::Plugin defaultPlugin;
            unsigned int defaultCacheSize;

            bool BuildMainMenus();
            bool LoadSettings();
        public:
            Instance();
            bool Init();
            bool AddFileWindow(const std::filesystem::path& path);
            void Run();
        };
        class FileWindow : public View::Window
        {            
            Reference<Splitter> vertical, horizontal;
            Reference<Tab> view, verticalPanels, horizontalPanels;
        public:
            FileWindow(std::unique_ptr<GView::Object> obj);
            bool Create(const GView::Type::Plugin& type);
        };
    }

}
