#include <AppCUI/include/AppCUI.hpp>
#include <../GViewCore/include/GView.hpp>

#include <set>

using namespace AppCUI::Controls;
using namespace AppCUI::Graphics;
using namespace AppCUI::Utils;

namespace GView
{
    namespace Type
    {
        constexpr unsigned int MAX_PATTERN_VALUES = 21; // muwt be less than 255
        class SimplePattern
        {
            unsigned char CharactersToMatch[MAX_PATTERN_VALUES];
            unsigned char Count;
            unsigned short Offset;
        public:
            SimplePattern();
            bool Init(std::string_view text, unsigned int ofs);
            bool Match(Buffer buf) const;
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

            bool (*fnValidate)(const Buffer &buf, const std::string_view &extension);
            bool (*fnCreate)(GView::View::IBuilder& builder, const GView::Object& object);
            
            bool LoadPlugin();
        public:
            Plugin();
            bool Init(AppCUI::Utils::IniSection section);
            void Init();
            bool Validate(Buffer buf, std::string_view extension);
            bool Create(GView::View::IBuilder& builder, const GView::Object& object) const;
            inline bool operator< (const Plugin& plugin) const { return Priority > plugin.Priority; }
        };
    }
    namespace View
    {
        class BufferViewBuilder : public IBufferViewBuilder
        {
        public:
            BufferViewBuilder(const std::string_view& name);

            // interface
            void AddZone(unsigned long long start, unsigned long long size, AppCUI::Graphics::ColorPair col, std::string_view name) override;
            Pointer<AppCUI::Controls::Control> Build(GView::Object& obj) override;
        };
        class BufferView : public UserControl
        {
            GView::Object& fileObj;
        public:
            BufferView(GView::Object& obj, BufferViewBuilder* settings);

            virtual void Paint(Renderer& renderer) override;
        };

        class Builder : public IBuilder
        {            
        public:
            std::vector<std::unique_ptr<AppCUI::Controls::TabPage>> verticalPanels;
            std::vector<std::unique_ptr<AppCUI::Controls::TabPage>> horizontalPanels;
            std::vector<std::unique_ptr<IViewBuilder>> views;
            std::unique_ptr<GView::Object> fileObject;
        
            Builder(std::unique_ptr<GView::Object> obj);
            bool AddPanel(std::unique_ptr<AppCUI::Controls::TabPage> ctrl, bool vertical) override;
            Reference<IBufferViewBuilder> AddBufferView(const std::string_view& name) override;
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
        class FileWindow : public Window
        {            
            Reference<Splitter> vertical, horizontal;
            Reference<Tab> view, verticalPanels, horizontalPanels;
            View::Builder builder;
        public:
            FileWindow(std::unique_ptr<GView::Object> obj);
            bool Create(const GView::Type::Plugin& type);
        };
    }

}
