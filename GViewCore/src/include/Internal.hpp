#pragma once


#include "GView.hpp"

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
      public:
        Instance();
        bool Init();
        bool AddFileWindow(const std::filesystem::path& path);
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
        bool CreateViewer(const std::string_view& name, View::BufferViewer::Settings& settings) override;
        Reference<View::ViewControl> GetCurrentView() override;

        bool OnKeyEvent(AppCUI::Input::Key keyCode, char16_t unicode) override;
        bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
        bool OnEvent(Reference<Control>, Event eventType, int) override;
        void OnFocus(Reference<Control> control) override;
        
        
    };
} // namespace App

} // namespace GView
