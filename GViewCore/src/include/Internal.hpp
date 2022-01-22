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
        static constexpr uint32 MAX_SELECTION_ZONES = 4;
        struct
        {
            uint64 start, end, originalPoint;
            FixSizeString<32> stringRepresentation;
        } zones[MAX_SELECTION_ZONES];
        bool singleSelectionZone;

      public:
        Selection();
        void Clear();
        bool Clear(int index);
        inline constexpr uint32 GetCount() const
        {
            return Selection::MAX_SELECTION_ZONES;
        }
        bool GetSelection(uint32 index, uint64& Start, uint64& End);
        void EnableMultiSelection(bool enable);
        inline void InvertMultiSelectionMode()
        {
            EnableMultiSelection(singleSelectionZone);
        }
        inline bool IsMultiSelectionEnabled() const
        {
            return !singleSelectionZone;
        }
        inline bool IsSingleSelectionEnabled() const
        {
            return singleSelectionZone;
        }
        int OffsetToSelection(uint64 offset, uint64& Start, uint64& End);
        bool Contains(uint64 offset) const;
        bool UpdateSelection(int index, uint64 offset);
        int BeginSelection(uint64 offset);
        bool SetSelection(uint32 index, uint64 start, uint64 end);
        string_view GetStringRepresentation(uint32 index);
    };

    class CharacterSet
    {
        bool Ascii[256];

      public:
        CharacterSet();
        CharacterSet(bool asciiMask[256]);
        void ClearAll();
        void SetAll();
        bool Set(uint32 start, uint32 end, bool value);
        void Set(uint8 position, bool value);
        bool Set(std::string_view stringRepresentation, bool value);
        bool GetStringRepresentation(String& str) const;
        void CopySetTo(bool ascii[256]);
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
        constexpr int EXIT_GVIEW               = 100008;

        constexpr int CHECK_FOR_UPDATES = 110000;
        constexpr int ABOUT             = 110001;

    }; // namespace MenuCommands
    class Instance : public AppCUI::Utils::PropertiesInterface, public AppCUI::Controls::Handlers::OnEventInterface
    {
        AppCUI::Controls::Menu* mnuWindow;
        AppCUI::Controls::Menu* mnuHelp;
        std::vector<GView::Type::Plugin> typePlugins;
        GView::Type::Plugin defaultPlugin;
        uint32 defaultCacheSize;
        AppCUI::Input::Key keyToChangeViews, keyToSwitchToView;

        bool BuildMainMenus();
        bool LoadSettings();
        bool Add(std::unique_ptr<AppCUI::OS::IFile> file, const AppCUI::Utils::ConstString& name, std::string_view ext);

      public:
        Instance();
        bool Init();
        bool AddFileWindow(const std::filesystem::path& path);

        // inline getters
        constexpr inline uint32 GetDefaultCacheSize() const
        {
            return this->defaultCacheSize;
        }
        constexpr inline AppCUI::Input::Key GetKeyToChangeViewes() const
        {
            return this->keyToChangeViews;
        }
        constexpr inline AppCUI::Input::Key GetKeyToSwitchToView() const
        {
            return this->keyToSwitchToView;
        }

        // property interface
        virtual bool GetPropertyValue(uint32 propertyID, PropertyValue& value) override;
        virtual bool SetPropertyValue(uint32 propertyID, const PropertyValue& value, String& error) override;
        virtual void SetCustomPropertyValue(uint32 propertyID) override;
        virtual bool IsPropertyValueReadOnly(uint32 propertyID) override;
        virtual const vector<Property> GetPropertiesList() override;

        // AppCUI Handlers
        virtual bool OnEvent(Reference<Control> control, Event eventType, int ID) override;
    };
    class FileWindowProperties : public Window
    {
      public:
        FileWindowProperties(Reference<Tab> viewContainer);
        bool OnEvent(Reference<Control>, Event eventType, int) override;
    };
    class FileWindow : public Window, public GView::View::WindowInterface, public AppCUI::Controls::Handlers::OnFocusInterface
    {
        Reference<GView::App::Instance> gviewApp;
        Reference<Splitter> vertical, horizontal;
        Reference<Tab> view, verticalPanels, horizontalPanels;
        ItemHandle cursorInfoHandle;
        GView::Object obj;
        unsigned int defaultCursorViewSize;
        unsigned int defaultVerticalPanelsSize;
        unsigned int defaultHorizontalPanelsSize;
        int32 lastHorizontalPanelID;

        void UpdateDefaultPanelsSizes(Reference<Splitter> splitter);

      public:
        FileWindow(const AppCUI::Utils::ConstString& name, Reference<GView::App::Instance> gviewApp);

        void Start();

        Reference<Object> GetObject() override;
        bool AddPanel(Pointer<TabPage> page, bool vertical) override;
        bool CreateViewer(const std::string_view& name, View::BufferViewer::Settings& settings) override;
        bool CreateViewer(const std::string_view& name, View::ImageViewer::Settings& settings) override;
        bool CreateViewer(const std::string_view& name, View::GridViewer::Settings& settings) override;
        bool CreateViewer(const std::string_view& name, View::DissasmViewer::Settings& settings) override;
        bool CreateViewer(const std::string_view& name, View::TextViewer::Settings& settings) override;
        Reference<View::ViewControl> GetCurrentView() override;

        bool OnKeyEvent(AppCUI::Input::Key keyCode, char16_t unicode) override;
        bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
        bool OnEvent(Reference<Control>, Event eventType, int) override;
        void OnFocus(Reference<Control> control) override;
    };
} // namespace App

} // namespace GView
