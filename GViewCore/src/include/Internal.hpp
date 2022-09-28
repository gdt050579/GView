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
        inline constexpr bool HasSelection(uint32 index) const
        {
            if ((index >= 0) && (index < MAX_SELECTION_ZONES))
                return zones[index].start != INVALID_OFFSET;
            return false;
        }
        inline constexpr bool HasAnySelection() const
        {
            for (uint32 index = 0; index < MAX_SELECTION_ZONES; index++)
                if (zones[index].start != INVALID_OFFSET)
                    return true;
            return false;
        }
        inline constexpr uint32 GetCount() const
        {
            return Selection::MAX_SELECTION_ZONES;
        }
        bool GetSelection(uint32 index, uint64& Start, uint64& End);
        inline uint64 GetSelectionStart(uint32 index) const
        {
            if ((index >= 0) && (index < MAX_SELECTION_ZONES))
                return zones[index].start;
            return INVALID_OFFSET;
        }
        inline uint64 GetSelectionEnd(uint32 index) const
        {
            if ((index >= 0) && (index < MAX_SELECTION_ZONES))
                return zones[index].end;
            return INVALID_OFFSET;
        }
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
        void Set(uint64 s, uint64 e, AppCUI::Graphics::ColorPair c, std::string_view txt);
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
        bool Add(uint64 start, uint64 end, AppCUI::Graphics::ColorPair c, std::string_view txt);
        bool Reserve(unsigned int count);
        const Zone* OffsetToZone(uint64 offset);
    };

    struct UnicodeString
    {
        char16* text;
        uint32 size;
        uint32 allocated;

        UnicodeString() : text(nullptr), size(0), allocated(0)
        {
        }
        UnicodeString(char16* txt, uint32 sz, uint32 alloc) : text(txt), size(sz), allocated(alloc)
        {
        }
        inline UnicodeString Clone()
        {
            if (text == nullptr)
                return UnicodeString();
            auto* tmp = new char16[size];
            memcpy(tmp, text, this->size * sizeof(char16));
            return UnicodeString(tmp, size, size);
        }
        inline void Destroy()
        {
            if (text != nullptr)
                delete[] text;
            text      = nullptr;
            size      = 0;
            allocated = 0;
        }
    };

    namespace CharacterEncoding
    {
        enum class Encoding : uint8
        {
            Binary      = 0,
            Ascii       = 1,
            UTF8        = 2,
            Unicode16LE = 3,
            Unicode16BE = 4
        };
        class ExpandedCharacter
        {
            char16 unicodeValue;
            uint16 length;

          public:
            ExpandedCharacter() : unicodeValue(0), length(0)
            {
            }
            inline operator char16() const
            {
                return unicodeValue;
            }
            inline char16 GetChar() const
            {
                return unicodeValue;
            }
            inline uint32 Length() const
            {
                return length;
            }
            inline bool IsValid() const
            {
                return length > 0;
            }
            bool FromUTF8Buffer(const uint8* start, const uint8* end);
            inline bool FromEncoding(Encoding e, const uint8* start, const uint8* end)
            {
                if (start >= end)
                {
                    unicodeValue = 0;
                    length       = 0;
                    return false;
                }
                switch (e)
                {
                case Encoding::Ascii:
                case Encoding::Binary:
                    unicodeValue = *start;
                    length       = 1;
                    return true;
                case Encoding::Unicode16LE:
                    if (start + 1 < end)
                    {
                        length       = 2;
                        unicodeValue = *(const char16*) start;
                        return true;
                    }
                    length       = 0;
                    unicodeValue = 0;
                    return false;
                case Encoding::Unicode16BE:
                    if (start + 1 < end)
                    {
                        length       = 2;
                        unicodeValue = ((uint16) (*start) << 8) | (start[1]);
                        return true;
                    }
                    length       = 0;
                    unicodeValue = 0;
                    return false;
                case Encoding::UTF8:
                    if ((*start) < 0x80)
                    {
                        unicodeValue = *start;
                        length       = 1;
                        return true;
                    }
                    return FromUTF8Buffer(start, end);
                default:
                    unicodeValue = 0;
                    length       = 0;
                    return false;
                }
            }
        };

        class EncodedCharacter
        {
            uint8 internalBuffer[16];

            BufferView ToUTF8(char16 ch);

          public:
            inline BufferView Encode(char16 ch, Encoding encoding)
            {
                switch (encoding)
                {
                case Encoding::UTF8:
                    if (ch < 256)
                    {
                        internalBuffer[0] = static_cast<uint8>(ch);
                        return BufferView(internalBuffer, 1);
                    }
                    return ToUTF8(ch);
                case Encoding::Ascii:
                    internalBuffer[0] = ch < 256 ? static_cast<uint8>(ch) : '?';
                    return BufferView(internalBuffer, 1);
                case Encoding::Binary:
                case Encoding::Unicode16LE:
                    *(char16*) &internalBuffer = ch;
                    return BufferView(internalBuffer, 2);
                case Encoding::Unicode16BE:
                    internalBuffer[0] = ch >> 8;
                    internalBuffer[1] = ch & 0xFF;
                    return BufferView(internalBuffer, 2);
                }
                return BufferView{};
            }
        };
        Encoding AnalyzeBufferForEncoding(BufferView buf, bool checkForBOM, uint32& BOMLength);
        UnicodeString ConvertToUnicode16(BufferView buf);
        BufferView GetBOMForEncoding(Encoding encoding);
    }; // namespace CharacterEncoding
} // namespace Utils

namespace Generic
{
    constexpr uint32 MAX_PLUGINS_COMMANDS = 8;
    class Plugin
    {
        FixSizeString<29> Name;
        struct
        {
            FixSizeString<25> Name;
            Input::Key ShortKey;
        } Commands[MAX_PLUGINS_COMMANDS];
        uint32 CommandsCount;
        bool (*fnRun)(const string_view command, Reference<GView::Object> currentObject);

      public:
        Plugin();
        bool Init(AppCUI::Utils::IniSection section);
        void UpdateCommandBar(AppCUI::Application::CommandBar& commandBar, uint32 commandID);
        void Run(uint32 commandIndex, Reference<GView::Object> currentObject);
    };
}; // namespace Generic

namespace Type
{
    namespace DefaultTypePlugin
    {
        bool Validate(const AppCUI::Utils::BufferView& buf, const std::string_view& extension);
        TypeInterface* CreateInstance();
        bool PopulateWindow(Reference<GView::View::WindowInterface> win);
    } // namespace DefaultTypePlugin

    namespace FolderViewPlugin
    {
        TypeInterface* CreateInstance(const std::filesystem::path& path);
        bool PopulateWindow(Reference<GView::View::WindowInterface> win);
    } // namespace FolderViewPlugin

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

    struct PluginCommand
    {
        FixSizeString<25> name;
        Input::Key key;
    };

    class Plugin
    {
        SimplePattern pattern;
        std::vector<SimplePattern> patterns;
        std::vector<PluginCommand> commands;
        uint64 extension;
        std::set<uint64> extensions;
        FixSizeString<27> name;
        FixSizeString<124> description;
        uint16 priority;
        bool Loaded, Invalid;

        bool (*fnValidate)(const AppCUI::Utils::BufferView& buf, const std::string_view& extension);
        TypeInterface* (*fnCreateInstance)();
        bool (*fnPopulateWindow)(Reference<GView::View::WindowInterface> win);

        bool LoadPlugin();

      public:
        Plugin();
        bool Init(AppCUI::Utils::IniSection section);
        void Init();
        bool Validate(AppCUI::Utils::BufferView buf, std::string_view extension);
        bool PopulateWindow(Reference<GView::View::WindowInterface> win) const;
        TypeInterface* CreateInstance() const;
        inline bool operator<(const Plugin& plugin) const
        {
            return priority > plugin.priority;
        }
        inline std::string_view GetName() const
        {
            return name;
        }
        inline std::string_view GetDescription() const
        {
            return description;
        }
        inline const std::vector<PluginCommand>& GetCommands() const
        {
            return commands;
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

        constexpr int OPEN_FILE         = 120000;
        constexpr int OPEN_FOLDER       = 120001;
        constexpr int OPEN_PID          = 120002;
        constexpr int OPEN_PROCESS_TREE = 120003;

    }; // namespace MenuCommands

    class Instance : public AppCUI::Utils::PropertiesInterface,
                     public AppCUI::Controls::Handlers::OnEventInterface,
                     public AppCUI::Controls::Handlers::OnStartInterface
    {
        AppCUI::Controls::Menu* mnuWindow;
        AppCUI::Controls::Menu* mnuHelp;
        AppCUI::Controls::Menu* mnuFile;
        std::vector<GView::Type::Plugin> typePlugins;
        std::vector<GView::Generic::Plugin> genericPlugins;
        GView::Type::Plugin defaultPlugin;
        GView::Utils::ErrorList errList;
        uint32 defaultCacheSize;
        struct
        {
            AppCUI::Input::Key changeViews;
            AppCUI::Input::Key switchToView;
            AppCUI::Input::Key goTo;
            AppCUI::Input::Key find;
        } Keys;

        bool BuildMainMenus();
        bool LoadSettings();
        void OpenFile();
        void ShowErrors();
        bool Add(
              GView::Object::Type objType,
              std::unique_ptr<AppCUI::OS::DataObject> data,
              const AppCUI::Utils::ConstString& name,
              const AppCUI::Utils::ConstString& path,
              uint32 PID,
              std::string_view ext);
        bool AddFolder(const std::filesystem::path& path);

      public:
        Instance();
        bool Init();
        bool AddFileWindow(const std::filesystem::path& path);
        bool AddBufferWindow(BufferView buf, const ConstString& name, string_view typeExtension);
        void UpdateCommandBar(AppCUI::Application::CommandBar& commandBar);

        // inline getters
        constexpr inline uint32 GetDefaultCacheSize() const
        {
            return this->defaultCacheSize;
        }
        constexpr inline AppCUI::Input::Key GetChangeViewesKey() const
        {
            return this->Keys.changeViews;
        }
        constexpr inline AppCUI::Input::Key GetSwitchToViewKey() const
        {
            return this->Keys.switchToView;
        }
        constexpr inline AppCUI::Input::Key GetGoToKey() const
        {
            return this->Keys.goTo;
        }
        constexpr inline AppCUI::Input::Key GetFindKey() const
        {
            return this->Keys.find;
        }

        // property interface
        virtual bool GetPropertyValue(uint32 propertyID, PropertyValue& value) override;
        virtual bool SetPropertyValue(uint32 propertyID, const PropertyValue& value, String& error) override;
        virtual void SetCustomPropertyValue(uint32 propertyID) override;
        virtual bool IsPropertyValueReadOnly(uint32 propertyID) override;
        virtual const vector<Property> GetPropertiesList() override;

        // AppCUI Handlers
        virtual bool OnEvent(Reference<Control> control, Event eventType, int ID) override;
        virtual void OnStart(Reference<Control> control) override;

        // infos
        uint32 GetObjectsCount();
        Reference<GView::Object> GetObject(uint32 index);
        Reference<GView::Object> GetCurrentObject();
        uint32 GetTypePluginsCount();
        std::string_view GetTypePluginName(uint32 index);
        std::string_view GetTypePluginDescription(uint32 index);
    };

    class FileWindowProperties : public Window
    {
      public:
        FileWindowProperties(Reference<Tab> viewContainer);
        bool OnEvent(Reference<Control>, Event eventType, int) override;
    };

    class FileWindow : public Window, public GView::View::WindowInterface
    {
        Reference<GView::App::Instance> gviewApp;
        Reference<Splitter> vertical, horizontal;
        Reference<Tab> view, verticalPanels, horizontalPanels;
        ItemHandle cursorInfoHandle;
        std::unique_ptr<GView::Object> obj;
        unsigned int defaultCursorViewSize;
        unsigned int defaultVerticalPanelsSize;
        unsigned int defaultHorizontalPanelsSize;
        int32 lastHorizontalPanelID;

        void ShowFilePropertiesDialog();
        void ShowGoToDialog();
        void ShowFindDialog();
        void ShowCopyDialog();

      public:
        FileWindow(std::unique_ptr<GView::Object> obj, Reference<GView::App::Instance> gviewApp);

        void Start();

        Reference<Object> GetObject() override;
        bool AddPanel(Pointer<TabPage> page, bool vertical) override;
        bool CreateViewer(const std::string_view& name, View::BufferViewer::Settings& settings) override;
        bool CreateViewer(const std::string_view& name, View::ImageViewer::Settings& settings) override;
        bool CreateViewer(const std::string_view& name, View::GridViewer::Settings& settings) override;
        bool CreateViewer(const std::string_view& name, View::DissasmViewer::Settings& settings) override;
        bool CreateViewer(const std::string_view& name, View::TextViewer::Settings& settings) override;
        bool CreateViewer(const std::string_view& name, View::ContainerViewer::Settings& settings) override;
        bool CreateViewer(const std::string_view& name, View::LexicalViewer::Settings& settings) override;

        Reference<View::ViewControl> GetCurrentView() override;

        bool OnKeyEvent(AppCUI::Input::Key keyCode, char16_t unicode) override;
        bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
        bool OnEvent(Reference<Control>, Event eventType, int) override;
    };

    class ErrorDialog : public AppCUI::Controls::Window
    {
      public:
        ErrorDialog(const GView::Utils::ErrorList& errList);
        bool OnEvent(Reference<Control> control, Event eventType, int ID) override;
    };
} // namespace App
} // namespace GView
