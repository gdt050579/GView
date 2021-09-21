#include <AppCUI/include/AppCUI.hpp>
#include <../GViewCore/include/GView.hpp>

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
            bool Match(const unsigned char* buffer, unsigned int bufferSize) const;
            inline bool Empty() const { return Count == 0; }
        };
        constexpr unsigned int PLUGIN_NAME_MAX_SIZE = 29;  // must be less than 255 !!!
        class Plugin
        {
            unsigned char Name[PLUGIN_NAME_MAX_SIZE];
            unsigned char NameLength;
            unsigned short Prioriy;
            bool Loaded, Invalid;
            Interface* (*fnCreateTypeObject)(const Object& obj);

        public:
            Plugin();
            bool Init(const AppCUI::Utils::IniObject& obj, AppCUI::Utils::IniSection section);
            inline bool operator< (const Plugin& plugin) const { return Prioriy > plugin.Prioriy; }
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

            bool AddTypePluginFromIni(AppCUI::Utils::IniSection &section);
            bool BuildMainMenus();
            bool LoadSettings();
        public:
            bool Init();
            void Run();
        };
    }

}
