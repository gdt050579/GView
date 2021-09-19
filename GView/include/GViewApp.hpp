#include <AppCUI/include/AppCUI.hpp>
#include <../GViewCore/include/GView.hpp>

namespace GView
{
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

            bool BuildMainMenus();
            bool LoadSettings();
        public:
            bool Init();
            void Run();
        };
    }
}
