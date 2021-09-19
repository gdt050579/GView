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
        };
        class Instance
        {
            AppCUI::Controls::Menu* mnuWindow;
            std::vector<GView::Type::Plugin> typePlugins;

            bool BuildMainMenus();
            bool LoadSettings();
        public:
            bool Init();
            void Run();
        };
    }
}
