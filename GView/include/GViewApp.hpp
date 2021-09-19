#include <AppCUI/include/AppCUI.hpp>
#include <../GViewCore/include/GView.hpp>

namespace GView
{
    namespace App
    {
        class Instance
        {
            std::vector<GView::Type::Plugin> typePlugins;
        public:
            bool Init();
            void Run();
        };
    }
}
