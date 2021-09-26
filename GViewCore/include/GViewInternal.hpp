#include "GView.hpp"

namespace GView
{
    namespace View
    {
        class Builder : public IBuilder
        {
            std::vector<std::unique_ptr<AppCUI::Controls::Control>> infoPanel;
        public:


            bool AddPanel(std::unique_ptr<AppCUI::Controls::Control> ctrl, bool vertical) override;
        };
    }
}