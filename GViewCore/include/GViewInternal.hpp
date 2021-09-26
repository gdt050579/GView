#include "GView.hpp"

namespace GView
{
    namespace View
    {
        class BufferViewBuilder : public IViewBuilder
        {
        public:
            BufferViewBuilder(const std::string_view& name);
            
            // interface
            AppCUI::Controls::Control* Build() override;
        };
        class Builder : public IBuilder
        {
            std::vector<std::unique_ptr<AppCUI::Controls::Control>> infoPanels;
            std::vector<std::unique_ptr<IViewBuilder>> views;
        public:
            Builder();
            bool AddPanel(std::unique_ptr<AppCUI::Controls::Control> ctrl, bool vertical) override;
            IBufferViewBuilder& AddBufferView(const std::string_view &name) override;
        };
    }
}