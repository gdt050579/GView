#pragma once

#include "Internal.hpp"

namespace GView::Type::LNK
{
class LNKFile : public TypeInterface
{
  public:
    Header header;

    LNKFile();
    virtual ~LNKFile()
    {
    }

    bool Update();

    std::string_view GetTypeName() override
    {
        return "LNK";
    }
};

namespace Panels
{
    class Information : public AppCUI::Controls::TabPage
    {
        Reference<Object> object;
        Reference<GView::Type::LNK::LNKFile> lnk;
        Reference<AppCUI::Controls::ListView> general;
        Reference<AppCUI::Controls::ListView> issues;

        inline static const auto dec = NumericFormat{ NumericFormatFlags::None, 10, 3, ',' };
        inline static const auto hex = NumericFormat{ NumericFormatFlags::HexPrefix, 16 };

        void UpdateGeneralInformation();
        void UpdateIssues();
        void RecomputePanelsPositions();

      public:
        Information(Reference<Object> _object, Reference<GView::Type::LNK::LNKFile> _lnk);

        void Update();
        virtual void OnAfterResize(int newWidth, int newHeight) override
        {
            RecomputePanelsPositions();
        }
        bool OnUpdateCommandBar(Application::CommandBar& commandBar) override;
        bool OnEvent(Reference<Control> ctrl, Event evnt, int controlID) override;
    };
}; // namespace Panels
} // namespace GView::Type::LNK
