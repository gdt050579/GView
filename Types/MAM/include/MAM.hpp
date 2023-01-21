#pragma once

#include "Internal.hpp"

namespace GView::Type::MAM
{
class MAMFile : public TypeInterface
{
  public:
    uint32 signature;
    uint32 uncompressedSize;
    uint32 compressedSize;

    MAMFile() = default;
    virtual ~MAMFile()
    {
    }

    bool Update();
    bool Decompress();

    std::string_view GetTypeName() override
    {
        return "MAM";
    }

    void RunCommand(std::string_view) override;

  public:
    Reference<GView::Utils::SelectionZoneInteface> selectionZoneInterface;

    uint32 GetSelectionZonesCount() override
    {
        CHECK(selectionZoneInterface.IsValid(), 0, "");
        return selectionZoneInterface->GetSelectionZonesCount();
    }

    TypeInterface::SelectionZone GetSelectionZone(uint32 index) override
    {
        static auto d = TypeInterface::SelectionZone{ 0, 0 };
        CHECK(selectionZoneInterface.IsValid(), d, "");
        CHECK(index < selectionZoneInterface->GetSelectionZonesCount(), d, "");

        return selectionZoneInterface->GetSelectionZone(index);
    }
};

namespace Panels
{
    class Information : public AppCUI::Controls::TabPage
    {
        Reference<Object> object;
        Reference<GView::Type::MAM::MAMFile> mam;
        Reference<AppCUI::Controls::ListView> general;
        Reference<AppCUI::Controls::ListView> issues;

        inline static const auto dec = NumericFormat{ NumericFormatFlags::None, 10, 3, ',' };
        inline static const auto hex = NumericFormat{ NumericFormatFlags::HexPrefix, 16 };

        void UpdateGeneralInformation();
        void UpdateIssues();
        void RecomputePanelsPositions();

      public:
        Information(Reference<Object> _object, Reference<GView::Type::MAM::MAMFile> _mam);

        void Update();
        virtual void OnAfterResize(int newWidth, int newHeight) override
        {
            RecomputePanelsPositions();
        }
        bool OnUpdateCommandBar(Application::CommandBar& commandBar) override;
        bool OnEvent(Reference<Control> ctrl, Event evnt, int controlID) override;
    };
}; // namespace Panels
} // namespace GView::Type::MAM
