#pragma once

#include "Internal.hpp"

using namespace AppCUI;
using namespace AppCUI::OS;
using namespace AppCUI::Controls;
using namespace AppCUI::Application;
using namespace GView::Type;
using namespace GView::View;

namespace GView::Type::JT
{
class JTFile : public TypeInterface
{
  public:
    FileHeader fh{};
    TOCSegment tc{};

  public:
    JTFile();
    virtual ~JTFile()
    {
    }

    bool Update();

    std::string_view GetTypeName() override
    {
        return "JT";
    }
    void RunCommand(std::string_view) override
    {
    }

  public:
    Reference<GView::Utils::SelectionZoneInterface> selectionZoneInterface;

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
    static ListViewItem AddGUIDElement(Reference<ListView> list, std::string_view name, MyGUID& guid)
    {
        CHECK(list.IsValid(), ListViewItem{}, "");

        LocalString<1024> ls;
        auto element = list->AddItem({ name,
                                       ls.Format(
                                             "{%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX}",
                                             guid.a,
                                             guid.b,
                                             guid.c,
                                             guid.d[0],
                                             guid.d[1],
                                             guid.d[2],
                                             guid.d[3],
                                             guid.d[4],
                                             guid.d[5],
                                             guid.d[6],
                                             guid.d[7]) });
        element.SetType(ListViewItem::Type::Emphasized_1);

        return element;
    }

    class Information : public TabPage
    {
        Reference<Object> object;
        Reference<JT::JTFile> jt;
        Reference<ListView> general;
        Reference<ListView> issues;

        inline static const auto dec = NumericFormat{ NumericFormatFlags::None, 10, 3, ',' };
        inline static const auto hex = NumericFormat{ NumericFormatFlags::HexPrefix, 16 };

        void UpdateGeneralInformation();
        void UpdateIssues();
        void RecomputePanelsPositions();

        void AddDateTime(std::string_view name, std::string_view format, uint64 value)
        {
            LocalString<1024> ls;
            NumericFormatter nf;
            DateTime dt;
            dt.CreateFromFileTime(value);
            const auto valueHex = nf.ToString(value, hex);
            general->AddItem({ name, ls.Format(format.data(), dt.GetStringRepresentation().data(), valueHex.data()) })
                  .SetType(ListViewItem::Type::Emphasized_1);
        }

        template <typename T>
        ListViewItem AddDecAndHexElement(std::string_view name, std::string_view format, T value)
        {
            LocalString<1024> ls;
            NumericFormatter nf;
            NumericFormatter nf2;

            const auto v    = nf.ToString(value, dec);
            const auto vHex = nf2.ToString(value, hex);
            return general->AddItem({ name, ls.Format(format.data(), v.data(), vHex.data()) });
        }

      public:
        Information(Reference<Object> _object, Reference<JT::JTFile> _jt);

        void Update();
        virtual void OnAfterResize(int newWidth, int newHeight) override
        {
            RecomputePanelsPositions();
        }
        bool OnUpdateCommandBar(CommandBar& commandBar) override;
        bool OnEvent(Reference<Control> ctrl, Event evnt, int controlID) override;
    };

    class Segments : public TabPage
    {
        Reference<JTFile> jt;
        Reference<WindowInterface> win;
        Reference<ListView> list;
        int32 Base;

        std::string_view GetValue(NumericFormatter& n, uint64 value);
        void GoToSelectedSection();
        void SelectCurrentSection();

      public:
        Segments(Reference<JTFile> _jt, Reference<WindowInterface> win);

        void Update();
        bool OnUpdateCommandBar(CommandBar& commandBar) override;
        bool OnEvent(Reference<Control>, Event evnt, int controlID) override;
    };
}; // namespace Panels
} // namespace GView::Type::JT
