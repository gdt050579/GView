#pragma once

#include "Internal.hpp"

namespace GView::Type::PCAP
{
class PCAPFile : public TypeInterface
{
  public:
    Buffer data; // it s maximum 0xFFFF so just save it here

    Header header;
    std::vector<std::pair<PacketHeader*, uint32>> packetHeaders;

    PCAPFile();
    virtual ~PCAPFile()
    {
    }

    bool Update();

    std::string_view GetTypeName() override
    {
        return "PCAP";
    }
};

namespace Panels
{
    static ListViewItem AddMACElement(Reference<ListView> list, std::string_view name, const MAC& mac)
    {
        CHECK(list.IsValid(), ListViewItem{}, "");

        LocalString<64> tmp;
        return list->AddItem(
              { name.data(),
                tmp.Format("%02X:%02X:%02X:%02X:%02X:%02X", mac.arr[0], mac.arr[1], mac.arr[2], mac.arr[3], mac.arr[4], mac.arr[5]) });
    }

    static ListViewItem AddIPElement(Reference<ListView> list, std::string_view name, uint32 ip)
    {
        CHECK(list.IsValid(), ListViewItem{}, "");

        union
        {
            uint8 values[4];
            uint32 value;
        } ipv4{ .value = ip };

        LocalString<64> tmp;
        return list->AddItem(
              { name.data(), tmp.Format("%02u.%02u.%02u.%02u", ipv4.values[3], ipv4.values[2], ipv4.values[1], ipv4.values[0]) });
    }

    class Information : public AppCUI::Controls::TabPage
    {
        Reference<Object> object;
        Reference<GView::Type::PCAP::PCAPFile> pcap;
        Reference<AppCUI::Controls::ListView> general;
        Reference<AppCUI::Controls::ListView> issues;

        inline static const auto dec       = NumericFormat{ NumericFormatFlags::None, 10, 3, ',' };
        inline static const auto hexUint32 = NumericFormat{ NumericFormatFlags::HexPrefix, 16, 0, ' ', 4 };
        inline static const auto hexUint64 = NumericFormat{ NumericFormatFlags::HexPrefix, 16, 0, ' ', 8 };

        void UpdateGeneralInformation();
        void UpdateIssues();
        void RecomputePanelsPositions();

        void AddDateTime(std::string_view name, std::string_view format, uint64 value)
        {
            LocalString<1024> ls;
            NumericFormatter nf;
            AppCUI::OS::DateTime dt;
            dt.CreateFromFileTime(value);
            const auto valueHex = nf.ToString(value, hexUint64);
            general->AddItem({ name, ls.Format(format.data(), dt.GetStringRepresentation().data(), valueHex.data()) })
                  .SetType(ListViewItem::Type::Emphasized_1);
        }

        template <typename T>
        ListViewItem AddDecAndHexElement(std::string_view name, std::string_view format, T value)
        {
            LocalString<1024> ls;
            NumericFormatter nf;
            NumericFormatter nf2;

            static const auto hexBySize = NumericFormat{ NumericFormatFlags::HexPrefix, 16, 0, ' ', sizeof(T) * 2 };

            const auto v    = nf.ToString(value, dec);
            const auto vHex = nf2.ToString(value, hexBySize);
            return general->AddItem({ name, ls.Format(format.data(), v.data(), vHex.data()) });
        }

      public:
        Information(Reference<Object> _object, Reference<GView::Type::PCAP::PCAPFile> _pcap);

        void Update();
        virtual void OnAfterResize(int newWidth, int newHeight) override
        {
            RecomputePanelsPositions();
        }
        bool OnUpdateCommandBar(Application::CommandBar& commandBar) override;
        bool OnEvent(Reference<Control> ctrl, Event evnt, int controlID) override;
    };

    class Packets : public AppCUI::Controls::TabPage
    {
        Reference<PCAPFile> pcap;
        Reference<GView::View::WindowInterface> win;
        Reference<AppCUI::Controls::ListView> list;
        int32 Base;

        std::string_view GetValue(NumericFormatter& n, uint64 value);
        void GoToSelectedSection();
        void SelectCurrentSection();
        void OpenPacket();

      public:
        Packets(Reference<PCAPFile> _pcap, Reference<GView::View::WindowInterface> win);

        void Update();
        bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
        bool OnEvent(Reference<Control>, Event evnt, int controlID) override;
    };
}; // namespace Panels
} // namespace GView::Type::PCAP
