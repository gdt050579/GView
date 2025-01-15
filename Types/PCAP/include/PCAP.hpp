#pragma once

#include "Internal.hpp"
#include "Utils.hpp"
#include "StreamManager.hpp"

namespace GView::Type::PCAP
{
class PCAPFile : public TypeInterface, public View::ContainerViewer::EnumerateInterface, public View::ContainerViewer::OpenItemInterface
{
  public:
    Buffer data; // it's maximum 0xFFFF so just save it here

    Header header;
    std::vector<std::pair<PacketHeader*, uint32>> packetHeaders;
    StreamManager streamManager;

	uint32 currentItemIndex{ 0 };
    std::vector<uint32> currentChildIndexes{};

    PCAPFile();

    ~PCAPFile() override = default;

    bool Update();

    std::string_view GetTypeName() override
    {
        return "PCAP";
    }
    void RunCommand(std::string_view) override
    {
    }

    virtual bool BeginIteration(std::u16string_view path, AppCUI::Controls::TreeViewItem parent) override;
    virtual bool PopulateItem(TreeViewItem item) override;
    virtual void OnOpenItem(std::u16string_view path, AppCUI::Controls::TreeViewItem item) override;
    virtual bool UpdateKeys(KeyboardControlsInterface* interface) override
    {
        return true;
    }

    bool RegisterPayloadParser(unique_ptr<PayloadDataParserInterface> parser)
    {
        return streamManager.RegisterPayloadParser(std::move(parser));
    }

  public:
    void InitStreamManager(Reference<GView::View::WindowInterface> windowParam)
    {
        streamManager.InitStreamManager(windowParam);
    }
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

	std::vector<std::pair<std::string, std::string>> GetPropertiesForContainerView();
};

namespace Panels
{
    static ListViewItem AddMACElement(Reference<ListView> list, std::string_view name, const MAC& mac)
    {
        CHECK(list.IsValid(), ListViewItem{}, "");

        LocalString<64> tmp;
        return list->AddItem(
              { name.data(),
                tmp.Format("%02X:%02X:%02X:%02X:%02X:%02X (0x%X)", mac.arr[0], mac.arr[1], mac.arr[2], mac.arr[3], mac.arr[4], mac.arr[5], mac.value) });
    }

    static ListViewItem AddIPv4Element(Reference<ListView> list, std::string_view name, uint32 ip)
    {
        CHECK(list.IsValid(), ListViewItem{}, "");

        LocalString<64> tmp;
        Utils::IPv4ElementToString(ip, tmp);
        return list->AddItem({ name.data(), tmp.GetText() });
    }

    static ListViewItem AddIPv6Element(Reference<ListView> list, std::string_view name, uint16 ipv6[8])
    {
        CHECK(list.IsValid(), ListViewItem{}, "");

        LocalString<64> tmp;
        Utils::IPv6ElementToString(ipv6, tmp);
        return list->AddItem({ name.data(), tmp.GetText() });
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
        void UpdatePcapHeader();
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

        class PacketDialog : public Window
        {
            Reference<GView::Object> object;
            Reference<ListView> list;
            int32 base;

            std::string_view GetValue(NumericFormatter& n, uint64 value);
            void Add_PacketHeader(LinkType type, const PacketHeader* packet);
            void Add_Package_EthernetHeader(PacketData *packetData, const Package_EthernetHeader* peh, uint32 packetInclLen);
            void Add_Package_NullHeader(PacketData* packetData, const Package_NullHeader* pnh, uint32 packetInclLen);
            void Add_IPv4Header(PacketData* packetData, const IPv4Header* ipv4, uint32 packetInclLen);
            void Add_IPv6Header(PacketData* packetData, const IPv6Header* ipv6, uint32 packetInclLen);
            void Add_UDPHeader(PacketData* packetData, const UDPHeader* udp);
            void Add_DNSHeader(PacketData* packetData, const DNSHeader* dns);
            void Add_ICMPHeader(PacketData* packetData, const ICMPHeader_Base* icmpBase, uint32 icmpSize);
            void Add_DNSHeader_Question(const DNSHeader_Question& question);
            void Add_TCPHeader(PacketData* packetData, const TCPHeader* tcp, uint32 packetInclLen);
            void Add_TCPHeader_Options(const uint8* optionsPtr, uint32 optionsLen);

          public:
            PacketDialog(
                  Reference<GView::Object> _object, std::string_view name, std::string_view layout, LinkType type, const PacketHeader* packet, int32 _base);
        };
    };
}; // namespace Panels
} // namespace GView::Type::PCAP
