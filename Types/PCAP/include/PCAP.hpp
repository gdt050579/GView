#pragma once

#include "Internal.hpp"

namespace GView::Type::PCAP
{
class PCAPFile : public TypeInterface
{
  public:
    Header header;

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
}; // namespace Panels
} // namespace GView::Type::PCAP
