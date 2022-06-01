#pragma once

#include "utils.hpp"

namespace GView::Type::ELF
{
class ELFFile : public TypeInterface
{
  public:
    Elf32_Ehdr header32;
    Elf64_Ehdr header64;
    bool is64{ false };

    std::vector<Elf32_Phdr> programs32;
    std::vector<Elf64_Phdr> programs64;

  public:
    ELFFile();
    virtual ~ELFFile()
    {
    }

    bool Update();

    std::string_view GetTypeName() override
    {
        return "ELF";
    }
};

namespace Panels
{
    class Information : public AppCUI::Controls::TabPage
    {
        inline static const auto dec = NumericFormat{ NumericFormatFlags::None, 10, 3, ',' };
        inline static const auto hex = NumericFormat{ NumericFormatFlags::HexPrefix, 16 };

        const std::string_view format            = "%-16s (%s)";
        const std::string_view formatDescription = "%-16s (%s) %s";

        Reference<Object> object;
        Reference<GView::Type::ELF::ELFFile> elf;
        Reference<AppCUI::Controls::ListView> general;
        Reference<AppCUI::Controls::ListView> issues;

        void UpdateGeneralInformation();
        void UpdateHeader();
        void UpdateIssues();
        void RecomputePanelsPositions();

        template <typename T>
        ListViewItem AddDecAndHexElement(
              std::string_view name, std::string_view format, T value, ListViewItem::Type type = ListViewItem::Type::Normal)
        {
            LocalString<1024> ls;
            NumericFormatter nf;
            NumericFormatter nf2;

            // static const auto hexBySize = NumericFormat{ NumericFormatFlags::HexPrefix, 16, 0, ' ', sizeof(T) * 2 };
            static const auto hexBySize = NumericFormat{ NumericFormatFlags::HexPrefix, 16, 0, ' ' };

            const auto v    = nf.ToString(value, dec);
            const auto vHex = nf2.ToString(value, hexBySize);
            auto it         = general->AddItem({ name, ls.Format(format.data(), v.data(), vHex.data()) });
            it.SetType(type);

            return it;
        }

      public:
        Information(Reference<Object> _object, Reference<GView::Type::ELF::ELFFile> elf);

        void Update();
        virtual void OnAfterResize(int newWidth, int newHeight) override;
    };

    class Segments : public AppCUI::Controls::TabPage
    {
        Reference<ELFFile> elf;
        Reference<GView::View::WindowInterface> win;
        Reference<AppCUI::Controls::ListView> list;
        int32 Base;

        std::string_view GetValue(NumericFormatter& n, uint64 value);
        void GoToSelectedSection();
        void SelectCurrentSection();

      public:
        Segments(Reference<ELFFile> elf, Reference<GView::View::WindowInterface> win);

        void Update();
        bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
        bool OnEvent(Reference<Control>, Event evnt, int controlID) override;
    };
}; // namespace Panels
} // namespace GView::Type::ELF
