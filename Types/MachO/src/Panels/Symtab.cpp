#include "MachO.hpp"

namespace GView::Type::MachO::Panels
{
using namespace AppCUI::Controls;
using namespace AppCUI::Input;

enum class Action : int32
{
    GoTo       = 1,
    Select     = 2,
    ChangeBase = 4
};

SymTab::SymTab(Reference<MachOFile> _machO, Reference<GView::View::WindowInterface> _win) : TabPage("SymTa&b")
{
    machO = _machO;
    win   = _win;
    Base  = 16;

    list = Factory::ListView::Create(
          this,
          "d:c",
          { { "Index", TextAlignament::Left, 8 },
            { "Name", TextAlignament::Left, 60 },
            { "Type", TextAlignament::Right, 20 },
            { "Section", TextAlignament::Right, 30 },
            { "[Align|Ordinal|Reference] Desc", TextAlignament::Right, 60 },
            { "Value", TextAlignament::Right, 15 } },
          ListViewFlags::None);
    Update();
}

std::string_view SymTab::GetValue(NumericFormatter& n, uint64_t value)
{
    if (Base == 10)
    {
        return n.ToString(value, { NumericFormatFlags::None, 10, 3, ',' });
    }

    return n.ToString(value, { NumericFormatFlags::HexPrefix, 16 });
}

void SymTab::GoToSelectedSection()
{
    const auto offset =
          machO->dySymTab->sc.symoff + (machO->is64 ? sizeof(MAC::nlist_64) : sizeof(MAC::nlist)) * list->GetCurrentItem().GetData(0);
    win->GetCurrentView()->GoTo(offset);
}

void SymTab::SelectCurrentSection()
{
    const auto offset =
          machO->dySymTab->sc.symoff + (machO->is64 ? sizeof(MAC::nlist_64) : sizeof(MAC::nlist)) * list->GetCurrentItem().GetData(0);
    const auto size   = (machO->is64 ? sizeof(MAC::nlist_64) : sizeof(MAC::nlist));
    win->GetCurrentView()->Select(offset, size);
}

void SymTab::Update()
{
    LocalString<128> tmp;
    NumericFormatter n;
    list->DeleteAllItems();

    static const auto dec = NumericFormat{ NumericFormatFlags::None, 10, 3, ',' };
    static const auto hex = NumericFormat{ NumericFormatFlags::HexPrefix, 16 };

    for (auto i = 0U; i < machO->dySymTab->sc.nsyms; i++)
    {
        auto item = list->AddItem(GetValue(n, i));
        item.SetData(i);

        const auto& nl = machO->dySymTab->objects[i];

        item.SetText(1, nl.symbolNameDemangled.c_str());

        std::string _1s;
        std::string _2s;

        if ((nl.n_type & (uint32_t) MAC::N_TYPE::TYPE) == 1)
        {
            _1s = MAC::NTypeNames.at((MAC::N_TYPE)(nl.n_type & (uint32_t) MAC::N_TYPE::TYPE));
        }
        else
        {
            _1s = MAC::NTypeBitsNames.at((MAC::N_TYPE_BITS)(nl.n_type & (uint32_t) MAC::N_TYPE::TYPE));
        }

        if (nl.n_type & (uint32_t) MAC::N_TYPE::STAB)
        {
            _1s = MAC::NStabTypeNames.at((MAC::N_STAB_TYPE) nl.n_type);
            _2s = MAC::NTypeNames.at(MAC::N_TYPE::STAB);
        }
        else if (nl.n_type & (uint32_t) MAC::N_TYPE::PEXT)
        {
            _2s = MAC::NTypeNames.at(MAC::N_TYPE::PEXT);
        }
        else if (nl.n_type & (uint32_t) MAC::N_TYPE::EXT)
        {
            _2s = MAC::NTypeNames.at(MAC::N_TYPE::EXT);
        }
        else
        {
            _2s = "NONE";
        }

        item.SetText(2, tmp.Format("[%s | %s] (%s)", _2s.c_str(), _1s.c_str(), std::string(GetValue(n, nl.n_type)).c_str()));

        if (nl.n_sect == MAC::NO_SECT)
        {
            _1s = "NO_SECT";
            _2s = "NO_SEGN";
        }
        else
        {
            auto current        = 0U;
            const auto required = nl.n_sect - 1ULL;
            auto found = true;
            for (const auto& segment : machO->segments)
            {
                for (const auto& section : segment.sections)
                {
                    if (current == required)
                    {
                        _1s = section.sectname;
                        _2s = section.segname;

                        found = true;
                        break;
                    }

                    if (found)
                    {
                        break;
                    }

                    current++;
                }
            }
        }

        item.SetText(3, tmp.Format("[%s | %s] (%s)", _1s.c_str(), _2s.c_str(), GetValue(n, nl.n_sect).data()));

        const auto align = std::string(GetValue(n, MAC::GET_COMM_ALIGN(nl.n_desc)));
        std::string ordinal;

        if (machO->header.flags & (uint32_t) MAC::MachHeaderFlags::TWOLEVEL)
        {
            switch ((MAC::OrdinalType) MAC::GET_LIBRARY_ORDINAL(nl.n_desc))
            {
            case MAC::OrdinalType::SELF_LIBRARY:
            case MAC::OrdinalType::MAX_LIBRARY:
            case MAC::OrdinalType::DYNAMIC_LOOKUP:
            case MAC::OrdinalType::EXECUTABLE:
                ordinal = MAC::OrdinalTypeNames.at((MAC::OrdinalType) MAC::GET_LIBRARY_ORDINAL(nl.n_desc));
                break;
            default:
            {
                const auto ord = MAC::GET_LIBRARY_ORDINAL(nl.n_desc) - 1;
                ordinal        = machO->dylibs[ord].name;
                ordinal        = ordinal.substr(ordinal.find_last_of("/\\") + 1);
            }
            break;
            }
        }
        else
        {
            ordinal = GetValue(n, MAC::GET_LIBRARY_ORDINAL(nl.n_desc));
        }

        const auto reference = nl.n_desc & MAC::REFERENCE_TYPE;
        switch ((MAC::ReferenceFlag) reference)
        {
        case MAC::ReferenceFlag::UNDEFINED_NON_LAZY:
        case MAC::ReferenceFlag::UNDEFINED_LAZY:
        case MAC::ReferenceFlag::DEFINED:
        case MAC::ReferenceFlag::PRIVATE_DEFINED:
        case MAC::ReferenceFlag::PRIVATE_UNDEFINED_NON_LAZY:
        case MAC::ReferenceFlag::PRIVATE_UNDEFINED_LAZY:
            _1s = MAC::ReferenceFlagNames.at((MAC::ReferenceFlag) reference);
            break;
        default:
            _1s = MAC::NDescBitTypeNames.at((MAC::N_DESC_BIT_TYPE) reference);
            break;
        }

        if ((MAC::N_TYPE_BITS)(nl.n_type & (uint32_t) MAC::N_TYPE::TYPE) == MAC::N_TYPE_BITS::INDR)
        {
            /*
             TODO:
             The n_value field is an index into the string table specifying the name of the other symbol. When that symbol is
             linked, both this and the other symbol have the same defined type and value.
             */

            throw "MAC::N_TYPE_BITS::INDR not implement!";
        }

        item.SetText(4, tmp.Format("[%s | %s | %s] (%s)", align.c_str(), ordinal.c_str(), _1s.c_str(), GetValue(n, nl.n_desc).data()));
        item.SetText(5, GetValue(n, nl.n_value));
    }
}

bool SymTab::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    commandBar.SetCommand(Key::Enter, "GoTo", static_cast<int32_t>(Action::GoTo));
    commandBar.SetCommand(Key::F9, "Select", static_cast<int32_t>(Action::Select));
    commandBar.SetCommand(Key::F2, Base == 10 ? "Dec" : "Hex", static_cast<int32_t>(Action::ChangeBase));

    return true;
}

bool SymTab::OnEvent(Reference<Control> ctrl, Event evnt, int controlID)
{
    CHECK(TabPage::OnEvent(ctrl, evnt, controlID) == false, true, "");

    if (evnt == Event::ListViewItemClicked)
    {
        GoToSelectedSection();
        return true;
    }

    if (evnt == Event::Command)
    {
        switch (static_cast<Action>(controlID))
        {
        case Action::GoTo:
            GoToSelectedSection();
            return true;
        case Action::ChangeBase:
            Base = 26 - Base;
            Update();
            return true;
        case Action::Select:
            SelectCurrentSection();
            return true;
        }
    }

    return false;
}
} // namespace GView::Type::MachO::Panels
