#include "pe.hpp"

using namespace GView::Type::PE;
using namespace AppCUI::Controls;
using namespace AppCUI::Input;

constexpr int32 PE_SYMBOLS_CHANGEBASE = 1;

Panels::Symbols::Symbols(Reference<GView::Type::PE::PEFile> _pe, Reference<GView::View::WindowInterface> _win) : TabPage("S&ymbols")
{
    pe   = _pe;
    win  = _win;
    Base = 16;

    list = Factory::ListView::Create(
          this,
          "d:c",
          { "n:Index,w:8",
            "n:Name,w:60",
            "n:Name.Short,a:r,w:12",
            "n:Name.Long,a:r,w:12",
            "n:Value,a:r,w:10",
            "n:SectionNumber,a:r,w:24",
            "n:Type,a:r,w:20",
            "n:StorageClass,a:r,w:20",
            "n:NumberOfAuxSymbols,a:r,w:20" },
          ListViewFlags::None);

    Update();
}

std::string_view Panels::Symbols::GetValue(NumericFormatter& n, uint32 value)
{
    if (Base == 10)
    {
        return n.ToString(value, { NumericFormatFlags::None, 10, 3, ',' });
    }

    return n.ToString(value, { NumericFormatFlags::HexPrefix, 16 });
}

void Panels::Symbols::GetSymbolType(uint32 type, String& name)
{
    switch (type)
    {
    case SYM_NOT_A_FUNCTION:
        name.Set("NOT A FUNCTION");
        break;
    case SYM_FUNCTION:
        name.Set("FUNCTION");
        break;
    default:
        break;
    }
}

void Panels::Symbols::GetStorageClass(uint16 storageclass, String& name)
{
    switch (storageclass)
    {
    case IMAGE_SYM_CLASS_END_OF_FUNCTION:
        name.Set("END_OF_FUNCTION");
        break;
    case IMAGE_SYM_CLASS_NULL:
        name.Set("NULL");
        break;
    case IMAGE_SYM_CLASS_AUTOMATIC:
        name.Set("AUTOMATIC");
        break;
    case IMAGE_SYM_CLASS_EXTERNAL:
        name.Set("EXTERNAL");
        break;
    case IMAGE_SYM_CLASS_STATIC:
        name.Set("STATIC");
        break;
    case IMAGE_SYM_CLASS_REGISTER:
        name.Set("REGISTER");
        break;
    case IMAGE_SYM_CLASS_EXTERNAL_DEF:
        name.Set("EXTERNAL_DEF");
        break;
    case IMAGE_SYM_CLASS_LABEL:
        name.Set("LABEL");
        break;
    case IMAGE_SYM_CLASS_UNDEFINED_LABEL:
        name.Set("UNDEFINED_LABEL");
        break;
    case IMAGE_SYM_CLASS_MEMBER_OF_STRUCT:
        name.Set("MEMBER_OF_STRUCT");
        break;
    case IMAGE_SYM_CLASS_ARGUMENT:
        name.Set("ARGUMENT");
        break;
    case IMAGE_SYM_CLASS_STRUCT_TAG:
        name.Set("STRUCT_TAG");
        break;
    case IMAGE_SYM_CLASS_MEMBER_OF_UNION:
        name.Set("MEMBER_OF_UNION");
        break;
    case IMAGE_SYM_CLASS_UNION_TAG:
        name.Set("UNION_TAG");
        break;
    case IMAGE_SYM_CLASS_TYPE_DEFINITION:
        name.Set("TYPE_DEFINITION");
        break;
    case IMAGE_SYM_CLASS_UNDEFINED_STATIC:
        name.Set("UNDEFINED_STATIC");
        break;
    case IMAGE_SYM_CLASS_ENUM_TAG:
        name.Set("ENUM_TAG");
        break;
    case IMAGE_SYM_CLASS_MEMBER_OF_ENUM:
        name.Set("MEMBER_OF_ENUM");
        break;
    case IMAGE_SYM_CLASS_REGISTER_PARAM:
        name.Set("REGISTER_PARAM");
        break;
    case IMAGE_SYM_CLASS_BIT_FIELD:
        name.Set("BIT_FIELD");
        break;
    case IMAGE_SYM_CLASS_FAR_EXTERNAL:
        name.Set("FAR_EXTERNAL");
        break;
    case IMAGE_SYM_CLASS_BLOCK:
        name.Set("BLOCK");
        break;
    case IMAGE_SYM_CLASS_FUNCTION:
        name.Set("FUNCTION");
        break;
    case IMAGE_SYM_CLASS_END_OF_STRUCT:
        name.Set("END_OF_STRUCT");
        break;
    case IMAGE_SYM_CLASS_FILE:
        name.Set("FILE");
        break;
    case IMAGE_SYM_CLASS_SECTION:
        name.Set("SECTION");
        break;
    case IMAGE_SYM_CLASS_WEAK_EXTERNAL:
        name.Set("WEAK_EXTERNAL");
        break;
    case IMAGE_SYM_CLASS_CLR_TOKEN:
        name.Set("CLR_TOKEN");
        break;
    default:
        break;
    }
}

void Panels::Symbols::Update()
{
    LocalString<128> temp;
    NumericFormatter n;
    list->DeleteAllItems();

    for (auto i = 0U; i < pe->symbols.size(); i++)
    {
        const auto& s = pe->symbols.at(i);

        auto item = list->AddItem(GetValue(n, i));
        item.SetData<PE::PEFile::SymbolInformation>(&pe->symbols.at(i));

        item.SetText(1, s.name);
        item.SetText(2, GetValue(n, s.is.N.Name.Short));
        item.SetText(3, GetValue(n, s.is.N.Name.Long));
        item.SetText(4, GetValue(n, s.is.Value));

        String sectionName;
        pe->CopySectionName(s.is.SectionNumber > 0 ? s.is.SectionNumber - 1 : s.is.SectionNumber, sectionName);
        item.SetText(5, temp.Format("[%s] %s", sectionName.GetText(), GetValue(n, s.is.SectionNumber).data()));

        String sectionType;
        GetSymbolType(s.is.Type, sectionType);
        item.SetText(6, temp.Format("[%s] %s", sectionType.GetText(), GetValue(n, s.is.Type).data()));

        String storageClass;
        GetStorageClass(s.is.StorageClass, storageClass);
        item.SetText(7, temp.Format("[%s] %s", storageClass.GetText(), GetValue(n, s.is.StorageClass).data()));

        item.SetText(8, GetValue(n, s.is.NumberOfAuxSymbols));
    }
}

bool Panels::Symbols::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    if (this->Base == 10)
    {
        commandBar.SetCommand(Key::F2, "Dec", PE_SYMBOLS_CHANGEBASE);
    }
    else
    {
        commandBar.SetCommand(Key::F2, "Hex", PE_SYMBOLS_CHANGEBASE);
    }

    return true;
}

bool Panels::Symbols::OnEvent(Reference<Control> ctrl, Event evnt, int controlID)
{
    if (TabPage::OnEvent(ctrl, evnt, controlID))
    {
        return true;
    }

    if (evnt == Event::Command)
    {
        switch (controlID)
        {
        case PE_SYMBOLS_CHANGEBASE:
            this->Base = 26 - this->Base;
            Update();
            return true;
        default:
            break;
        }
    }

    return false;
}