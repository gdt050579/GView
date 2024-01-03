#include "MachO.hpp"

using namespace AppCUI::Controls;

constexpr auto ID_CHECKBOX_ALL    = 0x1001U;
constexpr auto ID_CHECKBOX_HEADER = 0x1002U;
constexpr auto ID_CHECKBOX_CALL   = 0x1003U;
constexpr auto ID_CHECKBOX_JMP    = 0x1005U;
constexpr auto ID_CHECKBOX_BP     = 0x1007U;
constexpr auto ID_CHECKBOX_FSTART = 0x1008U;
constexpr auto ID_CHECKBOX_FEND   = 0x1009U;

namespace GView::Type::MachO::Panels
{
OpCodes::OpCodes(Reference<Object> _object, Reference<GView::Type::MachO::MachOFile> _macho) : TabPage("Op&Codes"), object(_object), macho(_macho)
{
    value = Factory::Label::Create(this, "Mask", "x:1,y:1,w:60");

    list = Factory::ListView::Create(
          this, "x:1,y:2,h:20,w:60", { "n:Enabled,a:l,w:60" }, AppCUI::Controls::ListViewFlags::CheckBoxes | AppCUI::Controls::ListViewFlags::HideSearchBar);

    all = list->AddItem("All");
    all.SetData(ID_CHECKBOX_ALL);

    header = list->AddItem("Executable header(s)");
    header.SetColor(MachO::EXE_MARKER_COLOR);
    header.SetData(ID_CHECKBOX_HEADER);

    call = list->AddItem("CALL API");
    call.SetColor(MachO::INS_CALL_COLOR);
    call.SetData(ID_CHECKBOX_CALL);

    jmp = list->AddItem("JMP API");
    jmp.SetColor(MachO::INS_JUMP_COLOR);
    jmp.SetData(ID_CHECKBOX_JMP);

    bp = list->AddItem("Breakpoint");
    bp.SetColor(MachO::INS_BREAKPOINT_COLOR);
    bp.SetData(ID_CHECKBOX_BP);

    fstart = list->AddItem("Function Start");
    fstart.SetColor(MachO::START_FUNCTION_COLOR);
    fstart.SetData(ID_CHECKBOX_FSTART);

    fend = list->AddItem("Function End");
    fend.SetColor(MachO::END_FUNCTION_COLOR);
    fend.SetData(ID_CHECKBOX_FEND);

    Update();
}

void OpCodes::Update()
{
    macho->showOpcodesMask = 0;
    auto settings          = Application::GetAppSettings();
    if (settings->HasSection("Type.MACHO"))
    {
        auto pe       = settings->GetSection("Type.MACHO");
        auto optValue = pe["OpCodes.Mask"];
        if (optValue.HasValue())
        {
            auto optUInt32 = optValue.AsUInt32();
            if (optUInt32.has_value())
            {
                macho->showOpcodesMask = *optUInt32;
            }
        }
    }

    header.SetCheck((macho->showOpcodesMask >> 0) & 1U);
    call.SetCheck((macho->showOpcodesMask >> 1) & 1U);
    jmp.SetCheck((macho->showOpcodesMask >> 3) & 1U);
    bp.SetCheck((macho->showOpcodesMask >> 5) & 1U);
    fstart.SetCheck((macho->showOpcodesMask >> 6) & 1U);
    fend.SetCheck((macho->showOpcodesMask >> 7) & 1U);

    all.SetCheck(AllChecked());

    SetMaskText();
}

bool OpCodes::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    return false;
}

inline bool OpCodes::AllChecked()
{
    return header.IsChecked() && call.IsChecked() && jmp.IsChecked() && bp.IsChecked() && fstart.IsChecked() && fend.IsChecked();
}

inline bool OpCodes::AllUnChecked()
{
    return !AllChecked();
}

inline void OpCodes::SetMaskText()
{
    auto settings = Application::GetAppSettings();
    if (settings->HasSection("Type.MACHO"))
    {
        auto pe        = settings->GetSection("Type.MACHO");
        auto optValue  = pe["OpCodes.Mask"];
        uint32 mask    = 0;
        auto optUInt32 = optValue.AsUInt32();
        if (optValue.HasValue() && optUInt32.has_value())
        {
            mask = *optUInt32;
            LocalString<32> ls;
            value->SetText(ls.Format("Mask: 0x%X", mask));
        }
        else
        {
            value->SetText("Mask: 0x0");
        }
    }
}

inline void OpCodes::SetConfig(bool checked, uint16 position)
{
    auto settings = Application::GetAppSettings();
    if (settings->HasSection("Type.MACHO"))
    {
        auto viewBuffer = settings->GetSection("Type.MACHO");
        auto optValue   = viewBuffer["OpCodes.Mask"];
        uint32 value    = 0;
        if (optValue.HasValue())
        {
            value = *optValue.AsUInt32();
        }
        if (checked)
        {
            value |= 1UL << position;
        }
        else
        {
            value &= ~(1UL << position);
        }
        viewBuffer["OpCodes.Mask"] = value;

        settings->Save(Application::GetAppSettingsFile());
    }

    Update();
}

bool OpCodes::OnEvent(Reference<Control>, Event evnt, int controlID)
{
    CHECK(evnt == Event::ListViewItemChecked, false, "");
    const auto& item = list->GetCurrentItem();
    const auto& id   = item.GetData(-1);

    switch (id)
    {
    case ID_CHECKBOX_ALL:
    {
        const auto isChecked = all.IsChecked();

        header.SetCheck(isChecked);
        call.SetCheck(isChecked);
        jmp.SetCheck(isChecked);
        bp.SetCheck(isChecked);
        fstart.SetCheck(isChecked);
        fend.SetCheck(isChecked);

        auto settings = Application::GetAppSettings();
        if (settings->HasSection("Type.MACHO"))
        {
            auto viewBuffer            = settings->GetSection("Type.MACHO");
            viewBuffer["OpCodes.Mask"] = isChecked ? 0xFFFFFFFF : 0;
            settings->Save(Application::GetAppSettingsFile());
        }

        Update();

        return true;
    }
    case ID_CHECKBOX_HEADER:
    {
        all.SetCheck(AllChecked());
        SetConfig(header.IsChecked(), 0);
        return true;
    }
    case ID_CHECKBOX_CALL:
    {
        all.SetCheck(AllChecked());
        SetConfig(call.IsChecked(), 1);
        return true;
    }
    case ID_CHECKBOX_JMP:
    {
        all.SetCheck(AllChecked());
        SetConfig(jmp.IsChecked(), 3);
        return true;
    }
    case ID_CHECKBOX_BP:
    {
        all.SetCheck(AllChecked());
        SetConfig(bp.IsChecked(), 5);
        return true;
    }
    case ID_CHECKBOX_FSTART:
    {
        all.SetCheck(AllChecked());
        SetConfig(fstart.IsChecked(), 6);
        return true;
    }
    case ID_CHECKBOX_FEND:
    {
        all.SetCheck(AllChecked());
        SetConfig(fend.IsChecked(), 7);
        return true;
    }
    default:
        break;
    }

    return false;
}
} // namespace GView::Type::MachO::Panels
